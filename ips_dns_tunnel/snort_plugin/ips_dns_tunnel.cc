//--------------------------------------------------------------------------
// Copyright (C) 2014-2019 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------

// ips_dns_tunnel.cc authors
//    Damian Chilinski <damian.chilinski@traffordit.pl>
//    Artur Brodzki <artur@brodzki.org>

#include <cstdio>
#include "framework/decode_data.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "framework/range.h"
#include "framework/cursor.h"
#include "hash/hashfcn.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "protocols/udp.h"
#include <math.h>

using namespace snort;

static const char* s_name = "dns_tunnel";
static const char* s_help = "alert on suspicious DNS queries activity";

static THREAD_LOCAL ProfileStats dns_tunnel_perf_stats;

//-------------------------------------------------------------------------
// helpers
//-------------------------------------------------------------------------

#define MAX_NGRAM_LEN 5
#define DEFAULT_SCORE 0
#define MIN_DNS_SIZE 12
#define INIT_NGRAM_NUM 32768
#define INIT_WLIST_SIZE 4







enum DnsLogLevel {
  DNS_LOG_OFF = 0,
  DNS_LOG_STARTUP = 1,
  DNS_LOG_STARTUP_VERBOSE = 2,
  DNS_LOG_INFO_BAD = 3,
  DNS_LOG_INFO_ALL = 4,
  DNS_LOG_DEBUG = 5,
  DNS_LOG_DEBUG_FULL = 6
};

#define DnsLog_log(msg_level, ...)\
  if (config.verbose>=msg_level && logfile){\
    if (config.logprefix)\
      fprintf(logfile,"DNS-DEBUG: [%s] <%d> | ",config.logprefix,msg_level);\
    else \
      fprintf(logfile,"DNS-DEBUG: <%d> | ",msg_level);\
    fprintf(logfile,__VA_ARGS__);\
  }


//--------------------------

unsigned long djb2(unsigned const char *str){
  unsigned long hash = 5381;
  int c;

  while (c = *str++)
    hash = ((hash << 5) + hash) + c;

  return hash;
}

struct DnsTunnelModuleParams {
  u_int8_t verbose;         //verbose level
  const char* logfile;
  const char* logprefix;
};

struct DnsTunnelOptionParams {
  double    scorethreshold; //min score to consider domain not malicious
  u_int32_t sizethreshold;  //total length of negatively classified queries to consider domain malicious
  u_int32_t maxbuffersize;  //max total length of buffered requests
  u_int8_t minbufferlen;    //min number of buffered requests (more important than maxbuffersize)
  u_int8_t windowsize;      //size of classification window
  u_int8_t minreqsize;      //minimum subdomain size required to start prediction
  u_int32_t bucketlen;      //size of domains bucket
  u_int8_t verbose;         //verbose level
  char* datafile;     //file with n-gram weights
  char* whitelist;
  char* logfile;
  char* logprefix;
};

struct DnsTunnelNgFreqRecord {
  double score;
  char ng[MAX_NGRAM_LEN];         //minimize memory fragmentation
};

struct DnsTunnelNgFreqs {
  struct DnsTunnelNgFreqRecord* data;   //ngrams freq data
  u_int32_t ngnum;                //ngram list length
  u_int8_t nglen;                 //ngram record length
};

enum DnsTunnelDnsReputation {
  BAD = 0,
  UNKNOWN = 1,
  GOOD = 2
};

struct DnsTunnelDnsRankRecordSub {
  struct DnsTunnelDnsRankRecordSub* next;
  char* domain;
  u_int8_t len;
  bool bad;
};

struct DnsTunnelDnsRankRecord {
  char* domain;
  struct DnsTunnelDnsRankRecord* next;
  struct DnsTunnelDnsRankRecordSub* subdomain;
  u_int8_t off;
  enum DnsTunnelDnsReputation rep;
};

struct DnsTunnelDnsRank {
  u_int32_t recnum;
  struct DnsTunnelDnsRankRecord** data;
};

struct DnsTunnelPacket {
  struct Question {
    u_int8_t qlen;
    unsigned char* qname;
    u_int16_t qtype;
    u_int16_t qclass;
  };

  DnsTunnelPacket(Packet*p);
  ~DnsTunnelPacket();

  u_int16_t id;
  u_int16_t flags;
  u_int16_t question_num;
  u_int16_t answer_num;
  u_int16_t authority_num;
  u_int16_t additional_num;
  std::vector<DnsTunnelPacket::Question> questions;
  bool malformed = false;
};

DnsTunnelPacket::DnsTunnelPacket(Packet *p) :
  id            ((p->data[0] << 8) + p->data[1] ),
  flags         ((p->data[2] << 8) + p->data[3] ),
  question_num  ((p->data[4] << 8) + p->data[5] ),
  answer_num    ((p->data[6] << 8) + p->data[7] ),
  authority_num ((p->data[8] << 8) + p->data[9] ),
  additional_num((p->data[10]<< 8) + p->data[11]),
  malformed     (false),
  questions     ()   //1 would be sufficient tbh
{
  //printf("RAW: \n");
  //for (int i = 0 ; i < p->dsize ; ++i)
  //  printf("%02d ",p->data[i]);
  //printf("RAW= \n");
  int cur = 12;
  for (int i = 0 ; i < this->question_num ; ++i){
      struct DnsTunnelPacket::Question q = {0,nullptr,0,0};
      unsigned char buf[255];
      buf[0]=0;

      //printf("DNS-DEBUG: cur: %d size: %d\n",cur,p->dsize);

      while(cur < p->dsize && p->data[cur] && cur+p->data[cur] < p->dsize){
        //printf("DNS-DEBUG: cur: %d exp len: %d buf %s|\n",cur,p->data[cur],buf);

        strncat((char*)&buf[q.qlen],(char*)&(p->data[cur+1]),p->data[cur]);
        q.qlen += p->data[cur]+1;
        strcat((char*)&buf[q.qlen-1],".");
        cur += 1+p->data[cur];

        //printf("DNS-DEBUG: newcur: %d buf %s|\n",cur,buf);
      }

      //printf("DNS-DEBUG: done cur: %d size: %d\n",cur,p->dsize);

      if (p->data[cur] != 0 || cur+5 > p->dsize){
        malformed = true;
        break;
      }

      q.qtype =   (p->data[cur+1]<<8) + p->data[cur+2];
      q.qclass =  (p->data[cur+3]<<8) + p->data[cur+4];
      cur+=5;

      unsigned char* qname = (unsigned char*)malloc((q.qlen+1)*sizeof(char));
      memcpy(qname,buf,q.qlen+1);
      unsigned char *c = qname;
      while (*c)
        *c++=tolower(*c);
      q.qname = qname;
      questions.push_back(q);
  }
}

DnsTunnelPacket::~DnsTunnelPacket(){
  for (int i = 0 ; i < question_num ; ++i)
    free(questions[i].qname);
}

//-------------------------------------------------------------------------
// option
//-------------------------------------------------------------------------

class DnsTunnelOption : public IpsOption
{
public:
    DnsTunnelOption(const DnsTunnelOptionParams& c, const DnsTunnelNgFreqs &f, char **wlist);
    ~DnsTunnelOption();

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    EvalStatus eval(Cursor&, Packet*p) override;

    unsigned long ngBinSearch(const char* s);
    struct DnsTunnelDnsRankRecord* pushDnsRecord(const char* s, u_int8_t off);
    u_int32_t pushDnsRecordSub(const char* s, u_int8_t len, struct DnsTunnelDnsRankRecord* r);
    double getNgScore(char* s, u_int8_t);
    bool isBad(char* s);


private:
    struct DnsTunnelOptionParams config;
    struct DnsTunnelNgFreqs freqs;
    struct DnsTunnelDnsRank rank;
    FILE* logfile;
};

DnsTunnelOption::DnsTunnelOption(const DnsTunnelOptionParams &c, const DnsTunnelNgFreqs &f, char** wlist) : IpsOption(s_name){
  config.scorethreshold = c.scorethreshold;
  config.sizethreshold = c.sizethreshold;
  config.maxbuffersize = c.maxbuffersize;
  config.minbufferlen = c.minbufferlen;
  config.windowsize = c.windowsize;
  config.minreqsize = c.minreqsize;
  config.bucketlen = c.bucketlen;
  config.datafile = c.datafile;
  config.whitelist = c.whitelist;
  config.logfile = c.logfile;
  config.logprefix = c.logprefix;
  config.verbose = c.verbose;

  if (config.logfile) logfile = fopen(config.logfile, "a");
  else logfile = stdout;
  setbuf(logfile, nullptr);

  DnsLog_log(DNS_LOG_STARTUP,"--- CTOR-Option\n");

  freqs.ngnum = f.ngnum;
  freqs.nglen = f.nglen;
  freqs.data = f.data;

  rank.recnum = config.bucketlen;
  rank.data = (struct DnsTunnelDnsRankRecord**)malloc(sizeof(struct DnsTunnelDnsRankRecord*)*rank.recnum);
  for (int i = 0 ; i < rank.recnum ; ++i)
    rank.data[i] = nullptr;

  if (wlist){
    while (*wlist){
      DnsLog_log(DNS_LOG_STARTUP,"--- CTOR-Option::wlist : %s\n", *wlist);
      struct DnsTunnelDnsRankRecord* r = pushDnsRecord(*wlist,0);
      if (r != nullptr)
        r->rep = DnsTunnelDnsReputation::GOOD;
      free(*wlist);
      ++wlist;
    }
  }
}

DnsTunnelOption::~DnsTunnelOption(){
   free(freqs.data);
}

/* USED TO DETECT EXACTLY THE SAME RULE ENTRIES, AVOIDS DUPLICATION */
uint32_t DnsTunnelOption::hash() const
{
    DnsLog_log(DNS_LOG_STARTUP,"--- CTOR-Option::hash\n");
    uint32_t a, b, c;

    a = config.sizethreshold+(64*config.maxbuffersize)*config.scorethreshold;
    b = config.windowsize+(255*config.minbufferlen);
    c = freqs.ngnum*freqs.nglen;

    mix_str(a,b,c,get_name());
    finalize(a,b,c);

    DnsLog_log(DNS_LOG_STARTUP,"--- CTOR-Option::hash-exit %d\n",c);

    return c;
}

/* USED TO DETECT EXACTLY THE SAME RULE ENTRIES, AVOIDS DUPLICATION */
bool DnsTunnelOption::operator==(const IpsOption& ips) const
{
    DnsLog_log(DNS_LOG_STARTUP,"--- CTOR-Option::operator==\n");
    if ( strcmp(s_name, ips.get_name()) )
        return false;

    const DnsTunnelOption& rhs = (const DnsTunnelOption&)ips;
    int ret = (
          false &&    //this significantly simplifies memory deallocation
          config.scorethreshold == rhs.config.scorethreshold &&
          config.sizethreshold == rhs.config.sizethreshold &&
          config.maxbuffersize == rhs.config.maxbuffersize &&
          config.minbufferlen == rhs.config.minbufferlen &&
          config.windowsize == rhs.config.windowsize &&
          config.minreqsize == rhs.config.minreqsize &&
          config.bucketlen == rhs.config.bucketlen &&
          config.verbose == rhs.config.verbose &&
          (config.whitelist == rhs.config.whitelist ||
           (config.whitelist != nullptr && rhs.config.whitelist != nullptr &&
            strcmp(config.whitelist,rhs.config.whitelist) == 0)) &&
          strcmp(config.datafile,rhs.config.datafile) == 0 &&
          strcmp(config.logfile,rhs.config.logfile) == 0 &&
          strcmp(config.logprefix,rhs.config.logprefix) == 0);

    DnsLog_log(DNS_LOG_STARTUP,"--- CTOR-Option::operator== (%d)\n",ret);
    return ret;
}

unsigned long DnsTunnelOption::ngBinSearch(const char *s){
  int b = 0;
  int m, ret;
  int t = freqs.ngnum - 1;

  while(b <= t){
    m = (b + t)/2;
    if ((ret = strncmp(freqs.data[m].ng, s, freqs.nglen)) == 0) return m;
    else if (ret > 0) t = m - 1;
    else if (ret < 0) b = m + 1;
  }
  return freqs.ngnum; //not found
}

struct DnsTunnelDnsRankRecord* DnsTunnelOption::pushDnsRecord(const char *s, u_int8_t off){
  unsigned long pos = djb2((const unsigned char*)s+off) % rank.recnum;
  struct DnsTunnelDnsRankRecord** r = &rank.data[pos];

  while (*r != nullptr && strcmp((*r)->domain,s+off) != 0)
    r = &((*r)->next);

  if (*r != nullptr){
    DnsLog_log(DNS_LOG_DEBUG,". . -- pushRecord : found [%s] == [%s] (%s)\n",(*r)->domain, s+off, s);
    return *r;
  }

  if ((*r = (struct DnsTunnelDnsRankRecord*)malloc(sizeof(struct DnsTunnelDnsRankRecord))) == nullptr)
    return nullptr;
  if (((*r)->domain = (char*)malloc(strlen(s+off)+1)) == nullptr){
    free(*r);
    *r = nullptr;
    return nullptr;
  }
  strcpy((*r)->domain,s+off);
  (*r)->next = nullptr;
  (*r)->subdomain = nullptr;
  (*r)->off = off;
  (*r)->rep = DnsTunnelDnsReputation::UNKNOWN;

  DnsLog_log(DNS_LOG_DEBUG,". . -- pushRecord : new [%s]\n",(*r)->domain);

  return *r;
}

double DnsTunnelOption::getNgScore(char *s, u_int8_t len){
  double worst = INFINITY;
  int off = 0;
  if (len < config.minreqsize)
    return 0;
  if (len < config.windowsize){
    double score = 0;
    for (int i = 0 ; i <= len-freqs.nglen ; ++i){
      unsigned long ind = ngBinSearch(s+off+i);
      if (ind < freqs.ngnum){
        DnsLog_log(DNS_LOG_DEBUG_FULL,". . . -- getNgScore : [%s] %lf\n",freqs.data[ind].ng,freqs.data[ind].score);
        score+=freqs.data[ind].score;
      } else
        DnsLog_log(DNS_LOG_DEBUG_FULL,". . . -- getNgScore : [unknown] 0\n");
    }
    DnsLog_log(DNS_LOG_DEBUG_FULL,". . . -- ngShortScore : %lf\n",score);
    return score;
  } else {
    DnsLog_log(DNS_LOG_DEBUG_FULL,". . . -- ngVariantB\n");
    while (off <= len-config.windowsize){
      double score = 0;

      for (int i = 0 ; i <= config.windowsize-freqs.nglen ; ++i){
        unsigned long ind = ngBinSearch(s+off+i);
        if (ind < freqs.ngnum){
          DnsLog_log(DNS_LOG_DEBUG_FULL,". . . -- getNgScore : [%s] %lf\n",freqs.data[ind].ng,freqs.data[ind].score);
          score+=freqs.data[ind].score;
        } else
          DnsLog_log(DNS_LOG_DEBUG_FULL,". . . -- getNgScore : [unknown] 0\n");
      }
      off++;
      DnsLog_log(DNS_LOG_DEBUG_FULL,". . . -- ngLongScore : %lf\n",score);
      if (score < worst)
        worst = score;
    }
    return worst;
  }
  return 0;
}

u_int32_t DnsTunnelOption::pushDnsRecordSub(const char *s, u_int8_t len, struct DnsTunnelDnsRankRecord *r){
  struct DnsTunnelDnsRankRecordSub** b = &r->subdomain;
  u_int32_t totlen = 0;
  u_int32_t badlen = 0;
  u_int8_t subnum = 0;
  while (*b != nullptr && ((*b)->len != len || memcmp((*b)->domain,s,len) != 0)){
    totlen+=(*b)->len;
    ++subnum;
    if ((*b)->bad)
      badlen+=(*b)->len;
    b = &((*b)->next);
  }

  DnsLog_log(DNS_LOG_DEBUG_FULL,". . -- pushRecordSub : badlen before %d\n",badlen);

  if (*b == nullptr){   //not found
    DnsLog_log(DNS_LOG_DEBUG,". . -- pushRecordSub : not found [%s] %d\n",s,len);
    if ((*b = (struct DnsTunnelDnsRankRecordSub*)malloc(sizeof(struct DnsTunnelDnsRankRecordSub))) == nullptr)
      return -1;
    if (((*b)->domain = (char*)malloc(len+1)) == nullptr){
      free(*b);
      *b = nullptr;
      return -1;
    }
    strncpy((*b)->domain,s,len);
    (*b)->domain[len]=0;
    (*b)->len = len;
    (*b)->next = nullptr;
    (*b)->bad = false;

    double score = getNgScore((*b)->domain, len);
    if (score < config.scorethreshold){
      DnsLog_log(DNS_LOG_INFO_BAD,". . -- pushRecordSub : score %lf [%s/%s] (%d/%d %d/%d %d/%d)\n",
                 score, (*b)->domain, s+len, badlen+(score<config.scorethreshold?len:0),
                 config.sizethreshold,totlen,config.maxbuffersize,subnum,config.minbufferlen);
      (*b)->bad = true;
    }
  } else
    DnsLog_log(DNS_LOG_DEBUG,". . -- pushRecordSub : found [%s] %d\n",(*b)->domain,len);

  while (*b != nullptr){
    totlen+=(*b)->len;
    ++subnum;
    if ((*b)->bad)
      badlen+=(*b)->len;
    b = &((*b)->next);
  }

  while (totlen > config.maxbuffersize && subnum > config.minbufferlen){
    b = &r->subdomain;
    DnsLog_log(DNS_LOG_DEBUG,". . -- pushRecordSub : cleanup [%s]\n",(*b)->domain);
    struct DnsTunnelDnsRankRecordSub* bb = (*b)->next;
    totlen-=(*b)->len;
    --subnum;
    free((*b)->domain);
    free(*b);
    *b = bb;
  }

  DnsLog_log(DNS_LOG_DEBUG,". . -- pushRecordSub : badlen after %d\n",badlen);

  return badlen;
}

bool DnsTunnelOption::isBad(char *s){
  u_int8_t dot1 = 0,
           dot2 = 0,
           dot3 = 0,
           c = 0;
  char* cur = s;
  struct DnsTunnelDnsRankRecord* r;

  DnsLog_log(DNS_LOG_DEBUG_FULL,". -- isBad : get dots [%s]\n",s);

  while (s[c]){
    if (s[c] == '.'){
      dot3 = dot2;
      dot2 = dot1;
      dot1 = c;
    }
    ++c;
  }

  DnsLog_log(DNS_LOG_DEBUG_FULL,". -- isBad : dots %d %d %d [%s]\n",dot3, dot2, dot1,s);

  if (!dot3){
    DnsLog_log(DNS_LOG_DEBUG,". -- isBad : skipped [%s]\n",s);
    return 0;
  }

  s[dot1]=0;
  r = pushDnsRecord(s,dot3+1);
  if (r == nullptr || r->rep == DnsTunnelDnsReputation::BAD){
    DnsLog_log(DNS_LOG_INFO_BAD,r!=nullptr?". -- isBad : early BAD [%s]\n":". -- isBad : FAIL [%s]\n",s);
    return true;
  }

  if (r->rep == DnsTunnelDnsReputation::GOOD){
    DnsLog_log(DNS_LOG_INFO_ALL,". -- isBad : early GOOD [%s]\n",s);
    return false;
  }

  if (pushDnsRecordSub(s,dot3,r) > config.sizethreshold){
    DnsLog_log(DNS_LOG_INFO_BAD,". -- isBad : late BAD [%s]\n",s);
    r->rep = DnsTunnelDnsReputation::BAD;
  } else
    DnsLog_log(DNS_LOG_INFO_ALL,". -- isBad : late GOOD [%s]\n",s);

  return r->rep == DnsTunnelDnsReputation::BAD;
}

/* HERE WE PERFORM ACTUAL MATCHING */
IpsOption::EvalStatus DnsTunnelOption::eval(Cursor& c, Packet*p)
{
    DnsLog_log(DNS_LOG_DEBUG_FULL,"eval : begin\n");
    Profile profile(dns_tunnel_perf_stats);
    if ( p->is_udp() && p->has_udp_data() && p->dsize >= MIN_DNS_SIZE){
      DnsTunnelPacket pkt = DnsTunnelPacket(p);
      DnsLog_log(DNS_LOG_DEBUG_FULL,"-- eval : query size: %d questions:%d\n",p->dsize,pkt.question_num);

      if (!pkt.malformed) {
        for(int i = 0 ; i < pkt.questions.size() ; ++i){
          DnsLog_log(DNS_LOG_DEBUG_FULL,"-- eval : question enter %d : [%s]\n",i,pkt.questions[i].qname);
          if (isBad((char*)pkt.questions[i].qname)){
            DnsLog_log(DNS_LOG_DEBUG_FULL,"-- eval : exit MATCH %d : [%s]\n",i,pkt.questions[i].qname);
            return MATCH;
          }
          DnsLog_log(DNS_LOG_DEBUG_FULL,"-- eval : exit NO_MATCH %d : [%s]\n",i,pkt.questions[i].qname);
        }
        return NO_MATCH;
      }
    }
    DnsLog_log(DNS_LOG_DEBUG_FULL,"eval : exit FAIL\n");

    return MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "scorethreshold", Parameter::PT_REAL, nullptr, "Min domain score to be considered not malicious" },
    { "sizethreshold",  Parameter::PT_INT, "1:", nullptr, "Total length of negatively classified queries required to consider domain malicious" }, //name, type, range, default, description
    { "maxbuffersize",  Parameter::PT_INT, "32:", nullptr, "Max total length of buffered requests per domain" },
    { "minbufferlen",   Parameter::PT_INT, "1:200", nullptr, "Min number of buffered requests per domain" },
    { "windowsize",     Parameter::PT_INT, "4:32", nullptr, "domain analyze window size" },
    { "minreqsize",     Parameter::PT_INT, "1:32", nullptr, "Min subdomain length required to perform analyzis" },
    { "bucketlen",      Parameter::PT_INT, "1024:", nullptr, "Bucket size for domains storage" },
    { "verbose",        Parameter::PT_INT, "1:8", nullptr, "Verbosity level (requires logfile)" },
    { "datafile",       Parameter::PT_STRING, nullptr, nullptr, "File with n-gram scores" },
    { "whitelist",      Parameter::PT_STRING, nullptr, nullptr, "File with whitelisted domains" },
    { "logfile",        Parameter::PT_STRING, nullptr, nullptr, "Log file" },
    { "logprefix",      Parameter::PT_STRING, nullptr, nullptr, "Log prefix" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr } //i guess it's the end of params?
};

class DnsTunnelModule : public Module
{
public:
    DnsTunnelModule();

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &dns_tunnel_perf_stats; }

    Usage get_usage() const override
    { return DETECT; }

    bool readDataFile(const char* filename);
    bool readWhitelist(const char* filename);

public:
    struct DnsTunnelModuleParams config;
    struct DnsTunnelOptionParams nconfig;
    struct DnsTunnelNgFreqs nfreqs;
    char** nwlist;
    FILE* logfile;
};

DnsTunnelModule::DnsTunnelModule() : Module(s_name, s_help, s_params){
  logfile = stdout;
  config.verbose = DNS_LOG_STARTUP;
  config.logprefix = "global";
  DnsLog_log(DNS_LOG_STARTUP,"--- CTOR-Module::New\n");
}

/* HERE WE INITIALIZE IPS OPTION PARAMS */
bool DnsTunnelModule::begin(const char*, int, SnortConfig*)
{
    DnsLog_log(DNS_LOG_STARTUP,"--- CTOR-Module::Begin\n");
    nconfig.scorethreshold = 0;
    nconfig.sizethreshold = 32;
    nconfig.maxbuffersize = 256;
    nconfig.minbufferlen = 20;
    nconfig.windowsize = 12;
    nconfig.minreqsize = 3;
    nconfig.bucketlen = 8192;
    nconfig.verbose = 0;
    nconfig.datafile = nullptr;
    nconfig.whitelist = nullptr;
    nconfig.logfile = nullptr;
    nconfig.logprefix = nullptr;
    nfreqs.data = nullptr;
    nfreqs.ngnum = 0;
    nfreqs.nglen = 0;
    return true;
}

/* HERE WE READ IPS OPTION PARAMS */
bool DnsTunnelModule::set(const char*, Value& v, SnortConfig*)
{
    DnsLog_log(DNS_LOG_STARTUP,"--- CTOR-Module::Set\n");
    if ( v.is("scorethreshold") )
      nconfig.scorethreshold = v.get_real();  //hope it works the way I think it does...
    if ( v.is("sizethreshold") )
      nconfig.sizethreshold = v.get_uint32();
    else if ( v.is("maxbuffersize") )
      nconfig.maxbuffersize = v.get_uint32();
    else if ( v.is("minbufferlen") )
      nconfig.minbufferlen = v.get_uint8();
    else if ( v.is("windowsize") )
      nconfig.windowsize = v.get_uint8();
    else if ( v.is("bucketlen") )
      nconfig.bucketlen = v.get_uint32();
    else if ( v.is("verbose") )
      nconfig.verbose = v.get_uint8();
    else if ( v.is("logfile") ){
      if (nconfig.logfile != nullptr)
        return false;

      const char* s = v.get_string();
      nconfig.logfile = (char*)malloc(strlen(s)+1);
      strcpy(nconfig.logfile,s);
    }
    else if ( v.is("logprefix") ){
      if (nconfig.logprefix != nullptr)
        return false;

      const char* s = v.get_string();
      nconfig.logprefix = (char*)malloc(strlen(s)+1);
      strcpy(nconfig.logprefix,s);
    }
    else if ( v.is("datafile") ){
      if (nconfig.datafile != nullptr)
        return false;

      const char* s = v.get_string();
      nconfig.datafile = (char*)malloc(strlen(s)+1);
      strcpy(nconfig.datafile,s);

      return this->readDataFile(nconfig.datafile);
    }
    else if ( v.is("whitelist") ){
      if (nconfig.whitelist != nullptr)
        return false;

      const char* s = v.get_string();
      nconfig.whitelist = (char*)malloc(strlen(s)+1);
      strcpy(nconfig.whitelist,s);

      return this->readWhitelist(nconfig.whitelist);
    }
    else
      return false;

    return true;
}

/* SANITY CHECKS */
bool DnsTunnelModule::end(const char*, int, SnortConfig*){
  DnsLog_log(DNS_LOG_STARTUP,"--- CTOR-Module::End\n");
  if (nconfig.datafile == nullptr){
    DnsLog_log(DNS_LOG_STARTUP,"--- CTOR-Module::End::ERROR filename\n");
    return false;
  }
  if (nconfig.minreqsize < nfreqs.nglen){
    DnsLog_log(DNS_LOG_STARTUP,"--- CTOR-Module::End::ERROR minreqsize lower than ngram length (%d < %d)\n",nconfig.minreqsize,nfreqs.nglen);
    return false;
  }
  if (nconfig.windowsize < nfreqs.nglen){
    DnsLog_log(DNS_LOG_STARTUP,"--- CTOR-Module::End::ERROR windowsize lower than ngram length (%d >= %d)\n",nconfig.windowsize,nfreqs.nglen);
    return false;
  }

  return true;
}

bool DnsTunnelModule::readDataFile(const char *filename){
  DnsLog_log(DNS_LOG_STARTUP,"--- CTOR-Module::ReadDataFile (%s)\n",filename);
  char ng[255];
  double score;

  FILE *fp;

  if((fp = fopen(filename, "r")) == NULL)
      return false;

  int csize = INIT_NGRAM_NUM;
  int len, ret;
  nfreqs.data = (struct DnsTunnelNgFreqRecord*)malloc(sizeof(struct DnsTunnelNgFreqRecord)*csize);
  if (nfreqs.data == nullptr)
    return false;

  DnsLog_log(DNS_LOG_STARTUP,"--- CTOR-Module::ReadDataFile::beginRead\n");

  while (true) {
    DnsLog_log(DNS_LOG_STARTUP_VERBOSE,"--- CTOR-Module::ReadDataFile::line\n");
    if (nfreqs.ngnum == csize){
      DnsLog_log(DNS_LOG_STARTUP,"--- CTOR-Module::ReadDataFile::realloc\n");
      struct DnsTunnelNgFreqRecord* newreq = (struct DnsTunnelNgFreqRecord*)realloc(nfreqs.data, sizeof(struct DnsTunnelNgFreqRecord)*csize*2);
      if (newreq == nullptr){
        free(nfreqs.data);
        nfreqs.data = nullptr;
        return false;
      }
      nfreqs.data = newreq;
      csize*=2;
    }

    ret = fscanf(fp, "%[^,],%lf\n", ng, &score);
    DnsLog_log(DNS_LOG_STARTUP_VERBOSE,"--- CTOR-Module::ReadDataFile::fscanf %d %d %s %lf\n",nfreqs.nglen,ret,ng,score);
    if (ret != 2)
      break;
    len = strlen(ng);
    if (nfreqs.nglen == 0)
      nfreqs.nglen = len;
    else if (nfreqs.nglen != len){
      DnsLog_log(DNS_LOG_STARTUP,"--- CTOR-Module::ReadDataFile::fail\n");
      free(nfreqs.data);
      nfreqs.data = nullptr;
      return false;
    }

    nfreqs.data[nfreqs.ngnum].score = score;
    nfreqs.data[nfreqs.ngnum].ng[0] = 0;
    strncat(nfreqs.data[nfreqs.ngnum].ng,ng,MAX_NGRAM_LEN);
    DnsLog_log(DNS_LOG_STARTUP_VERBOSE,"--- CTOR-Module::ReadDataFile::freqs %s : %lf", nfreqs.data[nfreqs.ngnum].ng, score);
    ++nfreqs.ngnum;
  }
  fclose(fp);

  DnsLog_log(DNS_LOG_STARTUP,"--- CTOR-Module::ReadDataFile::success (%d)\n",nfreqs.ngnum);

  return true;
}

bool DnsTunnelModule::readWhitelist(const char *filename){
  DnsLog_log(DNS_LOG_STARTUP,"--- CTOR-Module::ReadWhiteList (%s)\n",filename);
  char dom[255];

  FILE *fp;

  if((fp = fopen(filename, "r")) == NULL)
      return false;

  int csize = INIT_WLIST_SIZE;
  int cur = 0;
  int len, ret;
  nwlist = (char**)malloc(sizeof(char*)*csize);
  if (nwlist == nullptr)
    return false;
  nwlist[cur]=nullptr;

  DnsLog_log(DNS_LOG_STARTUP,"--- CTOR-Module::ReadWhiteList::beginRead\n");

  while (true) {
    DnsLog_log(DNS_LOG_STARTUP_VERBOSE,"--- CTOR-Module::ReadWhiteList::line\n");
    if (cur == csize-1){
      DnsLog_log(DNS_LOG_STARTUP,"--- CTOR-Module::ReadWhiteList::realloc\n");
      char** newwlist = (char**)realloc(nwlist, sizeof(char*)*csize*2);
      if (newwlist == nullptr){
        free(nwlist);
        nwlist = nullptr;
        return false;
      }
      nwlist = newwlist;
      csize*=2;
    }

    ret = fscanf(fp, "%254s\n", dom);
    DnsLog_log(DNS_LOG_STARTUP_VERBOSE,"--- CTOR-Module::ReadWhiteList::fscanf %d %d %s\n",cur,ret,dom);
    if (ret != 1)
      break;
    len = strlen(dom);

    nwlist[cur] = (char*)malloc(sizeof(char)*len+1);
    nwlist[cur][0]=0;
    strncat(nwlist[cur],dom,255);
    DnsLog_log(DNS_LOG_STARTUP_VERBOSE,"--- CTOR-Module::ReadWhiteList::wlist %s", nwlist[cur]);
    ++cur;
    nwlist[cur]=0;
  }
  fclose(fp);

  DnsLog_log(DNS_LOG_STARTUP,"--- CTOR-Module::ReadWhiteList::success (%d)\n",cur);
  return true;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new DnsTunnelModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* dns_tunnel_ctor(Module* p, OptTreeNode*)
{
    DnsTunnelModule* m = (DnsTunnelModule*)p;
    return new DnsTunnelOption(m->nconfig, m->nfreqs, m->nwlist);
}

static void dns_tunnel_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi dns_tunnel_api =
{
    {
        PT_IPS_OPTION,
        sizeof(IpsApi),
        IPSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    1, PROTO_BIT__TCP,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    dns_tunnel_ctor,
    dns_tunnel_dtor,
    nullptr
};

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &dns_tunnel_api.base,
    nullptr
};

