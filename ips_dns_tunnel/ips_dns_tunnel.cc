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


unsigned long djb2(unsigned const char *str){
  unsigned long hash = 5381;
  int c;

  while (c = *str++)
    hash = ((hash << 5) + hash) + c;

  return hash;
}


struct DnsTunnelParams {
  u_int32_t threshold;      //total length of negatively classified queries to consider domain malicious
  u_int32_t maxbuffersize;  //max total length of buffered requests
  u_int8_t minbufferlen;    //min number of buffered requests (more important than maxbuffersize)
  u_int8_t windowsize;      //size of classification window
  u_int8_t minreqsize;      //minimum subdomain size required to start prediction
  u_int32_t bucketlen;      //size of domains bucket
  const char* datafile;
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
  bool bad;
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
    DnsTunnelOption(const DnsTunnelParams& c, const DnsTunnelNgFreqs &f);
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
    struct DnsTunnelParams config;
    struct DnsTunnelNgFreqs freqs;
    struct DnsTunnelDnsRank rank;
};

DnsTunnelOption::DnsTunnelOption(const DnsTunnelParams &c, const DnsTunnelNgFreqs &f) : IpsOption(s_name){
  printf("--- CTOR-Option\n");

  config.threshold = c.threshold;
  config.maxbuffersize = c.maxbuffersize;
  config.minbufferlen = c.minbufferlen;
  config.windowsize = c.windowsize;
  config.minreqsize = c.minreqsize;
  config.bucketlen = c.bucketlen;
  config.datafile = c.datafile;

  freqs.ngnum = f.ngnum;
  freqs.nglen = f.nglen;
  freqs.data = f.data;

  rank.recnum = config.bucketlen;
  rank.data = (struct DnsTunnelDnsRankRecord**)malloc(sizeof(struct DnsTunnelDnsRankRecord*)*rank.recnum);
  for (int i = 0 ; i < rank.recnum ; ++i)
    rank.data[i] = nullptr;
}

DnsTunnelOption::~DnsTunnelOption(){
   free(freqs.data);
}

/* USED TO DETECT EXACTLY THE SAME RULE ENTRIES, AVOIDS DUPLICATION */
uint32_t DnsTunnelOption::hash() const
{
    printf("--- CTOR-Option::hash\n");
    uint32_t a, b, c;

    a = config.threshold+(64*config.maxbuffersize);
    b = config.windowsize+(255*config.minbufferlen);
    c = freqs.ngnum*freqs.nglen;

    mix_str(a,b,c,get_name());
    finalize(a,b,c);

    printf("--- CTOR-Option::hash-exit %d\n",c);

    return c;
}

/* USED TO DETECT EXACTLY THE SAME RULE ENTRIES, AVOIDS DUPLICATION */
bool DnsTunnelOption::operator==(const IpsOption& ips) const
{
    printf("--- CTOR-Option::operator==\n");
    if ( strcmp(s_name, ips.get_name()) )
        return false;

    const DnsTunnelOption& rhs = (const DnsTunnelOption&)ips;
    int ret = (
          false &&    //this significantly simplifies memory deallocation
          config.threshold == rhs.config.threshold &&
          config.maxbuffersize == rhs.config.maxbuffersize &&
          config.minbufferlen == rhs.config.minbufferlen &&
          config.windowsize == rhs.config.windowsize &&
          config.minreqsize == rhs.config.minreqsize &&
          config.bucketlen == rhs.config.bucketlen &&
          strcmp(config.datafile,rhs.config.datafile) == 0);

    printf("--- CTOR-Option::operator== (%d)\n",ret);
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
    //printf("DNS-DEBUG pushRecord : found %s | %s (%s)\n",(*r)->domain, s+off, s);
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
  (*r)->bad = false;

  //printf("DNS-DEBUG pushRecord : new %s\n",(*r)->domain);

  return *r;
}

double DnsTunnelOption::getNgScore(char *s, u_int8_t len){
  double worst = INFINITY;
  int off = 0;
  if (len < config.minreqsize)
    return 0;
  while (off < len){
    double score = 0;
    int limiter = config.windowsize;

    if (len-off < config.windowsize)
      off = len-config.windowsize;
    if (off < 0){
      limiter+=off;
      off=0;
    }

    for (int i = 0 ; i <= limiter-freqs.nglen ; ++i){
      unsigned long ind = ngBinSearch(s+off+i);
      if (ind < freqs.ngnum){
        //printf("DNS-DEBUG getNgScore : %s  %lf\n",freqs.data[ind].ng,freqs.data[ind].score);
        score+=freqs.data[ind].score;
      }
    }
    off+=limiter;
    if (off > len)
      off = len-freqs.nglen;
    if (score < worst)
      worst = score;
  }
  return worst;
}

u_int32_t DnsTunnelOption::pushDnsRecordSub(const char *s, u_int8_t len, struct DnsTunnelDnsRankRecord *r){
  struct DnsTunnelDnsRankRecordSub** b = &r->subdomain;
  u_int32_t totlen = 0;
  u_int32_t badlen = 0;
  u_int8_t subnum = 0;
  while (*b != nullptr && ((*b)->len != len || strncmp((*b)->domain,s,len) != 0)){
    totlen+=(*b)->len;
    ++subnum;
    if ((*b)->bad)
      badlen+=(*b)->len;
    b = &((*b)->next);
  }

  //printf("DNS-DEBUG pushRecordSub : badlenA %d\n",badlen);

  if (*b == nullptr){   //not found
    //printf("DNS-DEBUG pushRecordSub : not found %s %d\n",s,len);
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
    if (score < 0){
      printf("DNS-DEBUG pushRecordSub : score %lf %s (%d/%d %d/%d %d/%d)\n",score, s, badlen+(score<0?len:0),config.threshold,totlen,config.maxbuffersize,subnum,config.minbufferlen);
      (*b)->bad = true;
    }
  } //else
    //printf("DNS-DEBUG pushRecordSub : found %s %d\n",(*b)->domain,len);

  while (*b != nullptr){
    totlen+=(*b)->len;
    ++subnum;
    if ((*b)->bad)
      badlen+=(*b)->len;
    b = &((*b)->next);
  }

  while (totlen > config.maxbuffersize && subnum > config.minbufferlen){
    b = &r->subdomain;
    printf("DNS-DEBUG pushRecordSub : cleanup %s\n",(*b)->domain);
    struct DnsTunnelDnsRankRecordSub* bb = (*b)->next;
    totlen-=(*b)->len;
    --subnum;
    free((*b)->domain);
    free(*b);
    *b = bb;
  }

  //printf("DNS-DEBUG pushRecordSub : badlenB %d\n",badlen);

  return badlen;
}

bool DnsTunnelOption::isBad(char *s){
  u_int8_t dot1 = 0,
           dot2 = 0,
           dot3 = 0,
           c = 0;
  char* cur = s;
  struct DnsTunnelDnsRankRecord* r;

  while (s[c]){
    if (s[c] == '.'){
      dot3 = dot2;
      dot2 = dot1;
      dot1 = c;
    }
    ++c;
  }

  //printf("DNS-DEBUG  dots %d %d %d\n",dot3, dot2, dot1);

  if (!dot3)
    return 0;

  r = pushDnsRecord(s,dot3+1);
  if (r == nullptr || r->bad){
    printf(r==nullptr?"DNS-DEBUG isBad : FAIL %s\n":"DNS-DEBUG isBad : earlyBAD %s\n",s);
    return true;
  }

  if (pushDnsRecordSub(s,dot3,r) > config.threshold){
    printf("DNS-DEBUG isBad : lateBAD %s\n",s);
    r->bad = true;
  } //else
    //printf("DNS-DEBUG isBad : GOOD\n");

  return r->bad;
}

/* HERE WE PERFORM ACTUAL MATCHING */
IpsOption::EvalStatus DnsTunnelOption::eval(Cursor& c, Packet*p)
{
    //printf("--- CTOR-Option::eval\n");
    Profile profile(dns_tunnel_perf_stats);
    if ( p->is_udp() && p->has_udp_data() && p->dsize >= MIN_DNS_SIZE){
      DnsTunnelPacket pkt = DnsTunnelPacket(p);
      //printf("DNS-DEBUG: size: %d questions:%d\n",p->dsize,pkt.question_num);

      if (!pkt.malformed) {
        for(int i = 0 ; i < pkt.questions.size() ; ++i){
          //printf("DNS-DEBUG  question %d : [%s]\n",i,pkt.questions[i].qname);
          if (isBad((char*)pkt.questions[i].qname))
            return MATCH;
        }
        return NO_MATCH;
      }
    }

    return MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "threshold",      Parameter::PT_INT, "1:", nullptr, "Total length of negatively classified queries required to consider domain malicious" }, //name, type, range, default, description
    { "maxbuffersize",  Parameter::PT_INT, "32:", nullptr, "Max total length of buffered requests per domain" },
    { "minbufferlen",   Parameter::PT_INT, "1:200", nullptr, "Min number of buffered requests per domain" },
    { "windowsize",     Parameter::PT_INT, "4:32", nullptr, "domain analyze window size" },
    { "minreqsize",     Parameter::PT_INT, "1:32", nullptr, "Min subdomain length required to perform analyzis" },
    { "bucketlen",      Parameter::PT_INT, "1024:", nullptr, "bucket size for domains storage" },
    { "datafile",       Parameter::PT_STRING, nullptr, nullptr, "bucket size for domains storage" },

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

public:
    struct DnsTunnelParams config;
    struct DnsTunnelNgFreqs freqs;
};

DnsTunnelModule::DnsTunnelModule() : Module(s_name, s_help, s_params){
  printf("--- CTOR-Module\n");
}

/* HERE WE INITIALIZE IPS OPTION PARAMS */
bool DnsTunnelModule::begin(const char*, int, SnortConfig*)
{
    printf("--- CTOR-Module::Begin\n");
    config.threshold = 32;
    config.maxbuffersize = 256;
    config.minbufferlen = 20;
    config.windowsize = 8;
    config.minreqsize = 4;
    config.bucketlen = 8192;
    config.datafile = nullptr;
    freqs.data = nullptr;
    freqs.ngnum = 0;
    freqs.nglen = 0;
    return true;
}

/* HERE WE READ IPS OPTION PARAMS */
bool DnsTunnelModule::set(const char*, Value& v, SnortConfig*)
{
    printf("--- CTOR-Module::Set\n");
    if ( v.is("threshold") )
      config.threshold = v.get_uint32(); //hope it works the way I think it does...
    else if ( v.is("maxbuffersize") )
      config.maxbuffersize = v.get_uint32();
    else if ( v.is("minbufferlen") )
      config.minbufferlen = v.get_uint8();
    else if ( v.is("windowsize") )
      config.windowsize = v.get_uint8();
    else if ( v.is("bucketlen") )
      config.bucketlen = v.get_uint32();
    else if ( v.is("datafile") ){
      if (config.datafile != nullptr)
        return false;

      config.datafile = v.get_string();
      return this->readDataFile(config.datafile);
    }
    else
      return false;

    return true;
}

/* SANITY CHECKS */
bool DnsTunnelModule::end(const char*, int, SnortConfig*){
  printf("--- CTOR-Module::End\n");
  if (config.datafile == nullptr){
    printf("--- CTOR-Module::End::ERROR filename\n");
    return false;
  }
  if (config.minreqsize < freqs.nglen){
    printf("--- CTOR-Module::End::ERROR minreqsize %d >= %d\n",config.minreqsize,freqs.nglen);
    return false;
  }
  if (config.windowsize < freqs.nglen){
    printf("--- CTOR-Module::End::ERROR windowsize %d >= %d\n",config.windowsize,freqs.nglen);
    return false;
  }

  return true;
}

bool DnsTunnelModule::readDataFile(const char *filename){
  printf("--- CTOR-Module::ReadDataFile (%s)\n",filename);
  char ng[255];
  double score;

  FILE *fp;

  if((fp = fopen(filename, "r")) == NULL)
      return false;

  int csize = INIT_NGRAM_NUM;
  int len, ret;
  freqs.data = (struct DnsTunnelNgFreqRecord*)malloc(sizeof(struct DnsTunnelNgFreqRecord)*csize);
  if (freqs.data == nullptr)
    return false;

  printf("--- CTOR-Module::ReadDataFile::beginRead\n");

  while (true) {
    //printf("--- CTOR-Module::ReadDataFile::line\n");
    if (freqs.ngnum == csize){
      printf("--- CTOR-Module::ReadDataFile::realloc\n");
      struct DnsTunnelNgFreqRecord* newreq = (struct DnsTunnelNgFreqRecord*)realloc(freqs.data, sizeof(struct DnsTunnelNgFreqRecord)*csize*2);
      if (newreq == nullptr){
        free(freqs.data);
        freqs.data = nullptr;
        return false;
      }
      freqs.data = newreq;
      csize*=2;
    }

    ret = fscanf(fp, "%[^,],%lf\n", ng, &score);
    //printf("--- CTOR-Module::ReadDataFile::fscanf %d %d %s %lf\n",freqs.nglen,ret,ng,score);
    if (ret != 2)
      break;
    len = strlen(ng);
    if (freqs.nglen == 0)
      freqs.nglen = len;
    else if (freqs.nglen != len){
      printf("--- CTOR-Module::ReadDataFile::fail\n");
      free(freqs.data);
      freqs.data = nullptr;
      return false;
    }

    freqs.data[freqs.ngnum].score = score;
    freqs.data[freqs.ngnum].ng[0] = 0;
    strncat(freqs.data[freqs.ngnum].ng,ng,MAX_NGRAM_LEN);
    //printf("%s : %lf", freqs.data[freqs.ngnum].ng, score);
    ++freqs.ngnum;
  }
  fclose(fp);

  printf("--- CTOR-Module::ReadDataFile::success (%d)\n",freqs.ngnum);

  return true;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    printf("--- CTOR-Module::Ctor\n");
    return new DnsTunnelModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* dns_tunnel_ctor(Module* p, OptTreeNode*)
{
    printf("--- CTOR-IPS::Ctor\n");
    DnsTunnelModule* m = (DnsTunnelModule*)p;
    return new DnsTunnelOption(m->config, m->freqs);
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

