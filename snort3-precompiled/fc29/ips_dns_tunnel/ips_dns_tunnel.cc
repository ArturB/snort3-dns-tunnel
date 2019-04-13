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

using namespace snort;

static const char* s_name = "dns_tunnel";
static const char* s_help = "alert on suspicious DNS queries activity";

static THREAD_LOCAL ProfileStats dns_tunnel_perf_stats;

//-------------------------------------------------------------------------
// helpers
//-------------------------------------------------------------------------

#define MIN_DNS_SIZE 12

struct DnsTunnelParams {
  u_int8_t testarg;
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

      while(cur < p->dsize && p->data[cur]){
        strncat((char*)&buf[q.qlen],(char*)&(p->data[cur+1]),p->data[cur]);
        q.qlen += p->data[cur]+1;
        strcat((char*)&buf[q.qlen-1],".");
        cur += 1+p->data[cur];
      }

      if (cur+5 < p->dsize){
        malformed = true;
        break;
      }

      q.qtype =   (p->data[cur+1]<<8) + p->data[cur+2];
      q.qclass =  (p->data[cur+3]<<8) + p->data[cur+4];
      cur+=5;

      unsigned char* qname = (unsigned char*)malloc((q.qlen+1)*sizeof(char));
      memcpy(qname,buf,q.qlen+1);
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
    DnsTunnelOption(const DnsTunnelParams& c) : IpsOption(s_name)
    { config = c; printf("--- CTOR-Option\n"); }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    EvalStatus eval(Cursor&, Packet*p) override;

private:
    DnsTunnelParams config;
};

/* USED TO DETECT EXACTLY THE SAME RULE ENTRIES, AVOIDS DUPLICATION */
uint32_t DnsTunnelOption::hash() const
{
    uint32_t a, b, c;

    a = config.testarg;
    b = 1;  //arbitrary crap, change to config params later
    c = 2;

    mix_str(a,b,c,get_name());
    finalize(a,b,c);

    return c;
}

/* USED TO DETECT EXACTLY THE SAME RULE ENTRIES, AVOIDS DUPLICATION */
bool DnsTunnelOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(s_name, ips.get_name()) )
        return false;

    const DnsTunnelOption& rhs = (const DnsTunnelOption&)ips;
    return ( config.testarg == rhs.config.testarg );
}

/* HERE WE PERFORM ACTUAL MATCHING */
IpsOption::EvalStatus DnsTunnelOption::eval(Cursor& c, Packet*p)
{
    Profile profile(dns_tunnel_perf_stats);

    if ( p->is_udp() && p->has_udp_data() && p->dsize >= MIN_DNS_SIZE){
        DnsTunnelPacket pkt = DnsTunnelPacket(p);
        printf("DNS-DEBUG: size: %d questions:%d\n",
               p->dsize,pkt.question_num);
        if (pkt.malformed){
          printf("DNS-DEBUG: MALFORMED\n");
        } else
          for(int i = 0 ; i < pkt.questions.size() ; ++i)
            printf("DNS-DEBUG  question %d : %s\n",i,pkt.questions[i].qname);
        if (pkt.question_num>0 && pkt.questions[0].qlen > config.testarg)
          return MATCH;
        else
          return NO_MATCH;
    }

    return NO_MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "testarg", Parameter::PT_INT, "1:50", nullptr,
      "just testing if it works" }, //name, type, range, default, description

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr } //i guess it's the end of params?
};

class DnsTunnelModule : public Module
{
public:
    DnsTunnelModule() : Module(s_name, s_help, s_params) { printf("--- CTOR-Module\n"); }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &dns_tunnel_perf_stats; }

    Usage get_usage() const override
    { return DETECT; }

public:
    DnsTunnelParams data;
};

/* HERE WE INITIALIZE IPS OPTION PARAMS */
bool DnsTunnelModule::begin(const char*, int, SnortConfig*)
{
    data.testarg = 0;
    return true;
}

/* HERE WE READ IPS OPTION PARAMS */
bool DnsTunnelModule::set(const char*, Value& v, SnortConfig*)
{
    printf("--- CTOR-Module::Parse\n");
    if ( v.is("testarg") )
      data.testarg = v.get_uint8(); //hope it works the way I think it does...
    else
      return false;

    return data.testarg>2;
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
    return new DnsTunnelOption(m->data);
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

