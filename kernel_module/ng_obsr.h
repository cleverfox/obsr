#ifndef _NETGRAPH_NG_ZZNAT_H_
#define _NETGRAPH_NG_ZZNAT_H_

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <sys/tree.h>

/* Node type name. This should be unique among all netgraph node types */
#define NG_ZZNAT_NODE_TYPE	"obsr"

/* Node type cookie. Should also be unique. This value MUST change whenever
   an incompatible change is made to this header file, to insure consistency.
   The de facto method for generating cookies is to take the output of the
   date command: date -u +'%s' */
#define NGM_ZZNAT_COOKIE		1288908079

#define NG_ZZNAT_HOOK_LANO "lanout"
#define NG_ZZNAT_HOOK_WANO "wanout"
#define NG_ZZNAT_HOOK_WANR "wanrej"
#define NG_ZZNAT_HOOK_LAN "lan"
#define NG_ZZNAT_HOOK_WAN "wan"
#define NG_ZZNAT_HOOK_SOCK "ctl"

#define NG_ZZNAT_HOOK_DEBUG	"debug"

/* Netgraph commands understood by this node type */
enum {
	NGM_ZZNAT_REQ_SESSION=1,
	NGM_ZZNAT_START_SESSION,
	NGM_ZZNAT_GET_SESSION,
	NGM_ZZNAT_RESET_SESSION,
	NGM_ZZNAT_STOP_SESSION,
	NGM_ZZNAT_GET_SESSIONS,
//	NGM_ZZNAT_SET_FLAG,
//	NGM_ZZNAT_GET_STATUS,
	
};

#ifndef KERNEL
// defined in ../obsrd/obsr_commands.c
// please be sync with
extern char *commands[];
#endif

struct session {
        u_int32_t   sessionid;
	u_int32_t   pkt_l2w;
	u_int32_t   pkt_w2l;
        u_int64_t   oct_l2w;
        u_int64_t   oct_w2l;
        struct in_addr lan_ip;
        struct in_addr wan_ip;
        TAILQ_ENTRY(session) entries;
        RB_ENTRY(session) lan;
        RB_ENTRY(session) wan;
};

struct createsess_req {
    struct in_addr lan;
    struct in_addr wan;
    u_int32_t      sid;
    u_int32_t      userdata;
};

struct createsess_res {
    u_int32_t      sid;
    u_int32_t      userdata;
    u_int16_t      res;
};

#define NG_ZZNAT_CREATESESS { \
    { "lan", &ng_parse_ipaddr_type }, \
    { "wan", &ng_parse_ipaddr_type }, \
    { "sid", &ng_parse_uint32_type }, \
    { NULL } \
}

struct getsession_req {
    u_int32_t      sid;
    u_int32_t      userdata;
};

struct getsession_res {
    u_int32_t   sid;
    struct in_addr lan_ip;
    struct in_addr wan_ip;
    u_int32_t   pkt_l2w;
    u_int32_t   pkt_w2l;
    u_int64_t   oct_l2w;
    u_int64_t   oct_w2l;
    u_int16_t   res;
    u_int32_t      userdata;
};

#define NG_ZZNAT_GETSESS { \
    { "sid", &ng_parse_uint32_type }, \
    { "lan", &ng_parse_ipaddr_type }, \
    { "wan", &ng_parse_ipaddr_type }, \
    { "pkt_l2w", &ng_parse_uint32_type }, \
    { "pkt_w2l", &ng_parse_uint32_type }, \
    { "oct_l2w", &ng_parse_uint64_type }, \
    { "oct_w2l", &ng_parse_uint64_type }, \
    { "res", &ng_parse_uint32_type }, \
    { NULL } \
}


#endif /* _NETGRAPH_NG_ZZNAT_H*/

