#ifndef SESSION_H
#define SESSION_H
#include <sys/queue.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/time.h>

struct usersession_ipfw_table {
    struct in_addr* addr;
    u_int32_t value;
    u_int16_t table;
    u_int8_t plen;
    u_int8_t addrt;
    TAILQ_ENTRY(usersession_ipfw_table) entries;
};

struct usersession {
    struct in_addr lan;
    struct in_addr wan;
    struct ippool *pool;
    char *sessionid;
    char *poolname; //allocated by rad_cvt_string
    u_int32_t sid;
    u_int32_t interim;
    u_int32_t sessiontimeout;
    u_int32_t idletimeout;

    u_int32_t   pkt_l2w;
    u_int32_t   pkt_w2l;
    u_int64_t   oct_l2w;
    u_int64_t   oct_w2l;

    struct timeval start;
    struct timeval lastact;
    struct timeval lastupd;
    struct timeval lastsent;
    char           clear;
    char           started;
    TAILQ_HEAD(sessionipfwtablehead,usersession_ipfw_table) tables; 

    TAILQ_ENTRY(usersession) entries;
};

struct sessions {
    TAILQ_HEAD(sessionhead,usersession) head;
};


void init_sessions(struct sessions *h);
struct usersession* alloc_session(void);
void free_session(struct usersession *ses);
void add_session(struct sessions *h,struct usersession *ses);
void del_session(struct sessions *h,struct usersession *ses);
struct usersession* get_session(struct sessions *h,u_int32_t sid);
#endif
