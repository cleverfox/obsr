#ifndef _LOG_H_
#define _LOG_H_
#include <stdio.h>
#include <syslog.h>
#include <stdlib.h>
#include "itypes.h"


// NOTE: если включить LOG_STRINGS, будет течь память. Из за asprintf.
//#define LOG_STRINGS 1
extern int lastlid;

//extern uint16 log2syslog;
#ifdef LOG_STRINGS
#define LL_LSTRS   (1<<0)
#endif
#define LL_DEBUG (1<<1)
#define LL_INFO (1<<2)
#define LL_WARN (1<<3)
#define LL_ERROR (1<<4)
#define LL_NETDATA (1<<5)
#define LL_DEBUG2  (1<<6)
#define LL_CONFIG  (1<<7)
#define LL_CWDW    (1<<8)
#define LL_MY      (1<<9)
#define LL_CWARN   (1<<10)
#define LOG_LEVELS 11

#define LF_OTHER    (0<<16)
#define LF_DEFAULT  LF_OTHER
#define LF_SESSION  (1<<16)
#define LF_IPPOOL   (2<<16)
#define LF_CMD      (3<<16)
#define LF_RADIUS   (4<<16)
#define LFS          5

struct _data
{
    char      *c_name;
    int       c_val;
};

extern struct _data syslog_facility[];

extern uint16 facloglevel[LFS];
extern uint16 faclog2syslog[LFS];
extern uint16 faclogavail[LFS];
extern char* log_facilities[];
extern char* log_labels[];
extern char* progname;
extern int lastfac;


#ifdef LOG_STRINGS
char* getlogstr(int cloglevel, char*, int);
#else
char* getlogstr(int cloglevel);
#endif

#define CLL loglevel
#define LLS_STR "%s"

#ifdef LOG_STRINGS
#define LLS_EXPR(cloglevel) getlogstr(cloglevel,__FILE__, __LINE__)
#else
#define LLS_EXPR(cloglevel) getlogstr(cloglevel)
#endif

extern int syslog_llmap[];

#define dolog(loglevel,...) if(!faclog2syslog[(loglevel)>>16]){ \
        printf(__VA_ARGS__); \
    }else{ \
        if(lastfac!=faclog2syslog[(loglevel)>>16]){ \
            lastfac=faclog2syslog[(loglevel)>>16]; \
            openlog(progname,LOG_PID,lastfac); \
        } \
        syslog(syslog_llmap[lastlid],__VA_ARGS__); \
    }

extern char* logbuf;
extern unsigned int logbuflen;

#define LOG_WRITE(loglevel,...) ;if(((loglevel)&0xffff)&facloglevel[(loglevel)>>16]) { \
            if(logbuflen<256){ \
                if(logbuf) free(logbuf); \
                logbuflen=256; \
                logbuf=malloc(logbuflen); \
            } \
             snprintf(logbuf,logbuflen,__VA_ARGS__); \
            dolog(loglevel,"%s %s: %s\n", log_facilities[(loglevel)>>16], LLS_EXPR((loglevel)),logbuf);\
        }
#define HEXL 16

#define LOG_XWRITE(loglevel,str,ptr,len,...) if(((loglevel)&0xffff)&facloglevel[(loglevel)>>16]) { \
    if(logbuflen<256){ \
        if(logbuf) free(logbuf); \
        logbuflen=256; \
        logbuf=malloc(logbuflen); \
    } \
    snprintf(logbuf,logbuflen,str,__VA_ARGS__); \
    dolog((loglevel),"%s %s: %s\n", log_facilities[(loglevel)>>16], LLS_EXPR((loglevel)),logbuf); \
    uint16 p=0; \
    uint16 rlen=len; \
    if(logbuflen<(HEXL*3)+1){ \
        if(logbuf) free(logbuf); \
        logbuflen=(HEXL*3)+1; \
        logbuf=malloc(logbuflen); \
    } \
    for(;(p*HEXL)<len;p++){ \
        outhex(logbuf,((char*)ptr)+p*HEXL,rlen>HEXL?HEXL:rlen," %02x"," %02x"); \
        rlen-=HEXL; \
        dolog((loglevel),"\t%4x: %s\n", p*HEXL, logbuf);\
    } \
}
#define LOG_WRITE_HEX(loglevel,str,ptr,len) if(((loglevel)&0xffff)&facloglevel[(loglevel)>>16]) \
    LOG_XWRITE(loglevel,str "%s",ptr,len,"")

#if 0
            if(logbuflen<(len*3)+1){ \
                if(logbuf) free(logbuf); \
                logbuflen=(len*3)+1; \
                logbuf=malloc(logbuflen); \
            } \
            outhex(logbuf,ptr,len," %02x"," %02x"); \
            dolog((loglevel),"%s %s: %s %s\n", log_facilities[(loglevel)>>16], LLS_EXPR((loglevel)), str, logbuf);\
            }
#endif
void outhex(char* tbuf, void* sstr,int length,char* pattern, char* lpattern);

#endif // _LOG_H_
