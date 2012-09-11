#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include "log.h"

uint16 facloglevel[LFS];
uint16 faclog2syslog[LFS];
int lastfac=-1;

unsigned int logbuflen=0;
char *logbuf=NULL;
char *progname=NULL;


uint16 faclogavail[LFS]= {
    0xff,            //default
    LL_DEBUG|LL_INFO|LL_WARN|LL_ERROR,    // SESSION
    LL_DEBUG|LL_INFO|LL_WARN|LL_ERROR,    // IPPOOL
    LL_DEBUG|LL_INFO|LL_WARN|LL_ERROR,    // CMD
    LL_DEBUG|LL_INFO|LL_WARN|LL_ERROR,    // RADIUS
/*
    LL_DEBUG|LL_INFO|LL_WARN|LL_ERROR|LL_NETDATA|LL_DEBUG2, //client
    LL_DEBUG|LL_INFO|LL_WARN|LL_ERROR|LL_NETDATA|LL_DEBUG2, //server
    LL_INFO|LL_WARN|LL_ERROR|LL_CWDW, //request
    LL_DEBUG|        LL_WARN,//router
    LL_INFO|LL_WARN|LL_ERROR|LL_DEBUG2|LL_NETDATA, //cache
    LL_DEBUG|LL_INFO|LL_WARN|LL_ERROR, //balancer
    LL_DEBUG|LL_INFO|LL_WARN|LL_ERROR|LL_CWDW|LL_NETDATA|LL_DEBUG2, //upstream
    LL_INFO|LL_WARN, //anticasc
    LL_DEBUG|LL_INFO|LL_WARN,  //stat
    LL_DEBUG|LL_INFO|LL_WARN|LL_ERROR, // cluster
    LL_DEBUG|LL_DEBUG2|LL_INFO|LL_ERROR, // cluster */
};

struct _data syslog_facility[]=
{
    { "auth",       LOG_AUTH,       },
    { "authpriv",   LOG_AUTHPRIV,   },
    //    { "console",    LOG_CONSOLE,    },
    { "cron",       LOG_CRON,       },
    { "daemon",     LOG_DAEMON,     },
    { "ftp",        LOG_FTP,        },
    { "kern",       LOG_KERN,       },
    { "lpr",        LOG_LPR,        },
    { "mail",       LOG_MAIL,       },
    { "news",       LOG_NEWS,       },
    //    { "ntp",        LOG_NTP,        },
    //    { "security",   LOG_SECURITY,   },
    { "syslog",     LOG_SYSLOG,     },
    { "user",       LOG_USER,       },
    { "uucp",       LOG_UUCP,       },
    { "local0",     LOG_LOCAL0,     },
    { "local1",     LOG_LOCAL1,     },
    { "local2",     LOG_LOCAL2,     },
    { "local3",     LOG_LOCAL3,     },
    { "local4",     LOG_LOCAL4,     },
    { "local5",     LOG_LOCAL5,     },
    { "local6",     LOG_LOCAL6,     },
    { "local7",     LOG_LOCAL7,     },
    { NULL,         -1,             }
};

struct _data syslog_labels[]=
{
    { "emerg",      LOG_EMERG,      },
    { "alert",      LOG_ALERT,      },
    { "crit",       LOG_CRIT,       },
    { "err",        LOG_ERR,        },
    { "warning",    LOG_WARNING,    },
    { "notice",     LOG_NOTICE,     },
    { "info",       LOG_INFO,       },
    { "debug",      LOG_DEBUG,      },
    { NULL,         -1,             }
};


char* log_labels[LOG_LEVELS+1]={
    "lstrs","debug","info","warn","error","netdata","debug2","config","cwdw","my","client_warn",NULL};

char* log_facilities[LFS+1]={
    "default","session","ippool","cmd","radius",NULL};
    //"default","client","server","request","router","cache","balancer","upstream","anticasc","stat","cluster","cex",NULL};


static char* hlog_labels[LOG_LEVELS+1]={
    "UNKN",   "DEBUG",   "INFO",   "WARN",      "ERROR","NDATA","DEBU2","CONF","CWDW","MY","CWARN",NULL};

int syslog_llmap[LOG_LEVELS+1] = {
//   "UNKN",     "DEBUG",   "INFO",   "WARN",    "ERROR",  "NDATA",   "DEBU2",  "CONF",   "CWDW",    "MY",    "CWARN", NULL};
    LOG_INFO, LOG_DEBUG, LOG_INFO, LOG_WARNING, LOG_ERR, LOG_DEBUG, LOG_DEBUG,LOG_INFO, LOG_INFO, LOG_DEBUG, LOG_CRIT, -1 };

int lastlid;

#ifdef LOG_STRINGS
#warn Expect memory leaks
#endif

#ifdef LOG_STRINGS
char* getlogstr(int cloglevel,char* filename,int fileline){
#else
char* getlogstr(int cloglevel){
#endif
    int c=1;
#ifdef LOG_STRINGS
    //if(facloglevel[cloglevel>>16]&LL_LSTRS){
    if(facloglevel[0]&LL_LSTRS){
        char* r;
        for(;c<LOG_LEVELS;c++){
            if(cloglevel&(1<<c)){
                lastlid=c;
#warn this memory is never freed
                asprintf(&r,"%20s:%5d %s",filename,fileline,hlog_labels[c]);
                return r;
            }
        }
    }else
#endif
    {
        for(;c<LOG_LEVELS;c++)
        {
            if(cloglevel&(1<<c) && facloglevel[cloglevel&(1<<c)])
            {
                lastlid=c;
                return hlog_labels[c];
            }
        }
    }
    return hlog_labels[0];
}


void printhex(void* sstr,int length){
    int c;
    if(sstr==NULL){
	printf("NULL");

    }else{
	for(c=0;c<length;c++){
    	    printf(" %02x",*((unsigned char*)sstr+c));
	}
    }
    printf("\n");
}

void printchr(void* sstr,int length,char* pattern){
    int c;
    if(sstr==NULL){
	printf("NULL");

    }else{
	for(c=0;c<length;c++){
    	    printf(pattern,*((unsigned char*)sstr+c));
	}
    }
    printf("\n");
}


void outhex(char* tbuf,void* sstr,int length,char* pattern,char* lpattern){
    int c;
    char* ltb=tbuf;
    if(sstr==NULL){
        sprintf(tbuf,"NULL");
    }else if(length<=0){
        sprintf(tbuf,"ZERO");
    }else{
        for(c=0;c<length;c++){
            unsigned char ch=*((unsigned char*)sstr+c);
            int r;
            if(ch<0x20){
                r=sprintf(ltb,lpattern,ch);
            }else{
                r=sprintf(ltb,pattern,ch);
            }
            if(r<=0){
                return;
            }else{
                ltb+=r;
            }
        }
        *ltb=0;
    }
}


void fouthex(FILE* ob,void* sstr,int length,char* pattern,char* lpattern){
    int c;
    if(sstr==NULL){
        fprintf(ob,"NULL");
    }else if(length<=0){
        fprintf(ob,"ZERO");
    }else{
        for(c=0;c<length;c++){
            unsigned char ch=*((unsigned char*)sstr+c);
            int r;
            if(ch<0x20){
                r=fprintf(ob,lpattern,ch);
            }else{
                r=fprintf(ob,pattern,ch);
            }
            if(r<=0){
                return;
            }
        }
    }
}

