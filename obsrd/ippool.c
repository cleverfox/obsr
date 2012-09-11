#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "ippool.h"
#include "session.h"
#include "log.h"

#define LOG(loglevel, ...) LOG_WRITE(LF_IPPOOL|loglevel, __VA_ARGS__)

void pools_init(struct pools *pools){
    TAILQ_INIT(&pools->head);
};

struct ippool* pool_create(struct pools *pools,char *name){
    struct ippool *ipp;
    TAILQ_FOREACH(ipp,&pools->head,entries){
        if(strcmp(name,ipp->name)==0){
            return ipp;
        }
    }
    ipp=malloc(sizeof(struct ippool));
    if(!ipp)
        return NULL;
    TAILQ_INIT(&ipp->head);
    ipp->name=strdup(name);
    TAILQ_INSERT_TAIL(&pools->head,ipp,entries);
    return ipp;
};

struct ippool* get_pool(struct pools *pools,char *name)
{
    struct ippool *ipp;

    if (!pools)
        return NULL;

    TAILQ_FOREACH(ipp,&pools->head,entries){
        if(strcmp(name,ipp->name)==0){
            return ipp;
        }
    }

    return NULL;
};

int pool_add(struct ippool *pool, struct in_addr ip){ 
    struct ip_entry *e;
    TAILQ_FOREACH(e,&pool->head,entries){
        if(e->ip.s_addr==ip.s_addr)
            return 1;
    }
    e=malloc(sizeof(struct ip_entry));
    if(!e)
        return -1;
    e->ip=ip;
    e->sess=NULL;
    e->allocated=0;
    TAILQ_INSERT_TAIL(&pool->head,e,entries);
    return 0;
};

int pool_add_range(struct ippool *pool, struct in_addr sip, struct in_addr eip){
    struct in_addr cip;
    struct in_addr lip;

    if(sip.s_addr<=eip.s_addr){
        cip=sip;
        lip=eip;
    }else{
        cip=eip;
        lip=sip;
    };
    struct in_addr oneip;
    if(inet_aton("0.0.0.1",&oneip)!=1)
        return -1;
    int res=0;
    for(;;cip.s_addr+=oneip.s_addr){
        if(pool_add(pool, cip)==0){
            res++;
            pool->members++;
            pool->free++;
        }
        if(cip.s_addr>=lip.s_addr)
            break;
    }
    return res;
};

int pool_remove_range(struct ippool *pool, struct in_addr sip, struct in_addr eip)
{
    struct in_addr cip;
    struct in_addr lip;

    int ip_count = 0;

    if(sip.s_addr<=eip.s_addr)
    {
        cip=sip;
        lip=eip;
    } else {
        cip=eip;
        lip=sip;
    };

    struct ip_entry *e;
    TAILQ_FOREACH(e,&pool->head,entries)
    {
        if(e->ip.s_addr >= cip.s_addr && e->ip.s_addr <= lip.s_addr)
        {
            char tmp[16];
            inet_ntoa_r(e->ip, tmp, sizeof(tmp));

            if (e->sess)
            {
                e->mark_for_remove = 1;
                LOG(LL_INFO,"active session (id '%s') for ip '%s'. Address marked for future removing", e->sess->sessionid, tmp);
            } else {
//                LOG(LL_INFO,"remove ip address %s from pool '%s'", tmp, pool->name);

                ip_count++;

                pool->members--;
                pool->free--;

                TAILQ_REMOVE(&pool->head, e, entries);
                free(e);
            }
        }
    }

    return ip_count;
}

struct ip_entry * allocate_ip(struct ippool *pool){
    struct ip_entry *e;
    TAILQ_FOREACH(e,&pool->head,entries){
        if(!e->allocated){
            e->allocated=1;
            pool->members--;
            pool->free--;
            return e;
        }
    }
    return NULL;
};

struct ip_entry * allocate_my_ip(struct ippool *pool,struct in_addr ip){
    struct ip_entry *e;
    TAILQ_FOREACH(e,&pool->head,entries){
        if(e->ip.s_addr==ip.s_addr){
            if(!e->allocated){
                e->allocated=1;
                pool->members--;
                pool->free--;
                return e;
            }else{
                return NULL;
            }
        }
    }
    return NULL;
};

void deallocate(struct ippool *pool,struct ip_entry *ip){
    struct ip_entry *e;
    TAILQ_FOREACH(e,&pool->head,entries){
        if(e==ip){
            pool->members++;
            pool->free++;
        }
    }
    ip->allocated=0;
    ip->sess=NULL;
};



