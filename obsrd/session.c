#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "session.h"
#include "ippool.h"
#include "log.h"


#define LOG(loglevel, ...) LOG_WRITE(LF_SESSION|loglevel, __VA_ARGS__)


void init_sessions(struct sessions *h){
    TAILQ_INIT(&h->head);
}

void add_session(struct sessions *h,struct usersession *ses){
    TAILQ_INSERT_TAIL(&h->head,ses,entries);
}

void del_session(struct sessions *h,struct usersession *ses){
    TAILQ_REMOVE(&h->head,ses,entries);
}

struct usersession* get_session(struct sessions *h,u_int32_t sid){
    struct usersession *ses;
    TAILQ_FOREACH(ses,&h->head,entries){
        if(sid==ses->sid){
            return ses;
        }
    }
    return NULL;
}

struct usersession* alloc_session(void){
        struct usersession *ses=malloc(sizeof(struct usersession));
        LOG(LL_INFO, "****** Alloc Session %p ********",ses);
        //printf("****** Alloc Session %p ********\n",ses);
        bzero(ses,sizeof(struct usersession));
        TAILQ_INIT(&ses->tables);
        return ses;
};

void free_session(struct usersession *ses){
    struct usersession_ipfw_table *fwt,*fwt1;

    TAILQ_FOREACH_SAFE(fwt,&ses->tables,entries,fwt1)
    {
        LOG(LL_INFO,"delete fwt %p - %d %s",fwt,fwt->table,inet_ntoa(*fwt->addr));

        TAILQ_REMOVE(&ses->tables,fwt,entries);
        free(fwt);
    };

    // возвращаем ip'шник в pool
    struct ippool *pool = ses->pool;
    if (pool)
    {
        struct ip_entry *e;
        TAILQ_FOREACH(e,&pool->head,entries)
        {
            if (e->sess == ses)
            {
                char tmp[16];
                inet_ntoa_r(e->ip, tmp, sizeof(tmp));

                LOG(LL_INFO,"deallocating ip %s", tmp);

                if (e->mark_for_remove)
                {
                    // ip'шник помечен для удаления. теперь он освободился,
                    // удаляем ip'шник из пула

                    TAILQ_REMOVE(&pool->head, e, entries);
                    free(e);

                    LOG(LL_INFO,"removing unlocked ip %s from pool %s", tmp, pool->name);
                } else {
                    e->allocated=0;
                    pool->members++;
                    pool->free++;
                }
                break;
            }
        }
    } else {
        LOG(LL_INFO,"can't find pool for session %p", ses);
    }

    LOG(LL_INFO, "****** Free Session %p ********", ses);
    //printf("****** Free Session %p ********\n",ses);
    free(ses);
};


