#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/queue.h>

#include <net/if.h>
#include <netinet/in.h>

#include <arpa/inet.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <netgraph.h>
#include "../kernel_module/ng_obsr.h"
#include "ippool.h"
#include "session.h"

#include <radlib.h>
#include <radlib_vs.h>

#include <fcntl.h>

#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <signal.h>


#include <pthread.h>

#include "cli.h"
#include "obsrd.h"
#include "cliconfig.h"
#include "ipfw.h"

#include "log.h"

#define LOG(loglevel, ...) LOG_WRITE(LF_OTHER|loglevel, __VA_ARGS__)


int sock[4];
int kq;
struct kevent change[4];
//int	cs;
//int 	ds;
char	ng_nodename[NG_PATHSIZ];
int mi=1;
struct ngm_connect  cn;
struct sessions *usessions;
struct pools *pools;

extern int errno;


#define SORCVBUF_SIZE 1024
#define SES_POLL 10
#define SES_BAD  30

int setNonblocking(unsigned int sd)
{
    unsigned int flags;

    if (-1 == (flags = fcntl(sd, F_GETFL, 0)))
        flags = 0;

    return fcntl(sd, F_SETFL, flags | O_NONBLOCK);
}


struct rad_handle *auth;
struct rad_handle *racct;
struct rad_handle *coa;

struct usersession *request_session(struct in_addr xip,struct in_addr eip);
void send_update(struct usersession *ses,int type);



struct usersession *create_session(struct in_addr lan, struct in_addr wan, u_int32_t sid){
    struct usersession *s;
    TAILQ_FOREACH(s,&usessions->head,entries){
        if(s->lan.s_addr==lan.s_addr || s->wan.s_addr==wan.s_addr)
            return NULL;
    }
    
    
    struct usersession *ses=request_session(lan,wan);
    int error=0;
    if(ses){
        if(wan.s_addr==0){
            if(ses->wan.s_addr==0 && ses->poolname){
                struct ippool *p=get_pool(pools,ses->poolname);
                if(p){
                    struct ip_entry* ip=allocate_ip(p);
                    if(ip){
                        ip->sess=ses;
                        ses->wan=ip->ip;
                        ses->pool=p;
                    }else{
                        LOG(LL_INFO,"!!!ACHTUNG!!! Can't allocate IP from pool %s",ses->poolname);
                        free(ses);
                        error=1;
                    }
                }else{
                    LOG(LL_INFO,"Can't find ippool %s",ses->poolname);
                    free(ses);
                    error=1;
                }
            }else if(ses->wan.s_addr==(1<<24)){
                ses->wan=lan;
            }
        }else{
            if(ses->wan.s_addr==0 && ses->poolname){
                struct ippool *p=get_pool(pools,ses->poolname);
                if(p){
                    struct ip_entry* ip=allocate_my_ip(p,wan);
                    if(ip){
                        ip->sess=ses;
                        ses->wan=ip->ip;
                        ses->pool=p;
                    }else{
                        LOG(LL_INFO,"Can't allocate my IP %s from pool %s",inet_ntoa(wan),ses->poolname);
                        free(ses);
                        error=1;
                    }
                }else{
                    LOG(LL_INFO,"Can't find ippool %s",ses->poolname);
                    free(ses);
                    error=1;
                }
            }else if(ses->wan.s_addr!=wan.s_addr){
                error=2;
            }
        }


        if(!error)
        {
            add_session(usessions,ses);

            struct createsess_req s;

            s.lan=ses->lan;
            s.wan=ses->wan;

            int newsid=sid;

            if(!sid)
                newsid=mi++;

            ses->sid=newsid;

            char lan[INET_ADDRSTRLEN];
            char wan[INET_ADDRSTRLEN];
            LOG_WRITE(LF_SESSION|LL_INFO, "Sesion created %p, public IP %s, local IP %s, sid %d",
                    ses,
                    inet_ntop(AF_INET, &ses->wan, wan, INET_ADDRSTRLEN),
                    inet_ntop(AF_INET, &ses->lan, lan, INET_ADDRSTRLEN),
                    ses->sid);

            struct kevent ktmr;

            EV_SET(&ktmr,newsid+1000,EVFILT_TIMER,EV_ADD | EV_ENABLE | EV_ONESHOT ,0,SES_POLL*1000,ses);
            kevent(kq, &ktmr, 1, NULL, 0, NULL);

            s.sid=newsid;

            int token=NgSendMsg(sock[SOCK_NG], cn.path, NGM_ZZNAT_COOKIE,NGM_ZZNAT_START_SESSION, (void *)&s, sizeof(s));

            LOG(LL_DEBUG,"NG token START_SESSION %d", token);

            if(sid)
            {
                send_update(ses,0);
                ses->started=1;

                ipfw_couple(ses);
            } else {
                ses->started=0;
            }
        } else {
            if(sid)
            {
                struct getsession_req r; 
                r.sid=sid;
                r.userdata=SES_DELETE;
                NgSendMsg(sock[SOCK_NG], cn.path, NGM_ZZNAT_COOKIE,NGM_ZZNAT_STOP_SESSION, (void *)&r, sizeof(r));
            }else{
                LOG_WRITE(LF_SESSION|LL_INFO|LL_ERROR,"Session not created");
            }
        }
    }else{
        if(sid){
            struct getsession_req r; 
            r.sid=sid;
            r.userdata=SES_DELETE;
            NgSendMsg(sock[SOCK_NG], cn.path, NGM_ZZNAT_COOKIE,NGM_ZZNAT_STOP_SESSION, (void *)&r, sizeof(r));
        }else{
            struct createsess_req s;
            s.lan=lan;
            s.wan.s_addr=0;
            int newsid=mi++;
            struct kevent ktmr;
            EV_SET(&ktmr,newsid+1000,EVFILT_TIMER,EV_ADD | EV_ENABLE | EV_ONESHOT ,0,SES_BAD*1000,NULL);
            kevent(kq, &ktmr, 1, NULL, 0, NULL);
            s.sid=newsid;
            NgSendMsg(sock[SOCK_NG], cn.path, NGM_ZZNAT_COOKIE,NGM_ZZNAT_START_SESSION, (void *)&s, sizeof(s));
            LOG(LL_INFO,"Session rejected");
            LOG(LL_INFO,"created temporary session %d",s.sid);
 
        }
    }
    return NULL;
};

void send_update(struct usersession *ses,int type){
    LOG_WRITE(LF_RADIUS|LL_INFO,"rad_create_request for %p - %d",ses,rad_create_request(racct,RAD_ACCOUNTING_REQUEST));

    struct timeval now;
    gettimeofday(&now, NULL);
    if(!ses->sessionid){
        char buf[128];
        sprintf(buf,"%ld-%d",(unsigned long)ses->start.tv_sec,ses->sid);
        ses->sessionid=strdup(buf);
    }

    char usernamebuf[64];
    sprintf(usernamebuf,"IPoE_%s",inet_ntoa(ses->lan));
    rad_put_string(racct,RAD_USER_NAME,usernamebuf);
    rad_put_string(racct,RAD_ACCT_SESSION_ID,ses->sessionid);
    rad_put_int(racct,RAD_ACCT_AUTHENTIC,RAD_AUTH_RADIUS);

    switch(type)
    {
        case 0:
            rad_put_int(racct,RAD_ACCT_STATUS_TYPE,RAD_START);
            break;
        case 1:
            rad_put_int(racct,RAD_ACCT_STATUS_TYPE,RAD_UPDATE);
            break;
        case 2:
            rad_put_int(racct,RAD_ACCT_STATUS_TYPE,RAD_STOP);
            rad_put_int(racct,RAD_ACCT_TERMINATE_CAUSE,ses->clear);
            break;
        default:
            return;
    };


    rad_put_int(racct,RAD_NAS_PORT,ses->sid);
    rad_put_int(racct,RAD_NAS_PORT_TYPE,RAD_ETHERNET);
    rad_put_int(racct,RAD_FRAMED_PROTOCOL,10);
    rad_put_addr(racct,RAD_FRAMED_IP_ADDRESS,ses->wan);
    rad_put_addr(racct,RAD_NAS_IP_ADDRESS,global_config->thisserver);
    //rad_put_addr(racct,RAD_LOGIN_IP_HOST,ses->lan);
    rad_put_vendor_addr(racct,12344,1,ses->lan);
    rad_put_string(racct,RAD_CALLING_STATION_ID,inet_ntoa(ses->lan));
    rad_put_int(racct,RAD_ACCT_INPUT_PACKETS,ses->pkt_l2w);
    rad_put_int(racct,RAD_ACCT_OUTPUT_PACKETS,ses->pkt_w2l);
    rad_put_int(racct,RAD_ACCT_INPUT_OCTETS,ses->oct_l2w&0xffffffff);
    rad_put_int(racct,RAD_ACCT_OUTPUT_OCTETS,ses->oct_w2l&0xffffffff);
    rad_put_int(racct,RAD_ACCT_INPUT_GIGAWORDS,ses->oct_l2w>>32);
    rad_put_int(racct,RAD_ACCT_OUTPUT_GIGAWORDS,ses->oct_w2l>>32);

    rad_put_int(racct,RAD_ACCT_SESSION_TIME,now.tv_sec-ses->start.tv_sec);

    int res=rad_send_request(racct);

    if(res==-1)
    {
        LOG_WRITE(LF_RADIUS|LL_INFO|LL_ERROR|LL_DEBUG,"rad_send_request [update] radius does not respond [session %p, sid %d]", ses, ses->sid);
        LOG_WRITE(LF_RADIUS|LL_INFO|LL_ERROR|LL_DEBUG,"Error: %s",rad_strerror(racct));
    } else {
        ses->lastsent=now;
        LOG_WRITE(LF_RADIUS|LL_DEBUG,"rad_send_request [update] sent [session %p, sid %d]", ses, ses->sid);
    }
}

struct usersession *request_session(struct in_addr xip, struct in_addr eip)
{
    int rc;

    rc = rad_create_request(auth,RAD_ACCESS_REQUEST);

    LOG_WRITE(LF_RADIUS|LL_DEBUG,"rad_create_request %d",rc);

    char usernamebuf[64];
    sprintf(usernamebuf,"IPoE_%s",inet_ntoa(xip));

    rad_put_string(auth,RAD_USER_NAME,usernamebuf);

    rad_put_string(auth,RAD_USER_PASSWORD,"");
    rad_put_int(auth,RAD_NAS_PORT_TYPE,RAD_ETHERNET);
    rad_put_int(auth,RAD_FRAMED_PROTOCOL,10);
    rad_put_addr(auth,RAD_NAS_IP_ADDRESS,global_config->thisserver);
//    rad_put_addr(auth,RAD_LOGIN_IP_HOST,xip);
    rad_put_vendor_addr(auth,12344,1,xip);
    rad_put_string(auth,RAD_CALLING_STATION_ID,inet_ntoa(xip));
    if(eip.s_addr)
    rad_put_string(auth,RAD_FRAMED_IP_ADDRESS,inet_ntoa(eip));

    char lan[INET_ADDRSTRLEN];

    int res=rad_send_request(auth);

    if(res==-1)
    {
        LOG_WRITE(LF_RADIUS|LL_DEBUG|LL_INFO,"rad_send_request radius does not respond [user %s]",
                                                         inet_ntop(AF_INET, &xip, lan, INET_ADDRSTRLEN));
        LOG_WRITE(LF_RADIUS|LL_DEBUG|LL_INFO,"Error: %s",rad_strerror(auth));

        return NULL;
    } else if(res==RAD_ACCESS_REJECT) {

        LOG_WRITE(LF_RADIUS|LL_DEBUG|LL_INFO,"rad_send_request radius reject user [%s]",
                                                    inet_ntop(AF_INET, &xip, lan, INET_ADDRSTRLEN) );

        return NULL;
    }else if(res==RAD_ACCESS_ACCEPT) {
        struct usersession *ses=alloc_session();

        ses->lan=xip;
        ses->interim=300;

        LOG_WRITE(LF_RADIUS|LL_DEBUG,"rad_send_request radius accept user");

        const void *data;
        size_t len;

        while((res=rad_get_attr(auth,&data,&len))>0)
        {
            if(res==RAD_VENDOR_SPECIFIC)
            {
                u_int32_t vendor;

                int vres=rad_get_vendor_attr(&vendor,&data,&len);

                if(vendor==12344)
                {
                    if(vres==4)
                    {               //bsr-table-add (string)
                        char *r=rad_cvt_string(data,len);

                        LOG_WRITE(LF_RADIUS|LL_DEBUG,"ATTR: BSR-Table-Add %s",r);

                        char* d=NULL;

                        if((d=index(r,' '))!=NULL)
                        {
                            *d=0;
                            d++;
                            char *e=NULL;

                            if((e=index(d,' '))!=NULL)
                            {
                                *e=0;
                                e++;

                                LOG(LL_DEBUG,"Table %s add %s - %s",r,d,e);

                                int tip=0; 
                                int tid=0;
                                int tva=0;
                                if(strncasecmp(d,"wan",3)==0) tip=1;
                                if(sscanf(r,"%d",&tid)>0 && sscanf(e,"%d",&tva)>0){
                                    struct usersession_ipfw_table *fwt=malloc(sizeof(struct usersession_ipfw_table));
                                    fwt->table=tid;
                                    fwt->plen=32;
                                    fwt->value=tva;
                                    fwt->addr=tip?&ses->wan:&ses->lan;
                                    TAILQ_INSERT_TAIL(&ses->tables,fwt,entries);
                                    LOG(LL_DEBUG,"ipfw table %d add %s %d",tid,tip?"WAN":"LAN",tva);
                                }
                            };
                        }
                        free(r);


                    } else if(vres==3) {  // bsr-pipe (string)

                        //   примеры пайпов:
                        //    132 config bw 10242880 burst 1024K
                        //    232 config bw 10242880 burst 1024K
                        char *r=rad_cvt_string(data,len);
                        char tmp[255];
                        LOG_WRITE(LF_RADIUS|LL_DEBUG,"ATTR: BSR-Pipe %s",r);

                        // парсим команду ipfw pipe
                        strncpy(tmp, r, sizeof(tmp)-1);
                        char *x = NULL;
                        char *ipfw_string = tmp;
                        char *ipfw_arg[16];
                        int i=0;
                        while((x=strsep(&ipfw_string, " "))!=NULL)
                        {
                            ipfw_arg[i]=x;
                            i++;
                            if(i>=15)
                                break;
                        }

                        // меняем местами 1 и 2 аргументы
                        x=ipfw_arg[1];
                        ipfw_arg[1]=ipfw_arg[0];
                        ipfw_arg[0]=x;


                        // конфигурим пайп
                        if (!ipfw_config_pipe(i, ipfw_arg))
                        {
                            LOG(LL_INFO|LL_ERROR, "can't configure pipe: '%s'", r);
                        }

                        free(r);

                    } else if (vres==5) { // bsr-service-info
                        char *r=rad_cvt_string(data,len);
                        LOG_WRITE(LF_RADIUS|LL_DEBUG,"ATTR: BSR-Service-Info %s",r);

                        free(r);
                    } else {
                        LOG(LL_INFO,"unknown VSA %d (vendor %d)", vres, vendor);
                    }



                }
            } else {
                if(res==RAD_FRAMED_IP_ADDRESS)
                {
                    struct in_addr uip=rad_cvt_addr(data);
                    LOG_WRITE(LF_RADIUS|LL_DEBUG,"ATTR: Framed-IP-Address %s",inet_ntoa(uip));
                    ses->wan=uip;
                }
                else if(res==RAD_SESSION_TIMEOUT)
                {
                    LOG_WRITE(LF_RADIUS|LL_DEBUG,"ATTR: Session-Timeout %d",rad_cvt_int(data));
                    ses->sessiontimeout=rad_cvt_int(data);
                }
                else if(res==RAD_IDLE_TIMEOUT)
                {
                    LOG_WRITE(LF_RADIUS|LL_DEBUG,"ATTR: Idle-Timeout %d",rad_cvt_int(data));
                    ses->idletimeout=rad_cvt_int(data);
                }
                else if(res==RAD_ACCT_INTERIM_INTERVAL)
                {
                    LOG_WRITE(LF_RADIUS|LL_DEBUG,"ATTR: Interim-Interval %d",rad_cvt_int(data));
                    ses->interim=rad_cvt_int(data);
                }
                else if(res==88)
                {
                    char *r=rad_cvt_string(data,len);
                    LOG_WRITE(LF_RADIUS|LL_DEBUG,"ATTR: Framed-Pool %s",r);
                    ses->poolname=r;
                }
            }
        }

        gettimeofday(&ses->start, NULL);

        return ses;
    }

    return NULL;
}


int SockUDP(int id, struct in_addr ip, int port)
{
    if((sock[id]=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP))==-1)
    {
        LOG(LL_INFO|LL_ERROR,"can't create UDP socket: %s", strerror(errno));
        return -1;
    }

    struct sockaddr_in si_me;

    bzero(&si_me,sizeof(si_me));

    si_me.sin_family = AF_INET;
    si_me.sin_port = htons(port);
    si_me.sin_addr = ip;

    if (bind(sock[id], (struct sockaddr *)&si_me, sizeof(si_me))==-1)
    {
        LOG(LL_INFO|LL_ERROR,"can't bind UDP socket to %s:%d",inet_ntoa(si_me.sin_addr),ntohs(si_me.sin_port));
        return(-2);
    }

    if(setNonblocking(sock[id])==-1)
    {
        LOG(LL_INFO|LL_ERROR, "can't set socket to nonblocking: %s", strerror(errno));
        return -3;
    }

    EV_SET(&change[id],sock[id],EVFILT_READ,EV_ADD | EV_ENABLE,0,0,NULL);
    kevent(kq, &change[id], 1, NULL, 0, NULL);

    return (int)0;
}

void gotsessioninfo(struct getsession_res *ses)
{
    struct usersession *uses=get_session(usessions,ses->sid);

    LOG_WRITE(LF_SESSION|LL_DEBUG,"session sid %d, sess %p",ses->sid,uses);

    if(uses)
    {
        if(ses->lan_ip.s_addr!=uses->lan.s_addr || ses->wan_ip.s_addr!=uses->wan.s_addr)
        {
            LOG(LL_INFO|LL_ERROR,"ACHTUNG!!! Kernel and daemon sessions out of sync:");
            char saddr[16];
            char daddr[16];
            inet_ntoa_r(ses->lan_ip,saddr,16);
            inet_ntoa_r(ses->wan_ip,daddr,16);
            LOG(LL_INFO|LL_ERROR,"\t kernel sid %d lip %s eip %s",ses->sid,saddr,daddr);
            inet_ntoa_r(uses->lan,saddr,16);
            inet_ntoa_r(uses->wan,daddr,16);
            LOG(LL_INFO|LL_ERROR,"\t daemon sid %d lip %s eip %s",uses->sid,saddr,daddr);

        }
        if(uses->pkt_l2w!=ses->pkt_l2w || uses->pkt_w2l!=ses->pkt_w2l)
        {
            gettimeofday(&uses->lastact, NULL);
            uses->pkt_l2w=ses->pkt_l2w;
            uses->pkt_w2l=ses->pkt_w2l;
            uses->oct_l2w=ses->oct_l2w;
            uses->oct_w2l=ses->oct_w2l;
            gettimeofday(&uses->lastupd, NULL);
        } else {
            gettimeofday(&uses->lastupd, NULL);

            if(uses->lastupd.tv_sec-uses->lastact.tv_sec>=uses->idletimeout)
            {
                LOG_WRITE(LF_SESSION|LL_INFO, "Session %d [%s] idle %d sec. Timeout %d",uses->sid,inet_ntoa(uses->lan),(int)(uses->lastupd.tv_sec-uses->lastact.tv_sec),uses->idletimeout);
                uses->clear=RAD_TERM_IDLE_TIMEOUT;
            }
        }

        if(uses->sessiontimeout>0 && uses->lastupd.tv_sec-uses->start.tv_sec>=uses->sessiontimeout)
        {
            LOG_WRITE(LF_SESSION|LL_INFO,"Session %d [%s] sessiontime %d. Timeout %d",uses->sid,inet_ntoa(uses->lan),(int)(uses->lastupd.tv_sec-uses->start.tv_sec),uses->sessiontimeout);
            uses->clear=RAD_TERM_SESSION_TIMEOUT;
        }

        char srcb[16];
        char dstb[16];
        inet_ntoa_r(ses->lan_ip,srcb,16);
        inet_ntoa_r(ses->wan_ip,dstb,16);
        LOG_WRITE(LF_SESSION|LL_DEBUG,"Session %d lan %s %dpkt %lldbytes, wan %s %dpkt %lldbytes", ses->sid,
                srcb,ses->pkt_l2w,(unsigned long long int)ses->oct_l2w,
                dstb,ses->pkt_w2l,(unsigned long long int)ses->oct_w2l);

        if(uses->clear)
        {
            send_update(uses,2);
            struct getsession_req r; 
            r.sid=ses->sid;
            r.userdata=SES_DELETE;
            NgSendMsg(sock[SOCK_NG], cn.path, NGM_ZZNAT_COOKIE,NGM_ZZNAT_STOP_SESSION, (void *)&r, sizeof(r));
            LOG_WRITE(LF_SESSION|LL_INFO,"Stop session. cause %d",uses->clear);
        } else {
            if(((uses->lastupd.tv_sec-uses->lastsent.tv_sec)+3)>=uses->interim)
                send_update(uses,1);
        }
    }

}
void finish_all_radius_sessions(int signal)
{
    LOG(LL_INFO,"SIGTERM received. Terminating....");

    struct usersession *ses;
    TAILQ_FOREACH(ses,&usessions->head,entries)
    {
        ses->clear=RAD_TERM_NAS_REBOOT;
        send_update(ses,2);

        struct getsession_req r; 
        r.sid=ses->sid;
        r.userdata=0;
        NgSendMsg(sock[SOCK_NG], cn.path, NGM_ZZNAT_COOKIE,NGM_ZZNAT_RESET_SESSION, (void *)&r, sizeof(r));
    }


    // TODO: удаляем все pools
    // TODO: удаляем все usessions


    destroy_global_config();

    exit(1);
}

int main(int argc, char **argv)
{
    char sname[NG_NODESIZ];
    int rcvbuf = SORCVBUF_SIZE;
    char	*ng_name;

    // дефолтовые настройки логов
    progname=strdup("obsrd");

    for(int i=0; i<LFS; i++)
    {
        faclog2syslog[i]=0;
        facloglevel[i] = 0xffff;
    }

    if(argc<2){
        LOG(LL_INFO,"%s <ng_node_name>",argv[0]);
        return 0;
    };

    signal(SIGTERM,finish_all_radius_sessions);
    signal(SIGUSR1,finish_all_radius_sessions);

    // инициализируем структуру с глобальным конфигом
    init_global_config();

    // запускаем интерпретатор
    run_cli();

    kq=kqueue();
    if (kq == -1) perror("kqueue");

    pools=malloc(sizeof(struct pools));
    usessions=malloc(sizeof(struct sessions));
    pools_init(pools);

    init_sessions(usessions);

    if (!pool_create(pools,"default"))
    {
        LOG(LL_INFO|LL_ERROR, "can't create pool default");
        exit(1);
    }

    // грузим конфиги
    global_config->initial_boot = 1;  // разрешаем boot only команды

    if (config_load("obsr.conf")!=CLI_OK)
    {
        err(1, "Can't load config");
    }

    global_config->initial_boot = 0;  // запрещаем boot only команды

    // проверяем валидность конфигурации
    if (global_config->thisserver.s_addr==0 ||
        !global_config->radius_config       ||
        TAILQ_EMPTY(&global_config->radius_head))
    {
        LOG(LL_INFO|LL_ERROR, "EPIC FAIL. Server configuration isn't valid");
        exit(1);
    }

    auth  = rad_auth_open();
    racct = rad_acct_open();
    int rc;
    rc = rad_config(auth, global_config->radius_config);
    LOG_WRITE(LF_RADIUS|LL_DEBUG,"rad_config (auth): %d", rc);

    rc = rad_config(racct, global_config->radius_config);
    LOG_WRITE(LF_RADIUS|LL_DEBUG,"rad_config (racct): %d", rc);

    strcpy(cn.ourhook,"cfg");
    strcpy(cn.path,argv[1]);
    strcpy(cn.peerhook,"ctl");

    snprintf(ng_nodename, sizeof(ng_nodename), "%s:", ng_name);

    /* create control socket. */
    snprintf(sname, sizeof(sname), "zznatd%i", getpid());
    char* snamep=malloc(strlen(sname)+2);
    sprintf(snamep,"%s:",sname);

    if (NgMkSockNode(sname, &sock[SOCK_NG], NULL) == -1)
        err(1, "NgMkSockNode");

    if(NgSendMsg(sock[SOCK_NG], snamep, 
                NGM_GENERIC_COOKIE, NGM_CONNECT, &cn, sizeof(cn)) < 0)
    {
        err(1, "NgSendMsg");
    }

    if (setsockopt(sock[SOCK_NG], SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(int)) == -1)
        err(1, "setsockopt(SOL_SOCKET, SO_RCVBUF)");

    int token; 
    token=NgSendMsg(sock[SOCK_NG], cn.path, NGM_ZZNAT_COOKIE,NGM_ZZNAT_GET_SESSIONS, NULL, 0);

    LOG(LL_DEBUG,"NG token ZZNAT_GET_SESSIONS %d",token);

    setNonblocking(sock[SOCK_NG]);

    rc = SockUDP(SOCK_COA,global_config->thisserver,3799);

    if(rc<0)
    {
        LOG_WRITE(LF_RADIUS|LL_INFO|LL_ERROR, "Can't create radius COA socket: %d", rc);
    }

    coa = rad_server_open(sock[SOCK_COA]);
    if (!coa)
    {
        LOG_WRITE(LF_RADIUS|LL_INFO,"radius server open error.");
        exit(-1);
    }

    struct radius_client *rad;

    TAILQ_FOREACH(rad, &global_config->radius_head, entries)
    {
        // pass noviynascoa
        if (rad_add_server(coa,rad->client,0,rad->password,0,0)<0 )
        {
            LOG_WRITE(LF_RADIUS|LL_INFO|LL_DEBUG,"radius add server error for '%s': %s", rad->client, rad_strerror(coa));
            LOG(LL_INFO|LL_DEBUG,"radius add server error for '%s': %s", rad->client, rad_strerror(coa));
        }
    }



    int nev;
    struct kevent kep;
    /* Netgrah socket */
    EV_SET(&change[0],sock[SOCK_NG],EVFILT_READ,EV_ADD | EV_ENABLE,0,0,NULL); //netgraph
    kevent(kq, &change[0], 1, NULL, 0, NULL);

#define SOLEN 4096
    struct ng_mesg *cl=malloc(SOLEN);
    char chook[NG_HOOKSIZ];
    while(1)
    {
        nev = kevent(kq, NULL, 0, &kep, 1, NULL);
        if(nev < 0)
        {
            LOG(LL_ERROR,"KEvent error at line");
            return 1;
        }

        if(nev == 0)
            LOG(LL_DEBUG2, "KEvent timeout");

        LOG(LL_DEBUG2, "FD %ld Filter %d",(unsigned long)kep.ident,kep.filter);

        if(kep.filter==EVFILT_READ)
        {
            if(kep.ident==sock[SOCK_COA])
            {
                int coares=rad_receive_request(coa);

                LOG_WRITE(LF_RADIUS|LL_INFO, "Coa %d",coares);

                if(coares==40 || coares==43)
                {
                    int res;
                    const void *data;
                    size_t len;
                    struct in_addr lip;
                    lip.s_addr=0;
                    char   sid[64];
                    sid[0]=0;

                    while((res=rad_get_attr(coa,&data,&len))>0){
                        if(res!=RAD_VENDOR_SPECIFIC){
                            /*
                               if(res==RAD_LOGIN_IP_HOST){
                               struct in_addr uip=rad_cvt_addr(data);
                            //printf("ATTR: Login-IP-Host %s",inet_ntoa(uip));
                            lip.s_addr=uip.s_addr;
                            }else*/ if(res==RAD_ACCT_SESSION_ID){
                                char *r=rad_cvt_string(data,len);
                                //printf("ATTR: Session-ID %s\n",r);
                                strncpy(sid,r,64);
                                free(r);
                            }
                        }else{
                            u_int32_t vendor;
                            int vres=rad_get_vendor_attr(&vendor,&data,&len);
                            if(vendor==12344 && vres==1){ // bsr-client-local-ip
                                struct in_addr uip=rad_cvt_addr(data);
                                lip.s_addr=uip.s_addr;
                            }
                        }
                    }

                    LOG_WRITE(LF_SESSION|LL_INFO,"Kill ses from %s SID %s",inet_ntoa(lip),sid);

                    struct usersession *u,*r=NULL;

                    TAILQ_FOREACH(u,&usessions->head,entries)
                    {
                        if(u->lan.s_addr==lip.s_addr && u->sessionid && strncmp(u->sessionid,sid,64)==0)
                        {
                            r=u;
                            break;
                        };
                    };

                    if(r)
                    {
                        LOG_WRITE(LF_SESSION|LL_DEBUG, "Session SID %d found", r->sid);

                        u->clear=RAD_TERM_ADMIN_RESET;

                        struct getsession_req kr;

                        kr.sid=r->sid;
                        kr.userdata=SES_UPDATE;

                        token=NgSendMsg(sock[SOCK_NG], cn.path, NGM_ZZNAT_COOKIE,NGM_ZZNAT_GET_SESSION, (void *)&kr, sizeof(kr));

                        rad_create_response(coa,41);
                        rad_send_response(coa);
                    } else {
                        rad_create_response(coa,42);
                        rad_send_response(coa);
                    }
                }
                else if(coares==43)
                {
                    int res;
                    const void *data;
                    size_t len;
                    struct in_addr lip;

                    lip.s_addr=0;

                    char   sid[64];

                    sid[0]=0;

                    TAILQ_HEAD(sessionipfwtablehead1,usersession_ipfw_table) ttables; 
                    TAILQ_INIT(&ttables);

                    struct usersession *r=NULL;
                    while((res=rad_get_attr(coa,&data,&len))>0)
                    {
                        if(res!=RAD_VENDOR_SPECIFIC)
                        {
                        }
                        if(res==RAD_VENDOR_SPECIFIC)
                        {
                            u_int32_t vendor;
                            int vres=rad_get_vendor_attr(&vendor,&data,&len);
                            if(vendor==12344)
                            {
                                if(vres==4)    //bsr-table-add (string)
                                {
                                    char *r=rad_cvt_string(data,len);
                                    LOG_WRITE(LF_RADIUS|LL_DEBUG,"ATTR: BSR-Table-Add %s",r);
                                    char* d=NULL;
                                    if((d=index(r,' '))!=NULL){
                                        *d=0;
                                        d++;
                                        char *e=NULL;
                                        if((e=index(d,' '))!=NULL){
                                            *e=0;
                                            e++;
                                            LOG(LL_DEBUG,"Table %s add %s - %s",r,d,e);
                                            int tip=0; 
                                            int tid=0;
                                            int tva=0;
                                            if(strncasecmp(d,"wan",3)==0) tip=1;
                                            if(sscanf(r,"%d",&tid)>0 && sscanf(e,"%d",&tva)>0){
                                                struct usersession_ipfw_table *fwt=malloc(sizeof(struct usersession_ipfw_table));
                                                fwt->table=tid;
                                                fwt->plen=32;
                                                fwt->value=tva;
                                                fwt->addr=NULL;
                                                fwt->addrt=tip;
                                                TAILQ_INSERT_TAIL(&ttables,fwt,entries);
                                                LOG(LL_INFO,"ipfw table %d add %s %d",tid,tip?"WAN":"LAN",tva);
                                            }
                                        };
                                    }
                                    free(r);
                                } else if(vres==1) {   // bsr-client-local-ip

                                    struct in_addr uip=rad_cvt_addr(data);
                                    lip.s_addr=uip.s_addr;

                                } else if(vres==3) {  // bsr-pipe

                                    //    132 config bw 10242880 burst 1024K
                                    //    232 config bw 10242880 burst 1024K
                                    char *r=rad_cvt_string(data,len);
                                    LOG_WRITE(LF_RADIUS|LL_DEBUG,"ATTR: BSR-Table-Add %s",r);

                                    free(r);

                                } else {
                                    LOG(LL_INFO,"unknown VSA %d (vendor %d)", vres, vendor);
                                }

                            } else {
                                LOG(LL_INFO,"unknown vendor %d VSA %d", vendor, vres);
                            }
                        } else {
                            /*
                               if(res==RAD_LOGIN_IP_HOST){
                               struct in_addr uip=rad_cvt_addr(data);
                            //printf("ATTR: Login-IP-Host %s",inet_ntoa(uip));
                            lip.s_addr=uip.s_addr;
                            }else*/
                            if(res==RAD_ACCT_SESSION_ID)
                            {
                                char *r=rad_cvt_string(data,len);
                                //printf("ATTR: Session-ID %s\n",r);
                                strncpy(sid,r,64);
                                free(r);
                            } else if(res==RAD_SESSION_TIMEOUT)
                            {
                                LOG_WRITE(LF_RADIUS|LL_DEBUG, "ATTR: Session-Timeout %d",rad_cvt_int(data));
                            }
                            else if(res==RAD_IDLE_TIMEOUT)
                            {
                                LOG_WRITE(LF_RADIUS|LL_DEBUG, "ATTR: Idle-Timeout %d",rad_cvt_int(data));
                            }
                            else if(res==RAD_ACCT_INTERIM_INTERVAL)
                            {
                                LOG_WRITE(LF_RADIUS|LL_DEBUG, "ATTR: Interim-Interval %d",rad_cvt_int(data));
                            }
                            else
                            {
                                LOG_WRITE(LF_RADIUS|LL_DEBUG, "ATTR %d len: %d",res,(int)len);
                            }
                            if(!r && (res==RAD_LOGIN_IP_HOST||res==RAD_ACCT_SESSION_ID) && sid[0] && lip.s_addr)
                            {

                            }
                        }
                    }

                    LOG_WRITE(LF_RADIUS|LL_INFO, "COA ses from %s SID %s",inet_ntoa(lip),sid);
                    struct usersession *u=NULL;
                    TAILQ_FOREACH(u,&usessions->head,entries)
                    {
                        if(u->lan.s_addr==lip.s_addr && u->sessionid && strncmp(u->sessionid,sid,64)==0)
                        {
                            r=u;
                            break;
                        };
                    };
                    if(r)
                    {
                        LOG_WRITE(LF_SESSION|LL_DEBUG,"Session SID %d found", r->sid);

                        u->clear=RAD_TERM_ADMIN_RESET;
                        struct getsession_req kr; 
                        kr.sid=r->sid;
                        kr.userdata=SES_UPDATE;
                        token=NgSendMsg(sock[SOCK_NG], cn.path, NGM_ZZNAT_COOKIE,NGM_ZZNAT_GET_SESSION, (void *)&kr, sizeof(kr));
                        rad_create_response(coa,41);
                        rad_send_response(coa);
                    } else {
                        rad_create_response(coa,42);
                        rad_send_response(coa);
                    }

                };

            } else if(kep.ident==sock[SOCK_NG]) {
                int b=NgRecvMsg(sock[SOCK_NG],cl,SOLEN,chook);
                if(b>0)
                {
                    LOG(LL_DEBUG,"Netgraph msg received %d bytes from %s: cmd: %s [%d], with %d bytes of payload",b,chook,commands[cl->header.cmd],cl->header.cmd, cl->header.arglen);
                    if(cl->header.cmd==NGM_ZZNAT_REQ_SESSION)
                    {
                        if(cl->header.arglen==sizeof(struct in_addr))
                        {
                            struct in_addr a;
                            struct in_addr b;
                            memcpy(&a,cl->data,4);
                            LOG(LL_DEBUG,"Request session from %s",inet_ntoa(a));
                            bzero(&b,4);
                            create_session(a,b,0);
                        }
                    } else if(cl->header.cmd==NGM_ZZNAT_START_SESSION) {
                        if(cl->header.arglen==sizeof(struct createsess_res))
                        {
                            struct createsess_res *sres=(struct createsess_res *)cl->data;

                            if(sres->res)
                            {
                                struct usersession *ses=get_session(usessions,sres->sid);
                                if(ses)
                                {
                                    send_update(ses,0);
                                    ses->started=1;
                                    ipfw_couple(ses);
                                }else{
                                    struct kevent ktmr;
                                    EV_SET(&ktmr,sres->sid+1000,EVFILT_TIMER,EV_DELETE | EV_DISABLE ,0,0,NULL);
                                    kevent(kq, &ktmr, 1, NULL, 0, NULL);
                                    //del_session(usessions,ses);
                                }
                            }
                        }

                    } else if(cl->header.cmd==NGM_ZZNAT_STOP_SESSION) {
                        if(cl->header.arglen==sizeof(struct createsess_res))
                        {
                            struct createsess_res *sres=(struct createsess_res *)cl->data;
                            //                            if(sres->userdata==SES_DELETE){
                            struct kevent ktmr;

                            EV_SET(&ktmr,sres->sid+1000,EVFILT_TIMER,EV_DELETE | EV_DISABLE ,0,0,NULL);
                            kevent(kq, &ktmr, 1, NULL, 0, NULL);

                            struct usersession *uses=get_session(usessions,sres->sid);
                            if(uses)
                            {
                                ipfw_decouple(uses);
                                del_session(usessions,uses);
                                free_session(uses);
                            }
                            //                            }
                        }
                    }else if(cl->header.cmd==NGM_ZZNAT_GET_SESSION){
                        if(cl->header.arglen==sizeof(struct getsession_res))
                        {
                            struct getsession_res *sres=(struct getsession_res *)cl->data;
                            if(sres->res)
                            {
                                switch(sres->userdata)
                                {
                                    case SES_CREATE:
                                        create_session(sres->lan_ip,sres->wan_ip,sres->sid);
                                        break;
                                    case SES_UPDATE:
                                        gotsessioninfo(sres);
                                        break;
                                    default:
                                        break;
                                }
                            }
                        }
                    }else if(cl->header.cmd==NGM_ZZNAT_GET_SESSIONS){
                        u_int32_t *s=(u_int32_t *)cl->data;

                        if(cl->header.arglen>4 && cl->header.arglen==s[0]*sizeof(u_int32_t))
                        {
                            LOG_WRITE(LF_SESSION|LL_INFO,"Sessions %d",s[0]-1);

                            for(int c=1;c<s[0];c++)
                            {
                                if(s[c]>=mi) mi=s[c]+1;

                                struct getsession_req r;

                                r.sid=s[c];
                                r.userdata=SES_CREATE;

                                //token=NgSendMsg(sock[SOCK_NG], cn.path, NGM_ZZNAT_COOKIE,NGM_ZZNAT_GET_SESSION, (void *)&r, sizeof(r));
                                //create_session(cl->lan,cl->wan,cl->sid);
                                //NgSendMsg(cs, cn.path, NGM_ZZNAT_COOKIE,NGM_ZZNAT_GET_SESSION, (void *)&sid, sizeof(sid));

                                LOG_WRITE(LF_SESSION|LL_INFO,"\tsid %d found, stopping ",s[c]);
                                //token=NgSendMsg(cs, cn.path, NGM_ZZNAT_COOKIE,NGM_ZZNAT_GET_SESSION, (void *)&sid, sizeof(sid));
                                r.userdata=0;
                                NgSendMsg(sock[SOCK_NG], cn.path, NGM_ZZNAT_COOKIE,NGM_ZZNAT_STOP_SESSION, (void *)&r, sizeof(r));
                                //printf("token %d\n",token);

                            }
                        }
                    }
                    /*
                       for(int c=0;c<cl->header.arglen;c++){
                       LOG(LL_INFO,"%02x ",cl->data[c]);
                       }
                       LOG(LL_INFO,"");
                       for(int c=0;c<b;c++){
                       LOG(LL_INFO,"%02x ",cl[c]);
                       }
                       LOG(LL_INFO,"");
                       */
                }
            } else {

                LOG(LL_INFO|LL_ERROR|LL_DEBUG,"Unknown socket");
                return(10);
            }
        } else if(kep.filter==EVFILT_TIMER) {
            if(kep.ident>=1000)
            {
                LOG_WRITE(LF_SESSION|LL_DEBUG,"Timer %d",(int)kep.ident);

                struct usersession *ses=(struct usersession*)kep.udata;

                if(ses)
                {
                    struct kevent ktmr;

                    EV_SET(&ktmr,kep.ident,EVFILT_TIMER,EV_ADD | EV_ENABLE | EV_ONESHOT ,0,SES_POLL*1000,ses);
                    kevent(kq, &ktmr, 1, NULL, 0, NULL);

                    LOG_WRITE(LF_SESSION|LL_DEBUG,"fetch info about session %d",ses->sid);

                    struct getsession_req r;

                    r.sid=ses->sid;
                    r.userdata=SES_UPDATE;

                    token=NgSendMsg(sock[SOCK_NG], cn.path, NGM_ZZNAT_COOKIE,NGM_ZZNAT_GET_SESSION, (void *)&r, sizeof(r));
                } else {
                    //temporary session-loopback for disabled users
                    LOG_WRITE(LF_SESSION|LL_INFO,"remove temporary session %d",(int)(kep.ident-1000));

                    struct getsession_req r;

                    r.sid=kep.ident-1000;
                    r.userdata=SES_DELETE;

                    NgSendMsg(sock[SOCK_NG], cn.path, NGM_ZZNAT_COOKIE,NGM_ZZNAT_STOP_SESSION, (void *)&r, sizeof(r));
                }
            }
        }
    }

    close(sock[SOCK_NG]);
    close(sock[SOCK_AUTH]);
    close(sock[SOCK_ACCT]);

    stop_cli();

    destroy_global_config();

    exit(0);
}


