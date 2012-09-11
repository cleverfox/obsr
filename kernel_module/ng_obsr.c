#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/mbuf.h>
#include <sys/malloc.h>
#include <sys/ctype.h>
#include <sys/errno.h>
#include <sys/syslog.h>

#include "ng_obsr.h"
#include <netgraph/ng_message.h>
#include <netgraph/ng_parse.h>
#include <netgraph/netgraph.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#ifdef NG_SEPARATE_MALLOC
MALLOC_DEFINE(M_NETGRAPH_ZZNAT, "netgraph_obsr", "netgraph obsr node ");
#else
#define M_NETGRAPH_ZZNAT M_NETGRAPH
#endif

static ng_constructor_t	ng_obsr_constructor;
static ng_rcvmsg_t	ng_obsr_rcvmsg;
static ng_shutdown_t	ng_obsr_shutdown;
static ng_newhook_t	ng_obsr_newhook;
static ng_connect_t	ng_obsr_connect;
static ng_rcvdata_t	ng_obsr_rcvdata;
static ng_disconnect_t	ng_obsr_disconnect;

/* Parse type for struct ngobsrstat */
//static const struct ng_parse_struct_field ng_obsr_stat_type_fields[] = NG_ZZNAT_STATS_TYPE_INFO;
//static const struct ng_parse_type ng_obsr_stat_type = { &ng_parse_struct_type, &ng_obsr_stat_type_fields };

static const struct ng_parse_struct_field ng_obsr_start_type_fields[] = NG_ZZNAT_CREATESESS;
static const struct ng_parse_type ng_obsr_start_type = { &ng_parse_struct_type, &ng_obsr_start_type_fields };

static const struct ng_parse_struct_field ng_obsr_get_type_fields[] = NG_ZZNAT_GETSESS;
static const struct ng_parse_type ng_obsr_get_type = { &ng_parse_struct_type, &ng_obsr_get_type_fields };

/* List of commands and how to convert arguments to/from ASCII */
static const struct ng_cmdlist ng_obsr_cmdlist[] = {
	{
	  NGM_ZZNAT_COOKIE,
	  NGM_ZZNAT_START_SESSION,
	  "startsession",
	  &ng_obsr_start_type,
	  NULL
	},
	{
	  NGM_ZZNAT_COOKIE,
	  NGM_ZZNAT_STOP_SESSION,
	  "stopsession",
	  &ng_parse_int32_type,
	  NULL
	},
	{
	  NGM_ZZNAT_COOKIE,
	  NGM_ZZNAT_GET_SESSION,
	  "getsession",
	  &ng_parse_int32_type,
	  &ng_obsr_get_type,
	},
	{ 0 }
};


/* Netgraph node type descriptor */
static struct ng_type typestruct = {
	.version =	NG_ABI_VERSION,
	.name =		NG_ZZNAT_NODE_TYPE,
	.constructor =	ng_obsr_constructor,
	.rcvmsg =	ng_obsr_rcvmsg,
	.shutdown =	ng_obsr_shutdown,
	.newhook =	ng_obsr_newhook,
/*	.findhook =	ng_obsr_findhook, 	*/
	.connect =	ng_obsr_connect,
	.rcvdata =	ng_obsr_rcvdata,
	.disconnect =	ng_obsr_disconnect,
	.cmdlist =	ng_obsr_cmdlist,
};
NETGRAPH_INIT(obsr, &typestruct);

/* Information we store for each node */
struct ZZNAT {
	hook_p	lan;
	hook_p	wan;
	hook_p	sock;
	hook_p	lanout;
	hook_p	wanout;
	hook_p	wanrej;
        TAILQ_HEAD(sesshead, session) sessions;
//        TAILQ_HEAD(poolhead, ip_pool) pools;
        RB_HEAD(map_lan,session) lan2sess;
        RB_HEAD(map_wan,session) wan2sess;


	node_p		node;		/* back pointer to node */
	hook_p  	debughook;
	u_int   	packets_in;	/* packets in from downstream */
	u_int   	packets_out;	/* packets out towards downstream */
	u_int32_t	flags;
};
typedef struct ZZNAT *obsr_p;

inline int lan_cmp(struct session *left,struct session *right);
inline int wan_cmp(struct session *left,struct session *right);
RB_GENERATE_STATIC(map_lan,session,lan,lan_cmp);
RB_GENERATE_STATIC(map_wan,session,wan,wan_cmp);

inline int lan_cmp(struct session *left,struct session *right){
    return left->lan_ip.s_addr-right->lan_ip.s_addr;
};
inline int wan_cmp(struct session *left,struct session *right){
    return left->wan_ip.s_addr-right->wan_ip.s_addr;
};

int createsess(obsr_p node,u_int32_t sessionid,struct in_addr lan_ip,struct in_addr wan_ip);
int stopsess(obsr_p node,struct session *ses);

int createsess(obsr_p node,u_int32_t sessionid,struct in_addr lan_ip,struct in_addr wan_ip){
    struct session *ses;
    struct session s;
    s.lan_ip=lan_ip;
    s.wan_ip=wan_ip;
    s.sessionid=sessionid;
    if((ses=RB_FIND(map_lan,&node->lan2sess,&s))!=NULL){
        return 100;
    }
    if((ses=RB_FIND(map_wan,&node->wan2sess,&s))!=NULL){
        return 100;
    }
    TAILQ_FOREACH(ses,&node->sessions,entries){
        if(ses->sessionid==sessionid){
            return 101;
        }
    }
    ses=malloc(sizeof(struct session),M_NETGRAPH,M_NOWAIT | M_ZERO);
    if(!ses)
        return (ENOMEM);
    ses->sessionid=sessionid;
    ses->lan_ip=lan_ip;
    ses->wan_ip=wan_ip;
    TAILQ_INSERT_TAIL(&node->sessions,ses,entries);
    if(lan_ip.s_addr)
        RB_INSERT(map_lan,&node->lan2sess,ses);
    if(wan_ip.s_addr)
        RB_INSERT(map_wan,&node->wan2sess,ses);


    return 0;
}
int stopsess(obsr_p node,struct session *ses){
    if(ses->lan_ip.s_addr)
        RB_REMOVE(map_lan,&node->lan2sess,ses);
    if(ses->wan_ip.s_addr)
        RB_REMOVE(map_wan,&node->wan2sess,ses);
    TAILQ_REMOVE(&node->sessions,ses,entries);

    free(ses, M_NETGRAPH);

    return 0;
}

int alert_sess(obsr_p node, struct ip *ip);
int alert_sess(obsr_p node, struct ip *ip){
    char srcb[16];
    inet_ntoa_r(ip->ip_src,srcb);
    char dstb[16];
    inet_ntoa_r(ip->ip_dst,dstb);
    log(LOG_WARNING, "ng_obsr: need send alert about new session from user %s to %s\n",srcb,dstb);
    struct ng_mesg *msg;
    int error;
    NG_MKMESSAGE(msg, NGM_ZZNAT_COOKIE, NGM_ZZNAT_REQ_SESSION, 4, M_NOWAIT);
    memcpy(msg->data,&ip->ip_src,4);
    if (msg == NULL)
        return (ENOBUFS);
    NG_SEND_MSG_HOOK(error, node->node, msg, node->sock, NG_NODE_ID(node->node));
/*
            NG_SEND_MSG_ID(error, privp->node, msg,                                                                                                                                         
                                NG_NODE_ID(NG_PEER_NODE(privp->ethernet_hook)),                                                                                                                             
                                            NG_NODE_ID(privp->node));  
*/
    return error;
}


void checksumadjust(u_int16_t *chksum, unsigned char *optr, unsigned char *nptr, int xlen);
      /* assuming: unsigned char is 8 bits, long is 32 bits.
       *      - chksum points to the chksum in the packet
       *           - optr points to the old data in the packet
       *                - nptr points to the new data in the packet
       *                   */

void checksumadjust(u_int16_t *chksum, unsigned char *optr, unsigned char *nptr, int len) {
    long x, old, new, xlen;
    x=*chksum;
    x=~x & 0xFFFF;
    xlen=len;
    while (xlen)
    {
        old=optr[0]*256+optr[1]; optr+=2;
        x-=old & 0xffff;
        if (x<=0) { x--; x&=0xffff; }
        xlen-=2;
    }
    xlen=len;
    while (xlen)
    {
        new=nptr[0]*256+nptr[1]; nptr+=2;
        x+=new & 0xffff;
        if (x & 0x10000) { x++; x&=0xffff; }
        xlen-=2;
    }
    x=~x & 0xFFFF;
    *chksum=x&0xffff;
}


        
static int
ng_obsr_constructor(node_p node)
{
	obsr_p d;
	/* Initialize private descriptor */
	d = malloc(sizeof(*d), M_NETGRAPH,
		M_NOWAIT | M_ZERO);
	if (d == NULL)
		return (ENOMEM);
        TAILQ_INIT(&d->sessions);
        RB_INIT(&d->lan2sess);
        RB_INIT(&d->wan2sess);
	NG_NODE_SET_PRIVATE(node, d);
	d->node = node;
	return (0);
}

static int
ng_obsr_newhook(node_p node, hook_p hook, const char *name)
{
	const obsr_p obsrp = NG_NODE_PRIVATE(node);
	if (strcmp(name, NG_ZZNAT_HOOK_LAN) == 0) {
	    obsrp->lan=hook;
	} else if (strcmp(name, NG_ZZNAT_HOOK_LANO) == 0) {
	    obsrp->lanout=hook;
	} else if (strcmp(name, NG_ZZNAT_HOOK_WAN) == 0) {
	    obsrp->wan=hook;
	} else if (strcmp(name, NG_ZZNAT_HOOK_WANR) == 0) {
	    obsrp->wanrej=hook;
	} else if (strcmp(name, NG_ZZNAT_HOOK_WANO) == 0) {
	    obsrp->wanout=hook;
	} else if (strcmp(name, NG_ZZNAT_HOOK_SOCK) == 0) {
	    obsrp->sock=hook;
	} else
		return (EINVAL);	/* not a hook we know about */
	return(0);
}

static int
ng_obsr_rcvmsg(node_p node, item_p item, hook_p lasthook)
{
	const obsr_p obsrp = NG_NODE_PRIVATE(node);
	struct ng_mesg *resp = NULL;
	int error = 0;
	struct ng_mesg *msg;

	NGI_GET_MSG(item, msg);
	/* Deal with message according to cookie and command */
	switch (msg->header.typecookie) {
	case NGM_ZZNAT_COOKIE:
		switch (msg->header.cmd) {
		case NGM_ZZNAT_START_SESSION:
                    {
                        if(msg->header.arglen!=sizeof(struct createsess_req)){
                            error = EINVAL;
                            break;
                        }
			struct createsess_res *rses;
                        NG_MKRESPONSE(resp, msg, sizeof(*rses), M_NOWAIT);
                        rses = (struct createsess_res *) resp->data;
                        struct createsess_req *s=(struct createsess_req *)msg->data;
                        if(createsess(obsrp,s->sid,s->lan,s->wan)==0){
                            rses->sid=s->sid;
                            rses->userdata=s->userdata;
                            rses->res=1;
                        }else{
                            rses->sid=s->sid;
                            rses->userdata=s->userdata;
                            rses->res=0;
                        }
                    }
                case NGM_ZZNAT_GET_SESSION:
                    {
                        if(msg->header.arglen!=sizeof(struct getsession_req)){
                            error = EINVAL;
                            break;
                        }
			struct getsession_res *rses;
                        NG_MKRESPONSE(resp, msg, sizeof(*rses), M_NOWAIT);
                        struct getsession_req *req=(struct getsession_req *)msg->data;
                        struct session *ses;
                        rses = (struct getsession_res *) resp->data;
                        rses->sid=req->sid;
                        rses->userdata=req->userdata;
                        rses->res=0;
                        TAILQ_FOREACH(ses,&obsrp->sessions,entries){
                            if(req->sid==ses->sessionid){
                                rses->sid=ses->sessionid;
                                rses->lan_ip=ses->lan_ip;
                                rses->wan_ip=ses->wan_ip;
                                rses->pkt_l2w=ses->pkt_l2w;
                                rses->pkt_w2l=ses->pkt_w2l;
                                rses->oct_l2w=ses->oct_l2w;
                                rses->oct_w2l=ses->oct_w2l;
                                rses->res=1;
                                break;
                            }
                        }
                        break;
                    }
                case NGM_ZZNAT_RESET_SESSION:
                    {
                        if(msg->header.arglen!=sizeof(struct getsession_req)){
                            error = EINVAL;
                            break;
                        }
                        struct createsess_res *rses;
                        NG_MKRESPONSE(resp, msg, sizeof(*rses), M_NOWAIT);
                        struct getsession_req *req=(struct getsession_req *)msg->data;
                        rses = (struct createsess_res *) resp->data;

                        rses->res=0;
                        rses->sid=req->sid;
                        rses->userdata=req->userdata;
                        struct session *ses;
                        TAILQ_FOREACH(ses,&obsrp->sessions,entries){
                            if(req->sid==ses->sessionid){
                                ses->pkt_l2w=0;
                                ses->pkt_w2l=0;
                                ses->oct_l2w=0;
                                ses->oct_w2l=0;
                                rses->res=1;
                                break;
                            }
                        }
                        break;
                    }
                 case NGM_ZZNAT_STOP_SESSION:
                    {
                        if(msg->header.arglen!=sizeof(struct getsession_req)){
                            error = EINVAL;
                            break;
                        }
                        struct createsess_res *rses;
                        NG_MKRESPONSE(resp, msg, sizeof(*rses), M_NOWAIT);
                        struct getsession_req *req=(struct getsession_req *)msg->data;
                        rses = (struct createsess_res *) resp->data;

                        rses->res=0;
                        rses->sid=req->sid;
                        rses->userdata=req->userdata;
                        struct session *ses;
                        TAILQ_FOREACH(ses,&obsrp->sessions,entries){
                            if(req->sid==ses->sessionid){
                                rses->res=stopsess(obsrp,ses)+1;
                                break;
                            }
                        }
                        break;
                    }
                case NGM_ZZNAT_GET_SESSIONS:
                    {
                        int cnt=0;
                        struct session *ses;
                        TAILQ_FOREACH(ses,&obsrp->sessions,entries){
                            cnt++;
                        };
//                        log(LOG_WARNING, "ng_obsr: sessions %d, prepare %d bytes\n",cnt,sizeof(u_int32_t)*(cnt+1));
                        NG_MKRESPONSE(resp, msg, sizeof(u_int32_t)*(cnt+1), M_NOWAIT);
                        u_int32_t *s=(u_int32_t *)resp->data;
                        int ci=1;
                        TAILQ_FOREACH(ses,&obsrp->sessions,entries){
                            s[ci]=ses->sessionid;
                            ci++;
                            if(ci>cnt)
                                break;
                        }
                        s[0]=ci;

                    }
		default:
			error = EINVAL;		/* unknown command */
			break;
		}
		break;
	default:
		error = EINVAL;			/* unknown cookie type */
		break;
	}

	/* Take care of synchronous response, if any */
	NG_RESPOND_MSG(error, node, item, resp);
	/* Free the message and return */
	NG_FREE_MSG(msg);
	return(error);
}



#define	M_CHECK(length)	do {					\
    pullup_len += length;					\
    if ((m)->m_pkthdr.len < (pullup_len)) {			\
        error = EINVAL;					\
        goto bypass;					\
    } 							\
    if ((m)->m_len < (pullup_len) &&			\
            (((m) = m_pullup((m),(pullup_len))) == NULL)) {	\
        error = ENOBUFS;				\
        goto done;					\
    }							\
} while (0)

static int
ng_obsr_rcvdata(hook_p hook, item_p item ) {
    const obsr_p node = NG_NODE_PRIVATE(NG_HOOK_NODE(hook));
    int error=0;
    int pullup_len = 0;
    struct mbuf *m;
    hook_p out=NULL;

    NGI_GET_M(item, m);


    pullup_len=0;
    struct ip *ip;

    M_CHECK(sizeof(struct ip));
    ip = mtod(m, struct ip *);

    if ((ip->ip_off & htons(IP_OFFMASK)) == 0) {
        pullup_len += (ip->ip_hl << 2) - sizeof(struct ip);

        switch (ip->ip_p) {
            case IPPROTO_TCP:
                M_CHECK(sizeof(struct tcphdr));
                break;
            case IPPROTO_UDP:
                M_CHECK(sizeof(struct udphdr));
                break;
                /*
            case IPPROTO_ICMP:
                M_CHECK(sizeof(struct icmphdr));
                break;
                */
        }
    }

    ip = mtod(m, struct ip *);
    int csdiff=0;

    hook_p xwan=node->wanout?node->wanout:node->wan;
    hook_p xlan=node->lanout?node->lanout:node->lan;

    char srcb[16];
    inet_ntoa_r(ip->ip_src,srcb);
    char dstb[16];
    inet_ntoa_r(ip->ip_dst,dstb);
    //log(LOG_WARNING, "ng_obsr: data %d - %s -> %s!\n",ip->ip_p,srcb,dstb);
    struct session *ses=NULL;
    struct in_addr oldhdr[2];
    memcpy(oldhdr,&ip->ip_src,sizeof(struct in_addr)*2);
    if(hook==node->lan){
        struct session s;
        s.lan_ip.s_addr=ip->ip_src.s_addr;
        if((ses=RB_FIND(map_lan,&node->lan2sess,&s))!=NULL){
//            log(LOG_WARNING, "ng_obsr: session from LAN %s -> %s found, wan %s\n",srcb,dstb,inet_ntoa(ses->wan_ip));
            if(ses->wan_ip.s_addr && xwan){

                csdiff-=ip->ip_src.s_addr;
                csdiff+=ses->wan_ip.s_addr;
                ip->ip_src.s_addr=ses->wan_ip.s_addr;

                ses->pkt_l2w++;
                ses->oct_l2w+=ntohs(ip->ip_len);
                out=xwan;
                goto bypass;
            }else{
                if(node->wanrej){
                    log(LOG_WARNING, "ng_obsr: bypass from %s to wanrej for %s\n",srcb,dstb);
                    out=node->wanrej;
                    goto bypass;
                }else{
                    log(LOG_WARNING, "ng_obsr: reject IP in session from %s to %s\n",srcb,dstb);
                    error=ENETUNREACH;
                    goto done;
                }
            }
        }else{
            alert_sess(node,ip);
            log(LOG_WARNING, "ng_obsr: session from LAN %s -> %s not found\n",srcb,dstb);
            //error=ECONNABORTED;
            //    error=ENETUNREACH;
                goto done;
        }
    }else if(hook==node->wan){
        struct session s;
        s.wan_ip.s_addr=ip->ip_dst.s_addr;
        if((ses=RB_FIND(map_wan,&node->wan2sess,&s))!=NULL){
//            log(LOG_WARNING, "ng_obsr: session from WAN %s -> %s found, lan %s\n",srcb,dstb,inet_ntoa(ses->lan_ip));
            if(ses->lan_ip.s_addr && xlan){

                csdiff-=ip->ip_dst.s_addr;
                csdiff+=ses->lan_ip.s_addr;
                ip->ip_dst.s_addr=ses->lan_ip.s_addr;

                ses->pkt_w2l++;
                ses->oct_w2l+=ntohs(ip->ip_len);
                out=xlan;
                goto bypass;
            }else{
                log(LOG_WARNING, "ng_obsr: reject IP in session\n");
                error=ENETUNREACH;
                goto done;
            }
        }else{
            //            log(LOG_WARNING, "ng_obsr: session from WAN %s -> %s not found\n",srcb,dstb);
            error=ENETUNREACH;
            goto done;
        }
    }else{
        log(LOG_WARNING, "ng_obsr: incoming data on other hook, dropped!\n");
        //NG_FWD_NEW_DATA(error, item, node->sock.hook, m);
        error=ENETUNREACH;
        goto done;
    }


bypass:
    if (out != NULL) {
        if(csdiff){
            if ((ip->ip_off & htons(IP_OFFMASK)) == 0) {
                switch (ip->ip_p) {
                    case IPPROTO_TCP:
                        {
                            /*
                               char buf[2048];
                               char *tb=buf;
                               for(int tx=0;tx<sizeof(struct ip)+sizeof(struct tcphdr);tx++){
                               tb+=sprintf(tb,"%02x ",((unsigned char*)ip)[tx]);
                               }
                               log(LOG_WARNING, "ng_obsr: TCP %s!\n",buf);
                               */
                            struct tcphdr *th=(struct tcphdr *)(ip+1);
                            u_int16_t csum=ntohs(th->th_sum);
                            checksumadjust(&csum,(unsigned char*)oldhdr,(unsigned char*)&ip->ip_src,sizeof(struct in_addr)*2);
                            //                        log(LOG_WARNING, "ng_obsr: need recalc TCP checksum from %x to %x!\n",ntohs(th->th_sum),csum);
                            th->th_sum=htons(csum);

                            break;
                        }
                    case IPPROTO_UDP:
                        {
                            struct udphdr *uh=(struct udphdr *)(ip+1);
                            u_int16_t csum=ntohs(uh->uh_sum);
                            checksumadjust(&csum,(unsigned char*)oldhdr,(unsigned char*)&ip->ip_src,sizeof(struct in_addr)*2);
                            //                        log(LOG_WARNING, "ng_obsr: need recalc UDP checksum from %x to %x!\n",ntohs(uh->uh_sum),csum);
                            uh->uh_sum=htons(csum);
                            break;
                        }
                        /*
                           case IPPROTO_ICMP:
                           {
                        //                        (struct icmp *)ip_next(pip)
                        struct icmphdr *ih=(struct icmphdr *)(ip+1);
                        u_int16_t csum=ntohs(ih->icmp_cksum);
                        checksumadjust(&csum,(unsigned char*)oldhdr,(unsigned char*)&ip->ip_src,sizeof(struct in_addr)*2);
                        log(LOG_WARNING, "ng_obsr: need recalc UDP checksum from %x to %x!\n",ntohs(ih->icmp_cksum),csum);
                        ih->icmp_cksum=htons(csum);
                        break;
                        }
                        */
                }
            }
        }

        /* XXX: error gets overwritten here */
        NG_FWD_NEW_DATA(error, item, out, m);
        return (error);
    }
done:
    if (item)
        NG_FREE_ITEM(item);
    if (m)
        NG_FREE_M(m);

    return (error);	
}

static int
ng_obsr_shutdown(node_p node)
{
	const obsr_p privdata = NG_NODE_PRIVATE(node);

#ifndef PERSISTANT_NODE
	NG_NODE_SET_PRIVATE(node, NULL);
	NG_NODE_UNREF(node);
	free(privdata, M_NETGRAPH);
#else
	if (node->nd_flags & NGF_REALLY_DIE) {
		/*
		 * WE came here because the widget card is being unloaded,
		 * so stop being persistant.
		 * Actually undo all the things we did on creation.
		 */
		NG_NODE_SET_PRIVATE(node, NULL);
		NG_NODE_UNREF(privdata->node);
		free(privdata, M_NETGRAPH);
		return (0);
	}
	NG_NODE_REVIVE(node);		/* tell ng_rmnode() we will persist */
#endif /* PERSISTANT_NODE */
	return (0);
}

/*
 * This is called once we've already connected a new hook to the other node.
 * It gives us a chance to balk at the last minute.
 */
static int
ng_obsr_connect(hook_p hook)
{
#if 0
	/*
	 * If we were a driver running at other than splnet then
	 * we should set the QUEUE bit on the edge so that we
	 * will deliver by queing.
	 */
	if /*it is the upstream hook */
	NG_HOOK_FORCE_QUEUE(NG_HOOK_PEER(hook));
#endif
	return (0);
}

static int ng_obsr_disconnect(hook_p hook) {
    const obsr_p node = NG_NODE_PRIVATE(NG_HOOK_NODE(hook));
    if(hook==node->lan){
        node->lan=NULL;
    }else
        if(hook==node->wan){
            node->wan=NULL;
        }else
            if(hook==node->sock){
                node->sock=NULL;
            }
        /*
           if (NG_HOOK_PRIVATE(hook))
           ((struct ZZNAT_hookinfo *) (NG_HOOK_PRIVATE(hook)))->hook = NULL;
           */
        if ((NG_NODE_NUMHOOKS(NG_HOOK_NODE(hook)) == 0)
                && (NG_NODE_IS_VALID(NG_HOOK_NODE(hook)))) /* already shutting down? */
            ng_rmnode_self(NG_HOOK_NODE(hook));
        return (0);
}


