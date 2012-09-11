#include <sys/queue.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip_fw.h>
#include <netinet/ip_dummynet.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <libutil.h>
#include <sys/sysctl.h>

#include "session.h"
#include "ipfw.h"
#include "log.h"

#define LOG(loglevel, ...) LOG_WRITE(LF_OTHER|loglevel, __VA_ARGS__)


#if 1
// temp definitions


struct cmdline_opts {
	/* boolean options: */
	int	do_value_as_ip;	/* show table value as IP */
	int	do_resolv;	/* try to resolve all ip to names */
	int	do_time;	/* Show time stamps */
	int	do_quiet;	/* Be quiet in add and flush */
	int	do_pipe;	/* this cmd refers to a pipe/queue/sched */
	int	do_nat; 	/* this cmd refers to a nat config */
	int	do_dynamic;	/* display dynamic rules */
	int	do_expired;	/* display expired dynamic rules */
	int	do_compact;	/* show rules in compact mode */
	int	do_force;	/* do not ask for confirmation */
	int	show_sets;	/* display the set each rule belongs to */
	int	test_only;	/* only check syntax */
	int	comment_only;	/* only print action and comment */
	int	verbose;	/* be verbose on some commands */

	/* The options below can have multiple values. */

	int	do_sort;	/* field to sort results (0 = no) */
		/* valid fields are 1 and above */

	int	use_set;	/* work with specified set number */
		/* 0 means all sets, otherwise apply to set use_set - 1 */

};

struct cmdline_opts co;

#endif



static struct _s_x dummynet_params[] = {
	{ "plr",		TOK_PLR },
	{ "noerror",		TOK_NOERROR },
	{ "buckets",		TOK_BUCKETS },
	{ "dst-ip",		TOK_DSTIP },
	{ "src-ip",		TOK_SRCIP },
	{ "dst-port",		TOK_DSTPORT },
	{ "src-port",		TOK_SRCPORT },
	{ "proto",		TOK_PROTO },
	{ "weight",		TOK_WEIGHT },
	{ "lmax",		TOK_LMAX },
	{ "maxlen",		TOK_LMAX },
	{ "all",		TOK_ALL },
	{ "mask",		TOK_MASK }, /* alias for both */
	{ "sched_mask",		TOK_SCHED_MASK },
	{ "flow_mask",		TOK_FLOW_MASK },
	{ "droptail",		TOK_DROPTAIL },
	{ "red",		TOK_RED },
	{ "gred",		TOK_GRED },
	{ "bw",			TOK_BW },
	{ "bandwidth",		TOK_BW },
	{ "delay",		TOK_DELAY },
	{ "link",		TOK_LINK },
	{ "pipe",		TOK_PIPE },
	{ "queue",		TOK_QUEUE },
	{ "flowset",		TOK_FLOWSET },
	{ "sched",		TOK_SCHED },
	{ "pri",		TOK_PRI },
	{ "priority",		TOK_PRI },
	{ "type",		TOK_TYPE },
	{ "flow-id",		TOK_FLOWID},
	{ "dst-ipv6",		TOK_DSTIP6},
	{ "dst-ip6",		TOK_DSTIP6},
	{ "src-ipv6",		TOK_SRCIP6},
	{ "src-ip6",		TOK_SRCIP6},
	{ "profile",		TOK_PROFILE},
	{ "burst",		TOK_BURST},
	{ "dummynet-params",	TOK_NULL },
	{ NULL, 0 }	/* terminator */
};





int ipfw_table_do(u_int16_t table,struct in_addr addr,u_int8_t plen,u_int32_t value,u_int8_t action)
{
    ipfw_table_entry ent;
    ent.tbl=table;
    ent.masklen=plen;
    ent.addr=addr.s_addr;
    ent.value=value;

    static int s = -1;      /* the socket */
    if (s == -1)
        s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (s < 0){
        LOG(LL_INFO,"Can't create socket to control IPFW");
        return(-1);
    }
    return setsockopt(s, IPPROTO_IP, action?IP_FW_TABLE_ADD:IP_FW_TABLE_DEL, &ent, sizeof(ent));
};

void ipfw_session(struct usersession *ses,u_int8_t action)
{
//           ipfw_table_do(5,uses->lan,32,11,0);
    struct usersession_ipfw_table *fwt;
    TAILQ_FOREACH(fwt,&ses->tables,entries)
    {
        ipfw_table_do(fwt->table,*(fwt->addr),fwt->plen,fwt->value,action);
    }
}

void ipfw_couple(struct usersession *ses)
{
    ipfw_session(ses,1);
}


void ipfw_decouple(struct usersession *ses)
{
    ipfw_session(ses,0);
}





/* n2mask sets n bits of the mask */
void
n2mask(struct in6_addr *mask, int n)
{
	static int	minimask[9] =
	    { 0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff };
	u_char		*p;

	memset(mask, 0, sizeof(struct in6_addr));
	p = (u_char *) mask;
	for (; n > 0; p++, n -= 8) {
		if (n >= 8)
			*p = 0xff;
		else
			*p = minimask[n];
	}
	return;
}

/*
 * conditionally runs the command.
 * Selected options or negative -> getsockopt
 */
int
do_cmd(int optname, void *optval, uintptr_t optlen)
{
	static int s = -1;	/* the socket */
	int i;

	if (co.test_only)
		return 0;

	if (s == -1)
		s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (s < 0) {
        LOG(LL_ERROR, "firewall socket unawailable");
        return 0;
    }

	if (optname == IP_FW_GET || optname == IP_DUMMYNET_GET ||
	    optname == IP_FW_ADD || optname == IP_FW_TABLE_LIST ||
	    optname == IP_FW_TABLE_GETSIZE || 
	    optname == IP_FW_NAT_GET_CONFIG || 
	    optname < 0 ||
	    optname == IP_FW_NAT_GET_LOG) {
		if (optname < 0)
			optname = -optname;
		i = getsockopt(s, IPPROTO_IP, optname, optval,
			(socklen_t *)optlen);
	} else {
		i = setsockopt(s, IPPROTO_IP, optname, optval, optlen);
	}
	return i;
}



/*
 * _substrcmp takes two strings and returns 1 if they do not match,
 * and 0 if they match exactly or the first string is a sub-string
 * of the second.  A warning is printed to stderr in the case that the
 * first string is a sub-string of the second.
 *
 * This function will be removed in the future through the usual
 * deprecation process.
 */
int
_substrcmp(const char *str1, const char* str2)
{
	
	if (strncmp(str1, str2, strlen(str1)) != 0)
		return 1;

	if (strlen(str1) != strlen(str2))
		LOG(LL_INFO, "DEPRECATED: '%s' matched '%s' as a sub-string",
		    str1, str2);
	return 0;
}

/*
 * _substrcmp2 takes three strings and returns 1 if the first two do not match,
 * and 0 if they match exactly or the second string is a sub-string
 * of the first.  A warning is printed to stderr in the case that the
 * first string does not match the third.
 *
 * This function exists to warn about the bizzare construction
 * strncmp(str, "by", 2) which is used to allow people to use a shotcut
 * for "bytes".  The problem is that in addition to accepting "by",
 * "byt", "byte", and "bytes", it also excepts "by_rabid_dogs" and any
 * other string beginning with "by".
 *
 * This function will be removed in the future through the usual
 * deprecation process.
 */
int
_substrcmp2(const char *str1, const char* str2, const char* str3)
{
	
	if (strncmp(str1, str2, strlen(str2)) != 0)
		return 1;

	if (strcmp(str1, str3) != 0)
		LOG(LL_INFO, "DEPRECATED: '%s' matched '%s'",
		    str1, str3);
	return 0;
}


#define O_NEXT(p, len) ((void *)((char *)p + len))
#if 0
static void
oid_fill(struct dn_id *oid, int len, int type, uintptr_t id)
{
	oid->len = len;
	oid->type = type;
	oid->subtype = 0;
	oid->id = id;
}

/* make room in the buffer and move the pointer forward */
static void *
o_next(struct dn_id **o, int len, int type)
{
	struct dn_id *ret = *o;
	oid_fill(ret, len, type, 0);
	*o = O_NEXT(*o, len);
	return ret;
}
#endif
/**
 * match_token takes a table and a string, returns the value associated
 * with the string (-1 in case of failure).
 */

int
match_token(struct _s_x *table, char *string)
{
	struct _s_x *pt;
	uint i = strlen(string);

	for (pt = table ; i && pt->s != NULL ; pt++)
		if (strlen(pt->s) == i && !bcmp(string, pt->s, i))
			return pt->x;
	return -1;
}

/*
 * Take as input a string describing a bandwidth value
 * and return the numeric bandwidth value.
 * set clocking interface or bandwidth value
 */
static void
read_bandwidth(char *arg, int *bandwidth, char *if_name, int namelen)
{
	if (*bandwidth != -1)
    {
		LOG(LL_INFO, "duplicate token, override bandwidth value!");
    }

	if (arg[0] >= 'a' && arg[0] <= 'z') {
		if (!if_name) {
            LOG(LL_ERROR, "no if support");
            return;
		}
		if (namelen >= IFNAMSIZ)
        {
			LOG(LL_INFO, "interface name truncated");
        }
		namelen--;
		/* interface name */
		strncpy(if_name, arg, namelen);
		if_name[namelen] = '\0';
		*bandwidth = 0;
	} else {	/* read bandwidth value */
		int bw;
		char *end = NULL;

		bw = strtoul(arg, &end, 0);
		if (*end == 'K' || *end == 'k') {
			end++;
			bw *= 1000;
		} else if (*end == 'M' || *end == 'm') {
			end++;
			bw *= 1000000;
		}
		if ((*end == 'B' &&
			_substrcmp2(end, "Bi", "Bit/s") != 0) ||
		    _substrcmp2(end, "by", "bytes") == 0)
			bw *= 8;

		if (bw < 0)
        {
            LOG(LL_ERROR, "bandwidth too large");
            return;
        }

		*bandwidth = bw;
		if (if_name)
			if_name[0] = '\0';
	}
}




/*
 * configuration of pipes, schedulers, flowsets.
 * When we configure a new scheduler, an empty pipe is created, so:
 * 
 * do_pipe = 1 -> "pipe N config ..." only for backward compatibility
 *	sched N+Delta type fifo sched_mask ...
 *	pipe N+Delta <parameters>
 *	flowset N+Delta pipe N+Delta (no parameters)
 *	sched N type wf2q+ sched_mask ...
 *	pipe N <parameters>
 *
 * do_pipe = 2 -> flowset N config
 *	flowset N parameters
 *
 * do_pipe = 3 -> sched N config
 *	sched N parameters (default no pipe)
 *	optional Pipe N config ...
 * pipe ==>
 *
 * return: 1 -- no errors
 *         0 -- somthing wrong
 */
int
ipfw_config_pipe(int ac, char **av)
{
    int samples[ED_MAX_SAMPLES_NO];
    struct dn_pipe p;
    int i;
    char *end;
    void *par = NULL;

    memset(&p, 0, sizeof p);
    p.bandwidth = -1;

    av++; ac--;
    /* Pipe number */
    if (ac && isdigit(**av)) {
        i = atoi(*av); av++; ac--;
        if (co.do_pipe == 1)
            p.pipe_nr = i;
        else
            p.fs.fs_nr = i;
    }
    while (ac > 0) {
        double d;
        int tok = match_token(dummynet_params, *av);
        ac--; av++;

        switch(tok) {
            case TOK_NOERROR:
                p.fs.flags_fs |= DN_NOERROR;
                break;

            case TOK_PLR:
                return 0;
                //NEED1("plr needs argument 0..1\n");
                d = strtod(av[0], NULL);
                if (d > 1)
                    d = 1;
                else if (d < 0)
                    d = 0;
                p.fs.plr = (int)(d*0x7fffffff);
                ac--; av++;
                break;

            case TOK_QUEUE:
                return 0;
                //NEED1("queue needs queue size\n");
                end = NULL;
                p.fs.qsize = strtoul(av[0], &end, 0);
                if (*end == 'K' || *end == 'k') {
                    p.fs.flags_fs |= DN_QSIZE_IS_BYTES;
                    p.fs.qsize *= 1024;
                } else if (*end == 'B' ||
                        _substrcmp2(end, "by", "bytes") == 0) {
                    p.fs.flags_fs |= DN_QSIZE_IS_BYTES;
                }
                ac--; av++;
                break;

            case TOK_BUCKETS:
                return 0;
                //NEED1("buckets needs argument\n");
                p.fs.rq_size = strtoul(av[0], NULL, 0);
                ac--; av++;
                break;

            case TOK_MASK:
                return 0;
                //NEED1("mask needs mask specifier\n");
                /*
                 * per-flow queue, mask is dst_ip, dst_port,
                 * src_ip, src_port, proto measured in bits
                 */
                par = NULL;

                bzero(&p.fs.flow_mask, sizeof(p.fs.flow_mask));
                end = NULL;

                while (ac >= 1) {
                    uint32_t *p32 = NULL;
                    uint16_t *p16 = NULL;
                    uint32_t *p20 = NULL;
                    struct in6_addr *pa6 = NULL;
                    uint32_t a;

                    tok = match_token(dummynet_params, *av);
                    ac--; av++;
                    switch(tok) {
                        case TOK_ALL:
                            /*
                             * special case, all bits significant
                             */
                            p.fs.flow_mask.dst_ip = ~0;
                            p.fs.flow_mask.src_ip = ~0;
                            p.fs.flow_mask.dst_port = ~0;
                            p.fs.flow_mask.src_port = ~0;
                            p.fs.flow_mask.proto = ~0;
                            n2mask(&(p.fs.flow_mask.dst_ip6), 128);
                            n2mask(&(p.fs.flow_mask.src_ip6), 128);
                            p.fs.flow_mask.flow_id6 = ~0;
                            p.fs.flags_fs |= DN_HAVE_FLOW_MASK;
                            goto end_mask;

                        case TOK_DSTIP:
                            p32 = &p.fs.flow_mask.dst_ip;
                            break;

                        case TOK_SRCIP:
                            p32 = &p.fs.flow_mask.src_ip;
                            break;

                        case TOK_DSTIP6:
                            pa6 = &(p.fs.flow_mask.dst_ip6);
                            break;

                        case TOK_SRCIP6:
                            pa6 = &(p.fs.flow_mask.src_ip6);
                            break;

                        case TOK_FLOWID:
                            p20 = &p.fs.flow_mask.flow_id6;
                            break;

                        case TOK_DSTPORT:
                            p16 = &p.fs.flow_mask.dst_port;
                            break;

                        case TOK_SRCPORT:
                            p16 = &p.fs.flow_mask.src_port;
                            break;

                        case TOK_PROTO:
                            break;

                        default:
                            ac++; av--; /* backtrack */
                            goto end_mask;
                    }
                    if (ac < 1)
                        //errx(EX_USAGE, "mask: value missing");
                        return 0;
                    if (*av[0] == '/') {
                        a = strtoul(av[0]+1, &end, 0);
                        if (pa6 == NULL)
                            a = (a == 32) ? ~0 : (1 << a) - 1;
                    } else
                        a = strtoul(av[0], &end, 0);
                    if (p32 != NULL)
                        *p32 = a;
                    else if (p16 != NULL) {
                        if (a > 0xFFFF)
                            //errx(EX_DATAERR, "port mask must be 16 bit"); 
                            return 0;
                        *p16 = (uint16_t)a;
                    } else if (p20 != NULL) {
                        if (a > 0xfffff)
                            //errx(EX_DATAERR, "flow_id mask must be 20 bit");
                            return 0;
                        *p20 = (uint32_t)a;
                    } else if (pa6 != NULL) {
                        if (a > 128)
                            //errx(EX_DATAERR, "in6addr invalid mask len");
                            return 0;
                        else
                            n2mask(pa6, a);
                    } else {
                        if (a > 0xFF)
                            //errx(EX_DATAERR, "proto mask must be 8 bit");
                            return 0;
                        p.fs.flow_mask.proto = (uint8_t)a;
                    }
                    if (a != 0)
                        p.fs.flags_fs |= DN_HAVE_FLOW_MASK;
                    ac--; av++;
                } /* end while, config masks */
end_mask:
                break;

            case TOK_RED:
            case TOK_GRED:
                //NEED1("red/gred needs w_q/min_th/max_th/max_p\n");
                return 0;
                p.fs.flags_fs |= DN_IS_RED;
                if (tok == TOK_GRED)
                    p.fs.flags_fs |= DN_IS_GENTLE_RED;
                /*
                 * the format for parameters is w_q/min_th/max_th/max_p
                 */
                if ((end = strsep(&av[0], "/"))) {
                    double w_q = strtod(end, NULL);
                    if (w_q > 1 || w_q <= 0)
                        //errx(EX_DATAERR, "0 < w_q <= 1");
                        return 0;
                    p.fs.w_q = (int) (w_q * (1 << SCALE_RED));
                }
                if ((end = strsep(&av[0], "/"))) {
                    p.fs.min_th = strtoul(end, &end, 0);
                    if (*end == 'K' || *end == 'k')
                        p.fs.min_th *= 1024;
                }
                if ((end = strsep(&av[0], "/"))) {
                    p.fs.max_th = strtoul(end, &end, 0);
                    if (*end == 'K' || *end == 'k')
                        p.fs.max_th *= 1024;
                }
                if ((end = strsep(&av[0], "/"))) {
                    double max_p = strtod(end, NULL);
                    if (max_p > 1 || max_p <= 0)
                        //errx(EX_DATAERR, "0 < max_p <= 1");
                        return 0;
                    p.fs.max_p = (int)(max_p * (1 << SCALE_RED));
                }
                ac--; av++;
                break;

            case TOK_DROPTAIL:
                p.fs.flags_fs &= ~(DN_IS_RED|DN_IS_GENTLE_RED);
                break;

            case TOK_BW:
                //NEED1("bw needs bandwidth or interface\n");
                if (co.do_pipe != 1)
                    //errx(EX_DATAERR, "bandwidth only valid for pipes");
                    return 0;
                read_bandwidth(av[0], &p.bandwidth, p.if_name, sizeof(p.if_name));
                ac--; av++;
                break;

            case TOK_DELAY:
                if (co.do_pipe != 1)
                    return 0;
                //errx(EX_DATAERR, "delay only valid for pipes");
                //NEED1("delay needs argument 0..10000ms\n");
                p.delay = strtoul(av[0], NULL, 0);
                ac--; av++;
                break;

            case TOK_WEIGHT:
                if (co.do_pipe == 1)
                    return 0;
                //				errx(EX_DATAERR,"weight only valid for queues");
                //NEED1("weight needs argument 0..100\n");
                p.fs.weight = strtoul(av[0], &end, 0);
                ac--; av++;
                break;

            case TOK_PIPE:
                if (co.do_pipe == 1)
                    return 0;
                //				errx(EX_DATAERR,"pipe only valid for queues");
                //			NEED1("pipe needs pipe_number\n");
                p.fs.parent_nr = strtoul(av[0], &end, 0);
                ac--; av++;
                break;

                /*
            case TOK_PIPE_PROFILE:
                if (co.do_pipe != 1)
                    errx(EX_DATAERR, "extra delay only valid for pipes");
                //			NEED1("extra delay needs the file name\n");
                p.samples = &samples[0];
                load_extra_delays(av[0], &p);
                --ac; ++av;
                break;
*/
            case TOK_BURST:
                if (co.do_pipe != 1)
                    return 0;
                //				errx(EX_DATAERR, "burst only valid for pipes");
                //			NEED1("burst needs argument\n");
                errno = 0;
                if (expand_number(av[0], &p.burst) < 0)
                    if (errno != ERANGE)
                        return 0;
                //					errx(EX_DATAERR, "burst: invalid argument");
                if (errno || p.burst > (1ULL << 48) - 1)
                    return 0;
                //				errx(EX_DATAERR, "burst: out of range (0..2^48-1)");
                ac--; av++;
                break;

            default:
                return 0;
                //			errx(EX_DATAERR, "unrecognised option ``%s''", av[-1]);
        }
    }
    if (co.do_pipe == 1) {
        if (p.pipe_nr == 0)
            return 0;
        //			errx(EX_DATAERR, "pipe_nr must be > 0");
        if (p.delay > 10000)
            return 0;
        //			errx(EX_DATAERR, "delay must be < 10000");
    } else { /* co.do_pipe == 2, queue */
        if (p.fs.parent_nr == 0)
            return 0;
        //			errx(EX_DATAERR, "pipe must be > 0");
        if (p.fs.weight >100)
            return 0;
        //			errx(EX_DATAERR, "weight must be <= 100");
    }

    /* check for bandwidth value */
    if (p.bandwidth == -1) {
        p.bandwidth = 0;
        if (p.samples_no > 0)
            return 0;
        //			errx(EX_DATAERR, "profile requires a bandwidth limit");
    }

    if (p.fs.flags_fs & DN_QSIZE_IS_BYTES) {
        size_t len;
        long limit;

        len = sizeof(limit);
        if (sysctlbyname("net.inet.ip.dummynet.pipe_byte_limit",
                    &limit, &len, NULL, 0) == -1)
            limit = 1024*1024;
        if (p.fs.qsize > limit)
            return 0;
        //			errx(EX_DATAERR, "queue size must be < %ldB", limit);
    } else {
        size_t len;
        long limit;

        len = sizeof(limit);
        if (sysctlbyname("net.inet.ip.dummynet.pipe_slot_limit",
                    &limit, &len, NULL, 0) == -1)
            limit = 100;
        if (p.fs.qsize > limit)
            return 0;
        //			errx(EX_DATAERR, "2 <= queue size <= %ld", limit);
    }
    if (p.fs.flags_fs & DN_IS_RED) {
        size_t len;
        int lookup_depth, avg_pkt_size;
        double s, idle, weight, w_q;
        struct clockinfo ck;
        int t;

        if (p.fs.min_th >= p.fs.max_th)
            return 0;
        //		    errx(EX_DATAERR, "min_th %d must be < than max_th %d", p.fs.min_th, p.fs.max_th);
        if (p.fs.max_th == 0)
            return 0;
        //		    errx(EX_DATAERR, "max_th must be > 0");

        len = sizeof(int);
        if (sysctlbyname("net.inet.ip.dummynet.red_lookup_depth",
                    &lookup_depth, &len, NULL, 0) == -1)
            return 0;
        //		    errx(1, "sysctlbyname(\"%s\")", "net.inet.ip.dummynet.red_lookup_depth");
        if (lookup_depth == 0)
            return 0;
        //		    errx(EX_DATAERR, "net.inet.ip.dummynet.red_lookup_depth" " must be greater than zero");

        len = sizeof(int);
        if (sysctlbyname("net.inet.ip.dummynet.red_avg_pkt_size",
                    &avg_pkt_size, &len, NULL, 0) == -1)

            return 0;
        //		    errx(1, "sysctlbyname(\"%s\")", "net.inet.ip.dummynet.red_avg_pkt_size");
        if (avg_pkt_size == 0)
            return 0;
        //			errx(EX_DATAERR, "net.inet.ip.dummynet.red_avg_pkt_size must" " be greater than zero");

        len = sizeof(struct clockinfo);
        if (sysctlbyname("kern.clockrate", &ck, &len, NULL, 0) == -1)
            return 0;
        //			errx(1, "sysctlbyname(\"%s\")", "kern.clockrate");

        /*
         * Ticks needed for sending a medium-sized packet.
         * Unfortunately, when we are configuring a WF2Q+ queue, we
         * do not have bandwidth information, because that is stored
         * in the parent pipe, and also we have multiple queues
         * competing for it. So we set s=0, which is not very
         * correct. But on the other hand, why do we want RED with
         * WF2Q+ ?
         */
        if (p.bandwidth==0) /* this is a WF2Q+ queue */
            s = 0;
        else
            s = (double)ck.hz * avg_pkt_size * 8 / p.bandwidth;

        /*
         * max idle time (in ticks) before avg queue size becomes 0.
         * NOTA:  (3/w_q) is approx the value x so that
         * (1-w_q)^x < 10^-3.
         */
        w_q = ((double)p.fs.w_q) / (1 << SCALE_RED);
        idle = s * 3. / w_q;
        p.fs.lookup_step = (int)idle / lookup_depth;
        if (!p.fs.lookup_step)
            p.fs.lookup_step = 1;
        weight = 1 - w_q;
        for (t = p.fs.lookup_step; t > 1; --t)
            weight *= 1 - w_q;
        p.fs.lookup_weight = (int)(weight * (1 << SCALE_RED));
    }
    if (p.samples_no <= 0) {
        i = do_cmd(IP_DUMMYNET_CONFIGURE, &p, sizeof p);
    } else {
        struct dn_pipe_max pm;
        int len = sizeof(pm);

        memcpy(&pm.pipe, &p, sizeof(pm.pipe));
        memcpy(&pm.samples, samples, sizeof(pm.samples));

        i = do_cmd(IP_DUMMYNET_CONFIGURE, &pm, len);
    }

    if (i)
        return 0;
    //		err(1, "setsockopt(%s)", "IP_DUMMYNET_CONFIGURE");
    return 1;
}
