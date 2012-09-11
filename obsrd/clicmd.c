
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <string.h>
#include <radlib.h>
#include <radlib_vs.h>
#include <sys/stat.h>
#include <unistd.h>

#include <netgraph.h>


#include "obsrd.h"
#include "ippool.h"
#include "clicmd.h"
#include "cliconfig.h"
#include "log.h"

#include "session.h"

#include "../kernel_module/ng_obsr.h"


#define LOG(loglevel, ...) LOG_WRITE(LF_CMD|loglevel, __VA_ARGS__)


extern struct sessions *usessions;
extern int sock[4];
extern struct ngm_connect cn;
extern struct pools *pools;

extern int errno;



// показываем все текущие сессии
int cmd_show_sessions(struct cli_client *cc, char *command, char *argv[], int argc)
{

    if (argc != 0)
    {
        cli_print(cc, "usage:\nshow active sessions");

        return CLI_OK;
    }

    cli_print(cc,"  %15s %15s %15s %10s %6s %s",
            "sessionid","LAN IP","WAN IP","Pool","SID","start");

    struct usersession *us;
    TAILQ_FOREACH(us,&usessions->head,entries)
    {
        char lan[INET_ADDRSTRLEN];
        char wan[INET_ADDRSTRLEN];
        char xtime[32];

        time_t t = us->start.tv_sec;
        strftime(xtime,32,"%Y-%m-%d %T",localtime(&t));

        cli_print(cc,"  %15s %15s %15s %10s %6d %s",
                us->sessionid, 
                inet_ntop(AF_INET,&us->lan,lan,INET_ADDRSTRLEN),
                inet_ntop(AF_INET,&us->wan,wan,INET_ADDRSTRLEN),
                us->poolname,us->sid,xtime);
    }

    cli_print(cc, "-end-of-list-");

    return CLI_OK;
}

// убиваем сессию
int cmd_close_session(struct cli_client *cc, char *command, char *argv[], int argc)
{

    if (argc != 1 || (argc == 1 && argv[0][strlen(argv[0])-1] == '?'))
    {
        cli_print(cc, "usage:\nclose session sessionid/SID");

        return CLI_OK;
    }

    // проверяем формат аргумента: у нас sid или sessionid?
    int is_sid;
    int sid;

    is_sid = sscanf(argv[0], "%i-%i", &sid, &sid);

    // пробуем найти сессию
    struct usersession *us;
    int is_killed = 0;
    TAILQ_FOREACH(us,&usessions->head,entries)
    {
        if((is_sid == 1 && sid == us->sid) || (us->sessionid && strcmp(us->sessionid, argv[0])==0))
        {

            struct usersession *user_session=get_session(usessions,us->sid);
            if (user_session)
            {
                user_session->clear=RAD_TERM_ADMIN_RESET;

                struct getsession_req r;
                r.sid=us->sid;
                r.userdata=SES_UPDATE;
                NgSendMsg(sock[SOCK_NG], cn.path, NGM_ZZNAT_COOKIE,NGM_ZZNAT_GET_SESSION, (void *)&r, sizeof(r));

                cli_print(cc, "killing session sid: %d, sessid: %s", us->sid, us->sessionid);
                LOG(LL_INFO,"killing session (%p) sid: %d, sessid: %s", us, us->sid, us->sessionid);
                is_killed = 1;
            }

            break;
        }
    }

    if (!is_killed)
    {
        if (is_sid == 1)
        {
            cli_print(cc, "Session with sid '%d' not found", sid);
        } else {
            cli_print(cc, "Session with sess_id '%s' not found", argv[0]);
        }
    }

    return CLI_OK;
}


int dump_log_config(struct cli_client *cc, FILE *fh){
    int c=0; 
    int d=0; 
    if(progname){
        fprintf(fh,"syslogname %s\r\n",progname);
    }
    for(;;d++){
        if(log_facilities[d]==NULL)
            break;
        for(c=0;c<LOG_LEVELS;c++){
            if(log_labels[c]==NULL)
                break;
            if(faclogavail[d]&(1<<c)){
                if(facloglevel[d]&(1<<c)){ 
                    fprintf(fh,"loglevel %s %s\r\n",log_facilities[d],log_labels[c]);
                }else{
                    fprintf(fh,"loglevel %s %s no\r\n",log_facilities[d],log_labels[c]);
                }    
            }    
        }    


        if(!faclog2syslog[d]){
            fprintf(fh,"syslog %s no\r\n",log_facilities[d]);
        }else{
            for(c=0;;c++){
                if(syslog_facility[c].c_name==NULL)
                    break;
                if(syslog_facility[c].c_val==faclog2syslog[d]){
                    fprintf(fh,"syslog %s %s\r\n",log_facilities[d],syslog_facility[c].c_name);
                    break;
                }    
            }    
        }    
    }    
    return CLI_OK;
}


void config_generator_2cli(struct cli_client* cli,FILE* fh,char* string){ cli_print(cli,"%s",string); }

// показываем конфиги
int cmd_show_config(struct cli_client *cc, char *command, char *argv[], int argc)
{
    dump_running_config(cc, cc->client);
#if 0
    int showmask=0xffff;
    if(argc==1){
        int p=0;
        int slen=strlen(argv[0]);
        while(config_sections[p].name!=NULL){
            if(strncasecmp(argv[0],config_sections[p].name,slen)==0){
                showmask=(1<<config_sections[p].mask);
                break;
            }
            p++;
        }
    }
#endif

    cli_print(cc, "#-end-of-config-");

    return CLI_OK;
}

// сохраняем конфиги
int cmd_save_config(struct cli_client *cc, char *command, char *argv[], int argc)
{
    if (argc == 1 && argv[0][strlen(argv[0])-1] == '?')
    {
        cli_print(cc, "usage:\nsave config [filename]");

        return CLI_OK;
    }

    char * config_name;
    char resolved_path[PATH_MAX + 1];

    config_name = (argc == 0)?"obsr.conf":argv[0];
    config_name = realpath(config_name, resolved_path);;

    if (!config_name)
    {
        cli_print(cc, "invalid config name. GURU meditation 0x0003");
        return CLI_ERROR;
    }

    // sanity check. пока сохраняем конфиги только в текущую директорию
    char *working_dir;
    if((working_dir = getwd(NULL)) == NULL)
    {
        cli_print(cc, "internal error. GURU meditation 0x0006");
        return CLI_ERROR;
    }

    if (strncmp(working_dir, config_name, strlen(working_dir)))
    {
        cli_print(cc, "ERROR: you can save configs only to current dir");

        if (working_dir) free(working_dir);
        if (config_name) free(config_name);

        return CLI_ERROR;
    }

    if (working_dir) free(working_dir);

    cli_print(cc, "saving configs to '%s'", config_name);

    FILE *fh;

    if (!(fh = fopen(config_name, "w")))
    {
        // для errorstr не нужно делать free
        char * errorstr = strerror(errno);

        cli_print(cc, "can't write config: %s", errorstr);

        if (config_name) free(config_name);

        return CLI_ERROR;
    }

    dump_running_config(cc, fh);

    fclose(fh);

    cli_print(cc, "done");

    return CLI_OK;
}

// добавляем pool ip адресов
int cmd_pool_add(struct cli_client *cc, char *command, char *argv[], int argc)
{
    char * pool_name;
    if ((argc!=2 && argc!=3)|| argv[0][strlen(argv[0])-1] == '?')
    {
        cli_print(cc, "usage:\npool add first_ip last_ip [pool_name]");

        return CLI_OK;
    }

    // проверяем валидность аргументов
    struct in_addr xip;
    struct in_addr yip;

    if (!inet_aton(argv[0], &xip))
    {
        cli_print(cc, "invalid ip address: '%s'", argv[0]);
        return CLI_OK;
    }

    if (!inet_aton(argv[1], &yip))
    {
        cli_print(cc, "invalid ip address: '%s'", argv[1]);
        return CLI_OK;
    }

    pool_name = (argc==3)?argv[2]:"default";

    struct ippool *p = get_pool(pools, pool_name);
    if (!p)
    {
        cli_print(cc, "can't find pool '%s'", pool_name);

        return CLI_OK;
    }

    cli_print(cc, "pool %s: added %d ips\n", pool_name, pool_add_range(p, xip, yip));

    return CLI_OK;
}


// показывает пул ip адресов
int cmd_show_pool(struct cli_client *cc, char *command, char *argv[], int argc)
{
    if (argc > 1 || (argc == 1 && argv[0][strlen(argv[0])-1] == '?'))
    {
        cli_print(cc, "usage:\nshow pool [name]");

        return CLI_OK;
    }

    char *pool_name;

    pool_name = (argc==0)? "default" : argv[0];

    struct ippool *pool = get_pool(pools, pool_name);

    if (!pool)
    {
        cli_print(cc, "pool '%s' not found", pool_name);
        return CLI_OK;
    }

    long used_ips = 0;
    long sessions = 0;
    long allocated = 0;

    struct in_addr one_ip;
    if(inet_aton("0.0.0.1",&one_ip)!=1)
    {
        cli_print(cc, "internal error: guru meditation 0x0001");
        return CLI_OK;
    }

    struct in_addr last_ip;
    struct in_addr pool_from_ip;
    struct ip_entry *e;

    last_ip.s_addr = 0;

    TAILQ_FOREACH(e,&pool->head,entries){
        used_ips++;

        if (e->sess)
            sessions++;

        if (e->allocated)
            allocated++;

        struct in_addr next_ip;
        next_ip.s_addr = last_ip.s_addr + one_ip.s_addr;

        if (last_ip.s_addr == 0)
        {
            pool_from_ip.s_addr = e->ip.s_addr;
            last_ip.s_addr = e->ip.s_addr;
            continue;
        }

        if (next_ip.s_addr != e->ip.s_addr)
        {
            char pool_from[16];
            char pool_to[16];
            inet_ntoa_r(pool_from_ip, pool_from, sizeof(pool_from));
            inet_ntoa_r(last_ip, pool_to, sizeof(pool_to));
            cli_print(cc, "pool %s: %s - %s", pool_name, pool_from, pool_to);

            pool_from_ip.s_addr = e->ip.s_addr;
        }

        last_ip.s_addr = e->ip.s_addr;
    }

    if (last_ip.s_addr != 0)
    {
        char pool_from[16];
        char pool_to[16];
        inet_ntoa_r(pool_from_ip, pool_from, sizeof(pool_from));
        inet_ntoa_r(last_ip, pool_to, sizeof(pool_to));
        cli_print(cc, "pool %s: %s - %s", pool_name, pool_from, pool_to);
    }

    cli_print(cc, "pool %s: size=%ld allocated=%ld sessions=%ld\n", pool_name, used_ips, allocated, sessions);

    return CLI_OK;
}


// Прописываем ip'шник нашего сервака.
int cmd_this_server(struct cli_client *cc, char *command, char *argv[], int argc)
{
    if (argc > 1 || (argc == 1 && argv[0][strlen(argv[0])-1] == '?'))
    {
        cli_print(cc, "usage:\nthis server ip_address");

        return CLI_OK;
    }

    if (!inet_aton(argv[0], &global_config->thisserver))
    {
        cli_print(cc, "invalid argument: %s\nEPIC FAIL. can't configure ip address of this server", argv[0]);
        return CLI_ERROR;
    }

    if (!global_config->initial_boot)
    {
        cli_print(cc, "This is boot only command! You must save config now and restart the daemon");
    }

    return CLI_OK;
}
int cmd_radius_config(struct cli_client *cc, char *command, char *argv[], int argc)
{
    if (argc > 1 || (argc == 1 && argv[0][strlen(argv[0])-1] == '?'))
    {
        cli_print(cc, "usage:\nradius config file_name");

        return CLI_OK;
    }

    if (!global_config->initial_boot)
    {
        cli_print(cc, "This is boot only command!");
        return CLI_ERROR;
    }

    // проверяем существование файла
    struct stat tmp;
    if (stat(argv[0], &tmp))
    {
        perror("can't stat radius config");
        return CLI_ERROR;
    }

    global_config->radius_config = strdup(argv[0]);

    return CLI_OK;
}

int cmd_radius_client(struct cli_client *cc, char *command, char *argv[], int argc)
{
    if (argc >2 || (argc == 1 && argv[0][strlen(argv[0])-1] == '?'))
    {
        cli_print(cc, "usage:\nradius client ip_address password");

        return CLI_OK;
    }

    struct in_addr tmp;

    // проверяем валидность адреса
    if (!inet_aton(argv[0], &tmp))
    {
        cli_print(cc, "invalid argument: %s\nEPIC FAIL. can't configure ip address of radius client", argv[0]);
        return CLI_ERROR;
    }

    struct radius_client *rad = NULL;
    rad = malloc(sizeof(struct radius_client));
    if (!rad)
    {
        cli_print(cc, "out of memory in cmd_radius_client");
        return CLI_ERROR;
    }

    rad->client = strdup(argv[0]);
    rad->password = strdup(argv[1]);

    TAILQ_INSERT_TAIL(&global_config->radius_head, rad, entries);

    return CLI_OK;
}


// удаляем из пула один или несколько ip адресов
int cmd_pool_remove(struct cli_client *cc, char *command, char *argv[], int argc)
{
    if ((argc<1 || argc>3)|| argv[0][strlen(argv[0])-1] == '?')
    {
        cli_print(cc, "usage:\npool remove first_ip [last_ip] [pool_name]");

        return CLI_OK;
    }

    // проверяем валидность аргументов
    struct in_addr xip;
    struct in_addr yip;
    struct ippool *pool = NULL;

    xip.s_addr = 0;
    yip.s_addr = 0;

    // первый аргумент -- ip'шник, он есть всегда
    if (!inet_aton(argv[0], &xip))
    {
        cli_print(cc, "invalid ip address: '%s'", argv[0]);
        return CLI_OK;
    }

    // еще могут быть 2 необязательных аргумента
    switch(argc)
    {
        case 2:
            // в качестве второго аргумента может быть last_ip или pool_name
            // сначала попробуем интерпретировать второй аргумент как ip адрес
            if (!inet_aton(argv[1], &yip))
            {
                // теперь как pool name
                pool = get_pool(pools, argv[1]);
                if (!pool)
                {
                    cli_print(cc, "invalid argument: '%s' is nether ip address nor pool name", argv[1]);
                    return CLI_ERROR;
                }

            }
            break;

            // если передано 3 аргумента, то 2-й -- ip адрес, 3-й аргумент -- pool_name
        case 3:
            if (!inet_aton(argv[1], &yip))
            {
                cli_print(cc, "invalid ip address: '%s'", argv[1]);
                return CLI_ERROR;
            }

            pool = get_pool(pools, argv[2]);
            if (!pool)
            {
                cli_print(cc, "invalid pool name '%s'", argv[2]);
                return CLI_ERROR;
            }
            break;

        default:
            break;
    }

    if (!pool)
    {
        pool = get_pool(pools, "default");
        if (!pool)
        {
            cli_print(cc, "can't get default pool. GURU meditation code #0007");
            return CLI_ERROR;
        }
    }

    if (yip.s_addr && xip.s_addr > yip.s_addr)
    {
        cli_print(cc, "invalid ip range: from '%s' to '%s'", argv[0], argv[1]);
        return CLI_ERROR;
    }

    if (!yip.s_addr) yip.s_addr = xip.s_addr;

    struct in_addr tmpip;

    int ip_count = 0;

    if(yip.s_addr<=xip.s_addr)
    {
        tmpip.s_addr = xip.s_addr;
        xip.s_addr = yip.s_addr;
        yip.s_addr = tmpip.s_addr;
    }

    struct ip_entry *e;
    int has_locked = 0;
    TAILQ_FOREACH(e,&pool->head,entries)
    {
        if(e->ip.s_addr >= xip.s_addr && e->ip.s_addr <= yip.s_addr)
        {
            char tmp[16];
            inet_ntoa_r(e->ip, tmp, sizeof(tmp));

            if (e->sess)
            {
                e->mark_for_remove = 1;
                cli_print(cc, "active session (id '%s') for ip '%s'. Address marked for future removing\n", e->sess->sessionid, tmp);
                LOG_WRITE(LF_IPPOOL|LL_INFO,"active session (id '%s') for ip '%s'. Address marked for future removing", e->sess->sessionid, tmp);
                has_locked = 1;
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

    cli_print(cc, "removed %d addresses%s", ip_count, has_locked?" (some ips is locked by openned sessions)":"");

    return CLI_OK;

}


int cmd_show_allocated(struct cli_client *cc, char *command, char *argv[], int argc)
{
    if (argc > 1 || (argc == 1 && argv[0][strlen(argv[0])-1] == '?'))
    {
        cli_print(cc, "usage:\nshow alloacated [pool_name]");

        return CLI_OK;
    }

    // sanity check
    struct ippool *pool = get_pool(pools, argc==1?argv[0]:"default");
    if (!pool)
    {
        if (argc==1)
        {
            cli_print(cc, "can't locate pool '%s'", argv[0]);
        } else {
            cli_print(cc, "Internal error. Can't locate pool 'default'. GURU meditation code #0008");
        }

        return CLI_ERROR;
    }

    cli_print(cc, "allocated addresses for pool %s:", pool->name);
    LOG(LL_INFO,"allocated addreses for pool %s:", pool->name);


    struct ip_entry *e;

    TAILQ_FOREACH(e,&pool->head,entries)
    {
        if (e->allocated)
        {
            char tmp[16];

            inet_ntoa_r(e->ip, tmp, sizeof(tmp));

            if (e->sess)
            {
                LOG(LL_INFO,"%s ip %p session %p session_id %s sid %d", tmp, e, e->sess, e->sess->sessionid, e->sess->sid);
                cli_print(cc, "%s session_id %s", tmp, e->sess->sessionid);
            } else {
                LOG(LL_INFO,"%s ip %p session NULL", tmp, e);
                cli_print(cc, "%s (NULL session)", tmp);
            }
        }

    }

    cli_print(cc, "-end-of-list-");

    return CLI_OK;
}



int cmd_log_ippool(struct cli_client *cc, char *command, char *argv[], int argc)
{
    if (argc != 1 || (argc == 1 && argv[0][strlen(argv[0])-1] == '?'))
    {
        cli_print(cc, "usage:\nlog ippool log_level");

        return CLI_OK;
    }

    return CLI_OK;
}


int cmd_log_session(struct cli_client *cc, char *command, char *argv[], int argc)
{
    if (argc != 1 || (argc == 1 && argv[0][strlen(argv[0])-1] == '?'))
    {
        cli_print(cc, "usage:\nlog session log_level");

        return CLI_OK;
    }

    return CLI_OK;
}



int cmd_log_set(struct cli_client *cli, char *command, char *argv[], int argc)
{
    int res=CLI_OK;

    int i=0;
    int fac=0;

    char* f=index(command,' ');
    f++;

    char* s=index(f,' ');
    *s=0;
    s++;

    int c=0;
    for(;;c++)
    {
        if(log_facilities[c]==NULL)
            break;

        if(strcmp(f,log_facilities[c])==0)
        {
            fac=c;
        }
    }

    for(c=0;;c++)
    {
        if(log_labels[c]==NULL)
            break;

        if(strcmp(s,log_labels[c])==0)
        {
            i=(1<<c);
        }
    }

    if(argc>0 && strncasecmp("no",argv[0],2)==0)
    {
        facloglevel[fac]&=~i;
    } else {
        facloglevel[fac]|=i;
    }

    return res;
}


int cmd_syslog_set(struct cli_client *cli, char *command, char *argv[], int argc)
{
    int res=CLI_OK;

    int fac=0;
    char* f=index(command,' ');
    f++;

    char* s=index(f,' ');
    *s=0;
    s++;

    int c=0;
    for(c=0;;c++)
    {
        if(log_facilities[c]==NULL)
            break;

        if(strcmp(f,log_facilities[c])==0)
            fac=c;
    }


    if(strcmp(s,"no")==0)
    {
        faclog2syslog[fac]=0;
    } else {
        for(c=0;;c++)
        {
            if(syslog_facility[c].c_name==NULL)
                break;

            if(strcmp(s,syslog_facility[c].c_name)==0)
            {
                faclog2syslog[fac]=syslog_facility[c].c_val;
                break;
            }
        }
    }

    return res;
}

int cmd_set_logname(struct cli_client *cli, char *command, char *argv[], int argc)
{
    if(argc<1)
    {
        cli_print(cli, " syslogname <filename>");
        return CLI_ERROR;
    }

    char* oprog=progname;
    progname=strdup(argv[0]);

    if(oprog)
        free(oprog);

    openlog(progname,LOG_PID,lastfac);

    return CLI_OK;
}
