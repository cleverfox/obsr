#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/queue.h>

#include <net/if.h>
#include <netinet/in.h>

#include <arpa/inet.h>

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <errno.h>
#include <libcli.h>
#include <string.h>
#include <pthread.h>
#include "clicmd.h"
#include "log.h"


#define LOG(loglevel, ...) LOG_WRITE(LF_CMD|loglevel, __VA_ARGS__)


struct cli_def *xcli = NULL;
pthread_t cli_thread_id;


void* handle_cli(void* threadid)
{
    long fd=(long)threadid;
    struct cli_client *cc=NULL;

    cc = malloc( sizeof(struct cli_client) );

    cli_client_init(xcli, cc, fd);
    cli_loop(cc);
    cli_client_done(cc);

    free(cc);
    close(fd);

    return NULL;
}

int config_load(char* filename){
    FILE *fh;
    //    LOG_WRITE(LL_WARN, "load config %s", filename);
    struct cli_client *cc=NULL;

    char *config_name;

    if(!xcli)
    {
        LOG(LL_INFO,"xcli isn't defined yet ;-( GURU meditation code #0005");
        exit(1);
    }

    char resolved_path[PATH_MAX + 1];

    config_name = realpath(filename, resolved_path);
    if (!config_name)
    {
        LOG(LL_INFO,"config_load internal error. GURU meditation: 0x0004");

        return CLI_ERROR;
    }

    LOG(LL_INFO,"loading config from %s", config_name);

    cc = malloc( sizeof(struct cli_client) );

    if (!(fh = fopen(filename,"r")))
    {
        LOG(LL_INFO,"can't open config '%s'", config_name);
        free(cc);

        return CLI_ERROR;
    }

    // при загрузке конфига выводим сообщения в консольку
    cli_client_init(xcli, cc, dup(1));

    cli_file(cc, fh, PRIVILEGE_PRIVILEGED, MODE_CONFIG);

    cli_client_done(cc);

    fclose(fh);
    free(cc);

    return CLI_OK;
}

void* cli_worker_thread(void* threadid)
{
    long s, x;
    struct sockaddr_in addr;
    int on = 1;
    if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("socket");
        return 0;
    }
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    addr.sin_port = htons(7990);
    if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) < 0)
    {
        char ster[32];
        strerror_r(errno,(char*)&ster,sizeof(ster));
        LOG(LL_INFO,"Error bind(%d): %s",ntohs(addr.sin_port),(char*)&ster);
        return 0;
    }

    if (listen(s, 50) < 0)
    {
        LOG(LL_INFO,"Error listen(): %s",strerror(errno));
        return 0;
    }

    while ((x = accept(s, NULL, 0)))
    {
        pthread_t th;
        pthread_create(&th, NULL, handle_cli, (long*)x);
    }

    return NULL;
}
void run_cli()
{
    xcli = cli_init();

    struct cli_command *cmd;
    cmd = cli_register_command(xcli, NULL, "show", NULL, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "Show various things");
    cli_register_command(xcli, cmd, "sessions", cmd_show_sessions, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "Show current sessions");
    cli_register_command(xcli, cmd, "pool", cmd_show_pool, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "Show current pool");
    cli_register_command(xcli, cmd, "config", cmd_show_config, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "Show running config");
    cli_register_command(xcli, cmd, "allocated", cmd_show_allocated, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "Show allocated addresses");
    cli_register_command(xcli, cmd, "running-config", cmd_show_config, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "Show allocated addresses");

    cmd = cli_register_command(xcli, NULL, "kill", NULL, PRIVILEGE_PRIVILEGED, MODE_ANY, "Kill someone");
    cli_register_command(xcli, cmd, "session", cmd_close_session, PRIVILEGE_PRIVILEGED, MODE_ANY, "Kill session");

    cmd = cli_register_command(xcli, NULL, "close", NULL, PRIVILEGE_PRIVILEGED, MODE_ANY, "Close somthing");
    cli_register_command(xcli, cmd, "session", cmd_close_session, PRIVILEGE_PRIVILEGED, MODE_ANY, "Close session");

    cmd = cli_register_command(xcli, NULL, "save", NULL, PRIVILEGE_PRIVILEGED, MODE_ANY, "Save to hdd");
    cli_register_command(xcli, cmd, "config", cmd_save_config, PRIVILEGE_PRIVILEGED, MODE_ANY, "Save settings to hdd");

    cmd = cli_register_command(xcli, NULL, "pool", NULL, PRIVILEGE_PRIVILEGED, MODE_ANY, "Pool operations");
    cli_register_command(xcli, cmd, "add", cmd_pool_add, PRIVILEGE_PRIVILEGED, MODE_ANY, "Add IP range to pool");
    cli_register_command(xcli, cmd, "remove", cmd_pool_remove, PRIVILEGE_PRIVILEGED, MODE_ANY, "Remove range or single IP from pool");
    cli_register_command(xcli, cmd, "delete", cmd_pool_remove, PRIVILEGE_PRIVILEGED, MODE_ANY, "Remove range or single IP from pool");

    cmd = cli_register_command(xcli, NULL, "this", NULL, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "Configure this server");
    cli_register_command(xcli, cmd, "server", cmd_this_server, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "Configure external IP address of this server");

    cmd = cli_register_command(xcli, NULL, "radius", NULL, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "Configure radius");
    cli_register_command(xcli, cmd, "client", cmd_radius_client, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "Configure radius client");
    cli_register_command(xcli, cmd, "config", cmd_radius_config, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "Configure radius config");


    //cmd = cli_register_command(xcli, NULL, "log", NULL, PRIVILEGE_PRIVILEGED, MODE_ANY, "Fine-tuning of the loging subsystem");
    //cli_register_command(xcli, cmd, "ippool", cmd_log_ippool, PRIVILEGE_PRIVILEGED, MODE_ANY, "Tuning the ippool module logging");
    //cli_register_command(xcli, cmd, "session", cmd_log_session, PRIVILEGE_PRIVILEGED, MODE_ANY, "Tuning the session module logging");
    cli_register_command(xcli, NULL , "syslogname",  cmd_set_logname, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "Set program name for syslog");

    struct cli_command *cmds = cli_register_command(xcli, NULL, "syslog",     NULL, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "Enable logging to syslog and set syslog facility");
    cmd = cli_register_command(xcli, NULL,  "loglevel",    NULL, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "Set log level");

    int d=0;

    for(;d<LFS;d++)
    {
        if(log_facilities[d]==NULL)
            break;
        facloglevel[d]=LL_ERROR|LL_WARN|LL_INFO;
#ifdef LOG_STRINGS
        faclogavail[d]|=LL_LSTRS;
#endif

        struct cli_command *xcmd = cli_register_command(xcli, cmd, log_facilities[d], NULL, PRIVILEGE_UNPRIVILEGED, MODE_ANY, NULL);
        struct cli_command *xcmds = cli_register_command(xcli, cmds, log_facilities[d], NULL, PRIVILEGE_UNPRIVILEGED, MODE_ANY, NULL);

        int c=0;

        for(;c<LOG_LEVELS;c++)
        {
            if(log_labels[c]==NULL)
                break;

            if(faclogavail[d]&(1<<c))
                cli_register_command(xcli, xcmd, log_labels[c], cmd_log_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG, log_labels[c]);
        }

        cli_register_command(xcli, xcmds, "no",  cmd_syslog_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "logging to stderr");

        for(c=0;;c++)
        {
            if(syslog_facility[c].c_name==NULL) break;
            cli_register_command(xcli, xcmds, syslog_facility[c].c_name,  cmd_syslog_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG, syslog_facility[c].c_name);
        }
    }

    pthread_create(&cli_thread_id, NULL, cli_worker_thread, NULL);

    return ;
}

void stop_cli()
{
    if (xcli)
        cli_done(xcli);

    return ;
}


