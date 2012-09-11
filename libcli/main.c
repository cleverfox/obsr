#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include "libcli.h"
#include <pthread.h>
#include <signal.h>
#include "zmalloc.h"
#include <stdlib.h>


struct cli_def *xcli;

int cmd_server_set(struct cli_client *cc, char *command, char *argv[], int argc){
    cli_print(cc, "Server set Command %s", command);
    int i=0;
    while(i<argc){
	cli_print(cc, "\t argument %s", argv[i]);
	i++;
    }
    return CLI_OK;
}

int cmd_show_xx(struct cli_client *cc, char *command, char *argv[], int argc){
    cli_print(cc, "Command %s", command);
    int i=0;
    while(i<argc){
	cli_print(cc, "\t argument %s", argv[i]);
	i++;
    }
    return CLI_OK;
}

#define MODE_CONFIG_SERVER 10
int cmd_config_xx(struct cli_client *cc, char *command, char *argv[], int argc) {

    int res=CLI_OK;

    char* tbuf=NULL;
    asprintf(&tbuf,"xx%sxx",command);
    if(tbuf!=NULL){
        cli_set_configmode(cc, MODE_CONFIG_SERVER, tbuf);
        //            cli->service=tc;
    }else{
        res=CLI_ERROR;
    }
    return res;
}

void* handle_cli(void* threadid);






void sig1handler(int sigid){
    printf("Signal %d\n",sigid);
    //dumpStat();
}

int main (int argc, char **argv){

    signal(SIGPIPE,SIG_IGN);
    signal(SIGUSR1,sig1handler);

    xcli = cli_init();
    char buffer[64]="Hello!!!";
    cli_set_banner(xcli, buffer);
    struct cli_command *cmd;
    struct cli_command *cmds;
    /*    cli_register_command(xcli, NULL, "license", cmd_license, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "Add license file");
          cli_register_command(xcli, NULL, "operator", cmd_operator, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "Add operator");
          cli_register_command(xcli, NULL, "rpcoperator", cmd_rpcoperator, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "Add RPC operator");
          cli_register_command(xcli, NULL, "save", cmd_save_config, PRIVILEGE_PRIVILEGED, MODE_ANY, "Save running config");
          cli_register_command(xcli, NULL, "saveall", cmd_save_all, PRIVILEGE_PRIVILEGED, MODE_ANY, "Save users and config");
          cli_register_command(xcli, NULL, "saveusers", cmd_save_users, PRIVILEGE_PRIVILEGED, MODE_ANY, "Save users");
          cli_register_command(xcli, NULL, "//",    cmd_nop, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "No operation");

          cmd = cli_register_command(xcli, NULL, "plugin", NULL, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "Plugins control");
          cli_register_command(xcli, cmd, "list", cmd_show_plugin, PRIVILEGE_UNPRIVILEGED, MODE_CONFIG, "Show plugins");
          cli_register_command(xcli, cmd, "load", cmd_plugin_load, PRIVILEGE_UNPRIVILEGED, MODE_CONFIG, "Load plugin");
          cli_register_command(xcli, cmd, "unload", cmd_plugin_unload, PRIVILEGE_UNPRIVILEGED, MODE_CONFIG, "Unload plugins");
          */
    cmd = cli_register_command(xcli, NULL, "show", NULL, PRIVILEGE_UNPRIVILEGED, MODE_ANY, NULL);
    cli_register_command(xcli, cmd, "router", 		cmd_show_xx, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "Show router");
    cli_register_command(xcli, cmd, "stat" , 		cmd_show_xx, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "Show statistics");
    cli_register_command(xcli, cmd, "daystat" , 	cmd_show_xx, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "Show statistics");
    cli_register_command(xcli, cmd, "users", 		cmd_show_xx, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "Show users");
    cli_register_command(xcli, cmd, "upstreams", 	cmd_show_xx, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "Show upstreams");
    cli_register_command(xcli, cmd, "running-config", 	cmd_show_xx, PRIVILEGE_PRIVILEGED, MODE_ANY, "Show running config");
    cli_register_command(xcli, cmd, "startup-config", 	cmd_show_xx, PRIVILEGE_PRIVILEGED, MODE_ANY, "Show startup config");
    cli_register_command(xcli, cmd, "sessions",		cmd_show_xx, PRIVILEGE_PRIVILEGED, MODE_ANY, "Show curent user sessions");
    cli_register_command(xcli, cmd, "cache", 		cmd_show_xx, PRIVILEGE_PRIVILEGED, MODE_ANY, "Show cache current state");
    cli_register_command(xcli, cmd, "info", 		cmd_show_xx, PRIVILEGE_PRIVILEGED, MODE_ANY, "Show info");
    cli_register_command(xcli, cmd, "license", 		cmd_show_xx, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "Show license");

    /*
       cli_register_command(xcli, NULL, "cliport", cmd_cli_port, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "Set CLI port");
       cli_register_command(xcli, NULL, "rpcport", cmd_rpc_port, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "Set RPC port");

       cli_register_command(xcli, NULL, "upstream",  cmd_config_upstream, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "Configure upstream");
       cli_register_command(xcli, NULL, "name",      cmd_upstream_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_UPSTREAM, "Set upstream name");
       cli_register_command(xcli, NULL, "username",  cmd_upstream_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_UPSTREAM, "Set username");
       cli_register_command(xcli, NULL, "password",  cmd_upstream_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_UPSTREAM, "Set password");
       cli_register_command(xcli, NULL, "host",      cmd_upstream_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_UPSTREAM, "Set peer address");
       cli_register_command(xcli, NULL, "caid",      cmd_upstream_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_UPSTREAM, "Set newcamd CAID");
       cli_register_command(xcli, NULL, "carddata",  cmd_upstream_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_UPSTREAM, "Set newcamd carddata request enable/disable");
       cli_register_command(xcli, NULL, "port",      cmd_upstream_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_UPSTREAM, "Set peer port");
       cli_register_command(xcli, NULL, "clid",      cmd_upstream_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_UPSTREAM, "Set CLientID");
       cli_register_command(xcli, NULL, "deskey",    cmd_upstream_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_UPSTREAM, "Set DES key");
       cli_register_command(xcli, NULL, "connecttime", cmd_upstream_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_UPSTREAM, "Set reconnect interval");
       cli_register_command(xcli, NULL, "keepalive",  cmd_upstream_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_UPSTREAM, "Set keepalive interval");
       cli_register_command(xcli, NULL, "reconnecttime", cmd_upstream_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_UPSTREAM, "Set reconnect interval");
       cli_register_command(xcli, NULL, "reconnecttime1st", cmd_upstream_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_UPSTREAM, "Set first reconnect interval");
       cli_register_command(xcli, NULL, "reqtimeout", cmd_upstream_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_UPSTREAM, "Set request timeout");
       cli_register_command(xcli, NULL, "filter", cmd_upstream_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_UPSTREAM, "Set filter");
       cli_register_command(xcli, NULL, "autofilter", cmd_upstream_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_UPSTREAM, "Set autofilter");
       cli_register_command(xcli, NULL, "measuretime", cmd_upstream_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_UPSTREAM, "Enable measuretime");
       struct cli_command *ucmd = 
       cli_register_command(xcli, NULL, "pluginflt", NULL, PRIVILEGE_PRIVILEGED, MODE_CONFIG_UPSTREAM, "Filter plugin add/del");
       cli_register_command(xcli, ucmd, "add", cmd_upstream_fil, PRIVILEGE_PRIVILEGED, MODE_CONFIG_UPSTREAM, "Add plugin filter");
       cli_register_command(xcli, ucmd, "del", cmd_upstream_fil, PRIVILEGE_PRIVILEGED, MODE_CONFIG_UPSTREAM, "Del plugin filter");
       cli_register_command(xcli, ucmd, "ena", cmd_upstream_fil, PRIVILEGE_PRIVILEGED, MODE_CONFIG_UPSTREAM, "Enable plugin filter");
       cli_register_command(xcli, ucmd, "dis", cmd_upstream_fil, PRIVILEGE_PRIVILEGED, MODE_CONFIG_UPSTREAM, "Disable plugin filter");

       cli_register_command(xcli, NULL, "enable",    cmd_upstream_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_UPSTREAM, "Enable upstream");
       cli_register_command(xcli, NULL, "disable",   cmd_upstream_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_UPSTREAM, "Disable upstream");
       cli_register_command(xcli, NULL, "open",      cmd_upstream_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_UPSTREAM, "Try to connect");
       cli_register_command(xcli, NULL, "close",     cmd_upstream_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_UPSTREAM, "Disconnect");

       cli_register_command(xcli, NULL, "cache",    cmd_config_cache, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "Configure cache");
       cli_register_command(xcli, NULL, "name",      cmd_cache_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_CACHE, "Set cache name");
       cli_register_command(xcli, NULL, "cex",      cmd_cache_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_CACHE, "Set cache exchange peer");
       cli_register_command(xcli, NULL, "clean_interval", cmd_cache_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_CACHE, "Set cache clean interval");
       cli_register_command(xcli, NULL, "anticasc",    cmd_config_ac, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "Configure anticasc");
       cli_register_command(xcli, NULL, "default",     cmd_ac_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_AC, "set default");
       cli_register_command(xcli, NULL, "interval",    cmd_ac_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_AC, "Add interval");
       cli_register_command(xcli, NULL, "maxusage",    cmd_ac_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_AC, "max usage in % before penalty");
       cli_register_command(xcli, NULL, "maxusage_qb", cmd_ac_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_AC, "max usage in % before quick ban");
       cli_register_command(xcli, NULL, "ovint",       cmd_ac_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_AC, "Overdraft interval succession count to penalty");
       cli_register_command(xcli, NULL, "peninterval", cmd_ac_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_AC, "penalty for intervals");
       cli_register_command(xcli, NULL, "groups",      cmd_ac_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_AC, "Groups count");
       cli_register_command(xcli, NULL, "period",      cmd_ac_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_AC, "Period for each group");

       cli_register_command(xcli, NULL, "router",    cmd_config_router, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "Configure router");
       cli_register_command(xcli, NULL, "name",      cmd_router_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_ROUTER, "Set router name");
       cli_register_command(xcli, NULL, "route",     cmd_router_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_ROUTER, "Add route");
       cli_register_command(xcli, NULL, "cache",     cmd_router_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_ROUTER, "Set cache engine");
       cli_register_command(xcli, NULL, "cache_expire",     cmd_router_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_ROUTER, "Set expire time");
       cli_register_command(xcli, NULL, "nosave",     cmd_router_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_ROUTER, "No save objects to cache, just lookup");
       cli_register_command(xcli, NULL, "dosave",     cmd_router_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_ROUTER, "Save objects to cache");
       cli_register_command(xcli, NULL, "groupsid",   cmd_router_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_ROUTER, "Enable SID grouping");
       cli_register_command(xcli, NULL, "nogroupsid", cmd_router_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_ROUTER, "Disable SID grouping");

       cli_register_command(xcli, NULL, "enable",    cmd_router_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_ROUTER, "Enable router");
       cli_register_command(xcli, NULL, "disable",   cmd_router_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_ROUTER, "Disable router");

       cli_register_command(xcli, NULL, "balancer",  cmd_config_balancer, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "Configure balancer");
       cli_register_command(xcli, NULL, "discipline",cmd_balancer_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_BALANCER, "Set balancer discipline");
       cli_register_command(xcli, NULL, "name",      cmd_balancer_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_BALANCER, "Set balancer name");
       cli_register_command(xcli, NULL, "member",    cmd_balancer_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_BALANCER, "Add balancer member");
       cli_register_command(xcli, NULL, "nomember",    cmd_balancer_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_BALANCER, "Del balancer member");
       cli_register_command(xcli, NULL, "timeout",    cmd_balancer_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_BALANCER, "Set balancer ReRequesting timeout");
       cli_register_command(xcli, NULL, "retry",    cmd_balancer_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_BALANCER, "Set balancer maximum retry count");
       */

    cli_register_command(xcli, NULL, "server",    cmd_config_xx, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "Configure server");
    cli_register_command(xcli, NULL, "name",      cmd_server_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_SERVER, "Set server name");
    cli_register_command(xcli, NULL, "bind_ip4",  cmd_server_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_SERVER, "Set bind IP address");
    cli_register_command(xcli, NULL, "port",      cmd_server_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_SERVER, "Set port");
    cli_register_command(xcli, NULL, "caid",      cmd_server_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_SERVER, "Set newcamd caid");
    cli_register_command(xcli, NULL, "deskey",    cmd_server_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_SERVER, "Set newcamd DES key");
    cli_register_command(xcli, NULL, "router",    cmd_server_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_SERVER, "Set request router");
    cli_register_command(xcli, NULL, "tag",       cmd_server_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_SERVER, "Set server tag");
    cli_register_command(xcli, NULL, "srvid",     cmd_server_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_SERVER, "Set newcamd server ID");
    cli_register_command(xcli, NULL, "filter",    cmd_server_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_SERVER, "Set server filter");
    cli_register_command(xcli, NULL, "enable",    cmd_server_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_SERVER, "Enable server");
    cli_register_command(xcli, NULL, "disable",   cmd_server_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_SERVER, "Disable server");
    cli_register_command(xcli, NULL, "open",      cmd_server_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_SERVER, "Listen socket");
    cli_register_command(xcli, NULL, "close",     cmd_server_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_SERVER, "Don't listen socket");

    /*
       cli_register_command(xcli, NULL, "cluster",    cmd_config_cluster, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "Configure cluster");
       cli_register_command(xcli, NULL, "listen",    cmd_cluster_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_CLUSTER, "Set listen address/port");
       cli_register_command(xcli, NULL, "neighbor",   cmd_cluster_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_CLUSTER, "Set neighbor address/port");
       cli_register_command(xcli, NULL, "sharedkey",  cmd_cluster_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_CLUSTER, "Set cluster authentication key");
       cli_register_command(xcli, NULL, "crp",        cmd_cluster_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_CLUSTER, "Set CRP flag for this node");
       cli_register_command(xcli, NULL, "enable",     cmd_cluster_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_CLUSTER, "Enable clustering");
       cli_register_command(xcli, NULL, "disable",    cmd_cluster_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG_CLUSTER, "Disable clustering");

       cli_register_command(xcli, NULL, "usersflush", cmd_userf, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "Flush users who not in config[config only]");
       cli_register_command(xcli, NULL, "user", cmd_user, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "Configure user");
       cli_register_command(xcli, NULL, "kick", cmd_kick, PRIVILEGE_PRIVILEGED, MODE_ANY, "Kick user");
       cli_register_command(xcli, NULL, "nouser", cmd_nouser, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "Delete user");
       cli_register_command(xcli, NULL, "usersource", cmd_usersrc, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "Configure source of user database");
    //    plugin_menugen(xcli);
    */
    int s, x;
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

    addr.sin_port = htons(7779);
    if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) < 0)
    {
        char ster[32];
        strerror_r(errno,(char*)&ster,sizeof(ster));
        printf("Error bind(%d): %s",ntohs(addr.sin_port),(char*)&ster);
        return 0;
    }

    if (listen(s, 50) < 0)
    {
        printf("Error listen(): %s",strerror(errno));
        return 0;
    }


    while ((x = accept(s, NULL, 0)))
    {
        //        cli_set_privilege(xcli, PRIVILEGE_PRIVILEGED);
        pthread_t th;
        pthread_create(&th, NULL, handle_cli, x);
    }
    return 0;
}

void* handle_cli(void* threadid){
    int fd=(int)threadid;
    char buf[]="Hello, thread!\n";

    struct cli_client *cc=NULL;

    cc = zmalloc( sizeof(struct cli_client) );

    cli_client_init(xcli, cc, fd);

    write(fd,buf,strlen(buf));

    cli_loop(cc);

    cli_client_done(cc);
    zfree(cc);

    close(fd);
}

void config_load(char* filename){
    FILE *fh;
    //    LOG_WRITE(LL_WARN, "load config %s", filename);
    struct cli_client *cc=NULL;

    cc = zmalloc( sizeof(struct cli_client) );


    if ((fh = fopen(filename,"r"))){
        cli_client_init(xcli, cc, fh);
        cli_file(cc, fh, PRIVILEGE_PRIVILEGED, MODE_CONFIG);
        cli_client_done(cc);
        fclose(fh);
    }

    zfree(cc);
}

