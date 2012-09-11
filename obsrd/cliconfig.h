#ifndef _CLICONFIG_H_
#define _CLICONFIG_H_



struct radius_client
{
    char *client;
    char *password;
    TAILQ_ENTRY(radius_client) entries;
};


typedef struct _global_config
{
    struct in_addr thisserver;    // our ip
    char *radius_config;          // path to radius config (i.e. /etc/radius.conf)
    int initial_boot;             // TRUE on initial boot, FALSE after loading config. индикатор для boot only команд

    TAILQ_HEAD(radius_clients_head, radius_client) radius_head;  // radius clients array

} GLOBAL_CONFIG;

extern struct _global_config *global_config;


void init_global_config();
void destroy_global_config();
int dump_running_config(struct cli_client *cc, FILE *fh);



#endif // _CLICONFIG_H_
