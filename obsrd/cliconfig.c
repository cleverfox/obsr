#include "clicmd.h"
#include "session.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <string.h>
#include <radlib.h>
#include <radlib_vs.h>
#include <sys/stat.h>
#include <unistd.h>

#include <netgraph.h>
#include "../kernel_module/ng_obsr.h"
#include "obsrd.h"
#include "ippool.h"
#include "cliconfig.h"


#define LOG(loglevel, ...) LOG_WRITE(LF_CMD|loglevel, __VA_ARGS__)

extern struct sessions *usessions;
extern int sock[4];
extern struct ngm_connect cn;
extern struct pools *pools;

struct _global_config *global_config = NULL;

extern int errno;


void init_global_config()
{
    if (!global_config)
    {
        global_config = malloc(sizeof(struct _global_config));
        bzero(global_config, sizeof(struct _global_config));
        global_config->initial_boot = 1;
        TAILQ_INIT(&global_config->radius_head);
    }
}


void destroy_global_config()
{
    if (!global_config)
        return;

    struct radius_client *e;
    TAILQ_FOREACH(e, &global_config->radius_head, entries)
    {
        if (e->client)
            free(e->client);

        if(e->password)
            free(e->password);

        TAILQ_REMOVE(&global_config->radius_head, e, entries);
        free(e);
    }

    if (global_config->radius_config)
        free(global_config->radius_config);

    free(global_config);
}

int dump_running_config(struct cli_client *cc, FILE *fh)
{
    // глобальные настройки
    fprintf(fh, "# global server config\r\n");
    // this server
    char this_server_address[16];
    inet_ntoa_r(global_config->thisserver, this_server_address, sizeof(this_server_address));
    fprintf(fh,  "this server %s\r\n", this_server_address);

    // radius client
    struct radius_client *rad;

    TAILQ_FOREACH(rad, &global_config->radius_head, entries)
    {
        if (rad->client && rad->password)
        {
            fprintf(fh, "radius client %s %s\r\n", rad->client, rad->password);
        }
    }

    // radius config
    if (global_config->radius_config)
    {
        fprintf(fh, "radius config %s\r\n", global_config->radius_config);
    }

    // пулы ip адресов
    struct in_addr one_ip;
    if(inet_aton("0.0.0.1",&one_ip)!=1)
    {
        cli_print(cc, "internal error: GURU meditation 0x0002");
        return CLI_ERROR;
    }

    struct ippool *ipp;
    TAILQ_FOREACH(ipp,&pools->head,entries)
    {
        //cli_print(cc, "saving pool: %s", ipp->name);

        struct in_addr last_ip;
        struct in_addr pool_from_ip;
        struct ip_entry *e;

        last_ip.s_addr = 0;

        TAILQ_FOREACH(e,&ipp->head,entries)
        {
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
                fprintf(fh, "pool add %s %s %s\r\n", pool_from, pool_to, ipp->name);

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
            fprintf(fh, "pool add %s %s %s\r\n", pool_from, pool_to, ipp->name);
        }
    }

    fprintf(fh, "\r\n# logs\r\n");
    dump_log_config(cc,fh);

    return CLI_OK;
}


