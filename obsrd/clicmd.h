#ifndef CLICMD_H
#define CLICMD_H
#include <libcli.h>

int cmd_show_sessions(struct cli_client *cc, char *command, char *argv[], int argc);
int cmd_close_session(struct cli_client *cc, char *command, char *argv[], int argc);
int cmd_save_config(struct cli_client *cc, char *command, char *argv[], int argc);
int cmd_pool_add(struct cli_client *cc, char *command, char *argv[], int argc);
int cmd_show_pool(struct cli_client *cc, char *command, char *argv[], int argc);
int cmd_this_server(struct cli_client *cc, char *command, char *argv[], int argc);
int cmd_radius_client(struct cli_client *cc, char *command, char *argv[], int argc);
int cmd_radius_config(struct cli_client *cc, char *command, char *argv[], int argc);
int cmd_show_config(struct cli_client *cc, char *command, char *argv[], int argc);
int cmd_pool_remove(struct cli_client *cc, char *command, char *argv[], int argc);
int cmd_show_allocated(struct cli_client *cc, char *command, char *argv[], int argc);
int cmd_log_ippool(struct cli_client *cc, char *command, char *argv[], int argc);
int cmd_log_session(struct cli_client *cc, char *command, char *argv[], int argc);

int cmd_log_set(struct cli_client *cli, char *command, char *argv[], int argc);
int cmd_syslog_set(struct cli_client *cli, char *command, char *argv[], int argc);
int cmd_set_logname(struct cli_client *cli, char *command, char *argv[], int argc);
int dump_log_config(struct cli_client *cc, FILE *fh);



#endif
