#ifndef __LIBCLI_H__
#define __LIBCLI_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdarg.h>
#include <sys/time.h>

#define CLI_OK			      0
#define CLI_ERROR		     -1
#define CLI_ERR		         CLI_ERROR
#define CLI_QUIT		     -2
#define CLI_ERROR_ARG		 -3

#define MAX_HISTORY		      256

#define PRIVILEGE_UNPRIVILEGED	0
#define PRIVILEGE_PRIVILEGED	15
#define MODE_ANY		      -1
#define MODE_EXEC		       0
#define MODE_CONFIG		       1

#define LIBCLI_HAS_ENABLE	   1

#define PRINT_PLAIN		       0
#define PRINT_FILTERED	      0x01
#define PRINT_BUFFERED		  0x02

#define CLI_MAX_LINE_LENGTH   4096
#define CLI_MAX_LINE_WORDS     128

    struct cli_client;

    struct cli_def {
        int (*auth_callback)(char *, char *);
        int (*regular_callback)(struct cli_client *cc);
        int (*enable_callback)(char *);
        void (*print_callback)(struct cli_client *cc, char *string);
        int (*idle_timeout_callback)(struct cli_client *);
        int completion_callback;
        char *banner;
        struct unp *users;
        char *enable_password;
        struct cli_filter *filters;
        struct cli_command *commands;
        struct timeval timeout_tm;
        unsigned int idle_timeout;
        int negotiate; // set to 0 to disable Telnet negotiation
    };

    struct cli_client {
        struct cli_def *common;
        char *history[MAX_HISTORY];
        char showprompt;
        char *promptchar;
        char *hostname;
        char *modestring;
        int privilege;
        int mode;
        int state;
        FILE *client;
        void *service;
        char *commandname;
        char *buffer;
        unsigned buf_size;
        time_t last_action;
        int sockfd;
    };

    struct cli_filter {
        int (*filter)(struct cli_client *cc, char *string, void *data);
        void *data;
        struct cli_filter *next;
    };

    struct cli_command {
        char *command;
        int (*callback)(struct cli_client *, char *, char **, int);
        unsigned int unique_len;
        char *help;
        int privilege;
        int mode;
        struct cli_command *next;
        struct cli_command *children;
        struct cli_command *parent;
    };

    struct cli_def *cli_init();
    int cli_done(struct cli_def *cli);
    int cli_client_init(struct cli_def *cli, struct cli_client *cc, int fd);
    void cli_client_done(struct cli_client *cc);
    struct cli_command *cli_register_command(struct cli_def *cli, struct cli_command *parent, char *command, int (*callback)(struct cli_client *, char *, char **, int), int privilege, int mode, char *help);
    int cli_unregister_command(struct cli_def *cli, char *command);
    int cli_run_command(struct cli_client *cc, char *command);
    int cli_loop(struct cli_client *cc);
    int cli_file(struct cli_client *cc, FILE *fh, int privilege, int mode);
    void cli_set_auth_callback(struct cli_def *cli, int (*auth_callback)(char *, char *));
    void cli_set_enable_callback(struct cli_def *cli, int (*enable_callback)(char *));
    void cli_allow_user(struct cli_def *cli, char *username, char *password);
    void cli_allow_enable(struct cli_def *cli, char *password);
    void cli_deny_user(struct cli_def *cli, char *username);
    void cli_set_banner(struct cli_def *cli, char *banner);
    void cli_set_hostname(struct cli_client *cc, char *hostname);
    void cli_set_promptchar(struct cli_client *cc, char *promptchar);
    void cli_set_modestring(struct cli_client *cc, char *modestring);
    int cli_set_privilege(struct cli_client *cc, int privilege);
    int cli_set_configmode(struct cli_client *cc, int mode, char *config_desc);
    void cli_reprompt(struct cli_client *cc);
    void cli_regular(struct cli_def *cli, int (*callback)(struct cli_client *cli));
    void cli_regular_interval(struct cli_def *cli, int seconds);
    void cli_print(struct cli_client *cc, char *format, ...) __attribute__((format (printf, 2, 3)));
    void cli_bufprint(struct cli_client *cc, char *format, ...) __attribute__((format (printf, 2, 3)));
    void cli_vabufprint(struct cli_client *cc, char *format, va_list ap);
    void cli_error(struct cli_client *cc, char *format, ...) __attribute__((format (printf, 2, 3)));
    void cli_print_callback(struct cli_def *cli, void (*callback)(struct cli_client *, char *));
    void cli_free_history(struct cli_client *cc);
    void cli_set_idle_timeout(struct cli_client *cc, unsigned int seconds);
    void cli_set_idle_timeout_callback(struct cli_client *cc, unsigned int seconds, int (*callback)(struct cli_client *));
    void cli_set_negotiate(struct cli_def *cli, int should_negotiate);

#ifdef __cplusplus
}
#endif

#endif
