#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <memory.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>
#ifndef WIN32
#include <regex.h>
#endif
#include "libcli.h"

#include "zmalloc.h"

// vim:sw=4 ts=8

#ifdef __GNUC__
# define UNUSED(d) d __attribute__ ((unused))
#else
# define UNUSED(d) d
#endif

#ifdef WIN32
/*
 * Stupid windows has multiple namespaces for filedescriptors, with different
 * read/write functions required for each ..
 */
int read(int fd, void *buf, unsigned int count) {
    return recv(fd, buf, count, 0);
}

int write(int fd,const void *buf, unsigned int count) {
    return send(fd, buf, count, 0);
}

int vasprintf(char **strp, const char *fmt, va_list args) {
    int size;

    size = vsnprintf(NULL, 0, fmt, args);
    if ((*strp = zmalloc(2+size + 1)) == NULL) {
        return -1;
    }

    size = vsnprintf(*strp, size + 1, fmt, args);
    return size;
}

int asprintf(char **strp, const char *fmt, ...) {
    va_list args;
    int size;

    va_start(args, fmt);
    size = vasprintf(strp, fmt, args);

    va_end(args);
    return size;
}

int fprintf(FILE *stream, const char *fmt, ...) {
    va_list args;
    int size;
    char *buf;

    va_start(args, fmt);
    size = vasprintf(&buf, fmt, args);
    if (size < 0) {
        goto out;
    }
    size = write(stream->_file, buf, size);
    zfree(buf);

out:
    va_end(args);
    return size;
}

/*
 * Dummy definitions to allow compilation on Windows
 */
int regex_dummy() {return 0;};
#define regzfree(...) regex_dummy()
#define regexec(...) regex_dummy()
#define regcomp(...) regex_dummy()
#define regex_t int
#define REG_NOSUB	0
#define REG_EXTENDED	0
#define REG_ICASE	0
#endif

enum cli_states {
    STATE_LOGIN,
    STATE_PASSWORD,
    STATE_NORMAL,
    STATE_ENABLE_PASSWORD,
    STATE_ENABLE
};

struct unp {
    char *username;
    char *password;
    struct unp *next;
};

struct cli_filter_cmds
{
    char *cmd;
    char *help;
};

/* zfree and zero (to avoid double-free) */
#define free_z(p) do { if (p) { zfree(p); p = NULL; } } while (0)

int cli_match_filter_init(struct cli_client *cc, int argc, char **argv, struct cli_filter *filt);
int cli_range_filter_init(struct cli_client *cc, int argc, char **argv, struct cli_filter *filt);
int cli_count_filter_init(struct cli_client *cc, int argc, char **argv, struct cli_filter *filt);
int cli_match_filter(struct cli_client *cc, char *string, void *data);
int cli_range_filter(struct cli_client *cc, char *string, void *data);
int cli_count_filter(struct cli_client *cc, char *string, void *data);

static struct cli_filter_cmds filter_cmds[] =
{
    { "begin",   "Begin with lines that match" },
    { "between", "Between lines that match" },
    { "count",   "Count of lines"   },
    { "exclude", "Exclude lines that match" },
    { "include", "Include lines that match" },
    { "grep",    "Include lines that match regex (options: -v, -i, -e)" },
    { "egrep",   "Include lines that match extended regex" },
    { NULL, NULL}
};

char *cli_command_name(struct cli_client *cc, struct cli_command *command)
{
    char *name = cc->commandname;
    char *o;

    if (name) zfree(name);
    if (!(name = zcalloc(1, 1)))
        return NULL;

    while (command)
    {
        o = name;
        asprintf(&name, "%s%s%s", command->command, *o ? " " : "", o);
        command = command->parent;
        zfree(o);
    }
    cc->commandname = name;
    return name;
}

void cli_set_auth_callback(struct cli_def *cli, int (*auth_callback)(char *, char *))
{
    cli->auth_callback = auth_callback;
}

void cli_set_enable_callback(struct cli_def *cli, int (*enable_callback)(char *))
{
    cli->enable_callback = enable_callback;
}

void cli_allow_user(struct cli_def *cli, char *username, char *password)
{
    struct unp *u, *n;
    if (!(n = zmalloc(2+sizeof(struct unp))))
    {
        fprintf(stderr, "Couldn't allocate memory for user: %s", strerror(errno));
        return;
    }
    if (!(n->username = strdup(username)))
    {
        fprintf(stderr, "Couldn't allocate memory for username: %s", strerror(errno));
        zfree(n);
        return;
    }
    if (!(n->password = strdup(password)))
    {
        fprintf(stderr, "Couldn't allocate memory for password: %s", strerror(errno));
        zfree(n->username);
        zfree(n);
        return;
    }
    n->next = NULL;

    if (!cli->users)
        cli->users = n;
    else
    {
        for (u = cli->users; u && u->next; u = u->next);
        if (u) u->next = n;
    }
}

void cli_allow_enable(struct cli_def *cli, char *password)
{
    free_z(cli->enable_password);
    if (!(cli->enable_password = strdup(password)))
    {
        fprintf(stderr, "Couldn't allocate memory for enable password: %s", strerror(errno));
    }
}

void cli_deny_user(struct cli_def *cli, char *username)
{
    struct unp *u, *p = NULL;
    if (!cli->users) return;
    for (u = cli->users; u; u = u->next)
    {
        if (strcmp(username, u->username) == 0)
        {
            if (p)
                p->next = u->next;
            else
                cli->users = u->next;
            zfree(u->username);
            zfree(u->password);
            zfree(u);
            break;
        }
        p = u;
    }
}

void cli_set_banner(struct cli_def *cli, char *banner)
{
    free_z(cli->banner);
    if (banner && *banner)
        cli->banner = strdup(banner);
}

void cli_set_hostname(struct cli_client *cc, char *hostname)
{
    free_z(cc->hostname);
    if (hostname && *hostname)
        cc->hostname = strdup(hostname);
}

void cli_set_promptchar(struct cli_client *cc, char *promptchar)
{
    // printf("cc %p old pc: %p, new pc: %p \n",cc,cc->promptchar,promptchar);
    free_z(cc->promptchar);
    cc->promptchar = strdup(promptchar);
    //printf("new dup pc %p\n",cc->promptchar);
}

static int cli_build_shortest(struct cli_client *cc, struct cli_command *commands)
{
    struct cli_command *c, *p;
    char *cp, *pp;
    int len;

    if(!commands || !cc)
    {
        return CLI_ERROR;
    }

    for (c = commands; c; c = c->next)
    {
        if (!c->command)
            return CLI_ERROR;

        // BUG: FIXME: TODO: разобраться с этим куском.
        // в этом месте баг. глобальные shortest строятся только для текущего режима.
        // а режим пользователезависим. если коннектятся 2 пользователя, и один из
        // пользователей поменяет режим (например, введет conf t), у другого
        // пользователя сломаются shortest, не будут работать completions.
        c->unique_len = strlen(c->command);
        if ((c->mode != MODE_ANY && c->mode != cc->mode) ||
            c->privilege > cc->privilege)
            continue;

        c->unique_len = 1;
        for (p = commands; p; p = p->next)
        {
            if (c == p)
                    continue;

            if ((p->mode != MODE_ANY && p->mode != cc->mode) ||
                p->privilege > cc->privilege)
                    continue;

            cp = c->command;
            pp = p->command;
            len = 1;

            while (*cp && *pp && *cp++ == *pp++)
                len++;

            if (len > c->unique_len)
                c->unique_len = len;
        }

        if (c->children)
            cli_build_shortest(cc, c->children);
    }

    return CLI_OK;
}

int cli_set_privilege(struct cli_client *cc, int priv)
{
    struct cli_def *cli = cc->common;
    int old = cc->privilege;
    cc->privilege = priv;

    if (priv != old)
    {
        cli_set_promptchar(cc, priv == PRIVILEGE_PRIVILEGED ? "# \0" : "> \0");
        cli_build_shortest(cc, cli->commands);
    }

    return old;
}

void cli_set_modestring(struct cli_client *cc, char *modestring)
{
    //printf("old modestring =%s= new: =%s=\n",
    //        cc->modestring?cc->modestring:"NULL",
    //        modestring?modestring:"NULL" );
    free_z(cc->modestring);
    if (modestring)
        cc->modestring = strdup(modestring);
    //printf("strdup modestring: %p\n", cc->modestring);
}

int cli_set_configmode(struct cli_client *cc, int mode, char *config_desc)
{
    struct cli_def *cli = cc->common;
    int old = cc->mode;
    cc->mode = mode;

    if (mode != old)
    {
        if (!cc->mode)
        {
            // Not config mode
            cli_set_modestring(cc, NULL);
        }
        else if (config_desc && *config_desc)
        {
            char string[64];
            snprintf(string, sizeof(string), "(config-%s)", config_desc);
            cli_set_modestring(cc, string);
        }
        else
        {
            cli_set_modestring(cc, "(config)");
        }

        cli_build_shortest(cc, cli->commands);
    }

    return old;
}

struct cli_command *cli_register_command(struct cli_def *cli,
    struct cli_command *parent, char *command,
    int (*callback)(struct cli_client *cc, char *, char **, int),
    int privilege, int mode, char *help)
{
    struct cli_command *c, *p;

    if (!command) return NULL;
    if (!(c = zcalloc(sizeof(struct cli_command), 1))) return NULL;

    c->callback = callback;
    c->next = NULL;
    if (!(c->command = strdup(command)))
        return NULL;
    c->parent = parent;
    c->privilege = privilege;
    c->mode = mode;
    if (help)
        if (!(c->help = strdup(help)))
            return NULL;

    if (parent)
    {
        if (!parent->children)
        {
            parent->children = c;
        }
        else
        {
            for (p = parent->children; p && p->next; p = p->next);
            if (p) p->next = c;
        }
    }
    else
    {
        if (!cli->commands)
        {
            cli->commands = c;
        }
        else
        {
            for (p = cli->commands; p && p->next; p = p->next);
            if (p) p->next = c;
        }
    }
    return c;
}

static void cli_free_command(struct cli_command *cmd)
{
    struct cli_command *c,*p;

    for (c = cmd->children; c;)
    {
        p = c->next;
        cli_free_command(c);
        c = p;
    }

    zfree(cmd->command);
    if (cmd->help) zfree(cmd->help);
    zfree(cmd);
}

int cli_unregister_command(struct cli_def *cli, char *command)
{
    struct cli_command *c, *p = NULL;

    if (!command) return -1;
    if (!cli->commands) return CLI_OK;

    for (c = cli->commands; c; c = c->next)
    {
        if (strcmp(c->command, command) == 0)
        {
            if (p)
                p->next = c->next;
            else
                cli->commands = c->next;

            cli_free_command(c);
            return CLI_OK;
        }
        p = c;
    }

    return CLI_OK;
}

static int cli_show_help(struct cli_client *cc, struct cli_command *c)
{
    struct cli_command *p;

    for (p = c; p; p = p->next)
    {
        if (p->command && p->callback && cc->privilege >= p->privilege &&
            (p->mode == cc->mode || p->mode == MODE_ANY))
        {
            cli_error(cc, "  %-20s %s", cli_command_name(cc, p), p->help ? : "");
        }

        if (p->children)
            cli_show_help(cc, p->children);
    }

    return CLI_OK;
}

int cli_int_enable(struct cli_client *cc, UNUSED(char *command), UNUSED(char *argv[]), UNUSED(int argc))
{
    struct cli_def *cli=cc->common;

    if (cc->privilege == PRIVILEGE_PRIVILEGED)
        return CLI_OK;

    if (!cli->enable_password && !cli->enable_callback)
    {
        /* no password required, set privilege immediately */
        cli_set_privilege(cc, PRIVILEGE_PRIVILEGED);
        cli_set_configmode(cc, MODE_EXEC, NULL);
    }
    else
    {
        /* require password entry */
        cc->state = STATE_ENABLE_PASSWORD;
    }

    return CLI_OK;
}

int cli_int_disable(struct cli_client *cc, UNUSED(char *command), UNUSED(char *argv[]), UNUSED(int argc))
{
    cli_set_privilege(cc, PRIVILEGE_UNPRIVILEGED);
    cli_set_configmode(cc, MODE_EXEC, NULL);
    return CLI_OK;
}

int cli_int_help(struct cli_client *cc, UNUSED(char *command), UNUSED(char *argv[]), UNUSED(int argc))
{
    struct cli_def *cli = cc->common;
    cli_error(cc, "\nCommands available:");
    cli_show_help(cc, cli->commands);
    return CLI_OK;
}

int cli_int_history(struct cli_client *cc, UNUSED(char *command), UNUSED(char *argv[]), UNUSED(int argc))
{
    int i;

    cli_error(cc, "\nCommand history:");
    for (i = 0; i < MAX_HISTORY; i++)
    {
        if (cc->history[i])
            cli_error(cc, "%3d. %s", i, cc->history[i]);
    }

    return CLI_OK;
}

int cli_int_quit(struct cli_client *cc, UNUSED(char *command), UNUSED(char *argv[]), UNUSED(int argc))
{
    cli_set_privilege(cc, PRIVILEGE_UNPRIVILEGED);
    cli_set_configmode(cc, MODE_EXEC, NULL);
    return CLI_QUIT;
}

int cli_int_exit(struct cli_client *cc, char *command, char *argv[], int argc)
{
    if (cc->mode == MODE_EXEC)
        return cli_int_quit(cc, command, argv, argc);

    if (cc->mode > MODE_CONFIG)
        cli_set_configmode(cc, MODE_CONFIG, NULL);
    else
        cli_set_configmode(cc, MODE_EXEC, NULL);

    cc->service = NULL;
    return CLI_OK;
}

int cli_int_idle_timeout(struct cli_client *cc)
{
    cli_print(cc, "Idle timeout");
    return CLI_QUIT;
}

int cli_int_configure_terminal(struct cli_client *cc, UNUSED(char *command), UNUSED(char *argv[]), UNUSED(int argc))
{
    cli_set_configmode(cc, MODE_CONFIG, NULL);
    return CLI_OK;
}

int cli_client_init(struct cli_def *cli, struct cli_client *cc, int fd){
    if (!cc || !cli)
    {
        return -1;
    }

    memset(cc, 0, sizeof(struct cli_client));

    cc->common=cli;
    cc->sockfd = fd;
    cc->buf_size = 1024;
    if (!(cc->buffer = zcalloc(cc->buf_size, 1)))
    {
        return -1;
    }

    cc->privilege = cc->mode = -1;
    cli_set_privilege(cc, PRIVILEGE_UNPRIVILEGED);
    cli_set_configmode(cc, MODE_EXEC, 0);

    // Set default idle timeout callback, but no timeout
    cli_set_idle_timeout_callback(cc, 0, cli_int_idle_timeout);

    return 0;
}

struct cli_def *cli_init()
{
    struct cli_def *cli;
    struct cli_command *c;

    if (!(cli = zcalloc(sizeof(struct cli_def), 1)))
        return 0;

    cli->negotiate = 1;
    cli_register_command(cli, 0, "help", cli_int_help, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "Show available commands");
    cli_register_command(cli, 0, "quit", cli_int_quit, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "Disconnect");
    cli_register_command(cli, 0, "logout", cli_int_quit, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "Disconnect");
    cli_register_command(cli, 0, "exit", cli_int_exit, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "Exit from current mode");
    cli_register_command(cli, 0, "history", cli_int_history, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "Show a list of previously run commands");
    cli_register_command(cli, 0, "enable", cli_int_enable, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "Turn on privileged commands");
    cli_register_command(cli, 0, "disable", cli_int_disable, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Turn off privileged commands");

    c = cli_register_command(cli, 0, "configure", 0, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Enter configuration mode");
    cli_register_command(cli, c, "terminal", cli_int_configure_terminal, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Configure from the terminal");

    // Default to 1 second timeout intervals
    cli->timeout_tm.tv_sec = 1;
    cli->timeout_tm.tv_usec = 0;


    return cli;
}

void cli_unregister_all(struct cli_def *cli, struct cli_command *command)
{
    struct cli_command *c, *p = NULL;

    if (!command) command = cli->commands;
    if (!command) return;

    for (c = command; c; )
    {
        p = c->next;

        // Unregister all child commands
        if (c->children)
            cli_unregister_all(cli, c->children);

        if (c->command) zfree(c->command);
        if (c->help) zfree(c->help);
        zfree(c);

        c = p;
    }
}


void cli_client_done(struct cli_client *cc)
{

    if (!cc) return;
    cli_free_history(cc);

    free_z(cc->commandname);
    free_z(cc->modestring);
    free_z(cc->promptchar);
    free_z(cc->hostname);
    free_z(cc->buffer);

    return;
}


int cli_done(struct cli_def *cli)
{

    if (!cli) return CLI_ERROR;

    // TODO: нужно освобождать память занятую всеми клиентами (cli_client_done)


    struct unp *u = cli->users, *n;

    // Free all users
    while (u)
    {
        if (u->username) zfree(u->username);
        if (u->password) zfree(u->password);
        n = u->next;
        zfree(u);
        u = n;
    }

    /* zfree all commands */
    cli_unregister_all(cli, 0);

    free_z(cli->banner);
    free_z(cli);

    return CLI_OK;
}

static int cli_add_history(struct cli_client *cc, char *cmd)
{
    int i;
    for (i = 0; i < MAX_HISTORY; i++)
    {
        if (!cc->history[i])
        {
            if (i == 0 || strcasecmp(cc->history[i-1], cmd))
            if (!(cc->history[i] = strdup(cmd)))
                return CLI_ERROR;
            return CLI_OK;
        }
    }
    // No space found, drop one off the beginning of the list
    zfree(cc->history[0]);
    for (i = 0; i < MAX_HISTORY-1; i++)
        cc->history[i] = cc->history[i+1];
    if (!(cc->history[MAX_HISTORY - 1] = strdup(cmd)))
        return CLI_ERROR;
    return CLI_OK;
}

void cli_free_history(struct cli_client *cc)
{
    int i;
    for (i = 0; i < MAX_HISTORY; i++)
    {
        if (cc->history[i])
            free_z(cc->history[i]);
    }
}

static int cli_parse_line(char *line, char *words[], int max_words)
{
    int nwords = 0;
    char *p = line;
    char *word_start = 0;
    int inquote = 0;

    while (*p)
    {
        if (!isspace(*p))
        {
            word_start = p;
            break;
        }
        p++;
    }

    while (nwords < max_words - 1)
    {
        if (!*p || *p == inquote || (word_start && !inquote && (isspace(*p) || *p == '|')))
        {
            if (word_start)
            {
                int len = p - word_start;

                memcpy(words[nwords] = zmalloc(2+len + 1), word_start, len);
                words[nwords++][len] = 0;
            }

            if (!*p)
                break;

            if (inquote)
                p++; /* skip over trailing quote */

            inquote = 0;
            word_start = 0;
        }
        else if (*p == '"' || *p == '\'')
        {
            inquote = *p++;
            word_start = p;
        }
        else
        {
            if (!word_start)
            {
                if (*p == '|')
                {
                    if (!(words[nwords++] = strdup("|")))
                        return 0;
                }
                else if (!isspace(*p))
                    word_start = p;
            }

            p++;
        }
    }

    return nwords;
}

static char *join_words(int argc, char **argv)
{
    char *p;
    int len = 0;
    int i;

    for (i = 0; i < argc; i++)
    {
        if (i)
            len += 1;

        len += strlen(argv[i]);
    }

    p = zmalloc(2+len + 1);
    p[0] = 0;

    for (i = 0; i < argc; i++)
    {
        if (i)
            strcat(p, " ");

        strcat(p, argv[i]);
    }

    return p;
}

static int cli_find_command(struct cli_client *cc, struct cli_command *commands, int num_words, char *words[], int start_word, int filters[])
{
    struct cli_command *c, *again = NULL;
    int c_words = num_words;

    if (!cc || !cc->common)
    {
        return CLI_ERROR;
    }

    struct cli_def *cli = cc->common;

    if (filters[0])
        c_words = filters[0];

    // Deal with ? for help
    if (!words[start_word])
        return CLI_ERROR;

    if (words[start_word][strlen(words[start_word]) - 1] == '?')
    {
        int l = strlen(words[start_word])-1;

        if (commands->parent && commands->parent->callback)
            cli_error(cc, "%-20s %s", cli_command_name(cc, commands->parent),  commands->parent->help ? : "");

        for (c = commands; c; c = c->next)
        {
            if (strncasecmp(c->command, words[start_word], l) == 0
                && (c->callback || c->children)
                && cc->privilege >= c->privilege
                && (c->mode == cc->mode || c->mode == MODE_ANY))
                    cli_error(cc, "  %-20s %s", c->command, c->help ? : "");
        }

        return CLI_OK;
    }

    for (c = commands; c; c = c->next)
    {
        if (cc->privilege < c->privilege)
            continue;

        if (strncasecmp(c->command, words[start_word], c->unique_len))
            continue;

        if (strncasecmp(c->command, words[start_word], strlen(words[start_word])))
            continue;

        AGAIN:
        if (c->mode == cc->mode || c->mode == MODE_ANY)
        {
            int rc = CLI_OK;
            int f;
            struct cli_filter **filt = &cli->filters;

            // Found a word!
            if (!c->children)
            {
                // Last word
                if (!c->callback)
                {
                    cli_error(cc, "No callback for \"%s\"", cli_command_name(cc, c));
                    return CLI_ERROR;
                }
            }
            else
            {
                if (start_word == c_words - 1)
                {
                    if (c->callback)
                        goto CORRECT_CHECKS;

                    cli_error(cc, "Incomplete command");
                    return CLI_ERROR;
                }
                rc = cli_find_command(cc, c->children, num_words, words, start_word + 1, filters);
                if (rc == CLI_ERROR_ARG)
                {
                    if (c->callback)
                    {
                        rc = CLI_OK;
                        goto CORRECT_CHECKS;
                    }
                    else
                    {
                        cli_error(cc, "Invalid %s \"%s\"", commands->parent ? "argument" : "command", words[start_word]);
                    }
                }
                return rc;
            }

            if (!c->callback)
            {
                cli_error(cc, "Internal server error processing \"%s\"", cli_command_name(cc, c));
                return CLI_ERROR;
            }

            CORRECT_CHECKS:
            for (f = 0; rc == CLI_OK && filters[f]; f++)
            {
                int n = num_words;
                char **argv;
                int argc;
                int len;

                if (filters[f+1])
                n = filters[f+1];

                if (filters[f] == n - 1)
                {
                    cli_error(cc, "Missing filter");
                    return CLI_ERROR;
                }

                argv = words + filters[f] + 1;
                argc = n - (filters[f] + 1);
                len = strlen(argv[0]);
                if (argv[argc - 1][strlen(argv[argc - 1]) - 1] == '?')
                {
                    if (argc == 1)
                    {
                        int i;

                        for(i = 0; filter_cmds[i].cmd; i++)
                        {
                            cli_error(cc, "  %-20s %s", filter_cmds[i].cmd, filter_cmds[i].help );
                        }
                    }
                    else
                    {
                        if (argv[0][0] != 'c') // count
                            cli_error(cc, "  WORD");

                        if (argc > 2 || argv[0][0] == 'c') // count
                            cli_error(cc, "  <cr>");
                    }

                    return CLI_OK;
                }

                if (argv[0][0] == 'b' && len < 3) // [beg]in, [bet]ween
                {
                    cli_error(cc, "Ambiguous filter \"%s\" (begin, between)", argv[0]);
                    return CLI_ERROR;
                }
                *filt = zcalloc(sizeof(struct cli_filter), 1);

                if (!strncmp("include", argv[0], len) ||
                    !strncmp("exclude", argv[0], len) ||
                    !strncmp("grep", argv[0], len) ||
                    !strncmp("egrep", argv[0], len))
                        rc = cli_match_filter_init(cc, argc, argv, *filt);
                else if (!strncmp("begin", argv[0], len) ||
                    !strncmp("between", argv[0], len))
                        rc = cli_range_filter_init(cc, argc, argv, *filt);
                else if (!strncmp("count", argv[0], len))
                    rc = cli_count_filter_init(cc, argc, argv, *filt);
                else
                {
                    cli_error(cc, "Invalid filter \"%s\"", argv[0]);
                    rc = CLI_ERROR;
                }

                if (rc == CLI_OK)
                {
                    filt = &(*filt)->next;
                }
                else
                {
                    zfree(*filt);
                    *filt = 0;
                }
            }

            if (rc == CLI_OK)
                rc = c->callback(cc, cli_command_name(cc, c), words + start_word + 1, c_words - start_word - 1);

            while (cli->filters)
            {
                struct cli_filter *filt = cli->filters;

                // call one last time to clean up
                filt->filter(cc, NULL, filt->data);
                cli->filters = filt->next;
                zfree(filt);
            }

            return rc;
        }
        else if (cc->mode > MODE_CONFIG && c->mode == MODE_CONFIG)
        {
            // command matched but from another mode,
            // remember it if we fail to find correct command
            again = c;
        }
    }

    // drop out of config submode if we have matched command on MODE_CONFIG
    if (again)
    {
        c = again;
        cli_set_configmode(cc, MODE_CONFIG, NULL);
        goto AGAIN;
    }

    if (start_word == 0)
        cli_error(cc, "Invalid %s \"%s\"", commands->parent ? "argument" : "command", words[start_word]);

    return CLI_ERROR_ARG;
}

int cli_run_command(struct cli_client *cc, char *command)
{
    int r;
    unsigned int num_words, i, f;
    char *words[CLI_MAX_LINE_WORDS] = {0};
    int filters[CLI_MAX_LINE_WORDS] = {0};

    struct cli_def *cli = cc->common;


    if (!command) return CLI_ERROR;
    while (isspace(*command))
        command++;

    if (!*command) return CLI_OK;

    num_words = cli_parse_line(command, words, CLI_MAX_LINE_WORDS);
    for (i = f = 0; i < num_words && f < CLI_MAX_LINE_WORDS - 1; i++)
    {
        if (words[i][0] == '|')
        filters[f++] = i;
    }

    filters[f] = 0;

    if (num_words)
        r = cli_find_command(cc, cli->commands, num_words, words, 0, filters);
    else
        r = CLI_ERROR;

    for (i = 0; i < num_words; i++)
        zfree(words[i]);

    if (r == CLI_QUIT)
        return r;

    return CLI_OK;
}

static int cli_get_completions(struct cli_client *cc, char *command, char **completions, int max_completions)
{
    struct cli_command *c;
    struct cli_command *n;
    int num_words, i, k=0;
    char *words[CLI_MAX_LINE_WORDS] = {0};
    int filter = 0;

    struct cli_def *cli = cc->common;

    if (!command) return 0;
    while (isspace(*command))
        command++;

    num_words = cli_parse_line(command, words, sizeof(words)/sizeof(words[0]));
    if (!command[0] || command[strlen(command)-1] == ' ')
        num_words++;

    if (!num_words)
            return 0;

    for (i = 0; i < num_words; i++)
    {
        if (words[i] && words[i][0] == '|')
            filter = i;
    }

    if (filter) // complete filters
    {
        unsigned len = 0;

        if (filter < num_words - 1) // filter already completed
            return 0;

        if (filter == num_words - 1)
            len = strlen(words[num_words-1]);

        for (i = 0; filter_cmds[i].cmd && k < max_completions; i++)
            if (!len || (len < strlen(filter_cmds[i].cmd)
                && !strncmp(filter_cmds[i].cmd, words[num_words - 1], len)))
                    completions[k++] = filter_cmds[i].cmd;

        completions[k] = NULL;
        return k;
    }

    for (c = cli->commands, i = 0; c && i < num_words && k < max_completions; c = n)
    {
        n = c->next;

        if (cc->privilege < c->privilege)
            continue;

        if (c->mode != cc->mode && c->mode != MODE_ANY)
            continue;

        if (words[i] && strncasecmp(c->command, words[i], strlen(words[i])))
            continue;

        if (i < num_words - 1)
        {
            if (strlen(words[i]) < c->unique_len)
                    continue;

            n = c->children;
            i++;
            continue;
        }

        completions[k++] = c->command;
    }

    return k;
}

static void cli_clear_line(int sockfd, char *cmd, int l, int cursor)
{
    int i;
    if (cursor < l) for (i = 0; i < (l - cursor); i++) write(sockfd, " ", 1);
    for (i = 0; i < l; i++) cmd[i] = '\b';
    for (; i < l * 2; i++) cmd[i] = ' ';
    for (; i < l * 3; i++) cmd[i] = '\b';
    write(sockfd, cmd, i);
    memset(cmd, 0, i);
    l = cursor = 0;
}

void cli_reprompt(struct cli_client *cc)
{
    if (!cc) return;
    cc->showprompt = 1;
}

void cli_regular(struct cli_def *cli, int (*callback)(struct cli_client *cli))
{
    if (!cli) return;
    cli->regular_callback = callback;
}

void cli_regular_interval(struct cli_def *cli, int seconds)
{
    if (seconds < 1) seconds = 1;
    cli->timeout_tm.tv_sec = seconds;
    cli->timeout_tm.tv_usec = 0;
}

#define DES_PREFIX "{crypt}"        /* to distinguish clear text from DES crypted */
#define MD5_PREFIX "$1$"

static int pass_matches(char *pass, char *try)
{
    int des;
    if ((des = !strncasecmp(pass, DES_PREFIX, sizeof(DES_PREFIX)-1)))
        pass += sizeof(DES_PREFIX)-1;

#ifndef WIN32
    /*
     * TODO - find a small crypt(3) function for use on windows
     */
    if (des || !strncmp(pass, MD5_PREFIX, sizeof(MD5_PREFIX)-1))
        try = crypt(try, pass);
#endif

    return !strcmp(pass, try);
}

#define CTRL(c) (c - '@')

static int show_prompt(struct cli_client *cc)
{
    int len = 0;

    if (cc->hostname)
        len += write(cc->sockfd, cc->hostname, strlen(cc->hostname));

    if (cc->modestring)
        len += write(cc->sockfd, cc->modestring, strlen(cc->modestring));

    return len + write(cc->sockfd, cc->promptchar, strlen(cc->promptchar));
}

int cli_loop(struct cli_client *cc)
{
    unsigned char c;
    int n, l, oldl = 0, is_telnet_option = 0, skip = 0, esc = 0;
    int cursor = 0, insertmode = 1;
    char *cmd = NULL, *oldcmd = 0;
    char *username = NULL, *password = NULL;
    char *negotiate =
        "\xFF\xFB\x03"
        "\xFF\xFB\x01"
        "\xFF\xFD\x03"
        "\xFF\xFD\x01";
 
    if (!cc) return CLI_ERROR;
    if (!cc->common) return CLI_ERROR;
    struct cli_def *cli = cc->common;
    int sockfd = cc->sockfd;

    cli_build_shortest(cc, cli->commands);
    cc->state = STATE_LOGIN;

    cli_free_history(cc);
   if (cli->negotiate)
        write(sockfd, negotiate, strlen(negotiate));

    if ((cmd = zmalloc(2+CLI_MAX_LINE_LENGTH)) == NULL)
        return CLI_ERROR;

#ifdef WIN32
    /*
     * OMG, HACK
     */
    if (!(cc->client = fdopen(_open_osfhandle(sockfd,0), "w+")))
        return CLI_ERROR;
    cc->client->_file = sockfd;
#else
    if (!(cc->client = fdopen(sockfd, "w+")))
        return CLI_ERROR;
#endif

    setbuf(cc->client, NULL);
    if (cli->banner)
        cli_error(cc, "%s", cli->banner);

    // Set the last action now so we don't time immediately
    if (cli->idle_timeout)
        time(&cc->last_action);

    /* start off in unprivileged mode */
    cli_set_privilege(cc, PRIVILEGE_PRIVILEGED);
    cli_set_configmode(cc, MODE_EXEC, NULL);

    /* no auth required? */
    if (!cli->users && !cli->auth_callback)
        cc->state = STATE_NORMAL;

    while (1)
    {
        signed int in_history = 0;
        int lastchar = 0;
        struct timeval tm;

        cc->showprompt = 1;

        if (oldcmd)
        {
            l = cursor = oldl;
            oldcmd[l] = 0;
            cc->showprompt = 1;
            oldcmd = NULL;
            oldl = 0;
        }
        else
        {
            memset(cmd, 0, CLI_MAX_LINE_LENGTH);
            l = 0;
            cursor = 0;
        }

        memcpy(&tm, &cli->timeout_tm, sizeof(tm));

        while (1)
        {
            int sr;
            fd_set r;
            if (cc->showprompt)
            {
                if (cc->state != STATE_PASSWORD && cc->state != STATE_ENABLE_PASSWORD)
                    write(sockfd, "\r\n", 2);

                switch (cc->state)
                {
                    case STATE_LOGIN:
                        write(sockfd, "Username: ", strlen("Username: "));
                        break;

                    case STATE_PASSWORD:
                        write(sockfd, "Password: ", strlen("Password: "));
                        break;

                    case STATE_NORMAL:
                    case STATE_ENABLE:
                        show_prompt(cc);
                        write(sockfd, cmd, l);
                        if (cursor < l)
                        {
                            int n = l - cursor;
                            while (n--)
                                write(sockfd, "\b", 1);
                        }
                        break;

                    case STATE_ENABLE_PASSWORD:
                        write(sockfd, "Password: ", strlen("Password: "));
                        break;

                }

                cc->showprompt = 0;
            }

            FD_ZERO(&r);
            FD_SET(sockfd, &r);

            if ((sr = select(sockfd + 1, &r, NULL, NULL, &tm)) < 0)
            {
                /* select error */
                if (errno == EINTR)
                    continue;

                perror("select");
                l = -1;
                break;
            }

            if (sr == 0)
            {
                /* timeout every second */
                if (cli->regular_callback && cli->regular_callback(cc) != CLI_OK)
                {
                    l = -1;
                    break;
                }

                if (cli->idle_timeout)
                {
                    if (time(NULL) - cc->last_action >= cli->idle_timeout)
                    {
                        if (cli->idle_timeout_callback)
                        {
                            // Call the callback and continue on if successful
                            if (cli->idle_timeout_callback(cc) == CLI_OK)
                            {
                                // Reset the idle timeout counter
                                time(&cc->last_action);
                                continue;
                            }
                        }
                        // Otherwise, break out of the main loop
                        l = -1;
                        break;
                    }
                }

                memcpy(&tm, &cli->timeout_tm, sizeof(tm));
                continue;
            }

            if ((n = read(sockfd, &c, 1)) < 0)
            {
                if (errno == EINTR)
                    continue;

                perror("read");
                l = -1;
                break;
            }

            if (cli->idle_timeout)
                time(&cc->last_action);

            if (n == 0)
            {
                l = -1;
                break;
            }

            if (skip)
            {
                skip--;
                continue;
            }

            if (c == 255 && !is_telnet_option)
            {
                is_telnet_option++;
                continue;
            }

            if (is_telnet_option)
            {
                if (c >= 251 && c <= 254)
                {
                    is_telnet_option = c;
                    continue;
                }

                if (c != 255)
                {
                    is_telnet_option = 0;
                    continue;
                }

                is_telnet_option = 0;
            }

            /* handle ANSI arrows */
            if (esc)
            {
                if (esc == '[')
                {
                    /* remap to readline control codes */
                    switch (c)
                    {
                        case 'A': /* Up */
                            c = CTRL('P');
                            break;

                        case 'B': /* Down */
                            c = CTRL('N');
                            break;

                        case 'C': /* Right */
                            c = CTRL('F');
                            break;

                        case 'D': /* Left */
                            c = CTRL('B');
                            break;

                        default:
                            c = 0;
                    }

                    esc = 0;
                }
                else
                {
                    esc = (c == '[') ? c : 0;
                    continue;
                }
            }

            if (c == 0) continue;
            if (c == '\n') continue;

            if (c == '\r')
            {
                if (cc->state != STATE_PASSWORD && cc->state != STATE_ENABLE_PASSWORD)
                    write(sockfd, "\r\n", 2);
                break;
            }

            if (c == 27)
            {
                esc = 1;
                continue;
            }

            if (c == CTRL('C'))
            {
                write(sockfd, "\a", 1);
                continue;
            }

            /* back word, backspace/delete */
            if (c == CTRL('W') || c == CTRL('H') || c == 0x7f)
            {
                int back = 0;

                if (c == CTRL('W')) /* word */
                {
                    int nc = cursor;

                    if (l == 0 || cursor == 0)
                        continue;

                    while (nc && cmd[nc - 1] == ' ')
                    {
                        nc--;
                        back++;
                    }

                    while (nc && cmd[nc - 1] != ' ')
                    {
                        nc--;
                        back++;
                    }
                }
                else /* char */
                {
                    if (l == 0 || cursor == 0)
                    {
                        write(sockfd, "\a", 1);
                        continue;
                    }

                    back = 1;
                }

                if (back)
                {
                    while (back--)
                    {
                        if (l == cursor)
                        {
                            cmd[--cursor] = 0;
                            if (cc->state != STATE_PASSWORD && cc->state != STATE_ENABLE_PASSWORD)
                                write(sockfd, "\b \b", 3);
                        }
                        else
                        {
                            int i;
                            cursor--;
                            if (cc->state != STATE_PASSWORD && cc->state != STATE_ENABLE_PASSWORD)
                            {
                                for (i = cursor; i <= l; i++) cmd[i] = cmd[i+1];
                                write(sockfd, "\b", 1);
                                write(sockfd, cmd + cursor, strlen(cmd + cursor));
                                write(sockfd, " ", 1);
                                for (i = 0; i <= (int)strlen(cmd + cursor); i++)
                                    write(sockfd, "\b", 1);
                            }
                        }
                        l--;
                    }

                    continue;
                }
            }

            /* redraw */
            if (c == CTRL('L'))
            {
                int i;
                int cursorback = l - cursor;

                if (cc->state == STATE_PASSWORD || cc->state == STATE_ENABLE_PASSWORD)
                    continue;

                write(sockfd, "\r\n", 2);
                show_prompt(cc);
                write(sockfd, cmd, l);

                for (i = 0; i < cursorback; i++)
                    write(sockfd, "\b", 1);

                continue;
            }

            /* clear line */
            if (c == CTRL('U'))
            {
                if (cc->state == STATE_PASSWORD || cc->state == STATE_ENABLE_PASSWORD)
                    memset(cmd, 0, l);
                else
                    cli_clear_line(sockfd, cmd, l, cursor);

                l = cursor = 0;
                continue;
            }

            /* kill to EOL */
            if (c == CTRL('K'))
            {
                if (cursor == l)
                    continue;

                if (cc->state != STATE_PASSWORD && cc->state != STATE_ENABLE_PASSWORD)
                {
                    int c;
                    for (c = cursor; c < l; c++)
                        write(sockfd, " ", 1);

                    for (c = cursor; c < l; c++)
                        write(sockfd, "\b", 1);
                }

                memset(cmd + cursor, 0, l - cursor);
                l = cursor;
                continue;
            }

            /* EOT */
            if (c == CTRL('D'))
            {
                if (cc->state == STATE_PASSWORD || cc->state == STATE_ENABLE_PASSWORD)
                    break;

                if (l)
                    continue;

                l = -1;
                break;
            }

            /* disable */
            if (c == CTRL('Z'))
            {
                if (cc->mode != MODE_EXEC)
                {
                    cli_clear_line(sockfd, cmd, l, cursor);
                    cli_set_configmode(cc, MODE_EXEC, NULL);
                    cc->showprompt = 1;
                }

                continue;
            }

            /* TAB completion */
            if (c == CTRL('I'))
            {
                char *completions[CLI_MAX_LINE_WORDS];
                int num_completions = 0;

                if (cc->state == STATE_LOGIN || cc->state == STATE_PASSWORD || cc->state == STATE_ENABLE_PASSWORD)
                    continue;

                if (cursor != l) continue;

                num_completions = cli_get_completions(cc, cmd, completions, CLI_MAX_LINE_WORDS);
                if (num_completions == 0)
                {
                    write(sockfd, "\a", 1);
                }
                else if (num_completions == 1)
                {
                    // Single completion
                    for (; l > 0; l--, cursor--)
                    {
                        if (cmd[l-1] == ' ' || cmd[l-1] == '|')
                            break;
                        write(sockfd, "\b", 1);
                    }
                    strcpy((cmd + l), completions[0]);
                    l += strlen(completions[0]);
                    cmd[l++] = ' ';
                    cursor = l;
                    write(sockfd, completions[0], strlen(completions[0]));
                    write(sockfd, " ", 1);
                }
                else if (lastchar == CTRL('I'))
                {
                    // double tab
                    int i;
                    write(sockfd, "\r\n", 2);
                    for (i = 0; i < num_completions; i++)
                    {
                        write(sockfd, completions[i], strlen(completions[i]));
                        if (i % 4 == 3)
                            write(sockfd, "\r\n", 2);
                        else
                            write(sockfd, "     ", 1);
                    }
                    if (i % 4 != 3) write(sockfd, "\r\n", 2);
                        cc->showprompt = 1;
                }
                else
                {
                    // More than one completion
                    lastchar = c;
                    write(sockfd, "\a", 1);
                }
                continue;
            }

            /* history */
            if (c == CTRL('P') || c == CTRL('N'))
            {
                int history_found = 0;

                if (cc->state == STATE_LOGIN || cc->state == STATE_PASSWORD || cc->state == STATE_ENABLE_PASSWORD)
                    continue;

                if (c == CTRL('P')) // Up
                {
                    in_history--;
                    if (in_history < 0)
                    {
                        for (in_history = MAX_HISTORY-1; in_history >= 0; in_history--)
                        {
                            if (cc->history[in_history])
                            {
                                history_found = 1;
                                break;
                            }
                        }
                    }
                    else
                    {
                        if (cc->history[in_history]) history_found = 1;
                    }
                }
                else // Down
                {
                    in_history++;
                    if (in_history >= MAX_HISTORY || !cc->history[in_history])
                    {
                        int i = 0;
                        for (i = 0; i < MAX_HISTORY; i++)
                        {
                            if (cc->history[i])
                            {
                                in_history = i;
                                history_found = 1;
                                break;
                            }
                        }
                    }
                    else
                    {
                        if (cc->history[in_history]) history_found = 1;
                    }
                }
                if (history_found && cc->history[in_history])
                {
                    // Show history item
                    cli_clear_line(sockfd, cmd, l, cursor);
                    memset(cmd, 0, CLI_MAX_LINE_LENGTH);
                    strncpy(cmd, cc->history[in_history], CLI_MAX_LINE_LENGTH - 1);
                    l = cursor = strlen(cmd);
                    write(sockfd, cmd, l);
                }

                continue;
            }

            /* left/right cursor motion */
            if (c == CTRL('B') || c == CTRL('F'))
            {
                if (c == CTRL('B')) /* Left */
                {
                    if (cursor)
                    {
                        if (cc->state != STATE_PASSWORD && cc->state != STATE_ENABLE_PASSWORD)
                            write(sockfd, "\b", 1);

                        cursor--;
                    }
                }
                else /* Right */
                {
                    if (cursor < l)
                    {
                        if (cc->state != STATE_PASSWORD && cc->state != STATE_ENABLE_PASSWORD)
                            write(sockfd, &cmd[cursor], 1);

                        cursor++;
                    }
                }

                continue;
            }

            /* start of line */
            if (c == CTRL('A'))
            {
                if (cursor)
                {
                    if (cc->state != STATE_PASSWORD && cc->state != STATE_ENABLE_PASSWORD)
                    {
                        write(sockfd, "\r", 1);
                        show_prompt(cc);
                    }

                    cursor = 0;
                }

                continue;
            }

            /* end of line */
            if (c == CTRL('E'))
            {
                if (cursor < l)
                {
                    if (cc->state != STATE_PASSWORD && cc->state != STATE_ENABLE_PASSWORD)
                        write(sockfd, &cmd[cursor], l - cursor);

                    cursor = l;
                }

                continue;
            }

            /* normal character typed */
            if (cursor == l)
            {
                 /* append to end of line */
                cmd[cursor] = c;
                if (l < CLI_MAX_LINE_LENGTH - 1)
                {
                    l++;
                    cursor++;
                }
                else
                {
                    write(sockfd, "\a", 1);
                    continue;
                }
            }
            else
            {
                // Middle of text
                if (insertmode)
                {
                    int i;
                    // Move everything one character to the right
                    if (l >= CLI_MAX_LINE_LENGTH - 2) l--;
                    for (i = l; i >= cursor; i--)
                        cmd[i + 1] = cmd[i];
                    // Write what we've just added
                    cmd[cursor] = c;

                    write(sockfd, &cmd[cursor], l - cursor + 1);
                    for (i = 0; i < (l - cursor + 1); i++)
                        write(sockfd, "\b", 1);
                    l++;
                }
                else
                {
                    cmd[cursor] = c;
                }
                cursor++;
            }

            if (cc->state != STATE_PASSWORD && cc->state != STATE_ENABLE_PASSWORD)
            {
                if (c == '?' && cursor == l)
                {
                    write(sockfd, "\r\n", 2);
                    oldcmd = cmd;
                    oldl = cursor = l - 1;
                    break;
                }
                write(sockfd, &c, 1);
            }

            oldcmd = 0;
            oldl = 0;
            lastchar = c;
        }

        if (l < 0) break;

        if (cc->state == STATE_LOGIN)
        {
            if (l == 0) continue;

            /* require login */
            free_z(username);
            if (!(username = strdup(cmd)))
                return 0;
            cc->state = STATE_PASSWORD;
            cc->showprompt = 1;
        }
        else if (cc->state == STATE_PASSWORD)
        {
            /* require password */
            int allowed = 0;

            free_z(password);
            if (!(password = strdup(cmd)))
                return 0;
            if (cli->auth_callback)
            {
                if (cli->auth_callback(username, password) == CLI_OK)
                    allowed++;
            }

            if (!allowed)
            {
                struct unp *u;
                for (u = cli->users; u; u = u->next)
                {
                    if (!strcmp(u->username, username) && pass_matches(u->password, password))
                    {
                        allowed++;
                        break;
                    }
                }
            }

            if (allowed)
            {
                //cli_error(cc, "");
                cc->state = STATE_NORMAL;
            }
            else
            {
                cli_error(cc, "\n\nAccess denied");
                free_z(username);
                free_z(password);
                cc->state = STATE_LOGIN;
            }

            cc->showprompt = 1;
        }
        else if (cc->state == STATE_ENABLE_PASSWORD)
        {
            int allowed = 0;
            if (cli->enable_password)
            {
                /* check stored static enable password */
                if (pass_matches(cli->enable_password, cmd))
                    allowed++;
            }

            if (!allowed && cli->enable_callback)
            {
                /* check callback */
                if (cli->enable_callback(cmd))
                    allowed++;
            }

            if (allowed)
            {
                cc->state = STATE_ENABLE;
                cli_set_privilege(cc, PRIVILEGE_PRIVILEGED);
            }
            else
            {
                cli_error(cc, "\n\nAccess denied");
                cc->state = STATE_NORMAL;
            }
        }
        else
        {
            if (l == 0) continue;
            if (cmd[l - 1] != '?' && strcasecmp(cmd, "history") != 0)
                cli_add_history(cc, cmd);

            if (cli_run_command(cc, cmd) == CLI_QUIT)
                break;
        }

        // Update the last_action time now as the last command run could take a
        // long time to return
        if (cli->idle_timeout)
            time(&cc->last_action);
    }

    cli_free_history(cc);
    free_z(username);
    free_z(password);
    free_z(cmd);

    fclose(cc->client);
    cc->client = 0;
    return CLI_OK;
}

int cli_file(struct cli_client *cc, FILE *fh, int privilege, int mode)
{
    int oldpriv = cli_set_privilege(cc, privilege);
    int oldmode = cli_set_configmode(cc, mode, NULL);
    char buf[CLI_MAX_LINE_LENGTH];
    FILE *old_client;

    // sanity check
    if (!cc || !cc->sockfd)
        return CLI_ERROR;

    old_client = cc->client;

    // открывает output handle
    if (!(cc->client = fdopen(cc->sockfd, "w+")))
        return CLI_ERROR;

    while (1)
    {
        char *p;
        char *cmd;
        char *end;

        if (fgets(buf, CLI_MAX_LINE_LENGTH - 1, fh) == NULL)
            break; /* end of file */

        if ((p = strpbrk(buf, "#\r\n")))
            *p = 0;

        cmd = buf;
        while (isspace(*cmd))
            cmd++;

        if (!*cmd)
            continue;

        for (p = end = cmd; *p; p++)
            if (!isspace(*p))
                end = p;

        *++end = 0;
        if (strncasecmp(cmd, "quit", 4) == 0)
            break;

        cli_print(cc, cmd);
        if (cli_run_command(cc, cmd) == CLI_QUIT)
            break;
    }

    cli_print(cc, "-end-of-config-");

    fclose(cc->client);
    cc->client = old_client;

    cli_set_privilege(cc, oldpriv);
    cli_set_configmode(cc, oldmode, NULL /* didn't save desc */);

    return CLI_OK;
}

static void _print(struct cli_client *cc, int print_mode, char *format, va_list ap)
{
    va_list aq;
    int n;
    char *p;

    if (!cc) return; // sanity check

    if(!cc->common) return;
    struct cli_def *cli = cc->common;

    while (1)
    {
        va_copy(aq, ap);
        n = vsnprintf(cc->buffer, cc->buf_size, format, ap);
        if (n >= cc->buf_size)
        {
            cc->buf_size = n + 1;
            cc->buffer = realloc(cc->buffer, cc->buf_size);
            if (!cc->buffer)
                return;
            va_end(ap);
            va_copy(ap, aq);
            continue;
        }
        break;
    }

    if (n < 0) // vsnprintf failed
        return;

    p = cc->buffer;
    do
    {
        char *next = strchr(p, '\n');
        struct cli_filter *f = (print_mode & PRINT_FILTERED) ? cli->filters : 0;
        int print = 1;

        if (next)
            *next++ = 0;
        else if (print_mode & PRINT_BUFFERED)
            break;

        while (print && f)
        {
            print = (f->filter(cc, p, f->data) == CLI_OK);
            f = f->next;
        }
        if (print)
        {
            if (cli->print_callback)
                cli->print_callback(cc, p);
            else if (cc->client)
                fprintf(cc->client, "%s\r\n", p);
        }

        p = next;
    } while (p);

    if (p && *p)
    {
        if (p != cc->buffer)
        memmove(cc->buffer, p, strlen(p));
    }
    else *cc->buffer = 0;
}

void cli_bufprint(struct cli_client *cc, char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    _print(cc, PRINT_BUFFERED|PRINT_FILTERED, format, ap);
    va_end(ap);
}

void cli_vabufprint(struct cli_client *cc, char *format, va_list ap)
{
    _print(cc, PRINT_BUFFERED, format, ap);
}

void cli_print(struct cli_client *cc, char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    _print(cc, PRINT_FILTERED, format, ap);
    va_end(ap);
}

void cli_error(struct cli_client *cc, char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    _print(cc, PRINT_PLAIN, format, ap);
    va_end(ap);
}

struct cli_match_filter_state
{
    int flags;
#define MATCH_REGEX                1
#define MATCH_INVERT               2
    union {
        char *string;
        regex_t re;
    } match;
};

int cli_match_filter_init(struct cli_client *cc, int argc, char **argv, struct cli_filter *filt)
{
    struct cli_match_filter_state *state;
    int rflags;
    int i;
    char *p;

    if (argc < 2)
    {
        if (cc->client)
            fprintf(cc->client, "Match filter requires an argument\r\n");

        return CLI_ERROR;
    }

    filt->filter = cli_match_filter;
    filt->data = state = zcalloc(sizeof(struct cli_match_filter_state), 1);

    if (argv[0][0] == 'i' || // include/exclude
        (argv[0][0] == 'e' && argv[0][1] == 'x'))
    {
        if (argv[0][0] == 'e')
            state->flags = MATCH_INVERT;

        state->match.string = join_words(argc-1, argv+1);
        return CLI_OK;
    }

#ifdef WIN32
    /*
     * No regex functions in windows, so return an error
     */
    return CLI_ERROR;
#endif

    state->flags = MATCH_REGEX;

    // grep/egrep
    rflags = REG_NOSUB;
    if (argv[0][0] == 'e') // egrep
        rflags |= REG_EXTENDED;

    i = 1;
    while (i < argc - 1 && argv[i][0] == '-' && argv[i][1])
    {
        int last = 0;
        p = &argv[i][1];

        if (strspn(p, "vie") != strlen(p))
            break;

        while (*p)
        {
            switch (*p++)
            {
                case 'v':
                    state->flags |= MATCH_INVERT;
                    break;

                case 'i':
                    rflags |= REG_ICASE;
                    break;

                case 'e':
                    last++;
                    break;
            }
        }

        i++;
        if (last)
            break;
    }

    p = join_words(argc-i, argv+i);
    if ((i = regcomp(&state->match.re, p, rflags)))
    {
        if (cc->client)
            fprintf(cc->client, "Invalid pattern \"%s\"\r\n", p);

        free_z(p);
        return CLI_ERROR;
    }

    free_z(p);
    return CLI_OK;
}

int cli_match_filter(UNUSED(struct cli_client *cc), char *string, void *data)
{
    struct cli_match_filter_state *state = data;
    int r = CLI_ERROR;

    if (!string) // clean up
    {
        if (state->flags & MATCH_REGEX)
            regfree(&state->match.re);
        else
            zfree(state->match.string);

        zfree(state);
        return CLI_OK;
    }

    if (state->flags & MATCH_REGEX)
    {
        if (!regexec(&state->match.re, string, 0, NULL, 0))
            r = CLI_OK;
    }
    else
    {
        if (strstr(string, state->match.string))
            r = CLI_OK;
    }

    if (state->flags & MATCH_INVERT)
    {
        if (r == CLI_OK)
            r = CLI_ERROR;
        else
            r = CLI_OK;
    }

    return r;
}

struct cli_range_filter_state {
    int matched;
    char *from;
    char *to;
};

int cli_range_filter_init(struct cli_client *cc, int argc, char **argv, struct cli_filter *filt)
{
    struct cli_range_filter_state *state;
    char *from = 0;
    char *to = 0;

    if (!strncmp(argv[0], "bet", 3)) // between
    {
        if (argc < 3)
        {
            if (cc->client)
                fprintf(cc->client, "Between filter requires 2 arguments\r\n");

            return CLI_ERROR;
        }

        if (!(from = strdup(argv[1])))
            return CLI_ERROR;
        to = join_words(argc-2, argv+2);
    }
    else // begin
    {
        if (argc < 2)
        {
            if (cc->client)
                fprintf(cc->client, "Begin filter requires an argument\r\n");

            return CLI_ERROR;
        }

        from = join_words(argc-1, argv+1);
    }

    filt->filter = cli_range_filter;
    filt->data = state = zcalloc(sizeof(struct cli_range_filter_state), 1);

    state->from = from;
    state->to = to;

    return CLI_OK;
}

int cli_range_filter(UNUSED(struct cli_client *cc), char *string, void *data)
{
    struct cli_range_filter_state *state = data;
    int r = CLI_ERROR;

    if (!string) // clean up
    {
        free_z(state->from);
        free_z(state->to);
        free_z(state);
        return CLI_OK;
    }

    if (!state->matched)
    state->matched = !!strstr(string, state->from);

    if (state->matched)
    {
        r = CLI_OK;
        if (state->to && strstr(string, state->to))
            state->matched = 0;
    }

    return r;
}

int cli_count_filter_init(struct cli_client *cc, int argc, UNUSED(char **argv), struct cli_filter *filt)
{
    if (argc > 1)
    {
        if (cc->client)
            fprintf(cc->client, "Count filter does not take arguments\r\n");

        return CLI_ERROR;
    }

    filt->filter = cli_count_filter;
    if (!(filt->data = zcalloc(sizeof(int), 1)))
        return CLI_ERROR;

    return CLI_OK;
}

int cli_count_filter(struct cli_client *cc, char *string, void *data)
{
    int *count = data;

    if (!string) // clean up
    {
        // print count
        if (cc->client)
            fprintf(cc->client, "%d\r\n", *count);

        zfree(count);
        return CLI_OK;
    }

    while (isspace(*string))
        string++;

    if (*string)
        (*count)++;  // only count non-blank lines

    return CLI_ERROR; // no output
}

void cli_print_callback(struct cli_def *cli, void (*callback)(struct cli_client *, char *))
{
    cli->print_callback = callback;
}

void cli_set_idle_timeout(struct cli_client *cc, unsigned int seconds)
{
    struct cli_def* cli=cc->common;
    if (seconds < 1) seconds = 0;
    cli->idle_timeout = seconds;
    time(&cc->last_action);
}

void cli_set_idle_timeout_callback(struct cli_client *cc, unsigned int seconds, int (*callback)(struct cli_client *))
{
    struct cli_def *cli=cc->common;
    cli_set_idle_timeout(cc, seconds);
    cli->idle_timeout_callback = callback;
}

void cli_set_negotiate(struct cli_def *cli, int should_negotiate)
{
    cli->negotiate = should_negotiate;
}