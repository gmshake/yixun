#include <unistd.h> // ftruncate()
#include <stdlib.h> // for daemon()
#include <string.h> // bzero() strlen() ...
#include <stdio.h>

#include <fcntl.h>
#include <signal.h> // for signals
#include <syslog.h> // openlog()

#include <arpa/inet.h> // inet_addr() inet_ntoa

#include "radius.h"
#include "common_macro.h"
#include "common_logs.h"
#include "../route/route_op.h"

#define LOCKFILE "/var/tmp/yixun.pid"        /* 锁文件 */
static int lockfd; // lockfile file description
static int flag_changeroute = 0;
static int flag_daemon      = 0;
static int flag_test        = 0;
static int flag_verbose     = 0;
static int flag_quit        = 0;
static char *progname;

static int log_opened = 0;
static int connected = 0;
static int flag_gre_if_isset = 0;

static in_addr_t default_route = 0;

//static char * interface;
static char * username;
static char * password;
static char * sip;
static char * cip;
static char * mac;
static char * conf_file;

static int extr_argc;
static char * const *extr_argv;

void usage();
void parse_args(int argc, char * const argv[]);
void parse_conf_file(const char *conf);
void process_signals(int sig);
int quit_daemon();
int set_gre_if_tunnel();
int remove_gre_if_tunnel();
int lock_file(const char *lockfile); // On error, return -1;
void cleanup();
void cleanup_exit(int i);

int main (int argc, char * const argv[])
{
    parse_args(argc, argv); //process args
    //atexit(clean_up);
    
    if (flag_daemon && !flag_verbose)
    {
        openlog(progname, LOG_PID | LOG_CONS, LOG_USER);
        log_opened = 1;
        setlogmask(LOG_UPTO(LOG_INFO));
#ifdef DEBUG
        setlogmask(LOG_UPTO(LOG_DEBUG));
#endif
        set_log_type(LDAEMON);
    }
    else
        set_log_type(LCONSOLE);
    
    if (flag_quit)
        return quit_daemon();

    if (conf_file != NULL)
        parse_conf_file(conf_file);
        
    if (set_config(username, password, sip, cip, mac) < 0)
    {
        log_err("[main] setting config\n");
        return -1;
    }
    
    if (flag_daemon)
    {
        if (daemon(0, 0) < 0)
        {
            log_perror("[main] daemon");
            return -5;
        }
        
        if (!log_opened)
        {
            openlog(progname, LOG_PID | LOG_CONS, LOG_USER);
            log_opened = 1;
            setlogmask(LOG_UPTO(LOG_INFO));
#ifdef DEBUG
            setlogmask(LOG_UPTO(LOG_DEBUG));
#endif
        }
        set_log_type(LDAEMON);
        
        if ((lockfd = lock_file(LOCKFILE)) < 0) // unable to lock
        {
            log_err("[main] unable to lock file:%s\n", LOCKFILE);
            goto ERROR;
        }
    }
    
    int retry_count = 2;
    do
    {
        int rval = log_in();
        if (rval == 0)
            break;
        else if (rval > 0) // Username or password error, do not retry
            goto ERROR;
        sleep(1);
    }while(--retry_count > 0);
    
    if (retry_count <= 0)
    {
        log_err("[main] when log in\n");
        goto ERROR;
    }
    
    connected = 1;
    
    if (!flag_test)
    {
        if (set_gre_if_tunnel() < 0)
        {
            log_perror("[main] set gre interface");
            goto ERROR;
        }
        flag_gre_if_isset = 1;
    }

    signal(SIGINT,  process_signals);
    signal(SIGTERM, process_signals);
    signal(SIGHUP,  process_signals); // If the terminal closes, we might get this
    signal(SIGQUIT, process_signals);
    signal(SIGALRM, process_signals);
    
    alarm(timeout);
    while(1)
    {
        accept_client();
    }
    
    return 0;
    
ERROR:
    cleanup();
    return -1;
}

void parse_args(int argc, char * const argv[])
{
    progname = argv[0];
    int ch;
    
    if (argc == 1)
    {
        usage();
        exit(-1);
    }
    
    //while ((ch = getopt(argc, argv, "i:u:p:f:Dqh")) != -1)
    while ((ch = getopt(argc, argv, "u:p:i:m:f:ADTvqh")) != -1)
    {
        switch (ch)
        {
            case 'u':
            username = optarg;
            break;
            
            case 'p':
            password = optarg;
            break;
            
            case 's':
            sip = optarg;
            break;
            
            case 'i':
            cip = optarg;
            break;
            
            case 'm':
            mac = optarg;
            break;
            
            case 'f':
            conf_file = optarg;
            break;
            
            case 'A':
            flag_changeroute = 1;
            break;
            
            case 'D':
            flag_daemon = 1;
            break;
            
            case 'T':
            flag_test = 1;
            break;
            
            case 'v':
            flag_verbose = 1;
            break;
            
            case 'q':
            flag_quit = 1;
            break;
            
            case 'h':
            case '?':
            default:
            usage();
        }
    }
    argc -= optind;
    argv += optind;
    
    extr_argc = argc;
    extr_argv = argv;
    
    if (!flag_quit)
    {
        if (conf_file == NULL) // if do not use configure file, username and password are required
        {
            if (username == NULL)
            {
                fprintf(stderr, "Error: Require <username>:\n");
                exit(-1);
            }
            if (password == NULL)
            {
                fprintf(stderr, "Error: Require <password>:\n");
                exit(-2);
            }
        }
/*        
        if (interface == NULL)
        {
            fprintf(stderr, "Caution: use first usable interface\n");
        }
*/
    }
}

void parse_conf_file(const char *conf)
{
    fputs("*****TODO*******\n", stderr);
}

/*
 * @param op, T_SET, T_REMOVE
 * @param flag, 0 indicates not to change route
 *              1, change default gateway and routes followed
 *              2, revert the changes
 */
#define FLAG_SET 0x01
#define FLAG_CROUTE 0x02
static int gre_if_op(int flag, in_addr_t src, in_addr_t dst, in_addr_t local, in_addr_t remote, in_addr_t netmask, int argc, char *const argv[])
{
    char cmd[512];
    char tmp[128];
    char ssrc[16], sdst[16], slocal[16], sremote[16], snetmask[16];
    snprintf(ssrc, 16, inet_itoa(src));
    snprintf(sdst, 16, inet_itoa(dst));
    snprintf(slocal, 16, inet_itoa(local));
    snprintf(sremote, 16, inet_itoa(remote));
    snprintf(snetmask, 16, inet_itoa(netmask));
    
    /*
    if (flag & FLAG_SET) {
        if (flag & FLAG_CROUTE) {
            strcpy(cmd, "/usr/local/bin/mac-gre -C210.37.152.1");
        } else {
            strcpy(cmd, "/usr/local/bin/mac-gre");
        }
    } else {
        if (flag & FLAG_CROUTE) {
            strcpy(cmd, "/usr/local/bin/mac-gre -u -C210.37.152.1");
        } else {
            strcpy(cmd, "/usr/local/bin/mac-gre -u");
        }
    } */
    
    strcpy(cmd, "/usr/local/bin/gre-config");
    if ((flag & FLAG_SET) == 0)
        strcat(cmd, " -u");
    
    sprintf(tmp, " -s%s -d%s -l%s -r%s", ssrc, sdst, slocal, sremote);
    strcat(cmd, tmp);
    
    if (flag & FLAG_SET) {
        sprintf(tmp, " -n%s", inet_itoa(netmask));
        strcat(cmd, tmp);
    }

    if (flag & FLAG_CROUTE) {
        if (default_route == 0) {
            in_addr_t dst = 0, mask = 0;
            if (route_get(&dst, &mask, &default_route, NULL) < 0)
                return -1;
        }
        sprintf(tmp, " -C%s ", inet_itoa(default_route));
        strcat(cmd, tmp);
        strcat(cmd, inet_itoa(auth_server_addr));
        if (msg_server_addr != 0) {
            strcat(cmd, " ");
            strcat(cmd, inet_itoa(msg_server_addr));
        }
        
        int i;
        for (i = 0; i < argc; i++) {
            size_t remain = sizeof(cmd) - strlen(cmd);
            if (remain <= 3 || argv[i] == NULL)
                break;
            
            strncat(cmd, " ", remain);
            strncat(cmd, argv[i], remain - 1);
        }
    }
    printf("cmd:%s\n", cmd);
    return system(cmd);
}

int set_gre_if_tunnel()
{
    return gre_if_op(flag_changeroute ? FLAG_SET | FLAG_CROUTE : FLAG_SET, \
                     gre_src, gre_dst, gre_local, gre_remote, net_mask, \
                     extr_argc, extr_argv);
}

int remove_gre_if_tunnel()
{
    return gre_if_op(flag_changeroute ? FLAG_CROUTE : 0, \
                     gre_src, gre_dst, gre_local, gre_remote, 0, \
                     extr_argc, extr_argv);
}

int quit_daemon()
{
    int fd = open(LOCKFILE, O_RDONLY);
    if (fd < 0)
    {
        log_perror("[quit_daemon] open:%s", LOCKFILE);
        return -1;
    }
    
    if (lockf(fd, F_TEST, 0) == 0) // no daemons
    {
        log_info("[quit_daemon] No daemons found\n");
        return 0;
    }

    char fbuff[32];
    read(fd, fbuff, sizeof(fbuff) - 1);
    fbuff[sizeof(fbuff) - 1] = '\0';
    long pid;
    sscanf(fbuff, "%ld", &pid);
    close(fd);
    
    if (kill(pid, SIGTERM) < 0)
    {
        log_perror("[quit_daemon] kill");
        return -1;
    }
    /*
    if (execl("/usr/bin/killall", "killall", "yixun", NULL) < 0)
    {
        perror("Error execl");
        return -1;
    }
    */
    return 0;
}

int lock_file(const char *lockfile)
{
    int fd = open(lockfile, O_RDWR | O_CREAT, 0640);
    if (fd < 0)
    {
        log_perror("[lock_file] open file");
        return -1;
    }
    if (lockf(fd, F_TLOCK, 0) < 0)
    {
        log_perror("[lock_file] lockf");
        return -1;
    }
    if (ftruncate(fd, 0) < 0)
    {
        log_perror("[lock_file] ftruncate");
        return -2;
    }
    
    char fbuff[32];
    snprintf(fbuff, sizeof(fbuff), "%ld", (long)getpid());

    if (write(fd, fbuff, strlen(fbuff)) < 0)
    {
        log_perror("[lock_file] write");
        close(fd);
        return -1;
    }
    return fd;
}

void usage()
{
    fprintf(stderr,"Usage: %s {options}\n",progname);
    fputs("\t-u <username>\tUser name used to authorise\n", stderr);
    fputs("\t-p <password>\tPassword used to authorise\n", stderr);
    fputs("\t-s <Server IP>\tAuth server IP used to authorise\n", stderr);
    fputs("\t-i <Client IP>\tClient IP used to authorise\n", stderr);
    fputs("\t-m <MAC>\tMAC address used to authorise\n", stderr);
/*    fputs("\t-f <file>\tConfigure file used to authorise. \ 
        If -f and -u or -p supplied at same time, \
        use -u or -p instead of the parameters in config file\n", stderr);
*/
    fputs("\t-A\t\tPass all traffic over gre interface\n", stderr);
    fputs("\t-D\t\tRun as daemon\n", stderr);
    fputs("\t-T\t\tTest mode, do NOT set gre tunnel and address\n", stderr);
    fputs("\t-v\t\tVerbose mode\n", stderr);
    fputs("\t-q\t\tQuit daemon\n",stderr);
}

void process_signals(int sig)
{
    switch (sig)
    {
        case SIGALRM:
            if (send_keep_alive() < 0)
            {
                sleep(1);
                if (send_keep_alive() < 0) // unable to send keep alive to BRAS
                {
                    log_warning("Failed sending keep-alive packets.");
                    stop_listen();
                    connected = 0;
                    goto end;
                }
            }
            alarm(timeout);
            break;
        case SIGHUP:
        case SIGINT:
            log_notice("[process_signals]: user interupted\n");
        case SIGQUIT:
        case SIGTERM:
            goto end;
            break;
        default:
            log_warning("[process_signals]: Unkown signal %d", sig);
        break;
    }      
    signal(sig, process_signals); // let signal be caught again
    return;
    
end:
    cleanup();
    exit(0);
}

void cleanup()
{
    if (flag_daemon) {
        lockf(lockfd, F_ULOCK, 0);
        close(lockfd);
    }
    if (flag_gre_if_isset) remove_gre_if_tunnel();
    if (connected) log_out();
    if (flag_daemon) log_notice("Daemon ended.");
    if (log_opened) closelog();
}
