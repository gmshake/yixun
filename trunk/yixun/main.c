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

#define LOCKFILE "/var/tmp/yixun.pid"        /* 锁文件 */
static int lockfd; // lockfile file description
static int daemon_flag = 0;
static int tun_gre_flag = 1;
static int verbose_flag = 0;
static int quit_flag = 0;
static char *progname;

static int log_opened = 0;
static int connected = 0;
static int tun_gre_running = 0;

//static char * interface;
static char * username;
static char * password;
static char * sip;
static char * cip;
static char * mac;
static char * conf_file;

void usage();
void parse_args(int argc, char * const argv[]);
void parse_conf_file(const char *conf);
void process_signals(int sig);
int quit_daemon();
int start_tun_gre();
int stop_tun_gre();
int lock_file(const char *lockfile); // On error, return -1;
void clean_up();

int main (int argc, char * const argv[])
{
    parse_args(argc, argv); //process args
    atexit(clean_up);
    
    if (daemon_flag && !verbose_flag)
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
    
    if (quit_flag)
        return quit_daemon();

    if (conf_file != NULL)
        parse_conf_file(conf_file);
        
    if (set_config(username, password, sip, cip, mac) < 0)
    {
        log_err("[main] setting config\n");
        return -1;
    }
    
    int retry_count = 2;
    do
    {
        int rval = log_in();

        if (rval == 0)
            break;
        else if (rval > 0) // Username or password error, do not retry
            return -2;

        sleep(1);
    }while(--retry_count >= 0);
    
    if (retry_count < 0)
    {
        log_err("[main] when log in\n");
        return -3;
    }
    
    connected = 1;
    
    if (tun_gre_flag)
    {
        if (start_tun_gre() < 0)
        {
            log_perror("[main] start tun-gre");
            return -4;
        }
        tun_gre_running = 1;
    }
    
    if (daemon_flag)
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
            return -6;
        }
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
    while ((ch = getopt(argc, argv, "u:p:i:m:f:DTvqh")) != -1)
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
                            
            case 'D':
            daemon_flag = 1;
            break;
            
            case 'T':
            tun_gre_flag = 0;
            break;
            
            case 'v':
            verbose_flag = 1;
            break;
            
            case 'q':
            quit_flag = 1;
            break;
            case 'h':
            case '?':
            default:
            usage();
        }
    }
    argc -= optind;
    argv += optind;
    
    if (!quit_flag)
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

int start_tun_gre()
{
    char cmd[256];
    char ssource[16], sdest[16], sremote[16], snetmask[16];
    snprintf(ssource, 16, inet_itoa(clientip));
    snprintf(sdest, 16, inet_itoa(gre));
    snprintf(sremote, 16, inet_itoa(gre_client_ip));
    snprintf(snetmask, 16, inet_itoa(net_mask));
    
    snprintf(cmd, sizeof(cmd), "/usr/local/bin/tun-gre -D -s%s -d%s -l%s -r%s -n%s", ssource, sdest, ssource, sremote, snetmask);

    return system(cmd);
}

int stop_tun_gre()
{
    return system("/usr/local/bin/tun-gre -q");
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
    fputs("\t-D\t\tRun as daemon\n", stderr);
    fputs("\t-T\t\tDo NOT start tun-gre after connected to auth server\n", stderr);
    fputs("\t-v\t\tVerbose mode\n", stderr);
    fputs("\t-q\t\tQuit all daemon\n",stderr);
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
                    goto end;
                }
            }
            alarm(timeout);
            break;
        case SIGHUP:
        case SIGINT:
            log_notice("[process_signals]: user interupted\n");
        case SIGTERM:
        case SIGQUIT:
            log_out();
            goto end;
            break;
        default:
            log_warning("[process_signals] Unkown signal %d", sig);
        break;
    }      
    signal(sig, process_signals); // let signal be caught again
    return;
    
end:
    if (daemon_flag)
    {
        lockf(lockfd, F_ULOCK, 0);
        close(lockfd);
        log_notice("Daemon ended.");
    }
    exit(0);
}

void clean_up()
{
    if (tun_gre_running) stop_tun_gre();
    if (connected) log_out();
    if (log_opened) closelog();
}
