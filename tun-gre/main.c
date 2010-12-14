#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h> //signal
#include <string.h> //bzero

#include <arpa/inet.h> // inet_aton()
#include <net/if.h> //struct ifreq
#include <netinet/in.h> //IPPROTO_GRE sturct sockaddr_in INADDR_ANY
#include <netinet/ip.h> // struct ip
#include <sys/file.h> //flock()

#include <pthread.h>
#include <syslog.h>

#include <errno.h>

#include "tun-dev.h"
#include "process_packet.h"
#include "common_macro.h"
#include "common_logs.h"
#include "print_hex.h"
#include "change_routes.h"

#define LOCKFILE "/var/run/tun-gre.pid"        /* 锁文件 */
static int lockfd; // lockfile

static char *tun_name = NULL;
static int chksum_flag = 0;
static int daemon_flag = 0;
static int verbose_flag = 0;
static int quit_flag = 0;
static int changeroute_flag = 1;
static char *progname;

static in_addr_t local, remote, source, dest, net_mask;
static in_addr_t ori_gateway;

static struct sockaddr_in sa_source;
static struct sockaddr_in sa_dest;

static int nfd, tfd;

static pthread_t tid;

static int log_opened = 0;

void * process_incoming_packets(void *p);
void process_outgoing_packets();

int quit_daemon();
int lock_file(const char *lockfile);
void usage();
void parse_args(int argc, char * const argv[]);
void process_signals(int sig);
void clean_up();

int main (int argc, char * const argv[])
{
    parse_args(argc, argv); //处理参数
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

    if (changeroute_flag && (ori_gateway = route_get(INADDR_ANY, 0)) == INADDR_ANY)
    {
        if ((ori_gateway = route_get(dest, 28)) == INADDR_ANY)
        {
            log_critical("[main] No default gateway, are you kidding me???\n");
            return -1;
        }
    }

    if ((tfd = open_tunnel(tun_name)) < 0)
        return -3;
        
    if (set_tunnel_addr(local, remote, net_mask) < 0)
        return -4;
  
    if (remote == dest && route_delete(dest, 0) < 0) // prevent possible packet loops in tunnel, may fail here
        log_warning("[main] Packets may loops in tunnel\n");

    if (changeroute_flag)
    {
        in_addr_t rt = route_get(dest, 28);
        if (rt != ori_gateway)
        {
            if (rt != 0)
                route_delete(dest, 28);
            if (route_add(dest, 28, ori_gateway, NULL, "-nostatic") < 0)
                return -5;
        }
    }
    
    if ((nfd = socket(AF_INET, SOCK_RAW, IPPROTO_GRE)) < 0)
    {
        log_perror("[main] socket");
        return -6;
    }
        
    if (connect(nfd, (struct sockaddr *)&sa_dest, sizeof(struct sockaddr_in)) < 0)
    {
        log_perror("[main] connect");
        return -7;
    }
    
    if (daemon_flag)
    {
        if (daemon(0, 0) < 0)
        {
            log_perror("[main] daemon");
            return -8;
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
            return -9;
        }
    }
    
    signal(SIGINT,  process_signals);
    signal(SIGTERM, process_signals);
    signal(SIGHUP,  process_signals);
    signal(SIGQUIT, process_signals);
    
    if (pthread_create(&tid, NULL, process_incoming_packets, NULL) < 0)
    {
        log_perror("[main] pthread_create");
        return -10;
    }
    
    if (changeroute_flag && route_delete(INADDR_ANY, 0) < 0) // Delete original default gateway
        return -11;

    if (changeroute_flag && route_add(INADDR_ANY, 0, 0, tun_if_name, "-nostatic") < 0) // Add default gateway, maybe tun[x]
    {
        route_add(INADDR_ANY, 0, ori_gateway, NULL, "-nostatic"); // restore original gateway if faild add route to tunnel
        return -12;
    }

    process_outgoing_packets(); // infinit loops here, will never break except for sys signals
    
    return 0;
}

void process_outgoing_packets()
{
    u_char buff[PACKET_BUFF_LEN + sizeof(struct gre_h)];
    void * tbuff = add_gre_header(buff, chksum_flag);
    
    while (1) // infinite loops 
    {
		size_t len = read(tfd, tbuff, PACKET_BUFF_LEN);
		if ((ssize_t)len <= 0)
        {
            if ((ssize_t)len < 0)
                log_perror("[process_outgoing_packets] read");
            else
                log_notice("[process_outgoing_packets] Get ZERO len");
            continue;
        }
                    
		//struct ip *p = (struct ip *)tbuff;
        if (((struct ip *)tbuff)->ip_dst.s_addr == dest) // prevent infinint packet loops in tunnel, it happens when the route entry to dest is not removed
        {
            log_warning("[process_outgoing_packets] packet loops in tunnel, please check route entries\n");
            continue; // If it happens, just drop the packet
        }
    
		//struct gre_h *hp = (struct gre_h *)buff;
		if (htons(((struct gre_h *)buff)->flags) & GRE_CP) // Checksum present
		{
            len += sizeof(struct gre_h);
            ((struct gre_h *)buff)->sum = 0xffff; // Filled with one's
            //hp->sum = chksum((uint16_t *)hp, len);
            ((struct gre_h *)buff)->sum = chksum((uint16_t *)buff, len);
		}
		else
            len += 4;
        
        if (write(nfd, buff, len) <= 0) // Write encapsulated packet to tunnel nfd, ie: send it from proper NIC
            log_perror("[process_outgoing_packets] write packet");
        /*      
			if (send(nfd, buff, len, 0) <= 0)
                perror("Error send");
              
            if (sendto(sfd, buff, len, 0, (struct sockaddr *)&sa_remote, sizeof(struct sockaddr_in)) <= 0)
                   perror("Error send packet");
        */
    }
}

void * process_incoming_packets(void *p)
{
    u_char in_buff[PACKET_BUFF_LEN];

    struct timeval tv;
    /*
    tv.tv_sec = 0;
    tv.tv_usec = 500000; //0.5 second
    */
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    if (setsockopt(nfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
        log_perror("[process_incoming_packets] setsockopt");

    while (1) // infinite loops 
    {
        size_t len = read(nfd, in_buff, PACKET_BUFF_LEN);
        
        if ((ssize_t)len <= 0)
        {
            pthread_testcancel();
            if ((ssize_t)len < 0)
            {
                if (errno != EAGAIN) // not timeout
                    log_perror("[process_incoming_packets] read");
            }                
            else
                log_notice("[process_incoming_packets] Get ZERO len\n");
            continue;
        }
        
        //struct ip *p = (struct ip *)in_buff; // ip packet
        if (((struct ip *)in_buff)->ip_src.s_addr == dest) // Packet is from tunnel end
		{
#ifdef DEBUG
            log_debug("[process_incoming_packets] got gre packet\n");
#endif
            char *p = process_gre_packet(in_buff, &len);
			if (p != NULL)
            {
    			if (write(tfd, p, len) <= 0)
                    log_perror("[process_incoming_packets] write packet");
			}
			else
                log_warning("[process_incoming_packets] drops packets:chksum ERROR\n");
		}
		else // Just drop it
    	    log_notice("[process_incoming_packets] Received packet from '%s'\n",inet_ntoa(((struct ip *)in_buff)->ip_src));

    }
    return NULL;
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
    snprintf(fbuff, sizeof(fbuff) , "%ld", (long)getpid());

    if (write(fd, fbuff, strlen(fbuff)) < 0)
    {
        log_perror("[lock_file] write");
        close(fd);
        return -1;
    }
    return fd;
}

int quit_daemon()
{
    int fd = open(LOCKFILE, O_RDONLY);
    if (fd < 0)
    {
        log_perror("[quit_daemon] open");
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
    return 0;
}

void usage()
{
    fprintf(stderr,"Usage: %s {options}\n",progname);
	fputs("  options:\n",stderr);
	fputs("\t-l <local address>\tset address of local tunnel host\n", stderr);
	fputs("\t-r <target address>\tset address of remote tunnel host\n", stderr);
	fputs("\t-s <source address>\tset address of source tunnel host\n", stderr);
	fputs("\t-d <dest address>\tset address of destination tunnel host\n", stderr);
	fputs("\t-t <tunnel device>\tset tunnel device name\n",stderr);
	fputs("\t-n <netmask>\t\tset tunnel network mask\n",stderr);
	fputs("\t-D\t\t\trun as daemon\n",stderr);
	fputs("\t-C\t\t\tdo NOT change route table\n",stderr);
	fputs("\t-c\t\t\ttun on checksum\n",stderr);
	fputs("\t-v\t\t\tverbose mode\n",stderr);
	fputs("\t-q\t\t\tquit all daemon\n",stderr);
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
    
    while ((ch = getopt(argc, argv, "l:r:s:d:t:n:DCcqvh")) != -1)
    {
        switch (ch)
        {
            case 'l':
            local = inet_addr(optarg);
            break;
                
            case 'r':
            remote = inet_addr(optarg);
            break;
            
            case 's':
            source = inet_addr(optarg);
            break;
                
            case 'd':
            dest = inet_addr(optarg);
            break;
            
            case 't':
            tun_name = optarg;
            break;
            
            case 'n':
            net_mask = inet_addr(optarg);
            break;
            
            case 'D':
            daemon_flag = 1;
            break;
            
            case 'C':
            changeroute_flag = 0;
            break;
            
            case 'c':
            chksum_flag = 1;
            break;
            
            case 'q':
            quit_flag = 1;
            break;
            
            case 'v':
            verbose_flag = 1;
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
        if (source == INADDR_ANY || source == INADDR_BROADCAST)
        {
            fprintf(stderr, "Error: Invalid source address:%s\n", inet_itoa(source));
            exit(-1);
        }
        bzero(&sa_source, sizeof(struct sockaddr_in));
        sa_source.sin_family = AF_INET;
        sa_source.sin_addr.s_addr = source;
        
        if (dest == INADDR_ANY || dest == INADDR_BROADCAST)
        {
            fprintf(stderr, "Error: Invalid destination address:%s\n", inet_itoa(dest));
            exit(-2);
        }
        bzero(&sa_dest, sizeof(struct sockaddr_in));
        sa_dest.sin_family = AF_INET;
        sa_dest.sin_addr.s_addr = dest;
        
        if (local == INADDR_ANY || local == INADDR_BROADCAST)
        {
            fprintf(stderr, "Caution: Invalid local address:%s\t", inet_itoa(local));
            local = source;
            fprintf(stderr, " Using:%s instead\n", inet_itoa(local));
        }
        if (remote == INADDR_ANY || remote == INADDR_BROADCAST)
        {
            fprintf(stderr, "Caution: Invalid remote address:%s\t", inet_itoa(remote));
            remote = dest;
            fprintf(stderr, " Using:%s instead\n", inet_itoa(remote));
        }
        if (net_mask == 0x0)
        {
            net_mask = htonl(0xfffffffc);
            fprintf(stderr, "Using default netmask:%s\n", inet_itoa(net_mask));
        }
    }
}


void process_signals(int sig)
{
    switch (sig)
    {
        case SIGINT:
            log_notice("[process_signals]: user interupted\n");
        case SIGHUP:
        case SIGTERM:
        case SIGQUIT:
            if (changeroute_flag)
            {
                route_delete(INADDR_ANY, 0);
                route_add(INADDR_ANY, 0, ori_gateway, NULL, "-nostatic");
            }

            pthread_cancel(tid);
            pthread_join(tid, NULL); // wait thread to end
              
            if (daemon_flag)
            {
                lockf(lockfd, F_ULOCK, 0);
                close(lockfd);
                log_notice("Daemon ended.");
            }
            
            exit(0);
            break;
        default:
            log_warning("[process_signals] Unkown signal %d\n", sig);
            break;
    }
    signal(sig, process_signals); // let signal be caught again
}


void clean_up()
{
    if (nfd > 0) close(nfd);
    if (tfd > 0) close_tunnel(tfd);
    if (log_opened) closelog();
}