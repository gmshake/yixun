#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>

#include <arpa/inet.h> // inet_aton()
#include <sys/ioctl.h> // ioctl()
#include <sys/socket.h> // place it before <net/if.h> struct sockaddr
#include <net/if.h> //struct ifreq
#include <netinet/in.h> //IPPROTO_GRE sturct sockaddr_in INADDR_ANY
#include <netinet/ip.h> // struct ip
#include <arpa/inet.h> // inet_addr()

#include <errno.h>

#ifndef inet_itoa(x)
#define inet_itoa(x) inet_ntoa(*(struct in_addr*)&(x))
#endif

static char *progname = NULL;
static int flag_chksum = 0;
static int flag_revert = 0;
static int flag_changeroute = 0;

static in_addr_t local, remote, src, dst, netmask, gateway;

void parse_args(int argc, char * const argv[]);
void usage();

int find_unused_if(char ifname[]);
int find_if_with_addr(char ifname[], in_addr_t local, in_addr_t remote, in_addr_t src, in_addr_t dst);

int set_if_addr_tunnel(char ifname[], in_addr_t local, in_addr_t remote, in_addr_t mask, in_addr_t src, in_addr_t dst);

int delete_if_addr_tunnel(char ifname[]);

int set_if_flag(char ifname[], int flag);

int route_delete(in_addr_t rt);
int route_add(in_addr_t dst, int maskbit, in_addr_t gateway, const char *iface);

int main (int argc, char * const argv[])
{
    char gre_if_name[IFNAMSIZ];
    
    parse_args(argc, argv); //处理参数
    
    if (!flag_revert) {
        if (find_unused_if(gre_if_name) < 0)
            return -1;
        if (set_if_addr_tunnel(gre_if_name, local, remote, netmask, src, dst) < 0)
            return -2;
        
        if (remote == dst)
            route_delete(remote);
        
        if (flag_changeroute) {
            route_add(dst, 28, gateway, NULL);
            route_delete(0);
            route_add(0, 0, 0, gre_if_name);
        }
    } else {
        if (find_if_with_addr(gre_if_name, local, remote, src, dst) < 0)
            return -1;
        if (delete_if_addr_tunnel(gre_if_name) < 0)
            return -2;

        if (flag_changeroute) {
            route_add(0, 0, gateway, NULL);
            route_delete(dst);
        }
    }
   
    return 0;
}

void parse_args(int argc, char * const argv[])
{
    progname = argv[0];
    int ch;
    
    if (argc == 1) {
        usage();
        exit(-1);
    }
    
    while ((ch = getopt(argc, argv, "l:r:s:d:n:C:cuh")) != -1) {
        switch (ch) {
            case 'l':
                local = inet_addr(optarg);
                break;
                
            case 'r':
                remote = inet_addr(optarg);
                break;
                
            case 's':
                src = inet_addr(optarg);
                break;
                
            case 'd':
                dst = inet_addr(optarg);
                break;
                
            case 'n':
                netmask = inet_addr(optarg);
                break;
            
            case 'C':
                gateway = inet_addr(optarg);
                flag_changeroute = 1;
                break;
                
            case 'c':
                flag_chksum = 1;
                break;

            case 'u':
                flag_revert = 1;
                break;
                
            case 'h':
            case '?':
            default:
                usage();
        }
    }
    argc -= optind;
    argv += optind;
    

    if (src == INADDR_BROADCAST) {
        fprintf(stderr, "Error: Invalid src address:%s\n", inet_itoa(src));
        exit(-1);
    }
    
    if (dst == INADDR_BROADCAST) {
        fprintf(stderr, "Error: Invalid dstination address:%s\n", inet_itoa(dst));
        exit(-2);
    }
    
    if (local == INADDR_BROADCAST) {
        fprintf(stderr, "Caution: Invalid local address:%s\t", inet_itoa(local));
        exit(-3);
    }
    if (remote == INADDR_BROADCAST) {
        fprintf(stderr, "Caution: Invalid remote address:%s\t", inet_itoa(remote));
        exit(-4);
    }
}


void usage()
{
    fprintf(stderr,"Usage: %s {options}\n",progname);
	fputs("  options:\n",stderr);
	fputs("\t-l <local address>\tset address of local host\n", stderr);
	fputs("\t-r <remote address>\tset address of remote host(p-p)\n", stderr);
	fputs("\t-s <src address>\tset address of tunnel src\n", stderr);
	fputs("\t-d <dst address>\tset address of tunnel dstination\n", stderr);
	fputs("\t-n <netmask>\t\tset interface netmask\n",stderr);
	fputs("\t-C <route>\t\tchange default route\n",stderr);
	fputs("\t-c\t\t\ttun on tunnel checksum\n",stderr);
	fputs("\t-v\t\t\trevert \n",stderr);
}


#define MAX_GREIF_CNT 16
int find_unused_if(char ifname[])
{
    int i;
    int sock;
    struct ifreq ifrq;
    
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("find_unused_if: socket");
        return -1;
    }
    
    for (i = 0; i < MAX_GREIF_CNT; i++) {
        bzero(&ifrq,sizeof(ifrq));
        sprintf(ifrq.ifr_name, "gre%d", i);
        if (ioctl(sock,SIOCGIFFLAGS, &ifrq) < 0)
            continue;
        if ((ifrq.ifr_flags & IFF_RUNNING) == 0) {
            strcpy(ifname, ifrq.ifr_name);
            break;
        }
    }
    
    close(sock);
    return i < MAX_GREIF_CNT ? 0 : -1;
}

int find_if_with_addr(char ifname[], in_addr_t local, in_addr_t remote, in_addr_t src, in_addr_t dst)
{
    fputs("find_if_with_addr: todo....\n", stderr);
    return -1;
}

int set_if_addr_tunnel(char ifname[], in_addr_t local, in_addr_t remote, in_addr_t mask, in_addr_t src, in_addr_t dst)
{
    int sock;
    
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("set_if_addr_tunnel: socket");
        return -1;
    }
    
    struct ifreq ifrq;
    bzero(&ifrq, sizeof(ifrq));
	strncpy(ifrq.ifr_name, ifname, IFNAMSIZ);
    
    if (ioctl(sock, SIOCDIFPHYADDR, &ifrq) < 0) {
        if (errno != EADDRNOTAVAIL) {
            perror("set_if_addr_tunnel: delete tunnel addr");
            goto ERROR;
        }
    }
    
    if (ioctl(sock, SIOCDIFADDR, &ifrq) < 0) {
        if (errno != EADDRNOTAVAIL) {
            perror("set_if_addr_tunnel: delete if addr");
            goto ERROR;
        }
    }
    
    struct sockaddr_in sa;
    bzero(&sa, sizeof(struct sockaddr_in));
    sa.sin_family = AF_INET;
    
    sa.sin_addr.s_addr = local;
    bcopy(&sa, &ifrq.ifr_addr, sizeof(sa));
    ((struct sockaddr_in *)&ifrq.ifr_addr)->sin_len = sizeof(struct sockaddr_in);
    if (ioctl(sock, SIOCSIFADDR, &ifrq) < 0)
    {
        fprintf(stderr, "set_if_addr_tunnel: set if address %s :%s", inet_ntoa(((struct sockaddr_in *)(&ifrq.ifr_addr))->sin_addr), strerror(errno));
        goto ERROR;
    }
    
    sa.sin_addr.s_addr = remote;
    bcopy(&sa, &ifrq.ifr_addr,sizeof(sa));
    ((struct sockaddr_in *)&ifrq.ifr_addr)->sin_len = sizeof(struct sockaddr_in);
    if (ioctl(sock, SIOCSIFDSTADDR, &ifrq) < 0)
    {
        perror("set_if_addr_tunnel: set remote ip address");
        goto ERROR;
    }
    
    ifrq.ifr_addr.sa_family = AF_INET;
    bcopy(&netmask, &((struct sockaddr_in *)&ifrq.ifr_addr)->sin_addr, sizeof(netmask));
    ((struct sockaddr_in *)&ifrq.ifr_addr)->sin_len = sizeof(netmask);
    if (ioctl(sock, SIOCSIFNETMASK, &ifrq) < 0)
    {
        perror("[set_tunnel_addr] set netmask");
        goto ERROR;
    }
    
    if (ioctl(sock, SIOCGIFFLAGS, &ifrq) < 0)
    {
        perror("[set_tunnel_addr] get if flag");
        goto ERROR;
    }
    ifrq.ifr_flags |= IFF_UP;
    if (ioctl(sock, SIOCSIFFLAGS, &ifrq) < 0)
    {
        perror("[set_tunnel_addr] set if flags");
        goto ERROR;
    }
    
    close(sock);
    return 0;
ERROR:
    close(sock);
    return -1;
}

int set_if_tunnel(char ifname[], in_addr_t src, in_addr_t dst)
{
    int sock;    
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("set_if_tunnel: socket");
        return -1;
    }
    
    struct ifreq ifrq;
    bzero(&ifrq, sizeof(ifrq));
	strncpy(ifrq.ifr_name, ifname, IFNAMSIZ);
    ifrq.ifr_addr.sa_family = AF_INET;
    
    if (ioctl(sock, SIOCDIFPHYADDR, &ifrq) < 0) {
        if (errno != EADDRNOTAVAIL) {
            perror("set_if_addr_tunnel: delete if addr");
            goto ERROR;
        }
    }
    
    close(sock);
    return 0;
ERROR:
    close(sock);
    return -1;
}

int delete_if_addr_tunnel(char ifname[])
{
    int sock;    
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("delete_if_addr_tunnel: socket");
        return -1;
    }
    
    struct ifreq ifrq;
    bzero(&ifrq, sizeof(ifrq));
	strncpy(ifrq.ifr_name, ifname, IFNAMSIZ);
    ifrq.ifr_addr.sa_family = AF_INET;
    
    if (ioctl(sock,SIOCGIFFLAGS, &ifrq) < 0) {
        perror("delete_if_addr_tunnel: get if flags");
        goto ERROR;
    }

    ifrq.ifr_flags &= ~(IFF_UP | IFF_RUNNING);
    if (ioctl(sock, SIOCSIFFLAGS, &ifrq) < 0) {
        perror("delete_if_addr_tunnel: set if flags");
        goto ERROR;
    }

    bzero(&ifrq.ifr_addr,sizeof(struct sockaddr));
    
    if (ioctl(sock, SIOCDIFPHYADDR, &ifrq) < 0) {
        if (errno != EADDRNOTAVAIL) {
            perror("delete_if_addr_tunnel: delete tunnel addr");
            goto ERROR;
        }
    }
        
    if (ioctl(sock,SIOCSIFDSTADDR,&ifrq) < 0)
    {
        perror("delete_if_addr_tunnel: delete remote address");
        goto ERROR;
    }
    
    if (ioctl(sock,SIOCDIFADDR,&ifrq) < 0)
    {
        if (errno != EADDRNOTAVAIL)
        {
            perror("delete_if_addr_tunnel: delete local address");
            goto ERROR;
        }
    }
        
    
    close(sock);
    return 0;
ERROR:
    close(sock);
    return -1;
}


int route_delete(in_addr_t rt)
{
    puts("route_delete: todo....\n");
    return 0;
}

int route_add(in_addr_t dst, int maskbit, in_addr_t gateway, const char *iface)
{
    puts("route_add: todo....\n");
    return 0;
}


