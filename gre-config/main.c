#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>

#include <arpa/inet.h> // inet_aton()
#include <sys/ioctl.h> // ioctl()
#include <sys/socket.h> // place it before <net/if.h> struct sockaddr
#include <net/if.h> //struct ifreq
#include <net/if_dl.h> //struct sockaddr_dl
#include <netinet/in.h> //IPPROTO_GRE sturct sockaddr_in INADDR_ANY
#include <netinet/in_var.h> //struct in_aliasreq
#include <netinet/ip.h> // struct ip
#include <arpa/inet.h> // inet_addr()

#include <net/route.h> // struct rt_msghdr

#include <ifaddrs.h> //getifaddrs() freeifaddrs()

#include <errno.h>


#ifndef inet_itoa
#define inet_itoa(x) inet_ntoa(*(struct in_addr*)&(x))
#endif

static struct rt_list {
    in_addr_t dst;
    in_addr_t mask;
    struct rt_list *next;
} *rt_list;

//static char *progname = NULL;
static int flag_chksum = 0;
static int flag_revert = 0;
static int flag_changeroute = 0;

static in_addr_t local, remote, src, dst, netmask, gateway;

//void usage();

void parse_args(int argc, char * const argv[]);

int find_unused_if(char ifname[]);
int find_if_with_addr(char ifname[], in_addr_t src, in_addr_t dst, in_addr_t local, in_addr_t remote);

int set_if_addr_tunnel(char ifname[], in_addr_t src, in_addr_t dst, in_addr_t local, in_addr_t remote, in_addr_t mask);
int delete_if_addr_tunnel(char ifname[]);

int add_gre_if(in_addr_t src, in_addr_t dst, in_addr_t local, in_addr_t remote, in_addr_t mask);
int remove_gre_if(in_addr_t src, in_addr_t dst, in_addr_t local, in_addr_t remote);

//int set_if_flag(char ifname[], int flag);

static int route_op(u_char op, in_addr_t dst, in_addr_t mask, in_addr_t *gateway, char *iface);
int route_get(in_addr_t dst, in_addr_t mask, in_addr_t *gateway, char iface[]);
int route_add(in_addr_t dst, in_addr_t mask, in_addr_t gateway, const char *iface);
int route_change(in_addr_t dst, in_addr_t mask, in_addr_t gateway, const char *iface);
int route_delete(in_addr_t dst, in_addr_t mask);

//static void free_rt_list(struct rt_list *list);

int main (int argc, char * const argv[])
{
    /*
    route_add(inet_addr("1.1.1.1"), htonl(0xffffffff), inet_addr("3.3.3.3"), "en0");
    sleep(2);
    route_add(inet_addr("2.2.2.2"), htonl(0xffffff00), inet_addr("3.3.3.3"), "gre0");
    sleep(2);
    route_change(inet_addr("1.1.1.1"), htonl(0xffffffff), 0, "gre0");
    sleep(2);
    route_delete(inet_addr("1.1.1.1"), htonl(0xffffffff));
    sleep(2);
    route_delete(inet_addr("2.2.2.2"), htonl(0xffffff00));
    
    
    return 0;
    */
    char ifp[IFNAMSIZ];
    
    parse_args(argc, argv); //处理参数
    
    if (!flag_revert) {        
        char ifname[IFNAMSIZ];
        if (find_unused_if(ifname) < 0) {
            fprintf(stderr, "add_gre_if: unable to find unused gre interface.\n");
            return -1;
        }
        
        if (set_if_addr_tunnel(ifname, src, dst, local, remote, netmask) < 0) {
            fprintf(stderr, "add_gre_if: error set address of %s\n", ifname);
            return -1;
        }
        
        if (remote == dst && route_get(remote, 0xffffffff, &gateway, ifp) == 0)
            route_delete(remote, 0xffffffff);
        
        if (flag_changeroute) {
            struct rt_list *p = rt_list;
            while (rt_list) {
                if (route_get(rt_list->dst, rt_list->mask, &gateway, ifp) == 0)
                    route_add(rt_list->dst, rt_list->mask, gateway, gateway ? NULL : ifp);
                p = rt_list->next;
                free(rt_list);
                rt_list = p;
            }
            
            if (route_get(dst, 0xffffffff, &gateway, ifp) == 0)
                route_add(dst, 0xffffffff, gateway, gateway ? NULL : ifp);
            //route_delete(0, 0);
            /*
            if (remote == dst)
                route_add(0, 0, 0, ifname);
            else
                route_add(0, 0, remote, NULL); */
            //route_add(0, 0, 0, ifname);
            route_change(0, 0, 0, ifname);
        }
    } else {
        if (remove_gre_if(src, dst, local, remote) < 0)
            return -1;

        if (flag_changeroute) {
            if (route_get(dst, 0xffffffff, &gateway, ifp) == 0) {
                route_add(0, 0, gateway, gateway ? NULL : ifp);
                route_delete(dst, 0xffffffff);
            }
            
            struct rt_list *p = rt_list;
            while (rt_list) {
                in_addr_t tg;
                char tp[IFNAMSIZ];
                if (route_get(rt_list->dst, rt_list->mask, &tg, tp) == 0) {
                    if (tg == gateway && strcmp(tp, ifp) == 0)
                        route_delete(rt_list->dst, rt_list->mask);
                }
                p = rt_list->next;
                free(rt_list);
                rt_list = p;
            }
        }
    }
   
    return 0;
}

void parse_args(int argc, char * const argv[])
{
    int ch;
    
    if (argc == 1)
        goto usage;
    
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
                goto usage;
        }
    }
    argc -= optind;
    argv += optind;

    if (!flag_changeroute)
        goto PASSROUTE;
    
    char tmp[20];
    char *instr;
    struct rt_list **p = &rt_list;
    char *par1;
    char *par2;
    int bits;
    uint32_t mask;
    
    for (ch = 0; ch < argc; ch++) {
        *p = (struct rt_list *) malloc(sizeof(struct rt_list));
        if (*p == NULL) {
            perror("malloc");
            exit(-1);
        }
        strncpy(tmp, argv[ch], sizeof(tmp));
        tmp[sizeof(tmp) - 1] = '\0';
        
        /* probable address: 1.2.3.4/24, or just 1.2.3.4 */ 
        instr = tmp;
        par1 = strsep(&instr, "/"); // first part, ip address, ie 1.2.3.4
        par2 = strsep(&instr, "/"); // second part, maskbit len, ie 24, or NULL(if not found)
                
        (*p)->dst = inet_addr(par1);
        if (par2 && strlen(par2) > 0) { // maskbit found, the addr is a net address
            sscanf(par2, "%d", &bits);
            if (bits < 0)
                bits = 0;
            else if (bits > 32)
                bits = 32;
            
            if (bits == 0)
                mask = 0x00000000;
            else {
                mask = 0xffffffff;
                mask >>= (32 - bits);
                mask <<= (32 - bits);
            }
            (*p)->mask = htonl(mask);
            (*p)->dst &= htonl(mask);
        } else // maskbit not found, set it to 0xffffffff to indicate it is a host address
            (*p)->mask = 0xffffffff;
        
        p = &(*p)->next;
    }
    *p = NULL;

PASSROUTE:
    if (src == INADDR_ANY || src == INADDR_BROADCAST) {
        fprintf(stderr, "Error: Invalid tunnel src address:%s\n", inet_itoa(src));
        exit(-1);
    }
    if (dst == INADDR_ANY || dst == INADDR_BROADCAST) {
        fprintf(stderr, "Error: Invalid tunnel dst address:%s\n", inet_itoa(dst));
        exit(-2);
    }
    
    if (local == INADDR_ANY || local == INADDR_BROADCAST) {
        fprintf(stderr, "Error: Invalid local address:%s\t", inet_itoa(local));
        exit(-3);
    }
    if (remote == INADDR_ANY || remote == INADDR_BROADCAST) {
        fprintf(stderr, "Error: Invalid remote address:%s\t", inet_itoa(remote));
        exit(-4);
    }
    
    return;
    
usage:
    fprintf(stderr,"Usage: %s {options} {routes to be changed} {...}\n",argv[0]);
	fputs("  options:\n",stderr);
	fputs("\t-l <local address>\tset address of local host\n", stderr);
	fputs("\t-r <remote address>\tset address of remote host(p-p)\n", stderr);
	fputs("\t-s <src address>\tset address of tunnel src\n", stderr);
	fputs("\t-d <dst address>\tset address of tunnel dst\n", stderr);
	fputs("\t-n <netmask>\t\tset interface netmask\n",stderr);
	fputs("\t-C <route>\t\tchange default route\n",stderr);
	fputs("\t-c\t\t\ttun on tunnel checksum\n",stderr);
	fputs("\t-u\t\t\trevert the changes, ie, remove tunnel, etc.\n",stderr);
    
    exit(-1);
}

/*
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
 */


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

int find_if_with_addr(char ifname[], in_addr_t src, in_addr_t dst, in_addr_t local, in_addr_t remote)
{
    int i;
    int sock;
    struct ifreq ifrq;
    
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("find_unused_if: socket");
        return -1;
    }
    
    for (i = 0; i < MAX_GREIF_CNT; i++) {
        bzero(&ifrq, sizeof(ifrq));
        sprintf(ifrq.ifr_name, "gre%d", i);
        
        /* get tunnel src address */
        if (ioctl(sock, SIOCGIFPSRCADDR, &ifrq) < 0)
            continue;
        if (((struct sockaddr_in *)&ifrq.ifr_addr)->sin_addr.s_addr != src)
            continue;
        
        /* get tunnel dst address */
        if (ioctl(sock, SIOCGIFPDSTADDR, &ifrq) < 0)
            continue;
        if (((struct sockaddr_in *)&ifrq.ifr_addr)->sin_addr.s_addr != dst)
            continue;

        /* get if local address */
        if (ioctl(sock, SIOCGIFADDR, &ifrq) < 0)
            continue;
        if (((struct sockaddr_in *)&ifrq.ifr_addr)->sin_addr.s_addr != local) 
            continue;

        /* get if p-p address */
        if (ioctl(sock, SIOCGIFDSTADDR, &ifrq) < 0)
            continue;
        if (((struct sockaddr_in *)&ifrq.ifr_addr)->sin_addr.s_addr != remote)
            continue;
        
        /* we have found one, and just find only one */
        //printf("find one: %s\n", ifrq.ifr_name);
        strcpy(ifname, ifrq.ifr_name);
        break;
    }
    
    close(sock);
    return i < MAX_GREIF_CNT ? 0 : -1;
}

int set_if_addr_tunnel(char ifname[], in_addr_t src, in_addr_t dst, in_addr_t local, in_addr_t remote, in_addr_t mask)
{
    int sock;
    
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
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
    
    /* set tunnel src and dst address */
    struct in_aliasreq in_req;
    bzero(&in_req, sizeof(struct in_aliasreq));
    
    strncpy(in_req.ifra_name, ifname, IFNAMSIZ);
    in_req.ifra_addr.sin_family = AF_INET;
    in_req.ifra_addr.sin_len = sizeof(struct sockaddr_in);
    in_req.ifra_addr.sin_addr.s_addr = src;
    
    in_req.ifra_dstaddr.sin_family = AF_INET;
    in_req.ifra_dstaddr.sin_len = sizeof(struct sockaddr_in);
    in_req.ifra_dstaddr.sin_addr.s_addr = dst;
    
    if (ioctl(sock, SIOCSIFPHYADDR, &in_req) < 0) {
        perror("set_if_addr_tunnel: set if tunnel address");
        goto ERROR;
    }
    
    /* set if local address */
    struct sockaddr_in sa;
    bzero(&sa, sizeof(struct sockaddr_in));
    sa.sin_family = AF_INET;
    
    sa.sin_addr.s_addr = local;
    bcopy(&sa, &ifrq.ifr_addr, sizeof(sa));
    ((struct sockaddr_in *)&ifrq.ifr_addr)->sin_len = sizeof(struct sockaddr_in);
    if (ioctl(sock, SIOCSIFADDR, &ifrq) < 0) {
        perror("set_if_addr_tunnel: set if local address");
        goto ERROR;
    }
    
    /* set if p-p address */
    sa.sin_addr.s_addr = remote;
    bcopy(&sa, &ifrq.ifr_addr,sizeof(sa));
    ((struct sockaddr_in *)&ifrq.ifr_addr)->sin_len = sizeof(struct sockaddr_in);
    if (ioctl(sock, SIOCSIFDSTADDR, &ifrq) < 0) {
        perror("set_if_addr_tunnel: set if remote address");
        goto ERROR;
    }
    
    if (netmask != INADDR_ANY) {
        /* set if netmask */
        ifrq.ifr_addr.sa_family = AF_INET;
        bcopy(&netmask, &((struct sockaddr_in *)&ifrq.ifr_addr)->sin_addr, sizeof(netmask));
        ((struct sockaddr_in *)&ifrq.ifr_addr)->sin_len = sizeof(netmask);
        if (ioctl(sock, SIOCSIFNETMASK, &ifrq) < 0) {
            perror("set_if_addr_tunnel: set netmask");
            goto ERROR;
        }
    }
    
    /* let if up */
    if (ioctl(sock, SIOCGIFFLAGS, &ifrq) < 0) {
        perror("set_if_addr_tunnel: get if flags");
        goto ERROR;
    }
    if ((ifrq.ifr_flags & IFF_UP) == 0) {
        ifrq.ifr_flags |= IFF_UP;
        if (ioctl(sock, SIOCSIFFLAGS, &ifrq) < 0) {
            perror("set_if_addr_tunnel: set if flags");
            goto ERROR;
        }
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
    
    if (ioctl(sock, SIOCGIFFLAGS, &ifrq) < 0) {
        perror("delete_if_addr_tunnel: get if flags");
        goto ERROR;
    }
    
    if (ifrq.ifr_flags & IFF_UP) {
        ifrq.ifr_flags &= ~IFF_UP;
        if (ioctl(sock, SIOCSIFFLAGS, &ifrq) < 0) {
            perror("delete_if_addr_tunnel: set if flags");
            goto ERROR;
        }
    }

    bzero(&ifrq.ifr_addr, sizeof(struct sockaddr));
    
    if (ioctl(sock, SIOCDIFPHYADDR, &ifrq) < 0) {
        if (errno != EADDRNOTAVAIL) {
            perror("delete_if_addr_tunnel: delete tunnel addr");
            goto ERROR;
        }
    }
        
    if (ioctl(sock, SIOCSIFDSTADDR, &ifrq) < 0) {
        if (errno != EADDRNOTAVAIL) {
            perror("delete_if_addr_tunnel: delete if remote address");
            goto ERROR;
        }
    }
    
    if (ioctl(sock, SIOCDIFADDR, &ifrq) < 0) {
        if (errno != EADDRNOTAVAIL) {
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


static int find_if_with_name(const char *iface, struct sockaddr_dl *out)
{
    struct ifaddrs *ifap, *ifa;
    struct sockaddr_dl *sdl = NULL;
    
    if (getifaddrs(&ifap)) {
        perror("getifaddrs");
        return -1;
    }
    
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr->sa_family == AF_LINK && \
            /*(ifa->ifa_flags & IFF_POINTOPOINT) && \ */
            strcmp(iface, ifa->ifa_name) == 0) {
            sdl = (struct sockaddr_dl *)ifa->ifa_addr;
            break;
        }
    }
    
    /* If we found it, then use it */
    if (sdl)
        bcopy((char *)sdl, (char *)out, (size_t)(sdl->sdl_len));

    freeifaddrs(ifap);
    
    if (sdl == NULL) {
        printf("interface %s not found or invalid(must be p-p)\n", iface);
        return -1;
    }
    return 0;
}


int add_gre_if(in_addr_t src, in_addr_t dst, in_addr_t local, in_addr_t remote, in_addr_t mask)
{
    char ifname[IFNAMSIZ];
    if (find_unused_if(ifname) < 0) {
        fprintf(stderr, "add_gre_if: unable to find unused gre interface.\n");
        return -1;
    }
    
    if (set_if_addr_tunnel(ifname, src, dst, local, remote, mask) < 0) {
        fprintf(stderr, "add_gre_if: error set address of %s\n", ifname);
        return -1;
    }
    
    return 0;
}


int remove_gre_if(in_addr_t src, in_addr_t dst, in_addr_t local, in_addr_t remote)
{
    char ifname[IFNAMSIZ];
    if (find_if_with_addr(ifname, src, dst, local, remote) < 0) {
        fprintf(stderr, "remove_gre_if: unable to find gre interface.\n");
        return -1;
    }
    
    if (delete_if_addr_tunnel(ifname) < 0) {
        fprintf(stderr, "remove_gre_if: unable to delete address of %s\n", ifname);
        return -1;
    }
    
    return 0;
}


static int route_op(u_char op, in_addr_t dst, in_addr_t mask, in_addr_t *gateway, char *iface)
{
  
#define ROUNDUP(n)  ((n) > 0 ? (1 + (((n) - 1) | (sizeof(uint32_t) - 1))) : sizeof(uint32_t))
#define ADVANCE(x, n) (x += ROUNDUP((n)->sa_len))

#define NEXTADDR(w, u) \
    if (msg.msghdr.rtm_addrs & (w)) {\
        len = ROUNDUP(u.sa.sa_len); bcopy((char *)&(u), cp, len); cp += len;\
    }
    
    static int seq = 0;
    int err = 0;
    size_t len = 0;
    char *cp;
    pid_t pid;
    
    union {
        struct	sockaddr sa;
        struct	sockaddr_in sin;
        struct	sockaddr_dl sdl;
        struct	sockaddr_storage ss; /* added to avoid memory overrun */
    } so_addr[RTAX_MAX];
    
    struct {
        struct rt_msghdr msghdr;
        char buf[512];
    } msg;

    bzero(so_addr, sizeof(so_addr));
    bzero(&msg, sizeof(msg));
    
    cp = msg.buf;
    pid = getpid();
    //msg.msghdr.rtm_msglen  = 0;
    msg.msghdr.rtm_version = RTM_VERSION;
    //msg.msghdr.rtm_type    = RTM_ADD;
    msg.msghdr.rtm_index   = 0;
    msg.msghdr.rtm_pid     = pid;
    msg.msghdr.rtm_addrs   = 0;
    msg.msghdr.rtm_seq     = ++seq;
    msg.msghdr.rtm_errno   = 0;
    msg.msghdr.rtm_flags   = 0;
    
    // Destination
    if (dst != 0xffffffff) {
        msg.msghdr.rtm_addrs |= RTA_DST;
        
        so_addr[RTAX_DST].sin.sin_len    = sizeof(struct sockaddr_in);
        so_addr[RTAX_DST].sin.sin_family = AF_INET;
        so_addr[RTAX_DST].sin.sin_addr.s_addr = dst & mask;
    } else {
        fprintf(stderr, "invalid dst address.\n");
        return -1;
    }
    
    // Netmask
    if (mask != 0xffffffff) {
        msg.msghdr.rtm_addrs |= RTA_NETMASK;

        so_addr[RTAX_NETMASK].sin.sin_len    = sizeof(struct sockaddr_in);
        so_addr[RTAX_NETMASK].sin.sin_family = AF_INET;
        so_addr[RTAX_NETMASK].sin.sin_addr.s_addr = mask;

    } else
        msg.msghdr.rtm_flags |= RTF_HOST;
    
    switch (op) {
        case RTM_ADD:
        case RTM_CHANGE:
            msg.msghdr.rtm_type = op;
            msg.msghdr.rtm_addrs |= RTA_GATEWAY;
            msg.msghdr.rtm_flags |= RTF_UP;
            
            // Gateway
            if ((gateway && *gateway != 0x0 && *gateway != 0xffffffff)) {
                msg.msghdr.rtm_flags |= RTF_GATEWAY;
                
                so_addr[RTAX_GATEWAY].sin.sin_len    = sizeof(struct sockaddr_in);
                so_addr[RTAX_GATEWAY].sin.sin_family = AF_INET;
                so_addr[RTAX_GATEWAY].sin.sin_addr.s_addr = *gateway;
                
                if (iface != NULL) {
                    msg.msghdr.rtm_addrs |= RTA_IFP;
                    so_addr[RTAX_IFP].sdl.sdl_family = AF_LINK;

                    //link_addr(iface, &so_addr[RTAX_IFP].sdl);
                    if (find_if_with_name(iface, &so_addr[RTAX_IFP].sdl) < 0)
                        return -2;
                }

            } else {
                if (iface == NULL) {
                    fprintf(stderr, "Requir gateway or iface.\n");
                    return -1;
                }
                
                if (find_if_with_name(iface, &so_addr[RTAX_GATEWAY].sdl) < 0)
                    return -1;
            }
            break;
        case RTM_DELETE:
            msg.msghdr.rtm_type = op;
            msg.msghdr.rtm_addrs |= RTA_GATEWAY;
            msg.msghdr.rtm_flags |= RTF_GATEWAY;
            break;
        case RTM_GET:
            msg.msghdr.rtm_type = op;
            msg.msghdr.rtm_addrs |= RTA_IFP;
            so_addr[RTAX_IFP].sa.sa_family = AF_LINK;
            so_addr[RTAX_IFP].sa.sa_len = sizeof(struct sockaddr_dl);
            break;
        default:
            return EINVAL;
    }
    
    NEXTADDR(RTA_DST, so_addr[RTAX_DST]);
	NEXTADDR(RTA_GATEWAY, so_addr[RTAX_GATEWAY]);
	NEXTADDR(RTA_NETMASK, so_addr[RTAX_NETMASK]);
	NEXTADDR(RTA_GENMASK, so_addr[RTAX_GENMASK]);
	NEXTADDR(RTA_IFP, so_addr[RTAX_IFP]);
	NEXTADDR(RTA_IFA, so_addr[RTAX_IFA]);
    
    msg.msghdr.rtm_msglen = len = cp - (char *)&msg;
    
    int sock = socket(PF_ROUTE, SOCK_RAW, AF_INET);
    if (sock < 0) {
        perror("socket(PF_ROUTE, SOCK_RAW, AF_INET) failed");
        return -1;
    }
    
    if (write(sock, (char *)&msg, len) < 0) {
        perror("write PF_ROUTE failed");
        err = -1;
    }
    
    if (op == RTM_GET) {
		do {
			len = read(sock, (char *)&msg, sizeof(msg));
		} while (len > 0 && (msg.msghdr.rtm_seq != seq || msg.msghdr.rtm_pid != pid));
		if (len < 0) {
            perror("read from routing socket");
            err = -1;
        } else {
            struct sockaddr *gate = NULL;
            struct sockaddr_dl *ifp = NULL;
            register struct sockaddr *sa;
            
            if (msg.msghdr.rtm_version != RTM_VERSION) {
                fprintf(stderr, "routing message version %d not understood\n", msg.msghdr.rtm_version);
                err = -1;
                goto end;
            }
            if (msg.msghdr.rtm_msglen > len) {
                fprintf(stderr, "message length mismatch, in packet %d, returned %lu\n", msg.msghdr.rtm_msglen, len);
            }
            if (msg.msghdr.rtm_errno)  {
                fprintf(stderr, "message indicates error %d, %s\n", msg.msghdr.rtm_errno, strerror(msg.msghdr.rtm_errno));
                err = -1;
                goto end;
            }
            cp = msg.buf;
            if (msg.msghdr.rtm_addrs) {
                int i;
                for (i = 1; i; i <<= 1) {
                    if (i & msg.msghdr.rtm_addrs) {
                        sa = (struct sockaddr *)cp;
                        switch (i) {
                            case RTA_DST:
                                break;
                            case RTA_GATEWAY:
                                gate = sa;
                                break;
                            case RTA_NETMASK:
                                break;
                            case RTA_IFP:
                                if (sa->sa_family == AF_LINK &&
                                    ((struct sockaddr_dl *)sa)->sdl_nlen)
                                    ifp = (struct sockaddr_dl *)sa;
                                break;
                        }
                        ADVANCE(cp, sa);
                    }
                }
            }
            
            if (gate == NULL && ifp == NULL)
                err = -1;
            else {
                if (gate && msg.msghdr.rtm_flags & RTF_GATEWAY && gateway)
                    *gateway = ((struct sockaddr_in *)gate)->sin_addr.s_addr;
                else
                    *gateway = 0;
                if (ifp && iface) {
                    strncpy(iface, ifp->sdl_data, ifp->sdl_nlen < IFNAMSIZ ? ifp->sdl_nlen : IFNAMSIZ);
                    iface[IFNAMSIZ - 1] = '\0';
                } else
                    bzero(iface, IFNAMSIZ);
            }
        }
	}

end:
    if (close(sock) < 0) {
        perror("close");
    }
    
    return err;
#undef MAX_INDEX
}

int route_get(in_addr_t dst, in_addr_t mask, in_addr_t *gateway, char iface[])
{
    return route_op(RTM_GET, dst, mask, gateway, iface);
}

int route_add(in_addr_t dst, in_addr_t mask, in_addr_t gateway, const char *iface)
{
    return route_op(RTM_ADD, dst, mask, &gateway, (char *)iface);
}

int route_change(in_addr_t dst, in_addr_t mask, in_addr_t gateway, const char *iface)
{
    return route_op(RTM_CHANGE, dst, mask, &gateway, (char *)iface);
}

int route_delete(in_addr_t dst, in_addr_t mask)
{
    return route_op(RTM_DELETE, dst, mask, 0, NULL);
}


/*
static void free_rt_list(struct rt_list *list)
{
    struct rt_list *p;
    while (list) {
        p = list->next;
        free(list);
        list = p;
    }
} */

