#include <unistd.h>
#include <string.h>
#include <fcntl.h> //open()
#include <stdlib.h> // system()
#include <stdio.h>

#include <sys/ioctl.h>
#include <sys/socket.h> // place it before <net/if.h> struct sockaddr
#include <net/if.h> //struct ifreq
#include <netinet/in.h> // sturct sockaddr_in
#include <arpa/inet.h> // inet_addr()
//#include <netdb.h> // gethostbyname()

#include <errno.h>

#include "common_macro.h"
#include "common_logs.h"

#define MAX_TUN_CNT 16
#define GREMTU	1476

char tun_if_name[IFNAMSIZ];

int open_tunnel(char *tun_name)
{
    int tunfd;
    char tun_dev_name[IFNAMSIZ+16];
    
    if (tun_name == NULL)
    {
        int i;
        for (i = 0; i < MAX_TUN_CNT; i++)
        {
            snprintf(tun_dev_name, sizeof(tun_dev_name), "/dev/tun%d", i);

            if ((tunfd = open(tun_dev_name, O_RDWR)) < 0)
            {
                if (errno != EBUSY) // if busy we try next tun device
                {
                    log_perror("[open_tunnel] open");
                    return -1;
                }
            }
            else
            {
                snprintf(tun_if_name, sizeof(tun_if_name), "tun%d", i);
                break;
            }
                
        }
    }
    else
    {
        if ((tunfd = open(tun_name, O_RDWR)) < 0)
        {
            log_perror("[open_tunnel] open");
            return -1;
        }
        
        char *ch = tun_name + strlen(tun_name);
        while(*ch != '/') ch--;
        ch++;
        strncpy(tun_if_name, ch, sizeof(tun_if_name));
        tun_if_name[sizeof(tun_if_name) - 1] = '\0';
    }
    
    return tunfd;
}

int set_tunnel_addr(in_addr_t local, in_addr_t remote, in_addr_t net_mask)
{
    int sock;
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        log_perror("[set_tunnel_addr] socket");
        return -1;
    }
    
    struct ifreq ifrq;
    bzero(&ifrq, sizeof(ifrq));
	strncpy(ifrq.ifr_name,tun_if_name,IFNAMSIZ);
	
    ifrq.ifr_mtu = GREMTU;
	if (ioctl(sock, SIOCSIFMTU, &ifrq) < 0)
	{
        log_perror("[set_tunnel_addr] set tun mtu");
        goto ERROR;
	}
	
	if (ioctl(sock, SIOCDIFADDR, &ifrq) < 0)
	{
	    if (errno != EADDRNOTAVAIL)
        {
            log_perror("[set_tunnel_addr] delete if addr");
            goto ERROR;
        }
	}
	
	struct sockaddr_in sa;
    bzero(&sa, sizeof(struct sockaddr_in));
	sa.sin_family = AF_INET;
    
    sa.sin_addr.s_addr = local;
    bcopy(&sa, &ifrq.ifr_addr,sizeof(sa));
    ((struct sockaddr_in *)&ifrq.ifr_addr)->sin_len = sizeof(struct sockaddr_in);
    if (ioctl(sock, SIOCSIFADDR, &ifrq) < 0)
    {
        log_perror("[set_tunnel_addr] set if address:%s", inet_ntoa(((struct sockaddr_in *)(&ifrq.ifr_addr))->sin_addr));
        goto ERROR;
    }
    
    sa.sin_addr.s_addr = remote;
    bcopy(&sa, &ifrq.ifr_addr,sizeof(sa));
    ((struct sockaddr_in *)&ifrq.ifr_addr)->sin_len = sizeof(struct sockaddr_in);
    if (ioctl(sock, SIOCSIFDSTADDR, &ifrq) < 0)
    {
        log_perror("[set_tunnel_addr] set remote ip address");
        goto ERROR;
    }
    
    ifrq.ifr_addr.sa_family = AF_INET;
    bcopy(&net_mask,&((struct sockaddr_in *)&ifrq.ifr_addr)->sin_addr,sizeof(net_mask));
    ((struct sockaddr_in *)&ifrq.ifr_addr)->sin_len = sizeof(net_mask);
    if (ioctl(sock,SIOCSIFNETMASK,&ifrq) < 0)
    {
        log_perror("[set_tunnel_addr] set netmask");
        goto ERROR;
    }
    
    if (ioctl(sock,SIOCGIFFLAGS, &ifrq) < 0)
	{
        log_perror("[set_tunnel_addr] get if flag");
		goto ERROR;
	}
	ifrq.ifr_flags |= IFF_UP;
	if (ioctl(sock,SIOCSIFFLAGS,&ifrq) < 0)
	{
        log_perror("[set_tunnel_addr] set if flags");
		goto ERROR;
	}
	
    return 0;
ERROR:
    close(sock);
    return -1;
}


int close_tunnel(int tunfd)
{
    int sock;
    struct ifreq ifrq;
    
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        log_perror("[close_tunnel] socket");
        return -1;
    }
    
    bzero(&ifrq,sizeof(ifrq));
    strncpy(ifrq.ifr_name, tun_if_name,IFNAMSIZ);
    if (ioctl(sock,SIOCGIFFLAGS, &ifrq) < 0)
    {
        log_perror("[close_tunnel] get if flags");
        goto ERROR;
    }
    else
    {
        ifrq.ifr_flags &= ~(IFF_UP | IFF_RUNNING);
        if (ioctl(sock,SIOCSIFFLAGS,&ifrq) < 0) 
        {
            log_perror("[close_tunnel] set if flags");
            goto ERROR;
        }
    }
    
    bzero(&ifrq.ifr_addr,sizeof(struct sockaddr));

    if (ioctl(sock,SIOCSIFDSTADDR,&ifrq) < 0)
    {
        log_perror("[close_tunnel] delete remote address");
        goto ERROR;
    }
    
    if (ioctl(sock,SIOCDIFADDR,&ifrq) < 0)
    {
        if (errno != EADDRNOTAVAIL)
        {
            log_perror("[close_tunnel] delete local address");
            goto ERROR;
        }
    }
    
    close(sock);
    close(tunfd);
    return 0;
ERROR:
    close(sock);
    close(tunfd);
    return -1;
}

/*
int set_addr_by_name(char *name, struct sockaddr_in *sa)
{
	bzero((char *)sa, sizeof(struct sockaddr_in));
	sa->sin_family = AF_INET;
	if ((sa->sin_addr.s_addr = inet_addr(name)) == -1L)
	{
		struct hostent *hep = gethostbyname(name);
		if (!hep)
		{
			dprintf("Error[set_addr_by_name]: Host name lookup failure for '%s'\n", name);
			return -1;
		}
		sa->sin_family = hep->h_addrtype;
		bcopy(hep->h_addr, (caddr_t)&sa->sin_addr, hep->h_length);    
	}
	
    return 0;
}
*/
