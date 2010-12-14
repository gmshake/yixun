#include <unistd.h>
#include <stdio.h>      // fprintf

#include <string.h>     // memcpy()
#include <strings.h>    //  bzero()
#include <stdarg.h>
#include <stdint.h>     // uint8_t

#include <arpa/inet.h>  // inet_addr(), htonl()
#include <sys/socket.h> // socket()
#include <sys/ioctl.h>  // SIOCGIFCONF, SIOCGIFADDR

#include <net/if.h>     //ifreq, ifconf
#include <net/if_dl.h>  // sockaddr_dl...
#include <net/if_types.h>       //IFT_ETHER
#include <netinet/in.h> // struct sockaddr_in

#include "common_macro.h"
#include "common_logs.h"

#ifndef IFCONF_BUF_LEN
#define IFCONF_BUF_LEN 1024
#endif

int get_ip_mac_by_socket(int socket, in_addr_t *address,   uint8_t eth_addr[]);
int get_ip_mac_by_name(const char *ifname, in_addr_t *addr, uint8_t eth_addr[]); 

int get_ip_mac_by_socket(int socket, in_addr_t *address,   uint8_t eth_addr[])
{
    struct sockaddr_in sa_addr;
    socklen_t len = sizeof(struct sockaddr_in);

    if (getsockname(socket, (struct sockaddr *)&sa_addr, &len) < 0)
    {
        log_perror("Error getsockname");
        return -1;
    }
    if (address != NULL)
        *address = sa_addr.sin_addr.s_addr;
    
    if (eth_addr == NULL) // IE: do not get mac_address
        return 0;
        
    char buffer[IFCONF_BUF_LEN];
    struct ifconf ifc;
    ifc.ifc_len=IFCONF_BUF_LEN;
    ifc.ifc_buf=buffer;
    
    if(ioctl(socket,SIOCGIFCONF,&ifc)<0)
    {
        log_perror("Error ioctl");
        return -2;
    }
    
    if(ifc.ifc_len<=IFCONF_BUF_LEN)
    {
        struct ifreq ifr, *ifrq = ifc.ifc_req;
        bzero(&ifr, sizeof(ifr));
        int space=0;
        do
        {
            struct sockaddr *sa=(struct sockaddr *)&ifrq->ifr_addr;
            strcpy(ifr.ifr_name, ifrq->ifr_name);
            if (ioctl(socket, SIOCGIFADDR, &ifr) == 0)
            {
                if (((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr == sa_addr.sin_addr.s_addr ) // found it
                {
                    memcpy (eth_addr, LLADDR((struct sockaddr_dl *)sa), 6);
                    return 0;
                }
            }
            
            ifrq=(struct ifreq*)(sa->sa_len + (caddr_t)&ifrq->ifr_addr);
            space+=(int)sa->sa_len + sizeof(ifrq->ifr_name);
        }while(space < ifc.ifc_len);
        
        log_err("Cannot find MAC addr...\n");
        return -3;
    }

    log_err("Error: ifc.ifc_len is greater then IFCONF_BUF_LEN:%d\n", IFCONF_BUF_LEN);

    return -4;
}

int get_ip_mac_by_name(const char *ifname, in_addr_t *addr, uint8_t eth_addr[])
{
    if (ifname == NULL)
    {
        log_err("Error: ifname is NULL\n");
        return -1;
    }
    int sockfd;
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        log_perror("Error create socket");
        return -1;
    }
    
    uint8_t tmp_eth_addr[6];
    in_addr_t tmp_addr;
    
    char buffer[IFCONF_BUF_LEN];
    struct ifconf ifc;
    ifc.ifc_len=IFCONF_BUF_LEN;
    ifc.ifc_buf=buffer;

    if(ioctl(sockfd,SIOCGIFCONF,&ifc)<0)
    {
        log_perror("Error ioctl");
        goto ERROR;
    }

    if(ifc.ifc_len<=IFCONF_BUF_LEN)
    {
        struct ifreq *ifrq = ifc.ifc_req;
        int space=0;
        do
        {
            struct sockaddr *sa=&ifrq->ifr_addr;

            if(((struct sockaddr_dl *)sa)->sdl_type==IFT_ETHER)
            {
                if (strcmp(ifname, ifrq->ifr_name) == 0)
                {                  
                    memcpy (tmp_eth_addr, LLADDR((struct sockaddr_dl *)sa), 6); // Found MAC address
                    
                    struct ifreq ifr;
                    bzero(&ifr, sizeof(ifr));
                    strncpy(ifr.ifr_name, ifrq->ifr_name, IFNAMSIZ - 1);

                    if(ioctl(sockfd,SIOCGIFADDR,&ifr)<0)
                    {
                        log_notice("Notice: no IP address with Interface %s\n", ifr.ifr_name);
                        tmp_addr = htonl((in_addr_t)0xA9FE0000 | (in_addr_t)(tmp_eth_addr[4] << 8) | (in_addr_t)(tmp_eth_addr[5])); // 没找到IP地址时，用169.254.0.0加上MAC地址的后两字节作为IP
                    }
                    else
                    {
                        tmp_addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;  // 找到IP地址
                    }
                    
                    if (eth_addr != NULL) memcpy(eth_addr, tmp_eth_addr, sizeof(tmp_eth_addr)); // Copy MAC address
                    if (addr != NULL) *addr = tmp_addr; // copy IP address
                    
                    return 0;
                }
            }
            ifrq=(struct ifreq*)(sa->sa_len + (caddr_t)&ifrq->ifr_addr);
            space+=(int)sa->sa_len + sizeof(ifrq->ifr_name);
            
        }while(space < ifc.ifc_len);
        
        log_err("Cannot find device %s.\n", ifname);
        goto ERROR;
    }
    log_err("Error: ifc.ifc_len is greater then IFCONF_BUF_LEN:%d\n", IFCONF_BUF_LEN);
ERROR:
    close(sockfd);
    return -1;
}

int string_to_lladdr(uint8_t lladdr[], const char *src)
{
    if (src == NULL || lladdr == NULL) return 0;
    char tmp[64];
    strncpy(tmp, src, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';
    char * args[6] = {NULL};
    char *instr = tmp;
    int i;
    for (i = 0; i < 6; i++)
    {
        args[i] = strsep(&instr, ":- ");
        if (args[i] != NULL)
        {
            int t;
            sscanf(args[i], "%x", &t);
            t &= 0xff;
            lladdr[i] = (uint8_t)t;
        }
        else
            lladdr[i] = (uint8_t)0;
    }
    return -1;
    /*
    
    unsigned int tmp[6];
    int rval = sscanf(src, "%2x %2x %2x %2x %2x %2x", tmp, tmp + 1, tmp + 2, tmp + 3, tmp + 4, tmp + 5);
    int i;
    for (i = 0; i < sizeof(tmp); i++)
        lladdr[i] = (uint8_t)tmp[i];
    return rval;
    */
}
