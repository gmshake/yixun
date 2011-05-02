/*
 *  get_ip_mac.c
 *
 *  Created by Summer Town on 9/18/10.
 *  Copyright 2010 __MyCompanyName__. All rights reserved.
 *
 */

#include <unistd.h>
#include <stdio.h>

#include <string.h>		/* strcpy(), strlcpy(), strncpy() */
#include <strings.h>	/* bzero() */
#include <stdarg.h>
#include <stdint.h>		/* uint8_t */

#include <arpa/inet.h>		/* inet_addr(), htonl() */
#include <sys/socket.h>		/* socket() */
#include <sys/ioctl.h>		/* SIOCGIFCONF, SIOCGIFADDR */

#include <net/ethernet.h>	/* ETHER_ADDR_LEN */
#include <net/if.h>		/* ifreq, ifconf */

#if defined(__APPLE__) || defined(__FreeBSD__)
#include <net/if_dl.h>		/* sockaddr_dl... */
#include <net/if_types.h>	/* IFT_ETHER */
#endif

#include <netinet/in.h>		/* struct sockaddr_in */

#include "sys.h"
#include "log_xxx.h"
#include "common_macro.h"

#ifndef IFCONF_BUF_LEN
#define IFCONF_BUF_LEN 1024
#endif


int
get_ip_mac_by_socket(int socket, in_addr_t * ip_addr, uint8_t eth_addr[])
{
	struct sockaddr_in sa_addr;
	socklen_t len = sizeof(struct sockaddr_in);

	if (getsockname(socket, (struct sockaddr *)&sa_addr, &len) < 0) {
		log_perror("Error getsockname");
		return -1;
	}
	if (ip_addr != NULL)
		*ip_addr = sa_addr.sin_addr.s_addr;

	if (eth_addr == NULL)	/* IE: do not get mac_address */
		return 0;

	char buffer[IFCONF_BUF_LEN];
	struct ifconf ifc;
	ifc.ifc_len = IFCONF_BUF_LEN;
	ifc.ifc_buf = buffer;

	if (ioctl(socket, SIOCGIFCONF, &ifc) < 0) {
		log_perror("Error ioctl(SIOCGIFCONF)");
		return -2;
	}

	if (ifc.ifc_len <= IFCONF_BUF_LEN) {
		struct ifreq ifr;
		struct ifreq *ifrq = ifc.ifc_req, *lifrq = (struct ifreq *)&ifc.ifc_buf[ifc.ifc_len];
		bzero(&ifr, sizeof(ifr));
		do {
#if defined(__APPLE__) || defined(__FreeBSD__)
			struct sockaddr *sa = (struct sockaddr *)&ifrq->ifr_addr;
			if (((struct sockaddr_dl *)sa)->sdl_type == IFT_ETHER)
#endif
			{
				strcpy(ifr.ifr_name, ifrq->ifr_name);

				if (ioctl(socket, SIOCGIFADDR, &ifr) == 0) {
					if (((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr == sa_addr.sin_addr.s_addr) {	// found it
#if defined(__APPLE__) || defined(__FreeBSD__)
						memcpy(eth_addr, LLADDR((struct sockaddr_dl *)sa), ETHER_ADDR_LEN);
						return 0;
#else
						if (ioctl(socket, SIOCGIFHWADDR, &ifr) == 0) {
							memcpy(eth_addr, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
							return 0;
						}
#endif
					}
				}
			}
#if defined(__APPLE__) || defined(__FreeBSD__)
			ifrq = (struct ifreq *)((caddr_t) ifrq + _SIZEOF_ADDR_IFREQ(*ifrq));
#else
			ifrq++;
#endif
		} while (ifrq < lifrq);

		log_err("Cannot find MAC addr...\n");
		return -3;
	}

	log_err("Error: ifc.ifc_len is greater then IFCONF_BUF_LEN:%d\n", IFCONF_BUF_LEN);
	return -4;
}


int
get_ip_mac_by_name(const char *ifname, in_addr_t * ip_addr, uint8_t eth_addr[])
{
	int sockfd;
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		log_perror("Error create socket");
		return -1;
	}

	if (ip_addr) {
		struct ifreq ifr;
		bzero(&ifr, sizeof(ifr));
		strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

		if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
			log_notice("Notice: no IP address with Interface %s\n", ifr.ifr_name);
			*ip_addr = 0;
		} else
			*ip_addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
	}

	if (eth_addr) {
#if defined(__APPLE__) || defined(__FreeBSD__)
		char buffer[IFCONF_BUF_LEN];
		struct ifconf ifc;
		ifc.ifc_len = IFCONF_BUF_LEN;
		ifc.ifc_buf = buffer;

		if (ioctl(sockfd, SIOCGIFCONF, &ifc) < 0) {
			log_perror("Error ioctl(SIOCGIFCONF)");
			goto ERROR;
		}

		if (ifc.ifc_len <= IFCONF_BUF_LEN) {
			struct ifreq *ifrq = ifc.ifc_req, *lifrq = (struct ifreq *)&ifc.ifc_buf[ifc.ifc_len];
			do {
				struct sockaddr *sa = &ifrq->ifr_addr;

				if (((struct sockaddr_dl *)sa)->sdl_type == IFT_ETHER) {
					if (strcmp(ifname, ifrq->ifr_name) == 0) {
						memcpy(eth_addr, LLADDR((struct sockaddr_dl *)sa), ETHER_ADDR_LEN);	// Found MAC address
						close(sockfd);
						return 0;
					}
				}
				ifrq = (struct ifreq *)((caddr_t) ifrq + _SIZEOF_ADDR_IFREQ(*ifrq));
			} while (ifrq < lifrq);

			log_err("Cannot find device %s.\n", ifname);
			goto ERROR;
		}
		log_err("Error: ifc.ifc_len is greater then IFCONF_BUF_LEN: %d\n", IFCONF_BUF_LEN);

#elif defined(__linux__)
		struct ifreq ifr;
		bzero(&ifr, sizeof(ifr));
		strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

		/* get MAC */
		if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
			log_perror("ioctl(SIOCGIFHWADDR)");
			goto ERROR;
		}
		memcpy(eth_addr, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
#else
#error Target OS not supported yet!
#endif
	}

	close(sockfd);
	return 0;
ERROR:
	close(sockfd);
	return -1;
}

int
string_to_lladdr(uint8_t lladdr[], const char *src)
{
	if (src == NULL || lladdr == NULL)
		return -1;

	if (strstr(src, ":") == NULL && strstr(src, "-") == NULL) {
		int i;
		for (i = 0; i < ETHER_ADDR_LEN; i++) {
			unsigned int t = 0;
			sscanf(src, "%2x", &t);
			lladdr[i] = (uint8_t) t;

			if (*++src == '\0')
				break;
			else if (*++src == '\0')
				break;
		}
		for (i++; i < ETHER_ADDR_LEN; i++)
			lladdr[i] = 0;

	} else {
		char tmp[64];
		strlcpy(tmp, src, sizeof(tmp));
		char *args[ETHER_ADDR_LEN] = { NULL };
		char *instr = tmp;
		int i;
		for (i = 0; i < ETHER_ADDR_LEN; i++) {
			args[i] = strsep(&instr, ":-");
			if (args[i] != NULL) {
				unsigned int t;
				sscanf(args[i], "%2x", &t);
				lladdr[i] = (uint8_t) t;
			} else
				lladdr[i] = (uint8_t) 0;
		}
	}

	return 0;
}
