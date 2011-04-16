/*
 * gre_tunnel.c
 * gre tunnel ops
 * By Summer Town
 * 2011.04.16
 */
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>		//ioctl()
#include <sys/socket.h>		//place it before <net/if.h> struct sockaddr

#include <net/if.h>		//struct ifreq
#include <netinet/in.h>		//IPPROTO_GRE sturct sockaddr_in INADDR_ANY
#if defined(__APPLE__) || defined(__FreeBSD__)
#include <net/if_var.h>		//struct ifaddr
#include <netinet/in_var.h>	//struct in_aliasreq
#endif

#include <netinet/ip.h>		//struct ip, /* linux: struct iphdr */

#if defined(__linux__)
#include <fcntl.h>			//open()...
#include <linux/if_tunnel.h>	//SIOCADDTUNNEL...
#endif

#include <errno.h>

#if defined(__linux__)
#define GRENAME "greyixun"
#endif

#if defined(__linux__)
static void
init_tunnel_parm(struct ip_tunnel_parm *p, const char *name)
{
	bzero(p, sizeof(*p));
	strncpy(p->name, name, IFNAMSIZ);
	p->iph.version = 4;
	p->iph.ihl = 5;
	p->iph.frag_off = htons(IP_DF);
	p->iph.protocol = IPPROTO_GRE;
	p->iph.ttl = 30;
}
#endif

int
gre_find_unused_tunnel(char ifname[])
{
	int fd;
	struct ifreq ifr;

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		fprintf(stderr, "%s: socket(): %s\n", __FUNCTION__, strerror(errno));
		return -1;
	}

	bzero(ifname, IFNAMSIZ);
#if defined(__linux__)
	/*
	 * hack: On linux, there will allways be a gre0 interface available
	 * if ip_gre.* is loaded into kernel.
	 * And, if you create a tunnel without local or remote parameter, 
	 * ioctl(fd, SIOCADDTUNNEL, &ifr) will not return a error, but
	 * you will NOT get the requied tunnel interface
	 * So, we only check if gre0 exist
	 */
	bzero(&ifr, sizeof(ifr));
	strncpy(ifr.ifr_name, "gre0", IFNAMSIZ);
	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0)
		fprintf(stderr, "%s ioctl(gre0):%s\n", __FUNCTION__, strerror(errno));
	else
		strncpy(ifname, GRENAME, IFNAMSIZ);

#else
	struct if_nameindex *p, *ifn = if_nameindex();
	for (p = ifn; p->if_index && p->if_name; p++) {
		if (strncmp(p->if_name, "gre", 3))
			continue;
		bzero(&ifr, sizeof(ifr));
		strncpy(ifr.ifr_name, p->if_name, IFNAMSIZ);
		if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0)
			continue;
		if ((ifr.ifr_flags & IFF_UP) == 0) {
			strncpy(ifname, ifr.ifr_name, IFNAMSIZ);
			break;
		}
	}
	if_freenameindex(ifn);

#if defined(__FreeBSD__)
	if (ifname[0] == '\0') {
		bzero(&ifr, sizeof(ifr));
		strncpy(ifr.ifr_name, "gre", IFNAMSIZ);
		if (ioctl(fd, SIOCIFCREATE2, &ifr) < 0)
			fprintf(stderr, "%s ioctl(SIOCIFCREATE2):%s\n", \
					__FUNCTION__, strerror(errno));
		else if (strncmp("gre", ifr.ifr_name, sizeof(ifr.ifr_name)) != 0)
			strncpy(ifname, ifr.ifr_name, IFNAMSIZ);
	}
#endif
#endif

	close(fd);
	return ifname[0] ? 0 : -1;
}

int
gre_find_tunnel_with_addr(char ifname[], in_addr_t src, in_addr_t dst, in_addr_t local, in_addr_t remote)
{
	int fd;
	struct ifreq ifr;

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		fprintf(stderr, "%s: socket(): %s\n", __FUNCTION__, strerror(errno));
		return -1;
	}

	bzero(ifname, IFNAMSIZ);

	struct if_nameindex *p, *ifn = if_nameindex();
	for (p = ifn; p->if_index && p->if_name; p++) {
#if defined(__linux__)
		/* linux version get tunnel src, dst addrs */
		struct ip_tunnel_parm parm;
		bzero(&ifr, sizeof(ifr));
		strncpy(ifr.ifr_name, p->if_name, IFNAMSIZ);
		init_tunnel_parm(&parm, p->if_name);
		ifr.ifr_ifru.ifru_data = (void *)&parm;

		if (ioctl(fd, SIOCGETTUNNEL, &ifr) < 0)
			continue;
		if (parm.iph.protocol != IPPROTO_GRE)
			continue;
		if (parm.iph.daddr != dst || parm.iph.saddr != src)
			continue;
#else
		/* BSD/Darwin version, get tunnel src, dst addr */
		if (strncmp(p->if_name, "gre", 3))
			continue;
		bzero(&ifr, sizeof(ifr));
		strncpy(ifr.ifr_name, p->if_name, IFNAMSIZ);

		/* get tunnel src address */
		if (ioctl(fd, SIOCGIFPSRCADDR, &ifr) < 0)
			continue;
		if (((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr != src)
			continue;

		/* get tunnel dst address */
		if (ioctl(fd, SIOCGIFPDSTADDR, &ifr) < 0)
			continue;
		if (((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr != dst)
			continue;
#endif
		/* get if local address */
		if (ioctl(fd, SIOCGIFADDR, &ifr) < 0)
			continue;
		if (((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr != local)
			continue;

		/* get if p-p address */
		if (ioctl(fd, SIOCGIFDSTADDR, &ifr) < 0)
			continue;
		if (((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr != remote)
			continue;

		/* we have found one, and just find only one */
		strncpy(ifname, ifr.ifr_name, IFNAMSIZ);
		break;
	}
	if_freenameindex(ifn);

	close(fd);
	return ifname[0] ? 0 : -1;
}

int
gre_set_tunnel_addr(const char *ifname, in_addr_t src, in_addr_t dst)
{
	int fd;
	struct ifreq ifr;

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		fprintf(stderr, "%s: socket(): %s\n", __FUNCTION__, strerror(errno));
		return -1;
	}

	bzero(&ifr, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

#if defined(__APPLE__) || defined(__FreeBSD__)
	if (ioctl(fd, SIOCDIFPHYADDR, &ifr) < 0) {
		if (errno != EADDRNOTAVAIL) {
			fprintf(stderr, "%s: ioctl(): %s\n", __FUNCTION__, strerror(errno));
			goto ERROR;
		}
	}
	struct in_aliasreq in_req;
	bzero(&in_req, sizeof(struct in_aliasreq));

	strncpy(in_req.ifra_name, ifname, IFNAMSIZ);
	in_req.ifra_addr.sin_family = AF_INET;
	in_req.ifra_addr.sin_len = sizeof(struct sockaddr_in);
	in_req.ifra_addr.sin_addr.s_addr = src;

	in_req.ifra_dstaddr.sin_family = AF_INET;
	in_req.ifra_dstaddr.sin_len = sizeof(struct sockaddr_in);
	in_req.ifra_dstaddr.sin_addr.s_addr = dst;

	if (ioctl(fd, SIOCSIFPHYADDR, &in_req) < 0) {
		fprintf(stderr, "%s: ioctl(): %s\n", __FUNCTION__, strerror(errno));
		goto ERROR;
	}
#else
#if defined(__linux__)
	struct ip_tunnel_parm p;
	init_tunnel_parm(&p, ifname);
	p.iph.daddr = dst;
	p.iph.saddr = src;

	bzero(&ifr, sizeof(ifr));
	ifr.ifr_ifru.ifru_data = (void *)&p;

	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
		/* if interface not found, create it */
		strncpy(ifr.ifr_name, "gre0", IFNAMSIZ);

		if (ioctl(fd, SIOCADDTUNNEL, &ifr) < 0) {
			fprintf(stderr, "%s: ioctl(): %s\n", __FUNCTION__, strerror(errno));
			goto ERROR;
		}
	} else { 
		strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
		if (ioctl(fd, SIOCCHGTUNNEL, &ifr) < 0) {
			fprintf(stderr, "%s: ioctl(): %s\n", __FUNCTION__, strerror(errno));
			goto ERROR;
		}
	}

#else
	fprintf(stderr, "os not supported yet\n");
	goto ERROR;
#endif
#endif
	close(fd);
	return 0;
ERROR:
	close(fd);
	return -1;
}

int
gre_set_if_addr(const char *ifname, in_addr_t local, in_addr_t remote, in_addr_t netmask)
{
	int fd;

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("set_if_addr_tunnel: socket");
		return -1;
	}

	struct ifreq ifr;
	bzero(&ifr, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

	/* delete old address */
	/* hack: On linux, add new ip address using ioctl(SIOCSIFADDR) will
	 * actually delete the old one, and SIOCDIFADDR was not supported
	 */
#if defined(__APPLE__) || defined(__FreeBSD__)
	if (ioctl(fd, SIOCDIFADDR, &ifr) < 0) {
		if (errno != EADDRNOTAVAIL) {
			fprintf(stderr, "%s: ioctl(): %s\n", __FUNCTION__, strerror(errno));
			goto ERROR;
		}
	}
#endif

	/* set if local address */
	struct sockaddr_in sa;
	bzero(&sa, sizeof(struct sockaddr_in));
	sa.sin_family = AF_INET;

	sa.sin_addr.s_addr = local;
	bcopy(&sa, &ifr.ifr_addr, sizeof(sa));
#if defined(__APPLE__) || defined(__FreeBSD__)
	((struct sockaddr_in *)&ifr.ifr_addr)->sin_len = sizeof(struct sockaddr_in);
#endif
	if (ioctl(fd, SIOCSIFADDR, &ifr) < 0) {
		fprintf(stderr, "%s: ioctl(): %s\n", __FUNCTION__, strerror(errno));
		goto ERROR;
	}

	/* set if p-p address */
	sa.sin_addr.s_addr = remote;
	bcopy(&sa, &ifr.ifr_addr, sizeof(sa));
#if defined(__APPLE__) || defined(__FreeBSD__)
	((struct sockaddr_in *)&ifr.ifr_addr)->sin_len = sizeof(struct sockaddr_in);
#endif
	if (ioctl(fd, SIOCSIFDSTADDR, &ifr) < 0) {
		fprintf(stderr, "%s: ioctl(): %s\n", __FUNCTION__, strerror(errno));
		goto ERROR;
	}

	if (netmask != INADDR_ANY) {
		/* set if netmask */
		ifr.ifr_addr.sa_family = AF_INET;
		bcopy(&netmask, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, sizeof(netmask));
#if defined(__APPLE__) || defined(__FreeBSD__)
		((struct sockaddr_in *)&ifr.ifr_addr)->sin_len = sizeof(netmask);
#endif
		if (ioctl(fd, SIOCSIFNETMASK, &ifr) < 0) {
			fprintf(stderr, "%s: ioctl(): %s\n", __FUNCTION__, strerror(errno));
			goto ERROR;
		}
	}

	/* let if up */
	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
		fprintf(stderr, "%s: ioctl(): %s\n", __FUNCTION__, strerror(errno));
		goto ERROR;
	}
	if ((ifr.ifr_flags & IFF_UP) == 0) {
		ifr.ifr_flags |= IFF_UP;
		if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
			fprintf(stderr, "%s: ioctl(): %s\n", __FUNCTION__, strerror(errno));
			goto ERROR;
		}
	}

	close(fd);
	return 0;

ERROR:
	close(fd);
	return -1;
}

int
gre_delete_if_tunnel_addr(char ifname[])
{
	int fd;
	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		fprintf(stderr, "%s: socket(): %s\n", __FUNCTION__, strerror(errno));
		return -1;
	}

	struct ifreq ifr;
	bzero(&ifr, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_addr.sa_family = AF_INET;

	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
		fprintf(stderr, "%s: ioctl(): %s\n", __FUNCTION__, strerror(errno));
		goto ERROR;
	}

	if (ifr.ifr_flags & IFF_UP) {
		ifr.ifr_flags &= ~IFF_UP;
		if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
			fprintf(stderr, "%s: ioctl(): %s\n", __FUNCTION__, strerror(errno));
			goto ERROR;
		}
	}

#if defined(__linux__)
	struct ip_tunnel_parm p;
	init_tunnel_parm(&p, ifname);
	ifr.ifr_ifru.ifru_data = (void *)&p;
	if (ioctl(fd, SIOCDELTUNNEL, &ifr) < 0) {
		if (errno != EADDRNOTAVAIL) {
			fprintf(stderr, "%s: ioctl(): %s\n", __FUNCTION__, strerror(errno));
			goto ERROR;
		}
	}

#else
	if (ioctl(fd, SIOCSIFDSTADDR, &ifr) < 0) {
		if (errno != EADDRNOTAVAIL) {
			fprintf(stderr, "%s: ioctl(): %s\n", __FUNCTION__, strerror(errno));
			goto ERROR;
		}
	}

	if (ioctl(fd, SIOCDIFADDR, &ifr) < 0) {
		if (errno != EADDRNOTAVAIL) {
			fprintf(stderr, "%s: ioctl(): %s\n", __FUNCTION__, strerror(errno));
			goto ERROR;
		}
	}

	bzero(&ifr.ifr_addr, sizeof(struct sockaddr));
	if (ioctl(fd, SIOCDIFPHYADDR, &ifr) < 0) {
		if (errno != EADDRNOTAVAIL) {
			fprintf(stderr, "%s: ioctl(): %s\n", __FUNCTION__, strerror(errno));
			goto ERROR;
		}
	}
#endif

	close(fd);
	return 0;
ERROR:
	close(fd);
	return -1;
}

int
gre_remove_tunnel(char ifname[])
{
	int fd;
	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		fprintf(stderr, "%s: socket(): %s\n", __FUNCTION__, strerror(errno));
		return -1;
	}

	struct ifreq ifr;
	bzero(&ifr, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

#if defined(__linux__)
	struct ip_tunnel_parm p;
	init_tunnel_parm(&p, ifname);
	ifr.ifr_ifru.ifru_data = (void *)&p;
	if (ioctl(fd, SIOCDELTUNNEL, &ifr) < 0) {
		if (errno != EADDRNOTAVAIL) {
			fprintf(stderr, "%s: ioctl(): %s\n", __FUNCTION__, strerror(errno));
			goto ERROR;
		}
	}
#else
#endif

	close(fd);
	return 0;
ERROR:
	close(fd);
	return -1;
}


