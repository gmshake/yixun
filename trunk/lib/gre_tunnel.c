/*
 * gre_tunnel.c
 * gre tunnel ops
 * By Summer Town
 * 2011.04.16
 */
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/ioctl.h>		/* ioctl() */
#include <sys/socket.h>		/* struct sockaddr */

#include <netinet/in.h>		/* IPPROTO_GRE sturct sockaddr_in INADDR_ANY */
#include <netinet/ip.h>		/* struct ip, linux: struct iphdr */
#include <net/if.h>		/* struct ifreq */

#if defined(__APPLE__) || defined(__FreeBSD__)
#include <net/if_var.h>		/* struct ifaddr */
#include <netinet/in_var.h>	/* struct in_aliasreq */
#endif

#if defined(__linux__)
#include <fcntl.h>			/* open()... */
#include <net/if_arp.h>		/* ARPHRD_IPGRE */
#include <linux/if_tunnel.h>	/* SIOCADDTUNNEL... */
#endif

#include "sys.h"		/* strlcpy() */

#if defined(__linux__)
#define GRENAME "greyixun"
#endif

#if defined(__linux__)
static void
init_tunnel_parm(struct ip_tunnel_parm *p, const char *name)
{
	bzero(p, sizeof(*p));
	strncpy(p->name, name, sizeof(p->name));
	p->iph.version = 4;
	p->iph.ihl = 5;
	p->iph.frag_off = htons(IP_DF);
	p->iph.protocol = IPPROTO_GRE;
	p->iph.ttl = 30;
}

static int
get_ifindex(const char *ifname)
{
	int fd;
	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		fprintf(stderr, "%s: socket(): %s\n", \
				__FUNCTION__, strerror(errno));
		return -1;
	}

	struct ifreq ifr;
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
		close(fd);
		return -1;
	}

	close(fd);
	return ifr.ifr_ifindex;
}
#endif

int
gre_find_unused_tunnel(char *ifname)
{
	int fd;
	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		fprintf(stderr, "%s: socket(): %s\n", \
				__FUNCTION__, strerror(errno));
		return -1;
	}

	struct ifreq ifr;
#if defined(__APPLE__) || defined(__FreeBSD__)
	bzero(ifname, IFNAMSIZ);
	struct if_nameindex *p, *ifn = if_nameindex();
	for (p = ifn; p->if_index && p->if_name; p++) {
		if (strncmp(p->if_name, "gre", 3))
			continue;
		bzero(&ifr, sizeof(ifr));
		strncpy(ifr.ifr_name, p->if_name, sizeof(ifr.ifr_name));
		if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0)
			continue;
		if (!(ifr.ifr_flags & IFF_UP)) {
			strlcpy(ifname, ifr.ifr_name, IFNAMSIZ);
			break;
		}
	}
	if_freenameindex(ifn);

#if defined(__FreeBSD__)
	/* if all greS are up, then we create a new one */
	if (ifname[0] == '\0') {
		bzero(&ifr, sizeof(ifr));
		strncpy(ifr.ifr_name, "gre", sizeof(ifr.ifr_name));
		if (ioctl(fd, SIOCIFCREATE2, &ifr) < 0)
			fprintf(stderr, "%s ioctl(SIOCIFCREATE2):%s\n", \
					__FUNCTION__, strerror(errno));
		else if (strncmp("gre", ifr.ifr_name, sizeof(ifr.ifr_name)) != 0)
			strlcpy(ifname, ifr.ifr_name, IFNAMSIZ);
	}
#endif

#elif defined(__linux__)
	/*
	 * hack: On linux, there will allways be a gre0 interface available
	 * if ip_gre.* is loaded into kernel.
	 * And, if you create a tunnel without local or remote parameter, 
	 * ioctl(fd, SIOCADDTUNNEL, &ifr) will not return a error, but
	 * you will NOT get the requied tunnel interface
	 * further more, if a tunnel is NOT p-t-p device, you can NOT assign
	 * a p-t-p address to it.
	 * So, here, we check if GRENAME exists, and if GNENAME is a p-t-p
	 * tunnel, we delete it and then try to re-create it in gre_set_tunnel()
	 */

	if (ifname[0] == '\0')
		strlcpy(ifname, GRENAME, IFNAMSIZ);

	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0)
		goto DONE; /* ifname not used yet */
	if (ifr.ifr_addr.sa_family != ARPHRD_IPGRE)
		goto NOTFOUND;
	if (ioctl(fd, SIOCGIFFLAGS, &ifr) == 0) {
		if (! (ifr.ifr_flags & IFF_POINTOPOINT)) {
			/* try to delete the tunnel */
			struct ip_tunnel_parm parm;
			bzero(&parm, sizeof(parm));

			ifr.ifr_ifru.ifru_data = (void *)&parm;
			if (ioctl(fd, SIOCDELTUNNEL, &ifr) < 0) {
				fprintf(stderr, "%s ioctl(SIOCDELTUNNEL):%s\n", \
						__FUNCTION__, strerror(errno));
				bzero(ifname, IFNAMSIZ);
				goto NOTFOUND;
			}
		}
	}
	goto DONE;

NOTFOUND:
	bzero(ifname, IFNAMSIZ);
DONE:
#else
#error Target OS not supported yet!
#endif

	close(fd);
	return ifname[0] ? 0 : -1;
}


int
gre_get_tunnel(const char *ifname, in_addr_t *src, in_addr_t *dst)
{
	int fd;
	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		fprintf(stderr, "%s: socket(): %s\n", \
				__FUNCTION__, strerror(errno));
		return -1;
	}

	struct ifreq ifr;
	bzero(&ifr, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	/* set to 0.0.0.0 */
	*dst = *src = 0;

#if defined(__APPLE__) || defined(__FreeBSD__)
	/* BSD/Darwin version, get tunnel src, dst addr */
	/* get tunnel src address */
	if (ioctl(fd, SIOCGIFPSRCADDR, &ifr) < 0) {
#ifdef DEBUG
		fprintf(stderr, "%s: ioctl(SIOCGIFPSRCADDR): %s\n", \
				__FUNCTION__, strerror(errno));
#endif
		goto NOTFOUND;
	}
	*src = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;

	/* get tunnel dst address */
	if (ioctl(fd, SIOCGIFPDSTADDR, &ifr) < 0) {
#ifdef DEBUG
		fprintf(stderr, "%s: ioctl(SIOCGIFPDSTADDR): %s\n", \
				__FUNCTION__, strerror(errno));
#endif
		goto NOTFOUND;
	}
	*dst = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;

#elif defined(__linux__)
	/*
	 * IMPORTANT, other kind of tunnel such as ppp tunnel do NOT use
	 * struct ip_tunnel_parm.
	 */
	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0)
		goto NOTFOUND;
	if (ifr.ifr_addr.sa_family != ARPHRD_IPGRE)
		goto NOTFOUND;

	struct ip_tunnel_parm parm;
	bzero(&parm, sizeof(parm));
	ifr.ifr_ifru.ifru_data = (void *)&parm;

	if (ioctl(fd, SIOCGETTUNNEL, &ifr) < 0) {
#ifdef DEBUG
		fprintf(stderr, "%s: ioctl(SIOCGETTUNNEL): %s\n", \
				__FUNCTION__, strerror(errno));
#endif
		goto NOTFOUND;
	}
	if (parm.iph.protocol != IPPROTO_GRE)
		goto NOTFOUND;
	*src = parm.iph.saddr;
	*dst = parm.iph.daddr;
#else
#error Target OS not supported yet!
#endif

	close(fd);
	return 0;
NOTFOUND:
	close(fd);
	return -1;
}

int
gre_get_addr(const char *ifname, in_addr_t *local, in_addr_t *remote)
{
	int fd;
	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		fprintf(stderr, "%s: socket(): %s\n", \
				__FUNCTION__, strerror(errno));
		return -1;
	}

	/* set to 0.0.0.0 */
	*remote = *local = 0;

	struct ifreq ifr;
	bzero(&ifr, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	/* get if local address */
	if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
#ifdef DEBUG
		fprintf(stderr, "%s: ioctl(SIOCGIFADDR): %s\n", \
				__FUNCTION__, strerror(errno));
#endif
		goto NOTFOUND;
	}
	*local = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;

	/* get if p-p address */
	if (ioctl(fd, SIOCGIFDSTADDR, &ifr) < 0) {
#ifdef DEBUG
		fprintf(stderr, "%s: ioctl(SIOCGIFDSTADDR): %s\n", \
				__FUNCTION__, strerror(errno));
#endif
		goto NOTFOUND;
	}
	*remote = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;

	close(fd);
	return 0;
NOTFOUND:
	close(fd);
	return -1;
}

int
gre_find_tunnel_with_addr(char *ifname, in_addr_t src, in_addr_t dst, in_addr_t local, in_addr_t remote)
{
	int fd;

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		fprintf(stderr, "%s: socket(): %s\n", \
				__FUNCTION__, strerror(errno));
		return -1;
	}

	bzero(ifname, IFNAMSIZ);

	in_addr_t tsrc, tdst, tlocal, tremote;

	struct if_nameindex *ifn = if_nameindex();
	struct if_nameindex *p;
	for (p = ifn; p->if_index && p->if_name; p++) {
		if (gre_get_tunnel(p->if_name, &tsrc, &tdst) < 0)
			continue;

		if (src != tsrc || dst != tdst)
			continue;

		if (local) {
			if (gre_get_addr(p->if_name, &tlocal, &tremote) < 0)
				continue;

			if (local != tlocal || remote != tremote)
				continue;
		}

		/* we have found one, and just find only one */
		strlcpy(ifname, p->if_name, IFNAMSIZ);
		break;
	}
	if_freenameindex(ifn);

	close(fd);
	return ifname[0] ? 0 : -1;
}

int
gre_set_tunnel(const char *ifname, in_addr_t src, in_addr_t dst)
{
	int fd;
	struct ifreq ifr;

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		fprintf(stderr, "%s: socket(): %s\n", \
				__FUNCTION__, strerror(errno));
		return -1;
	}

	bzero(&ifr, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

#if defined(__APPLE__) || defined(__FreeBSD__)
	if (ioctl(fd, SIOCDIFPHYADDR, &ifr) < 0) {
		if (errno != EADDRNOTAVAIL) {
			fprintf(stderr, "%s: ioctl(SIOCDIFPHYADDR): %s\n", \
					__FUNCTION__, strerror(errno));
			goto ERROR;
		}
	}
	struct in_aliasreq in_req;
	bzero(&in_req, sizeof(struct in_aliasreq));

	strncpy(in_req.ifra_name, ifname, sizeof(in_req.ifra_name));
	in_req.ifra_addr.sin_family = AF_INET;
	in_req.ifra_addr.sin_len = sizeof(struct sockaddr_in);
	in_req.ifra_addr.sin_addr.s_addr = src;

	in_req.ifra_dstaddr.sin_family = AF_INET;
	in_req.ifra_dstaddr.sin_len = sizeof(struct sockaddr_in);
	in_req.ifra_dstaddr.sin_addr.s_addr = dst;

	if (ioctl(fd, SIOCSIFPHYADDR, &in_req) < 0) {
		fprintf(stderr, "%s: ioctl(SIOCSIFPHYADDR): %s\n", \
				__FUNCTION__, strerror(errno));
		goto ERROR;
	}
#elif defined(__linux__)
	int exist;
	exist = ! ioctl(fd, SIOCGIFFLAGS, &ifr);
	/* should we check if tunnel has p-t-p flag ??? */

	struct ip_tunnel_parm parm;
	init_tunnel_parm(&parm, ifname);
	parm.iph.daddr = dst;
	parm.iph.saddr = src;
	/* should we find the device which has ip address src ??? */
	//parm.link = ??;

	bzero(&ifr, sizeof(ifr));
	strncpy(ifr.ifr_name, exist ? ifname : "gre0", sizeof(ifr.ifr_name));
	ifr.ifr_ifru.ifru_data = (void *)&parm;

	if (ioctl(fd, exist ? SIOCCHGTUNNEL : SIOCADDTUNNEL, &ifr) < 0) {
#ifdef DEBUG
		fprintf(stderr, "%s: ioctl(%s): %s\n", \
				__FUNCTION__, ifr.ifr_name, strerror(errno));
#endif
		goto ERROR;
	}

#else
#error Target OS not supported yet!
#endif
	close(fd);
	return 0;
ERROR:
	close(fd);
	return -1;
}



int
gre_set_addr(const char *ifname, in_addr_t local, in_addr_t remote, in_addr_t netmask)
{
	int fd;

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		fprintf(stderr, "%s: socket(): %s\n", \
				__FUNCTION__, strerror(errno));
		return -1;
	}

	struct ifreq ifr;
	bzero(&ifr, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	/* delete old address */
	/* hack: On linux, add new ip address using ioctl(SIOCSIFADDR) will
	 * actually delete the old one, and SIOCDIFADDR was not supported
	 */
#if defined(__APPLE__) || defined(__FreeBSD__)
	if (ioctl(fd, SIOCDIFADDR, &ifr) < 0) {
		if (errno != EADDRNOTAVAIL) {
			fprintf(stderr, "%s: ioctl(SIOCDIFADDR): %s\n", \
					__FUNCTION__, strerror(errno));
			goto ERROR;
		}
	}
#endif

	/* set if local address */
	struct sockaddr_in sa;
	bzero(&sa, sizeof(struct sockaddr_in));
	sa.sin_family = AF_INET;

	sa.sin_addr.s_addr = local;
	memcpy(&ifr.ifr_addr, &sa, sizeof(sa));
#if defined(__APPLE__) || defined(__FreeBSD__)
	((struct sockaddr_in *)&ifr.ifr_addr)->sin_len = sizeof(sa);
#endif
	if (ioctl(fd, SIOCSIFADDR, &ifr) < 0) {
		fprintf(stderr, "%s: ioctl(SIOCSIFADDR): %s\n", \
				__FUNCTION__, strerror(errno));
		goto ERROR;
	}

	/* set if p-t-p address */
	sa.sin_addr.s_addr = remote;
	memcpy(&ifr.ifr_addr, &sa, sizeof(sa));
#if defined(__APPLE__) || defined(__FreeBSD__)
	((struct sockaddr_in *)&ifr.ifr_addr)->sin_len = sizeof(sa);
#endif
	if (ioctl(fd, SIOCSIFDSTADDR, &ifr) < 0) {
		fprintf(stderr, "%s: ioctl(SIOCSIFDSTADDR): %s\n", \
				__FUNCTION__, strerror(errno));
		goto ERROR;
	}

	if (netmask != INADDR_ANY) {
		/* set if netmask */
		ifr.ifr_addr.sa_family = AF_INET;
		memcpy(&((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, &netmask, sizeof(netmask));
#if defined(__APPLE__) || defined(__FreeBSD__)
		((struct sockaddr_in *)&ifr.ifr_addr)->sin_len = sizeof(netmask);
#endif
		if (ioctl(fd, SIOCSIFNETMASK, &ifr) < 0) {
			fprintf(stderr, "%s: ioctl(SIOCSIFNETMASK): %s\n", \
					__FUNCTION__, strerror(errno));
			goto ERROR;
		}
	}

	/* let if up */
	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
		fprintf(stderr, "%s: ioctl(SIOCGIFFLAGS): %s\n", \
				__FUNCTION__, strerror(errno));
		goto ERROR;
	}
	if (! (ifr.ifr_flags & IFF_UP)) {
		ifr.ifr_flags |= IFF_UP;
		if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
			fprintf(stderr, "%s: ioctl(SIOCSIFFLAGS): %s\n", \
					__FUNCTION__, strerror(errno));
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
gre_set_link(const char *ifname, int up)
{
	int fd;

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		fprintf(stderr, "%s: socket(): %s\n", \
				__FUNCTION__, strerror(errno));
		return -1;
	}

	struct ifreq ifr;
	bzero(&ifr, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
		fprintf(stderr, "%s: ioctl(SIOCGIFFLAGS): %s\n", \
				__FUNCTION__, strerror(errno));
		goto ERROR;
	}

	int is_up = ifr.ifr_flags & IFF_UP;
	if (up) {
		if (!is_up)
			ifr.ifr_flags |= IFF_UP;
	} else {
		if (is_up)
			ifr.ifr_flags &= ~IFF_UP;
	}

	if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
		fprintf(stderr, "%s: ioctl(SIOCSIFFLAGS): %s\n", \
				__FUNCTION__, strerror(errno));
		goto ERROR;
	}

	close(fd);
	return 0;

ERROR:
	close(fd);
	return -1;
}


int
gre_delete_tunnel_addr(const char *ifname)
{
	int fd;
	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		fprintf(stderr, "%s: socket(): %s\n", \
				__FUNCTION__, strerror(errno));
		return -1;
	}

	struct ifreq ifr;
	bzero(&ifr, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	ifr.ifr_addr.sa_family = AF_INET;

	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
		fprintf(stderr, "%s: ioctl(SIOCGIFFLAGS): %s\n", \
				__FUNCTION__, strerror(errno));
		goto ERROR;
	}

	/* make the interface down */
	if (ifr.ifr_flags & IFF_UP) {
		ifr.ifr_flags &= ~IFF_UP;
		if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
			fprintf(stderr, "%s: ioctl(SIOCSIFFLAGS): %s\n", \
					__FUNCTION__, strerror(errno));
			goto ERROR;
		}
	}

#if defined(__APPLE__) || defined(__FreeBSD__)
	/* delete p-t-p address */
	if (ioctl(fd, SIOCSIFDSTADDR, &ifr) < 0) {
		if (errno != EADDRNOTAVAIL) {
			fprintf(stderr, "%s: ioctl(SIOCSIFDSTADDR): %s\n", \
					__FUNCTION__, strerror(errno));
			goto ERROR;
		}
	}

	/* delete local address */
	if (ioctl(fd, SIOCDIFADDR, &ifr) < 0) {
		if (errno != EADDRNOTAVAIL) {
			fprintf(stderr, "%s: ioctl(SIOCDIFADDR): %s\n", \
					__FUNCTION__, strerror(errno));
			goto ERROR;
		}
	}

	/* delete tunnel src/dst address */
	bzero(&ifr.ifr_addr, sizeof(struct sockaddr));
	if (ioctl(fd, SIOCDIFPHYADDR, &ifr) < 0) {
		if (errno != EADDRNOTAVAIL) {
			fprintf(stderr, "%s: ioctl(SIOCDIFPHYADDR): %s\n", \
					__FUNCTION__, strerror(errno));
			goto ERROR;
		}
	}
#elif defined(__linux__)
	/*
	 * hack: linux does NOT support SIOCDIFADDR,
	 * assign a 0.0.0.0 to the interface acctully
	 * has the same effect with SIOCDIFADDR 
	 */
	/* delete if local address */
	struct sockaddr_in sa;
	bzero(&sa, sizeof(struct sockaddr_in));
	sa.sin_family = AF_INET;

	sa.sin_addr.s_addr = 0;
	memcpy(&ifr.ifr_addr, &sa, sizeof(sa));
	if (ioctl(fd, SIOCSIFADDR, &ifr) < 0) {
		fprintf(stderr, "%s: ioctl(SIOCSIFADDR): %s\n", \
				__FUNCTION__, strerror(errno));
		goto ERROR;
	}

	/* delete if p-p address */
	sa.sin_addr.s_addr = 0;
	memcpy(&ifr.ifr_addr, &sa, sizeof(sa));
	if (ioctl(fd, SIOCSIFDSTADDR, &ifr) < 0) {
		fprintf(stderr, "%s: ioctl(SIOCSIFDSTADDR): %s\n", \
				__FUNCTION__, strerror(errno));
		goto ERROR;
	}

	/* delete tunnel src/dst address as well?
	 * sigh~, linux ip_gre does NOT support it
	 */

#else
#error Target OS not supported yet!
#endif

	close(fd);
	return 0;
ERROR:
	close(fd);
	return -1;
}

int
gre_remove_tunnel(const char *ifname)
{
	int fd;
	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		fprintf(stderr, "%s: socket(): %s\n", \
				__FUNCTION__, strerror(errno));
		return -1;
	}

	struct ifreq ifr;
	bzero(&ifr, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

#if defined(__FreeBSD__)
	fprintf(stderr, "BSD version remove tunnel, TOTO...\n");
#elif defined(__APPLE__)
	fprintf(stderr, "OSX version remove tunnel, TOTO...\n");

#elif defined(__linux__)
	struct ip_tunnel_parm p;
	init_tunnel_parm(&p, ifname);
	ifr.ifr_ifru.ifru_data = (void *)&p;
	if (ioctl(fd, SIOCDELTUNNEL, &ifr) < 0) {
		if (errno != ENODEV) {
			fprintf(stderr, "%s: ioctl(SIOCDELTUNNEL): %s\n", \
					__FUNCTION__, strerror(errno));
			goto ERROR;
		}
	}
#else
#error Target OS not supported yet!
#endif

	close(fd);
	return 0;
ERROR:
	close(fd);
	return -1;
}


