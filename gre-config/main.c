
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>

#include <sys/ioctl.h>		//ioctl()
#include <sys/socket.h>		//place it before <net/if.h> struct sockaddr
#if defined(__APPLE__) || defined(__linux__)
#include <sys/wait.h>
#endif
#if defined(__FreeBSD__)
#include <sys/param.h>
#include <sys/linker.h>		//kldload()
#include <sys/module.h>		//modfind()
#endif

#include <net/if.h>		//struct ifreq
#if defined(__FreeBSD__)
#include <net/if_var.h>
#endif

#include <netinet/in.h>		//IPPROTO_GRE sturct sockaddr_in INADDR_ANY
#if defined(__APPLE__) || defined(__FreeBSD__)
#include <netinet/in_var.h>	//struct in_aliasreq
#endif

#include <arpa/inet.h>		//inet_aton()
#include <netinet/ip.h>		//struct ip, /* linux: struct iphdr */

#if defined(__linux__)
#include <fcntl.h>			//open()...
#include <linux/if_tunnel.h>	//SIOCADDTUNNEL...
#endif

#include <errno.h>

#include "../route/route_op.h"

#ifndef inet_itoa
#define inet_itoa(x) inet_ntoa(*(struct in_addr*)&(x))
#endif

#if defined(__linux__)
#define GRENAME "greyixun"
#endif

static struct rt_list {
	in_addr_t dst;
	in_addr_t mask;
	struct rt_list *next;
} *rt_list;

static int flag_chksum = 0;
static int flag_revert = 0;
static int flag_changeroute = 0;

static in_addr_t local, remote, src, dst, netmask, gateway;

void parse_args(int argc, char *const argv[]);


int	load_gre_module();

int find_unused_if(char ifname[]);
int find_if_with_addr(char ifname[], in_addr_t src, in_addr_t dst, in_addr_t local, in_addr_t remote);

int set_gre_tunnel(const char *ifname, in_addr_t src, in_addr_t dst);
int set_gre_addrs(const char *ifname, in_addr_t local, in_addr_t remote);

int delete_if_addr_tunnel(char ifname[]);

//int add_gre_if(in_addr_t src, in_addr_t dst, in_addr_t local, in_addr_t remote, in_addr_t mask);
//int remove_gre_if(in_addr_t src, in_addr_t dst, in_addr_t local, in_addr_t remote);

#if defined(__linux__)
static void init_tunnel_parm(struct ip_tunnel_parm *p, const char *name);
#endif


int
main(int argc, char *const argv[])
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
	in_addr_t tmp_dst, tmp_mask, tmp_gateway;

	parse_args(argc, argv);	//处理参数

	if (!flag_revert) {
		/*
		 *  load needed module
		 *  On OSX, that is /Library/Extensions/GRE.kext, by SummerTown
		 *  On FreeBSD, that is if_gre.ko
		 *  On linux, it would be ip_gre.*
		 */
		if (load_gre_module() < 0)
			return -1;

		char ifname[IFNAMSIZ];
		if (find_if_with_addr(ifname, src, dst, local, remote) == 0) {
			fprintf(stderr, "tunnel already exists\n");
			return 0;
		}

		if (find_unused_if(ifname) < 0) {
			fprintf(stderr, "unable to find unused gre interface.\n");
			return -1;
		}

		if (set_gre_tunnel(ifname, src, dst) < 0) {
			fprintf(stderr, "error set tunnel address of %s\n", ifname);
			return -1;
		}

		if (set_gre_addrs(ifname, local, remote) < 0) {
			fprintf(stderr, "error set address of %s\n", ifname);
			return -1;
		}

		/*
		 * hack: if tunnel remote is the same as tunnel interface dst, as we have no 
		 * opportunity to access route directly(Apple has not addressed it to the developer)
		 * , we delete the loopback route. 
		 */
		if (remote == dst) {
			tmp_dst = remote;
			tmp_mask = 0xffffffff;
			if (route_get(&tmp_dst, &tmp_mask, NULL, NULL) == 0 && tmp_dst == remote && tmp_mask == 0xffffffff)
				route_delete(remote, 0xffffffff);
		}

		if (flag_changeroute) {
			struct rt_list *p = rt_list;
			while (rt_list) {
				tmp_dst = rt_list->dst;
				tmp_mask = rt_list->mask;
				tmp_gateway = 0;
				int err = route_get(&tmp_dst, &tmp_mask, &tmp_gateway, ifp);
				if (err || (err == 0 && tmp_dst == 0 && tmp_mask == 0))
					route_add(rt_list->dst, rt_list->mask, gateway ? gateway : tmp_gateway, tmp_gateway ? NULL : ifp);

				p = rt_list->next;
				free(rt_list);
				rt_list = p;
			}

			route_change(0, 0, remote, ifname);
			/*
			   route_delete(0, 0);
			   route_add(0, 0, remote, ifname);
			 */
		}
	} else {
		char ifname[IFNAMSIZ];
		if (find_if_with_addr(ifname, src, dst, local, remote) < 0) {
			fprintf(stderr, "find_if_with_addr(): unable to find gre interface.\n");
			return -1;
		}

		if (delete_if_addr_tunnel(ifname) < 0) {
			fprintf(stderr, "delete_if_addr_tunnel(): unable to delete address of %s\n", ifname);
			return -1;
		}

		if (flag_changeroute) {
			if (gateway)
				route_add(0, 0, gateway, NULL);
			else {
				tmp_dst = dst;
				tmp_mask = 0xffffffff;
				tmp_gateway = 0;
				if (route_get(&tmp_dst, &tmp_mask, &tmp_gateway, ifp) == 0)
					route_add(0, 0, tmp_gateway, tmp_gateway ? NULL : ifp);
				else
					fprintf(stderr, "route_get: error get ori gateway\n");
			}

			struct rt_list *p = rt_list;
			while (rt_list) {
				tmp_dst = rt_list->dst;
				tmp_mask = rt_list->mask;
				if (route_get(&tmp_dst, &tmp_mask, NULL, NULL) == 0) {
					if (tmp_dst == rt_list->dst && tmp_mask == rt_list->mask)
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

void
parse_args(int argc, char *const argv[])
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
		*p = (struct rt_list *)malloc(sizeof(struct rt_list));
		if (*p == NULL) {
			perror("malloc");
			exit(-1);
		}
		strncpy(tmp, argv[ch], sizeof(tmp));
		tmp[sizeof(tmp) - 1] = '\0';

		/* probable address: 1.2.3.4/24, or just 1.2.3.4 */
		instr = tmp;
		par1 = strsep(&instr, "/");	// first part, ip address, ie 1.2.3.4
		par2 = strsep(&instr, "/");	// second part, maskbit len, ie 24, or NULL(if not found)

		(*p)->dst = inet_addr(par1);
		if (par2 && strlen(par2) > 0) {	// maskbit found, the addr is a net address
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
		} else		// maskbit not found, set it to 0xffffffff to indicate it is a host address
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
	fprintf(stderr, "Usage: %s {options} {routes to be changed} {...}\n", argv[0]);
	fputs("  options:\n", stderr);
	fputs("\t-l <local address>\tset address of local host\n", stderr);
	fputs("\t-r <remote address>\tset address of remote host(p-p)\n", stderr);
	fputs("\t-s <src address>\tset address of tunnel src\n", stderr);
	fputs("\t-d <dst address>\tset address of tunnel dst\n", stderr);
	fputs("\t-n <netmask>\t\tset interface netmask\n", stderr);
	fputs("\t-C <route>\t\tchange default route\n", stderr);
	fputs("\t-c\t\t\ttun on tunnel checksum\n", stderr);
	fputs("\t-u\t\t\trevert the changes, ie, remove tunnel, etc.\n", stderr);

	exit(-1);
}

int
load_gre_module()
{
#if defined(__APPLE__)
	fprintf(stderr, "OSX, kextload GRE.kext\n");
	int pid;
	if ((pid = fork()) < 0)
		return -1;

	if (pid == 0) {
		execle("/sbin/kextload", "kextload", "/Library/Extensions/GRE.kext", NULL, NULL);
		exit(1);
	}

	while (waitpid(pid, 0, 0) < 0) {
		if (errno == EINTR)
			continue;
		return -1;
	}
	return 0;
#else
#if defined(__FreeBSD__)
	if (modfind("if_gre") < 0) {
#ifdef DEBUG
		fprintf(stderr, "FreeBSD, kldload if_gre\n");
#endif
		if (kldload("if_gre") < 0) {
			perror("can't load if_gre");
			return -1;
		}
	}
	return 0;
#else
#if defined(__linux__)
	fprintf(stderr, "Linux, insmod ip_gre\n");
	int fd;
	char buff[128];
	if ((fd = open("/proc/modules", O_RDONLY)) >= 0) {
		int i;
		while ((i = read(fd, buff, sizeof(buff)) > 0)) {
			if (strstr(buff, "ip_gre")) {
				close(fd);
				return 0;
			}
		}
		close(fd);
		/* module ip_gre not found, try to load ip_gre */
		fprintf(stderr, "load ip_gre...\n");
		int pid;
		if ((pid = fork()) < 0)
			return -1;

		if (pid == 0) {
			execle("/sbin/modprobe", "modprobe", "ip_gre", NULL, NULL);
			execle("/sbin/insmod", "insmod", "ip_gre", NULL, NULL);
			exit(1);
		}

		while (waitpid(pid, 0, 0) < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		return 0;
	}
	return -1;
#else
	fprintf(stderr, "%s: Your OS is not supported yet\n", __FUNCTION__);
	return -1;
#endif
#endif
#endif
}

#define MAX_GREIF_CNT 16
int
find_unused_if(char ifname[])
{
	int fd;
	struct ifreq ifr;

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("find_unused_if: socket");
		return -1;
	}

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
	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
		fprintf(stderr, "%s ioctl(gre0):%s\n", __FUNCTION__, strerror(errno));
		goto ERROR;
	}
	strncpy(ifname, GRENAME, IFNAMSIZ);

#else
	int i;
	for (i = 0; i < MAX_GREIF_CNT; i++) {
		bzero(&ifr, sizeof(ifr));
		sprintf(ifr.ifr_name, "gre%d", i);
		if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0)
			continue;
		if ((ifr.ifr_flags & IFF_UP) == 0) {
			strcpy(ifname, ifr.ifr_name);
			break;
		}
	}

#if defined(__FreeBSD__)
	if (i >= MAX_GREIF_CNT) {
		i = 0;
		bzero(&ifr, sizeof(ifr));
		strncpy(ifr.ifr_name, "gre", IFNAMSIZ);
		if (ioctl(fd, SIOCIFCREATE2, &ifr) < 0) {
			fprintf(stderr, "%s ioctl(SIOCIFCREATE2):%s\n", __FUNCTION__, strerror(errno));
			goto ERROR;
		}

		if (strncmp("gre", ifr.ifr_name, sizeof(ifr.ifr_name)) != 0)
			strncpy(ifname, ifr.ifr_name, IFNAMSIZ);
		else
			goto ERROR;
	}
#endif
	if (i >= MAX_GREIF_CNT)
		goto ERROR;
#endif

	close(fd);
	return 0;
ERROR:
	close(fd);
	return -1;
}

int
find_if_with_addr(char ifname[], in_addr_t src, in_addr_t dst, in_addr_t local, in_addr_t remote)
{
	int i;
	int fd;
	struct ifreq ifr;

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("find_unused_if: socket");
		return -1;
	}
#if defined(__linux__)
	struct ip_tunnel_parm p;
	i = MAX_GREIF_CNT;
	bzero(&ifr, sizeof(ifr));
	strncpy(ifr.ifr_name, GRENAME, IFNAMSIZ);
	init_tunnel_parm(&p, GRENAME);
	ifr.ifr_ifru.ifru_data = (void *)&p;

	if (ioctl(fd, SIOCGETTUNNEL, &ifr) < 0)
		goto ERROR;
	if (p.iph.protocol != IPPROTO_GRE)
		goto ERROR;
	if (p.iph.daddr != dst || p.iph.saddr != src)
		goto ERROR;
	/* get if local address */
	if (ioctl(fd, SIOCGIFADDR, &ifr) < 0)
		goto ERROR;
	if (((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr != local)
		goto ERROR;

	/* get if p-p address */
	if (ioctl(fd, SIOCGIFDSTADDR, &ifr) < 0)
		goto ERROR;
	if (((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr != remote)
		goto ERROR;

	strcpy(ifname, ifr.ifr_name);
	i = 0;

ERROR:

#else
	for (i = 0; i < MAX_GREIF_CNT; i++) {
		bzero(&ifr, sizeof(ifr));
		sprintf(ifr.ifr_name, "gre%d", i);

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
		//printf("find one: %s\n", ifr.ifr_name);
		strcpy(ifname, ifr.ifr_name);
		break;
	}
#endif

	close(fd);
	return i < MAX_GREIF_CNT ? 0 : -1;
}

int
set_gre_tunnel(const char *ifname, in_addr_t src, in_addr_t dst)
{
	int fd;

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		fprintf(stderr, "%s: socket(): %s\n", __FUNCTION__, strerror(errno));
		return -1;
	}

	struct ifreq ifr;
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
set_gre_addrs(const char *ifname, in_addr_t local, in_addr_t remote)
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
delete_if_addr_tunnel(char ifname[])
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

