
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
#include <linux/if_tunnel.h>	//SIOCADDTUNNEL, SIOCGETTUNNEL, SIOCDELTUNNEL
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

int set_if_addr_tunnel(char ifname[], in_addr_t src, in_addr_t dst, in_addr_t local, in_addr_t remote, in_addr_t mask);
int delete_if_addr_tunnel(char ifname[]);

int add_gre_if(in_addr_t src, in_addr_t dst, in_addr_t local, in_addr_t remote, in_addr_t mask);
int remove_gre_if(in_addr_t src, in_addr_t dst, in_addr_t local, in_addr_t remote);

#if defined(__linux__)
static int linux_gre_yixun_clonecreate();
#endif

#if defined(__FreeBSD__)
static int bsd_gre_if_clonecreate(char name[]);
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
		char ifname[IFNAMSIZ];
		if (find_unused_if(ifname) < 0) {
			fprintf(stderr, "unable to find unused gre interface.\n");
			return -1;
		}

		if (set_if_addr_tunnel(ifname, src, dst, local, remote, netmask) < 0) {
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
		if (remove_gre_if(src, dst, local, remote) < 0)
			return -1;

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

int
load_gre_module()
{
#if defined(__APPLE__)
	printf("OSX, kextload GRE.kext\n");
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
	printf("FreeBSD, kldload if_gre\n");
	if (modfind("if_gre") < 0) {
		printf("load if_gre...\n");
		if (kldload("if_gre") < 0) {
			perror("can't load if_gre");
			return -1;
		}
	}
	return 0;
#else
#if defined(__linux__)
	printf("Linux, insmod ip_gre\n");
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
		printf("load ip_gre...\n");
		int pid;
		if ((pid = fork()) < 0)
			return -1;

		if (pid == 0) {
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
	fprintf(stderr, "%s: OS not supported\n", __FUNCTION__);
	return -1;
#endif
#endif
#endif
}

#define MAX_GREIF_CNT 16
int
find_unused_if(char ifname[])
{
	int sock;
	struct ifreq ifrq;

	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("find_unused_if: socket");
		return -1;
	}

#if defined(__linux__)
	bzero(&ifrq, sizeof(ifrq));
	sprintf(ifrq.ifr_name, GRENAME);
	if (ioctl(sock, SIOCGIFFLAGS, &ifrq) < 0) {
		if (linux_gre_yixun_clonecreate() < 0) {
			fprintf(stderr, "%s ioctl(\"%s\"):%s\n", __FUNCTION__, GRENAME, strerror(errno));
			close(sock);
			return -1;
		}
	}

	close(sock);
	strcpy(ifname, GRENAME);
	return 0;
#else
	int i;
	for (i = 0; i < MAX_GREIF_CNT; i++) {
		bzero(&ifrq, sizeof(ifrq));
		sprintf(ifrq.ifr_name, "gre%d", i);
		if (ioctl(sock, SIOCGIFFLAGS, &ifrq) < 0)
			continue;
		if ((ifrq.ifr_flags & IFF_RUNNING) == 0) {
			strcpy(ifname, ifrq.ifr_name);
			break;
		}
	}

	close(sock);

#if defined(__FreeBSD__)
	if (i >= MAX_GREIF_CNT)
		if (bsd_gre_if_clonecreate(ifname) < 0)
			return -1;
#endif

	return i < MAX_GREIF_CNT ? 0 : -1;
#endif
}

int
find_if_with_addr(char ifname[], in_addr_t src, in_addr_t dst, in_addr_t local, in_addr_t remote)
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

#if defined(__APPLE__) || defined(__FreeBSD__)
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
#else				// Linux
		struct ip_tunnel_parm parm;
		bzero(&parm, sizeof(struct ip_tunnel_parm));
		ifrq.ifr_ifru.ifru_data = (void *)&parm;
		if (ioctl(sock, SIOCGETTUNNEL, &ifrq) < 0)
			continue;
		if (parm.iph.protocol != IPPROTO_GRE)
			continue;
		if (parm.iph.daddr != dst || parm.iph.saddr != src)
			continue;
#endif

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

int
set_if_addr_tunnel(char ifname[], in_addr_t src, in_addr_t dst, in_addr_t local, in_addr_t remote, in_addr_t mask)
{
	int sock;

	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("set_if_addr_tunnel: socket");
		return -1;
	}

	struct ifreq ifrq;
	bzero(&ifrq, sizeof(ifrq));
	strncpy(ifrq.ifr_name, ifname, IFNAMSIZ);

#if defined(__APPLE__) || defined(__FreeBSD__)
	if (ioctl(sock, SIOCDIFPHYADDR, &ifrq) < 0) {
		if (errno != EADDRNOTAVAIL) {
			perror("set_if_addr_tunnel: delete tunnel addr");
			goto ERROR;
		}
	}
#endif

	if (ioctl(sock, SIOCDIFADDR, &ifrq) < 0) {
		if (errno != EADDRNOTAVAIL) {
			perror("set_if_addr_tunnel: delete if addr");
			goto ERROR;
		}
	}

	/* set tunnel src and dst address */
#if defined(__APPLE__) || defined(__FreeBSD__)
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
#else
	struct ip_tunnel_parm parm;
	bzero(&parm, sizeof(struct ip_tunnel_parm));
	parm.iph.protocol = IPPROTO_GRE;
	parm.iph.daddr = dst;
	parm.iph.saddr = src;
	ifrq.ifr_ifru.ifru_data = (void *)&parm;
	if (ioctl(sock, SIOCADDTUNNEL, &ifrq) < 0) {
		perror("set_if_addr_tunnel: set if tunnel address");
		goto ERROR;
	}
#endif

	/* set if local address */
	struct sockaddr_in sa;
	bzero(&sa, sizeof(struct sockaddr_in));
	sa.sin_family = AF_INET;

	sa.sin_addr.s_addr = local;
	bcopy(&sa, &ifrq.ifr_addr, sizeof(sa));
#if defined(__APPLE__) || defined(__FreeBSD__)
	((struct sockaddr_in *)&ifrq.ifr_addr)->sin_len = sizeof(struct sockaddr_in);
#endif
	if (ioctl(sock, SIOCSIFADDR, &ifrq) < 0) {
		perror("set_if_addr_tunnel: set if local address");
		goto ERROR;
	}

	/* set if p-p address */
	sa.sin_addr.s_addr = remote;
	bcopy(&sa, &ifrq.ifr_addr, sizeof(sa));
#if defined(__APPLE__) || defined(__FreeBSD__)
	((struct sockaddr_in *)&ifrq.ifr_addr)->sin_len = sizeof(struct sockaddr_in);
#endif
	if (ioctl(sock, SIOCSIFDSTADDR, &ifrq) < 0) {
		perror("set_if_addr_tunnel: set if remote address");
		goto ERROR;
	}

	if (netmask != INADDR_ANY) {
		/* set if netmask */
		ifrq.ifr_addr.sa_family = AF_INET;
		bcopy(&netmask, &((struct sockaddr_in *)&ifrq.ifr_addr)->sin_addr, sizeof(netmask));
#if defined(__APPLE__) || defined(__FreeBSD__)
		((struct sockaddr_in *)&ifrq.ifr_addr)->sin_len = sizeof(netmask);
#endif
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

int
delete_if_addr_tunnel(char ifname[])
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
#if defined(__APPLE__) || defined(__FreeBSD__)
	bzero(&ifrq.ifr_addr, sizeof(struct sockaddr));
	if (ioctl(sock, SIOCDIFPHYADDR, &ifrq) < 0) {
		if (errno != EADDRNOTAVAIL) {
			perror("delete_if_addr_tunnel: delete tunnel addr");
			goto ERROR;
		}
	}
#else
	struct ip_tunnel_parm parm;
	bzero(&parm, sizeof(struct ip_tunnel_parm));
	parm.iph.protocol = IPPROTO_GRE;
	ifrq.ifr_ifru.ifru_data = (void *)&parm;
	if (ioctl(sock, SIOCDELTUNNEL, &ifrq) < 0) {
		if (errno != EADDRNOTAVAIL) {
			perror("delete_if_addr_tunnel: delete tunnel addr");
			goto ERROR;
		}
	}
#endif

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

#if defined(__linux__)
static int
linux_gre_yixun_clonecreate()
{
	return -1;
}
#endif

#if defined(__FreeBSD__)
static int
bsd_gre_if_clonecreate(char name[])
{
	int sock;
	struct ifreq ifr;

	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("bsd_gre_if_clonecreate: socket");
		return -1;
	}

	bzero(&ifr, sizeof(ifr));
	(void)strlcpy(ifr.ifr_name, "gre", sizeof(ifr.ifr_name));
	if (ioctl(sock, SIOCIFCREATE2, &ifr) < 0) {
		perror("SIOCIFCREATE2");
		goto ERROR;
	}

	if (strncmp("gre", ifr.ifr_name, sizeof(ifr.ifr_name)) != 0) {
		strlcpy(name, ifr.ifr_name, sizeof(ifr.ifr_name));
#ifdef DEBUG
		printf("%s\n", name);
#endif
		close(sock);
		return 0;
	}

ERROR:
	close(sock);
	return -1;
}
#endif

int
add_gre_if(in_addr_t src, in_addr_t dst, in_addr_t local, in_addr_t remote, in_addr_t mask)
{
	if (load_gre_module() < 0)
		return -1;
	char ifname[IFNAMSIZ];
	if (find_unused_if(ifname) < 0) {
		fprintf(stderr, "%s: unable to find unused gre interface.\n", __FUNCTION__);
		return -1;
	}

	if (set_if_addr_tunnel(ifname, src, dst, local, remote, mask) < 0) {
		fprintf(stderr, "%s: error set address of %s\n", __FUNCTION__, ifname);
		return -1;
	}

	return 0;
}


int
remove_gre_if(in_addr_t src, in_addr_t dst, in_addr_t local, in_addr_t remote)
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
