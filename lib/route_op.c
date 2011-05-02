/*
 * route_op.c
 * by SummerTown
 * 2011.01.01 12:07 am
 */

#include <unistd.h>
#include <sys/socket.h>		/* struct sockaddr */
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include <sys/ioctl.h>		/* ioctl() */
#include <net/if.h>		/* struct ifreq */

#if defined(__APPLE__) || defined(__FreeBSD__)
#include <net/if_dl.h>		/* struct sockaddr_dl */
#endif

#include <netinet/in.h>		/* IPPROTO_GRE sturct sockaddr_in INADDR_ANY */
#include <arpa/inet.h>		/* inet_addr() */
#include <net/route.h>		/* struct rt_msghdr, linux struct rtentry */
#include <ifaddrs.h>		/* getifaddrs() freeifaddrs() */

#include <errno.h>

#if defined(__APPLE__) || defined(__FreeBSD__)
static int find_if_with_name(const char *iface, struct sockaddr_dl *out);
static int route_op(u_char op, in_addr_t * dst, in_addr_t * mask, in_addr_t * gateway, char *iface);

static int
find_if_with_name(const char *iface, struct sockaddr_dl *out)
{
	struct ifaddrs *ifap, *ifa;
	struct sockaddr_dl *sdl = NULL;

	if (getifaddrs(&ifap)) {
		perror("getifaddrs");
		return -1;
	}

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr->sa_family == AF_LINK &&
		    /*(ifa->ifa_flags & IFF_POINTOPOINT) && \ */
		    strcmp(iface, ifa->ifa_name) == 0) {
			sdl = (struct sockaddr_dl *)ifa->ifa_addr;
			break;
		}
	}

	/* If we found it, then use it */
	if (sdl)
		memcpy((char *)out, (char *)sdl, (size_t) (sdl->sdl_len));

	freeifaddrs(ifap);

	if (sdl == NULL) {
		printf("interface %s not found or invalid(must be p-p)\n", iface);
		return -1;
	}
	return 0;
}

static int
route_op(u_char op, in_addr_t * dst, in_addr_t * mask, in_addr_t * gateway, char *iface)
{

#define ROUNDUP(n)  ((n) > 0 ? (1 + (((n) - 1) | (sizeof(uint32_t) - 1))) : sizeof(uint32_t))
#define ADVANCE(x, n) (x += ROUNDUP((n)->sa_len))

#define NEXTADDR(w, u) \
if (msg.msghdr.rtm_addrs & (w)) {\
len = ROUNDUP(u.sa.sa_len); memcpy(cp, (char *)&(u), len); cp += len;\
}

	static int seq = 0;
	int err = 0;
	size_t len = 0;
	char *cp;
	pid_t pid;

	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_dl sdl;
		struct sockaddr_storage ss;	/* added to avoid memory overrun */
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
	msg.msghdr.rtm_index = 0;
	msg.msghdr.rtm_pid = pid;
	msg.msghdr.rtm_addrs = 0;
	msg.msghdr.rtm_seq = ++seq;
	msg.msghdr.rtm_errno = 0;
	msg.msghdr.rtm_flags = 0;

	// Destination
	if (dst && *dst != 0xffffffff) {
		msg.msghdr.rtm_addrs |= RTA_DST;

		so_addr[RTAX_DST].sin.sin_len = sizeof(struct sockaddr_in);
		so_addr[RTAX_DST].sin.sin_family = AF_INET;
		so_addr[RTAX_DST].sin.sin_addr.s_addr = mask ? *dst & *mask : *dst;
	} else {
		fprintf(stderr, "invalid(require) dst address.\n");
		return -1;
	}

	// Netmask
	if (mask && *mask != 0xffffffff) {
		msg.msghdr.rtm_addrs |= RTA_NETMASK;

		so_addr[RTAX_NETMASK].sin.sin_len = sizeof(struct sockaddr_in);
		so_addr[RTAX_NETMASK].sin.sin_family = AF_INET;
		so_addr[RTAX_NETMASK].sin.sin_addr.s_addr = *mask;

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

				so_addr[RTAX_GATEWAY].sin.sin_len = sizeof(struct sockaddr_in);
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
		err = -1;
		goto end;
	}

	if (op == RTM_GET) {
		do {
			len = read(sock, (char *)&msg, sizeof(msg));
		} while (len > 0 && (msg.msghdr.rtm_seq != seq || msg.msghdr.rtm_pid != pid));

		if (len < 0) {
			perror("read from routing socket");
			err = -1;
		} else {
			struct sockaddr *s_dest = NULL;
			struct sockaddr *s_netmask = NULL;
			struct sockaddr *s_gate = NULL;
			struct sockaddr_dl *s_ifp = NULL;
			register struct sockaddr *sa;

			if (msg.msghdr.rtm_version != RTM_VERSION) {
				fprintf(stderr, "routing message version %d not understood\n", msg.msghdr.rtm_version);
				err = -1;
				goto end;
			}
			if (msg.msghdr.rtm_msglen > len) {
				fprintf(stderr, "message length mismatch, in packet %d, returned %lu\n", msg.msghdr.rtm_msglen, (unsigned long)len);
			}
			if (msg.msghdr.rtm_errno) {
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
								s_dest = sa;
								break;
							case RTA_GATEWAY:
								s_gate = sa;
								break;
							case RTA_NETMASK:
								s_netmask = sa;
								break;
							case RTA_IFP:
								if (sa->sa_family == AF_LINK && ((struct sockaddr_dl *)sa)->sdl_nlen)
									s_ifp = (struct sockaddr_dl *)sa;
								break;
						}
						ADVANCE(cp, sa);
					}
				}
			}

			if (s_dest && msg.msghdr.rtm_flags & RTF_UP) {
#if defined(__FreeBSD__)
				*dst = ((struct sockaddr_in *)s_dest)->sin_addr.s_addr;
#else
				if (msg.msghdr.rtm_flags & RTF_WASCLONED)
					*dst = 0;
				else
					*dst = ((struct sockaddr_in *)s_dest)->sin_addr.s_addr;
#endif
			}

			if (mask) {
				if (*dst == 0)
					*mask = 0;
				else if (s_netmask)
					*mask = ((struct sockaddr_in *)s_netmask)->sin_addr.s_addr;	// there must be something wrong here....Ah..
				else
					*mask = 0xffffffff;	// it is a host
			}

			if (gateway && s_gate) {
				if (msg.msghdr.rtm_flags & RTF_GATEWAY)
					*gateway = ((struct sockaddr_in *)s_gate)->sin_addr.s_addr;
				else
					*gateway = 0;
			}

			if (iface && s_ifp) {
				strncpy(iface, s_ifp->sdl_data, s_ifp->sdl_nlen < IFNAMSIZ ? s_ifp->sdl_nlen : IFNAMSIZ);
				iface[IFNAMSIZ - 1] = '\0';
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
#endif				//#if defined(__APPLE__) || defined(__FreeBSD__)

int
route_get(in_addr_t * dst, in_addr_t * mask, in_addr_t * gateway, char iface[])
{
#if defined(__APPLE__) || defined(__FreeBSD__)
	return route_op(RTM_GET, dst, mask, gateway, iface);
#else
	printf("%s: todo...\n", __FUNCTION__);
	return 0;
#endif
}

int
route_add(in_addr_t dst, in_addr_t mask, in_addr_t gateway, const char *iface)
{
#if defined(__APPLE__) || defined(__FreeBSD__)
	return route_op(RTM_ADD, &dst, &mask, &gateway, (char *)iface);
#elif defined(__linux__)
	int fd;
	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("socket()");
		return -1;
	}

	struct rtentry rt;
	bzero(&rt, sizeof(rt));
	((struct sockaddr_in *)&rt.rt_dst)->sin_family = AF_INET;
	((struct sockaddr_in *)&rt.rt_gateway)->sin_family = AF_INET;
	((struct sockaddr_in *)&rt.rt_genmask)->sin_family = AF_INET;

	/* make sure dst is network addr */
	dst &= mask;
	((struct sockaddr_in *)&rt.rt_dst)->sin_addr.s_addr = dst;
	((struct sockaddr_in *)&rt.rt_gateway)->sin_addr.s_addr = gateway;
	((struct sockaddr_in *)&rt.rt_genmask)->sin_addr.s_addr = mask;

	rt.rt_dev = (char *)iface;

	if (gateway != 0 && gateway != 0xffffffff)
		rt.rt_flags |= RTF_GATEWAY;
	if (mask == 0xffffffff)
		rt.rt_flags |= RTF_HOST;
	rt.rt_flags |= RTF_UP;

	int err;
	if ((err = ioctl(fd, SIOCADDRT, &rt)) < 0)
		perror("ioctl(SIOCADDRT)");

	close(fd);
	return err;
#else
#error Target OS not supported yet!
#endif
}

int
route_change(in_addr_t dst, in_addr_t mask, in_addr_t gateway, const char *iface)
{
#if defined(__APPLE__) || defined(__FreeBSD__)
	return route_op(RTM_CHANGE, &dst, &mask, &gateway, (char *)iface);
#else
	printf("%s: todo...\n", __FUNCTION__);
	return -1;
#endif
}

int
route_delete(in_addr_t dst, in_addr_t mask)
{
#if defined(__APPLE__) || defined(__FreeBSD__)
	return route_op(RTM_DELETE, &dst, &mask, 0, NULL);
#elif defined(__linux__)
	int fd;
	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("socket()");
		return -1;
	}

	struct rtentry rt;
	bzero(&rt, sizeof(rt));
	((struct sockaddr_in *)&rt.rt_dst)->sin_family = AF_INET;
	((struct sockaddr_in *)&rt.rt_gateway)->sin_family = AF_INET;
	((struct sockaddr_in *)&rt.rt_genmask)->sin_family = AF_INET;

	/* make sure dst is network addr */
	dst &= mask;
	((struct sockaddr_in *)&rt.rt_dst)->sin_addr.s_addr = dst;
	((struct sockaddr_in *)&rt.rt_genmask)->sin_addr.s_addr = mask;

	int err;
	if ((err = ioctl(fd, SIOCDELRT, &rt)) < 0)
		perror("ioctl(SIOCDELRT)");

	close(fd);
	return err;
#else
#error Target OS not supported yet!
#endif
}
