#include <sys/socket.h>	/* struct sockaddr */
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include <netinet/in.h>
#include <net/if.h>		/* IFNAMSIZ */

#include "sys.h"
#include "gre_module.h"
#include "gre_tunnel.h"
#include "route_op.h"
#include "radius.h"

extern bool flag_changeroute;
extern const char *arg_dev;

static char tunnel[IFNAMSIZ];
static bool flag_tunnel_isset = false;

int
set_tunnel(void)
{
	/*
	 *  load needed module
	 *  On OSX, that is /Library/Extensions/GRE.kext, by SummerTown
	 *  On FreeBSD, that is if_gre.ko
	 *  On linux, it would be ip_gre.*
	 */
	if (load_gre_module() < 0)
		return -1;

	if (gre_find_tunnel_with_addr(tunnel, \
				gre_src, \
				gre_dst, \
				gre_local, \
				gre_remote) == 0) {
		fprintf(stderr, "tunnel already exists: %s\n", tunnel);
		return 0;
	}

	if (arg_dev)
		strlcpy(tunnel, arg_dev, sizeof(tunnel));

	if (gre_find_unused_tunnel(tunnel) < 0) {
		if (arg_dev)
			fprintf(stderr, "tunnel %s unavailable.\n", arg_dev);
		else
			fprintf(stderr, "unable to find unused gre interface.\n");
		return -1;
	}

	if (gre_set_tunnel(tunnel, gre_src, gre_dst) < 0) {
		fprintf(stderr, "error set tunnel address of %s\n", tunnel);
		return -1;
	}

#if defined(__linux__)
	/* set link dev as well?? ie: ip_tunnel_parm.link */

	/* bring gre tunnel up */
	if (gre_set_link(tunnel, 1) < 0) {
		fprintf(stderr, "error bring %s up\n", tunnel);
		return -1;
	}
#else
	if (gre_set_addr(tunnel, gre_local, gre_remote, gre_netmask) < 0) {
		fprintf(stderr, "error set address of %s\n", tunnel);
		return -1;
	}
#endif

	flag_tunnel_isset = true;

	/*
	 * hack: if tunnel remote is the same as tunnel interface dst, as we have no 
	 * opportunity to access route directly(Apple has not addressed it to the developer)
	 * , we delete the loopback route. 
	 */
	if (gre_remote == gre_dst) {
		in_addr_t tmp_dst = gre_remote;
		in_addr_t tmp_mask = 0xffffffff;
		if (route_get(&tmp_dst, &tmp_mask, NULL, NULL) == 0 && \
				tmp_dst == gre_remote && \
				tmp_mask == 0xffffffff)
			route_delete(gre_remote, 0xffffffff);
	}

	if (flag_changeroute) {
		route_change(0, 0, gre_remote, tunnel);
		/*
		   route_delete(0, 0);
		   route_add(0, 0, remote, ifname);
		   */
	}

	return 0;
}

int
remove_tunnel(void)
{
	if (flag_changeroute) {
		/*
		if (gateway)
			route_add(0, 0, gateway, NULL);
		else {
			in_addr_t tmp_dst = dst;
			in_addr_t tmp_mask = 0xffffffff;
			in_addr_t tmp_gateway = 0;
			if (route_get(&tmp_dst, &tmp_mask, &tmp_gateway, ifp) == 0)
				route_add(0, 0, tmp_gateway, tmp_gateway ? NULL : ifp);
			else
				fprintf(stderr, "route_get: error get ori gateway\n");
		}
		*/
	}

	if (! flag_tunnel_isset)
		return 0;

#if defined(__linux__)
	if (gre_remove_tunnel(tunnel) < 0) {
		fprintf(stderr, "can NOT remove tunnel %s\n", tunnel);
		return -1;
	}
#else
	if (gre_find_tunnel_with_addr(tunnel, gre_src, \
				gre_dst, gre_local, gre_remote) < 0) {
		fprintf(stderr, "find_if_with_addr(): unable to find gre interface.\n");
		return -1;
	}

	if (gre_delete_tunnel_addr(tunnel) < 0) {
		fprintf(stderr, "delete_if_addr_tunnel(): unable to delete address of %s\n", tunnel);
		return -1;
	}
#endif

	flag_tunnel_isset = false;
	return 0;
}

int
reset_tunnel(void)
{
	if (! flag_tunnel_isset)
		return -1;

	char newtunnel[IFNAMSIZ];
	if (gre_find_tunnel_with_addr(newtunnel, \
				gre_src, \
				gre_dst, \
				gre_local, \
				gre_remote) == 0) {
		fprintf(stderr, "tunnel already exists: %s\n", newtunnel);
		return 0;
	}

	if (gre_set_tunnel(tunnel, gre_src, gre_dst) < 0) {
		fprintf(stderr, "error set tunnel address of %s\n", tunnel);
		return -1;
	}

#if defined(__linux__)
	/* set link dev as well?? ie: ip_tunnel_parm.link */

	/* bring gre tunnel up */
	if (gre_set_link(tunnel, 1) < 0) {
		fprintf(stderr, "error bring %s up\n", tunnel);
		return -1;
	}
#else
	if (gre_set_addr(tunnel, gre_local, gre_remote, gre_netmask) < 0) {
		fprintf(stderr, "error set address of %s\n", tunnel);
		return -1;
	}
#endif

	flag_tunnel_isset = true;

	/*
	 * hack: if tunnel remote is the same as tunnel interface dst, as we have no 
	 * opportunity to access route directly(Apple has not addressed it to the developer)
	 * , we delete the loopback route. 
	 */
	if (gre_remote == gre_dst) {
		in_addr_t tmp_dst = gre_remote;
		in_addr_t tmp_mask = 0xffffffff;
		if (route_get(&tmp_dst, &tmp_mask, NULL, NULL) == 0 && \
				tmp_dst == gre_remote && \
				tmp_mask == 0xffffffff)
			route_delete(gre_remote, 0xffffffff);
	}

	if (flag_changeroute) {
		route_change(0, 0, gre_remote, tunnel);
		/*
		   route_delete(0, 0);
		   route_add(0, 0, remote, ifname);
		   */
	}

	return 0;
}

