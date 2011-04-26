
#include <stdio.h>
#include <stdbool.h>

#include <netinet/in.h>
#include <net/if.h>		/* IFNAMSIZ */

#include "gre_module.h"
#include "gre_tunnel.h"
#include "route_op.h"
#include "radius.h"

extern bool flag_changeroute;
extern struct mcb mcb;

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

	if (gre_find_tunnel_with_addr(mcb.tunnel, \
				mcb.gre_src, \
				mcb.gre_dst, \
				mcb.gre_local, \
				mcb.gre_remote) == 0) {
		fprintf(stderr, "tunnel already exists\n");
		return 0;
	}

	if (gre_find_unused_tunnel(mcb.tunnel) < 0) {
		fprintf(stderr, "unable to find unused gre interface.\n");
		return -1;
	}

	if (gre_set_tunnel(mcb.tunnel, mcb.gre_src, mcb.gre_dst) < 0) {
		fprintf(stderr, "error set tunnel address of %s\n", mcb.tunnel);
		return -1;
	}

#if defined(__linux__)
	if (gre_set_link(mcb.tunnel, 1) < 0) {
		fprintf(stderr, "error bring %s up\n", mcb.tunnel);
		return -1;
	}
#else
	if (gre_set_addr(mcb.tunnel, mcb.gre_local, mcb.gre_remote, mcb.gre_netmask) < 0) {
		fprintf(stderr, "error set address of %s\n", mcb.tunnel);
		return -1;
	}
#endif

	/*
	 * hack: if tunnel remote is the same as tunnel interface dst, as we have no 
	 * opportunity to access route directly(Apple has not addressed it to the developer)
	 * , we delete the loopback route. 
	 */
	if (mcb.gre_remote == mcb.gre_dst) {
		in_addr_t tmp_dst = mcb.gre_remote;
		in_addr_t tmp_mask = 0xffffffff;
		if (route_get(&tmp_dst, &tmp_mask, NULL, NULL) == 0 && \
				tmp_dst == mcb.gre_remote && \
				tmp_mask == 0xffffffff)
			route_delete(mcb.gre_remote, 0xffffffff);
	}

	if (flag_changeroute) {
		route_change(0, 0, mcb.gre_remote, mcb.tunnel);
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

#if defined(__linux__)
	if (gre_remove_tunnel(mcb.tunnel) < 0) {
		fprintf(stderr, "can NOT remove tunnel %s\n", mcb.tunnel);
		return -1;
	}
#else
	if (gre_find_tunnel_with_addr(mcb.tunnel, mcb.gre_src, \
				mcb.gre_dst, mcb.gre_local, mcb.gre_remote) < 0) {
		fprintf(stderr, "find_if_with_addr(): unable to find gre interface.\n");
		return -1;
	}

	if (gre_delete_tunnel_addr(mcb.tunnel) < 0) {
		fprintf(stderr, "delete_if_addr_tunnel(): unable to delete address of %s\n", mcb.tunnel);
		return -1;
	}
#endif

	return 0;
}


