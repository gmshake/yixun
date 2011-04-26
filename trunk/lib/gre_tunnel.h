/*
 * gre_tunnel.h
 * gre tunnel ops
 * By Summer Town
 * 2011.04.16
 */
#ifndef _GRE_TUNNEL_H
#define _GRE_TUNNEL_H

int gre_find_unused_tunnel(char *ifname);

/* get tunnel ifname's src/dst */
int gre_get_tunnel(const char *ifname, in_addr_t *src, in_addr_t *dst);

/* get ifname's local/remote addr */
int gre_get_addr(const char *ifname, in_addr_t *local, in_addr_t *remote);

/* find tunnel if, if local is 0.0.0.0, do not check local/remote addr */
int gre_find_tunnel_with_addr(char *ifname, in_addr_t src, in_addr_t dst, in_addr_t local, in_addr_t remote);

/* set tunnel's src/dst addr */
int gre_set_tunnel(const char *ifname, in_addr_t src, in_addr_t dst);

/* set if's local/remote addr */
int gre_set_addr(const char *ifname, in_addr_t local, in_addr_t remote, in_addr_t netmask);

/* set if's link state, up/down */
int gre_set_link(const char *ifname, int up);

/* delete tunnel's src/dst addr */
int gre_delete_tunnel_addr(const char *ifname);

/* remove tunnel, OSX does not support remove tunnel yet */
int gre_remove_tunnel(const char *ifname);

#endif

