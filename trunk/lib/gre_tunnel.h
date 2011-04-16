/*
 * gre_tunnel.h
 * gre tunnel ops
 * By Summer Town
 * 2011.04.16
 */
#ifndef _GRE_TUNNEL_H
#define _GRE_TUNNEL_H

int gre_find_unused_tunnel(char ifname[]);

int gre_find_tunnel_with_addr(char ifname[], in_addr_t src, in_addr_t dst, in_addr_t local, in_addr_t remote);

int gre_set_tunnel_addr(const char *ifname, in_addr_t src, in_addr_t dst);

int gre_set_if_addr(const char *ifname, in_addr_t local, in_addr_t remote, in_addr_t netmask);

int gre_delete_if_tunnel_addr(char ifname[]);

int gre_remove_tunnel(char ifname[]);

#endif

