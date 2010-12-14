#ifndef _TUN_DEV_H
#define _TUN_DEV_H

extern char tun_if_name[];

extern int open_tunnel(char *tun_name);
extern int close_tunnel(int tunfd);
extern int set_tunnel_addr(in_addr_t local, in_addr_t remote, in_addr_t net_mask);
//extern int set_addr_by_name(char *name, struct sockaddr_in *sa);
#endif