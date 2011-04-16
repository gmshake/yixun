/*
 *  get_ip_mac.h
 *  YiXun
 *
 *  Created by Summer Town on 9/18/10.
 *  Copyright 2010 __MyCompanyName__. All rights reserved.
 *
 */

#ifndef _GETIPMAC_H
#define _GETIPMAC_H

extern int get_ip_mac_by_socket(int socket, in_addr_t * addr, uint8_t eth_addr[]);
extern int get_ip_mac_by_name(const char *ifname, in_addr_t * addr, uint8_t eth_addr[]);
extern int string_to_lladdr(uint8_t lladdr[], const char *src);

#endif
