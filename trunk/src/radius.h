/*
 *  radius.h
 *
 *  Created by Summer Town on 9/14/10.
 *  Copyright 2010 __MyCompanyName__. All rights reserved.
 *
 */

#ifndef RADIUS_H
#define RADIUS_H

#include <netinet/in.h>
#include <net/ethernet.h>	/* ETHER_ADDR_LEN */

enum login_state {
	offline,
	connecting,
	online,
	disconnection
};

extern enum login_state login_state;

extern uint8_t eth_addr[ETHER_ADDR_LEN];
extern struct sockaddr_in auth_server;
extern uint32_t auth_server_maskbits;
extern in_addr_t msg_server;

/* out parameters */
extern in_addr_t gre_src;
extern in_addr_t gre_dst;
extern in_addr_t gre_local;
extern in_addr_t gre_remote;
extern in_addr_t gre_netmask;
extern uint32_t gre_timeout;
extern uint32_t gre_upload_band;
extern uint32_t gre_download_band;

int login(void);
int logout(void);
int keep_alive(void);

#endif	/* RADIUS_H */

