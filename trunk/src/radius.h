/*
 *  Radius.h
 *  YiXun
 *
 *  Created by Summer Town on 9/14/10.
 *  Copyright 2010 __MyCompanyName__. All rights reserved.
 *
 */
#ifndef _RADIUS_H
#define _RADIUS_H

#include <netinet/in.h>
#include <net/ethernet.h>	/* ETHER_ADDR_LEN */
#include <net/if.h>			/* IFNAMSIZ */
#include "yixun_config.h"

struct mcb {
	/* in parameters */
	const char *username;
	const char *password;
	const char *serverip;
	const char *clientip;
	const char *mac;

	/* out parameters */
	in_addr_t gre_src;
	in_addr_t gre_dst;
	in_addr_t gre_local;
	in_addr_t gre_remote;
	in_addr_t gre_netmask;
	uint32_t timeout;
	uint32_t upload_band;
	uint32_t download_band;

	/* internal use */
	char tunnel[IFNAMSIZ];
	unsigned int select_timeout;
	int last_op;
	int pre_config_done;
	in_addr_t auth_server;
	in_addr_t msg_server;
	uint32_t auth_server_maskbits;
	uint8_t eth_addr[ETHER_ADDR_LEN];
	size_t s_buff_len;
	char s_buff[S_BUF_LEN];
	char server_info[SEGMENT_MAX_LEN + (SEGMENT_MAX_LEN >> 1)];
};

int login(struct mcb *mcb);
int logout(struct mcb *mcb);
int keep_alive(struct mcb *mcb);

extern int start_listen();
extern int stop_listen();
extern int wait_msg(struct mcb *mcb);

#endif				// _RADIUS_H
