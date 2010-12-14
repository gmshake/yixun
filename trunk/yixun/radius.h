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

#include <stdint.h>
#include <netinet/in.h>


extern in_addr_t gre, gre_client_ip, gateway_ip, net_mask;  //out parameters
extern uint32_t timeout, upload_band, download_band;
extern in_addr_t clientip;			// IP address

//extern int set_config(const char *ifname, const char *username, const char *password);
extern int set_config(const char *username, const char *password, const char *serverip, const char *clientip, const char *mac);

extern int log_in();
extern int log_out();

extern int send_keep_alive();

extern int start_listen();
extern int stop_listen();
extern int accept_client();



#endif // _RADIUS_H
