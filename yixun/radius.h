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

struct yixun_msg {
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
    /* internal use */
}

extern in_addr_t gre_src, gre_dst, gre_local, gre_remote, net_mask;  //out parameters
extern in_addr_t auth_server_addr, msg_server_addr;
extern uint32_t timeout, upload_band, download_band;

//extern int set_config(const char *ifname, const char *username, const char *password);
extern int set_config(const char *username, const char *password, const char *serverip, const char *clientip, const char *mac);

extern int log_in();
extern int log_out();

extern int send_keep_alive();

extern int start_listen();
extern int stop_listen();
extern int accept_client();

#endif // _RADIUS_H
