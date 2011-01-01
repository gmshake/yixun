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

//#include <stdint.h>
//#include <netinet/in.h>
#include "yixun_config.h"

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
    uint32_t timeout;
    uint32_t upload_band;
    uint32_t download_band;
    
    /* internal use */
    int pre_config_done;
    int make_send_buff_done;
    in_addr_t auth_server;
    uint32_t auth_server_maskbits;
    in_addr_t msg_server;
    uint8_t eth_addr[6];
    size_t s_buff_len;
    char s_buff[S_BUF_LEN];
};

/*
extern in_addr_t gre_src, gre_dst, gre_local, gre_remote, net_mask;  //out parameters
extern in_addr_t auth_server_addr, msg_server_addr;
extern uint32_t timeout, upload_band, download_band;

//extern int set_config(const char *ifname, const char *username, const char *password);
extern int set_config(const char *username, const char *password, const char *serverip, const char *clientip, const char *mac);

extern int log_in();
extern int log_out();
extern int send_keep_alive();
*/

int log_in(struct yixun_msg *msg);
int log_out(struct yixun_msg *msg);
int keep_alive(struct yixun_msg *msg);

extern int start_listen();
extern int stop_listen();
extern int accept_client(struct yixun_msg *msg);

#endif // _RADIUS_H
