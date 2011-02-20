/*
 *  rds_types.h
 *  YiXun
 *
 *  Created by Summer Town on 9/19/10.
 *  Copyright 2010 __MyCompanyName__. All rights reserved.
 *
 */

#ifndef _RDS_TYPES_H
#define _RDS_TYPES_H

#ifndef RDS_PACKET_LEN
#define RDS_PACKET_LEN(p) ntohs(((struct rds_packet_header *)(p))->length) + sizeof(struct rds_packet_header);
#endif

struct rds_segment;

#pragma pack(4)
struct rds_packet_header //radius包头
{
	uint8_t flag;
#define RADIUS_HEADER_FLAG 0x5f
	uint8_t type;   // rds_header_type
	uint16_t length; // extra segment length, network byte order
	uint32_t pad;   // to be zeroed
	char extra[0];
};

struct rds_segment { // 消息协议中的段
	uint8_t flag;
#define CLINET_SEGMENT_FLAG 0x14
#define SERVER_SEGMENT_FLAG 0x15
	uint8_t type;   // rds_segment_type
    uint8_t length;  // total length, including rds_segment header (sizeof(rds_segment))
	uint8_t pad;    // to be zeroed
	char content[0];
};
#pragma pack()

enum rds_header_type { //radius包头信息类型
    /* client send packet header type */
	u_login = 0x40, // user login
	u_ack = 0x41,   // user ack
	u_logout = 0x44, // user logout
	u_keepalive = 0x4f, // user keep alive
    
    /* server side header type */
	s_accept = 0x51,
	s_error = 0x52,
	s_keepalive = 0x54,
	s_info = 0xe0,
};

enum rds_segment_type { //段类型
    /* client side segment type */
	c_ip = 0x01,    //with ip
	c_mac = 0x02,   //with mac
	c_user = 0x03,  //with user name
	c_pwd = 0x04,   //with password
	c_ver = 0x05,   //version
	c_pad = 0x06,   //zeros
	
    /* server side segment type */
	s_gre_d = 0x05,   //server side, gre dst
	s_gre_l = 0x06,   //server side, gre local
	s_gre_r = 0x07,   //server side, gre remote
	s_timeout = 0x08,   //server side, keepalive timeout
	s_rule = 0x09,  // rules, the rules info are not used yet...
	s_mask = 0x0a,  // netmask
	s_pad = 0x0b,   // zeros
                    // unused, 0x0c
                    // unused, 0x0d
	s_upband = 0x0e,    // upload band
	s_downband = 0x0f,  // download band
	s_sinfo = 0x15, // server info
};

enum error_info_type {
    e_user = 100,  // username not match
    e_pwd,         // password wrong
    e_mac,      // mac bind error
    e_ip,       // ip bind error
    e_busy,     // server busy
    e_fee,      // account fee exausted
    e_gre,      // error create gre tunnel
};

struct str_err {
    const char *info;
    enum error_info_type error;
};

/* if the info returned by server has any of these keywords, then stop trying to
 * reconnect to auth server
 */
const struct str_err error_info[] = {
    {"##User not found", e_user},
    {"##Password Error", e_pwd},
    {"##MAC bind error", e_mac},
    {"##IP address bind error", e_ip},
    {"系统繁忙", e_busy},
    {"余额不足", e_fee},
    {NULL, 0}
};

#endif //_RDS_TYPES_H
