/*
 *  rds_types.h
 *
 *  Created by Summer Town on 9/19/10.
 *  Copyright 2010 __MyCompanyName__. All rights reserved.
 *
 */

#ifndef RDS_TYPES_H
#define RDS_TYPES_H

#ifndef RDS_PACKET_LEN
#define RDS_PACKET_LEN(p) ntohs(((struct rds_packet_header *)(p))->length) + sizeof(struct rds_packet_header);
#endif

struct rds_attr;

#pragma pack(4)
struct rds_packet_header {
	uint8_t vendor;		/* vendor, here it's 0x5f */
#define VENDOR_YIXUN 0x5f
	uint8_t type;		/* radius packet type */
	uint16_t length;	/* extra attributes length, network byte order */
	uint32_t pad;		/* to be zeroed */
	char extra[0];
};
#pragma pack()

/* radius attribute */
struct rds_attr {
	uint8_t flag;
#define CLINET_ATTR_FLAG 0x14
#define SERVER_ATTR_FLAG 0x15
	uint8_t type;		/* attribute type */
	uint8_t length;		/* attribute total length */
#define ATTR_MAX_LEN 0xff
	uint8_t pad;		/* to be zeroed */
	char content[0];
} __attribute__ ((__packed__));

/* radius packet type */
enum rds_type {
	/* client send packet header type */
	u_req = 0x40,		/* user start/access request */
	u_ack = 0x41,		/* user access acknowledge */
	u_stp = 0x44,		/* user stop/logout */
	u_keepalive = 0x4f,	/* user keep alive */

	/* server side header type */
	s_ack = 0x51,		/* server accept */
	s_rej = 0x52,		/* server reject */
	s_keepalive = 0x54,	/* server require keepalive */
	s_msg = 0xe0,		/* server side msg */
};

enum rds_attr_type {	/* radius attribute type */
	/* client side attribute type */
	c_ip = 0x01,		/* ip */
	c_mac = 0x02,		/* mac */
	c_user = 0x03,		/* user name */
	c_pwd = 0x04,		/* password */
	c_ver = 0x05,		/* version */
	c_pad = 0x06,		/* zeros */

	/* server side attribute type */
	s_gre_d = 0x05,		/* gre dst */
	s_gre_l = 0x06,		/* gre local */
	s_gre_r = 0x07,		/* gre remote */
	s_timeout = 0x08,	/* keepalive timeout */
	s_rule = 0x09,		/* rules, not used in current(BSD/OSX/Linux) implement... */
	s_mask = 0x0a,		/* netmask */
	s_pad = 0x0b,		/* zeros */
	// unused, 0x0c
	// unused, 0x0d
	s_downband = 0x0e,	/* download band */
	s_upband = 0x0f,	/* upload band */
	s_sinfo = 0x15,		/* server info */
};

enum error_info_type {
	e_user = 100,		/* user not found */
	e_mac,			/* mac bind error */
	e_pwd,			/* password wrong */
	e_ip,			/* ip bind error */
	e_fee,			/* account need recharge */
	e_tun,			/* can not create gre tunnel */
	e_busy,			/* server busy */
};

struct str_err {
	const char *info;
	enum error_info_type error;
};

/*
 * if the info returned by server has any of these keywords, then 
 * stop trying to re-connect to auth server
 *
 * NOT FULLY tested yet...
 */
const struct str_err error_info[] = {
	{"User not found", e_user},
	{"MAC bind error", e_mac},
	{"Password Error", e_pwd},
	{"IP address bind error", e_ip},
	{"Insufficient", e_fee},
/* 	{"Tunnel", e_tun}, 
	{"系统繁忙", e_busy}, */
	{NULL, 0}
};

#endif		/* RDS_TYPES_H */

