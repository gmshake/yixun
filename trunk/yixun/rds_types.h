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

#include "yixun_config.h"

#pragma pack(4)
typedef struct rds_segment {
	uint8_t flag;
	uint8_t type;
	uint16_t length;
	uint8_t content[SEGMENT_MAX_LEN];
	struct rds_segment *next;
}rds_segment;

typedef struct rds_packet //包头，构造时用用链式结构
	{
		uint8_t flag;
		uint8_t type;
		uint16_t length;
		uint32_t pad;
		
		rds_segment *extra;
	}rds_packet;

#pragma pack()

enum rds_head_type { //包头信息类型
	u_login = 0x40,
	u_ack = 0x41,
	u_logout = 0x44,
	u_keepalive = 0x4f,
	s_accept = 0x51,
	s_error = 0x52,
	s_keepalive = 0x54,
	s_info = 0xe0,
};

enum segment_type { //段类型
	c_ip = 0x01,
	c_mac = 0x02,
	c_user = 0x03,
	c_pwd = 0x04,
	c_ver = 0x05,
	c_pad = 0x06,
	
	s_gre = 0x05,
	s_cip = 0x06,
	s_gip = 0x07,
	s_timeout = 0x08,
	s_rule = 0x09,
	s_mask = 0x0a,
	s_pad = 0x0b,
	s_upband = 0x0e,
	s_downband = 0x0f,
	s_sinfo = 0x15,
};

enum error_info_type {
    e_user = 100,
    e_pwd,
    e_busy,
    //e_con,
    e_fee,
    e_gre,
};

const char * error_info_str[] = {
    "User not found",
    "Password Error",
    "系统繁忙",
    //"connect radius server failed",
    NULL,
};

#endif //_RDS_TYPES_H
