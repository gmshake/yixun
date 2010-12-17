/*
 *  yixun_config.h
 *  YiXun
 *
 *  Created by Summer Town on 9/17/10.
 *  Copyright 2010 __MyCompanyName__. All rights reserved.
 *
 */

#ifndef _YIXUN_CONFIG_H
#define _YIXUN_CONFIG_H

//用户名最大长度
#ifndef MAX_USER_NAME_LEN
#define MAX_USER_NAME_LEN 20
#endif

//用户密码最大长度
#ifndef MAX_PWD_LEN
#define MAX_PWD_LEN 16
#endif

//radius端口
#ifndef RADIUS_PORT
#define RADIUS_PORT 1812
#endif

//认证服务器
#ifndef AUTH_SERVER
#define AUTH_SERVER "10.0.100.2"
#endif

//接入服务器
//#ifndef BRAS_SERVER
//#define BRAS_SERVER "10.0.100.3"
//#endif

//接收连接数量
#ifndef MAX_CLIENT
#define MAX_CLIENT 10
#endif

//认证、接入服务器掩码长度
#ifndef AUTH_SERVER_MASKBITS
#define AUTH_SERVER_MASKBITS 28
#endif

//连接超时，单位，秒
#ifndef CONNECTION_TIME_OUT
#define CONNECTION_TIME_OUT 3
#endif

//发送、接收超时，单位，秒
#ifndef SND_RCV_TIME_OUT
#define SND_RCV_TIME_OUT 1
#endif

//与认证服务器保持连接最大超时时间，单位，秒
#ifndef MAX_TIME_OUT
#define MAX_TIME_OUT 180
#endif

//接收缓冲区大小
#ifndef R_BUF_LEN
#define R_BUF_LEN 1024
#endif

//发送缓冲区大小
#ifndef S_BUF_LEN
#define S_BUF_LEN 512
#endif

//radius协议，段最大长度
#ifndef SEGMENT_MAX_LEN
#define SEGMENT_MAX_LEN 256
#endif

//radius协议，消息头标志
#ifndef RADIUS_HEADER_FLAG
#define RADIUS_HEADER_FLAG 0x5f
#endif

//radius协议，客户端段标志
#ifndef CLINET_SEGMENT_FLAG
#define CLINET_SEGMENT_FLAG 0x14
#endif

//radius协议，服务端段标志
#ifndef SERVER_SEGMENT_FLAG
#define SERVER_SEGMENT_FLAG 0x15
#endif

#endif //_YIXUN_CONFIG_H
