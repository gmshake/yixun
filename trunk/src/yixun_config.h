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
/*
#ifndef MSG_SERVER
#define MSG_SERVER "10.0.100.3"
#endif
*/

//(客户端)接收连接数量
#ifndef MAX_CLIENT
#define MAX_CLIENT 10
#endif

//认证、接入服务器网段掩码长度
#ifndef AUTH_SERVER_MASKBITS
#define AUTH_SERVER_MASKBITS 28
#endif

//连接超时，单位，秒
#ifndef CONNECTION_TIMEOUT
#define CONNECTION_TIMEOUT 3
#endif

//发送、接收超时，单位，秒
#ifndef SND_TIMEOUT
#define SND_TIMEOUT 5
#endif

#ifndef RCV_TIMEOUT
#define RCV_TIMEOUT 5
#endif

//与认证服务器保持连接超时时间，单位，秒
#ifndef KEEP_ALIVE_TIMEOUT
#define KEEP_ALIVE_TIMEOUT 180
#endif

//接收缓冲区大小
#ifndef R_BUF_LEN
#define R_BUF_LEN 1024
#endif

//发送缓冲区大小
#ifndef S_BUF_LEN
#define S_BUF_LEN 512
#endif

//radius协议，段最大长度，8bit，2^8
#ifndef SEGMENT_MAX_LEN
#define SEGMENT_MAX_LEN 256
#endif

#endif				//_YIXUN_CONFIG_H
