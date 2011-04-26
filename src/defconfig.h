/*
 *  defconfig.h
 *
 *  Created by Summer Town on 9/17/10.
 *  Copyright 2010 __MyCompanyName__. All rights reserved.
 *
 */

#ifndef DEFCONFIG_H
#define DEFCONFIG_H

//用户名最大长度
#ifndef MAX_USER_NAME_LEN
#define MAX_USER_NAME_LEN 20
#endif

//用户密码最大长度
#ifndef MAX_PWD_LEN
#define MAX_PWD_LEN 16
#endif

//radius端口
#ifndef SERVER_PORT
#define SERVER_PORT 1812
#endif

#ifndef LISTEN_PORT
#define LISTEN_PORT 1812
#endif

//认证服务器
#ifndef AUTH_SERVER
#define AUTH_SERVER "10.0.100.2"
#endif

//接入服务器
#ifndef MSG_SERVER
#define MSG_SERVER "10.0.100.3"
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
#ifndef HEART_BEAT_TIMEOUT
#define HEART_BEAT_TIMEOUT 60
#endif

#endif	/* DEFCONFIG_H */
