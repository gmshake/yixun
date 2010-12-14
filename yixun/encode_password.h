/*
 *  encode_password.h
 *  YiXun
 *
 *  Created by Summer Town on 9/17/10.
 *  Copyright 2010 __MyCompanyName__. All rights reserved.
 *
 */

#ifndef _ENCODE_PASSWORD_H
#define _ENCODE_PASSWORD_H

extern uint8_t * encode_pwd_with_ip(uint8_t *sec_pwd, const char *pwd, in_addr_t ip_addr); //用加密算法加密传送的密码

#endif //_ENCODE_PASSWORD_H
