/*
 *  encode_password.c
 *  YiXun
 *
 *  Created by Summer Town on 9/17/10.
 *  Copyright 2010 __MyCompanyName__. All rights reserved.
 *
 */

#include <string.h>
#include <stdint.h>
#include <netinet/in.h> // in_addr_t sockaddr_in INADDR_ANY

uint8_t * encode_pwd_with_ip(uint8_t sec_pwd[], const char *pwd, in_addr_t ip_addr)
{
    uint8_t key = (uint8_t)(ip_addr >> 24);
	
    uint8_t *p = sec_pwd;
    while (*pwd)
        *p++ = (uint8_t)*pwd++ ^ key;
    
    *p++ = key;
    *p = '\0';

    return sec_pwd;
}
