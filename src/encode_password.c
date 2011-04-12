/*
 *  encode_password.c
 *  YiXun
 *
 *  Created by Summer Town on 9/17/10.
 *  Copyright 2010 __MyCompanyName__. All rights reserved.
 *
 */

#include <stdint.h>
#include <netinet/in.h>		// in_addr_t sockaddr_in INADDR_ANY

#ifdef DEBUG
#include "print_hex.h"
#endif

uint8_t *
encode_pwd_with_ip(uint8_t sec_pwd[], const char *pwd, in_addr_t ip_addr)
{
#ifdef DEBUG
	printf("encode password with ip addr\n");
	print_hex(&ip_addr, sizeof(ip_addr));
#endif
	uint8_t key = *((uint8_t *) & ip_addr + 3);
#ifdef DEBUG
	printf("key is %02x\n", key);
#endif

	uint8_t *p = sec_pwd;
	while (*pwd)
		*p++ = (uint8_t) * pwd++ ^ key;

	*p++ = key;
	*p = '\0';

	return sec_pwd;
}
