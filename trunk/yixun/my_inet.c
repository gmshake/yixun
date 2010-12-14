/*
 *  my_inet.c
 *  YiXun
 *
 *  Created by Summer Town on 9/26/10.
 *  Copyright 2010 __MyCompanyName__. All rights reserved.
 *
 */

#include <arpa/inet.h>

char *inet_itoa(in_addr_t t)
{
    return inet_ntoa(*(struct in_addr *)&t);    
}
