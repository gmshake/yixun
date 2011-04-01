/*
 *  print_hex.h
 *  YiXun
 *
 *  Created by Summer Town on 9/16/10.
 *  Copyright 2010 __MyCompanyName__. All rights reserved.
 *
 */

#ifndef _PRINT_HEX_H
#define _PRINT_HEX_H

extern void print_hex(const void *data, size_t len);
extern int hex_to_ascii(char out_buff[], size_t out_len, const void *in_buff, size_t in_len);

#endif
