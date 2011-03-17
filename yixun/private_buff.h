/*
 *  private_buff.h
 *  yixun
 *
 *  Created by Summer Town on 3/18/11.
 *  Copyright 2011 __MyCompanyName__. All rights reserved.
 *
 */

#ifndef _PRIVATE_BUFF_H
#define _PRIVATE_BUFF_H

extern int vlogf(const char *fmt, va_list args); //Log formated
extern void append_msg(const char *msg);

extern void print_info();
extern void trunc_info(); // trunc info
extern char * copy_info(char outbuff[], size_t n); // copy info to outbuff
extern char * copy_info_trunc(char outbuff[], size_t n); // copy info and trunc

extern void free_print_info_locks();

#endif //_PRIVATE_BUFF_H