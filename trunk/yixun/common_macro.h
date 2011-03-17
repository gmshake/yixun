/*
 *  common_macro.h
 *  YiXun
 *
 *  Created by Summer Town on 10/2/10.
 *  Copyright 2010 __MyCompanyName__. All rights reserved.
 *
 */

#ifndef _COMMON_MACRO_H
#define _COMMON_MACRO_H

#ifndef inet_itoa
#define inet_itoa(x) inet_ntoa(*(struct in_addr*)&(x))
#endif

/* make buff that is aligned to 4 bytes */
#ifndef BUFF_ALIGNED
#define BUFF_ALIGNED(name, size) char name[(size)]__attribute__((aligned(sizeof(uint32_t))))
#endif

#ifdef DEBUG
#define dprintf(...) do { fprintf(stderr, "Debug: In %s at line: %u\n", __FILE__, __LINE__ ); \
fprintf(stderr, __VA_ARGS__); } while(0)
#else
#define dprintf(...) (void)0
#endif

#ifdef DEBUG
#define dperror(x) do { fprintf(stderr, "Debug && Error: in %s at line: %u\n", __FILE__, __LINE__ ); \
perror(x); } while(0)
#else
#define dperror(x) (void)0
#endif

#endif
