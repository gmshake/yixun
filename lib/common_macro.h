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

#ifdef DEBUG
#define log_perror(...) do { fprintf(stderr, "Error: in %s at line: %u\n", __FILE__, __LINE__ ); \
log_perror(__VA_ARGS__); } while(0)
#endif

#ifdef DEBUG
#define log_err(...) do { fprintf(stderr, "Error: in %s at line: %u\n", __FILE__, __LINE__ ); \
log_err(__VA_ARGS__); } while(0)
#endif

#ifdef DEBUG
#define log_warning(...) do { fprintf(stderr, "Warning: in %s at line: %u\n", __FILE__, __LINE__ ); \
log_warning(__VA_ARGS__); } while(0)
#endif

#ifdef DEBUG
#define log_notice(...) do { fprintf(stderr, "Notice: in %s at line: %u\n", __FILE__, __LINE__ ); \
log_notice(__VA_ARGS__); } while(0)
#endif

#ifdef DEBUG
#define log_info(...) do { fprintf(stderr, "Info: in %s at line: %u\n", __FILE__, __LINE__ ); \
log_info(__VA_ARGS__); } while(0)
#endif

#ifdef DEBUG
#define log_debug(...) do { fprintf(stderr, "Debug: In %s at line: %u\n", __FILE__, __LINE__ ); \
log_debug(__VA_ARGS__); } while(0)
#endif

#ifdef DEBUG
#define dprint_info() do { fprintf(stderr, "Debug && Info: In %s at line: %u\n", __FILE__, __LINE__ ); \
print_info(); } while(0)
#else
#define dprint_info() (void)0
#endif

#endif
