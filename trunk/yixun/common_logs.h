/*
 *  common_logs.h
 *  YiXun
 *
 *  Created by Summer Town on 10/3/10.
 *  Copyright 2010 __MyCompanyName__. All rights reserved.
 *
 */
#ifndef _COMMON_LOGS_H
#define _COMMON_LOGS_H

#define LCONSOLE 0
#define LDAEMON 1
#define LBUFF 2

extern void set_log_type(int flag);
extern int get_log_type();

extern int log_log(const char *fmt, ...);
extern int log_perror(const char *fmt, ...);
extern int log_critical(const char *fmt, ...);
extern int log_err(const char *fmt, ...);
extern int log_warning(const char *fmt, ...);
extern int log_notice(const char *fmt, ...);
extern int log_info(const char *fmt, ...);
extern int log_debug(const char *fmt, ...);

extern int log_hex(const void *data, size_t cnt);

extern void print_info();
extern void trunc_info(); // trunc info
extern char * copy_info(char outbuff[], size_t n); // copy info to outbuff
extern char * copy_info_trunc(char outbuff[], size_t n); // copy info and trunc

extern void free_print_info_locks();

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

#endif //_COMMON_LOGS_H
