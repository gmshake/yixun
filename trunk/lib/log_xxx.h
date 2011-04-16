/*
 *  log_xxx.h
 *  yixun
 *
 *  Created by Summer Town on 3/17/11.
 *  Copyright 2011 __MyCompanyName__. All rights reserved.
 *
 */

#ifndef _LOG_XXX_H
#define _LOG_XXX_H

#ifndef LNONE
#define LNONE 0
#endif
#ifndef LCONSOLE
#define LCONSOLE 0x01
#endif
#ifndef LDAEMON
#define LDAEMON 0x02
#endif
#ifndef LBUFF
#define LBUFF 0x04
#endif

#ifdef YIXUN_MULTI_THREAD
#define USE_PTHREAD 1
#else
#define USE_PTHREAD 0
#endif


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

extern size_t my_strcpy(char *dst, const char *src, size_t n);

#endif
