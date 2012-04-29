/*
 *  log_xxx.c
 *  yixun
 *
 *  Created by Summer Town on 3/17/11.
 *  Copyright 2011 __MyCompanyName__. All rights reserved.
 *
 */

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <syslog.h>

#include "log_xxx.h"

#if USE_PTHREAD
#include <pthread.h>
#include "private_buff.h"
#endif

#include <errno.h>

#include "hexdump.h"

//消息缓冲区大小 4KB
#ifndef INFO_BUF_LEN
#define INFO_BUF_LEN 4096
#endif

static int log_type = LCONSOLE;


void
set_log_type(int flag)
{
	log_type = flag;
}

int
get_log_type()
{
	return log_type;
}

int
log_log(const char *fmt, ...)
{
	int cnt = 1;
	va_list ap;
	va_list ap2;
#if USE_PTHREAD
	va_list ap3;
#endif
	va_start(ap, fmt);
	va_copy(ap2, ap);
#if USE_PTHREAD
	va_copy(ap3, ap);
#endif

	int i = 1;
	while (i != LMAX) {
		switch (log_type & i) {
			case LCONSOLE:
				cnt = vfprintf(stdout, fmt, ap);
				break;
			case LDAEMON:
				vsyslog(LOG_NOTICE, fmt, ap2);
				break;
#if USE_PTHREAD
			case LBUFF:
				cnt = vlogf(fmt, ap3);
				break;
#endif
			default:
				break;
		}
		i <<= 1;
	}

	va_end(ap);
	va_end(ap2);
#if USE_PTHREAD
	va_end(ap3);
#endif
	return cnt;
}

int
log_perror(const char *fmt, ...)
{
	int cnt;
	va_list ap;
	va_start(ap, fmt);

	char buff[INFO_BUF_LEN];
	cnt = my_strcpy(buff, "Error: ", sizeof(buff));
	if (cnt < sizeof(buff))
		cnt += vsnprintf(buff + cnt, sizeof(buff) - cnt, fmt, ap);
	if (cnt < sizeof(buff))
		cnt += snprintf(buff + cnt, sizeof(buff) - cnt, ": %s", strerror(errno));

	va_end(ap);

	int i = 1;
	while (i != LMAX) {
		switch (log_type & i) {
			case LCONSOLE:
				cnt = fprintf(stdout, "%s\n", buff);
				break;
			case LDAEMON:
				syslog(LOG_ERR, buff);
				break;
#if USE_PTHREAD
			case LBUFF:
				cnt += snprintf(buff + cnt, sizeof(buff) - cnt, "\n");
				append_msg(buff);
				break;
#endif
			default:
				break;
		}
		i <<= 1;
	}

	return cnt;
}

static int
vlog_xxx(const char *prepend, int log_level, const char *fmt, va_list ap)
{
	int cnt;
	va_list ap2;
	va_copy(ap2, ap);
#if USE_PTHREAD
	va_list ap3;
	va_copy(ap3, ap);
#endif
	char newfmt[INFO_BUF_LEN];
	cnt = my_strcpy(newfmt, prepend, sizeof(newfmt));
	if (cnt < sizeof(newfmt))
		cnt += my_strcpy(newfmt + cnt, fmt, sizeof(newfmt) - cnt);

	int i = 1;
	while (i != LMAX) {
		switch (log_type & i) {
			case LCONSOLE:
				cnt = vfprintf(stdout, newfmt, ap);
				break;
			case LDAEMON:
				vsyslog(log_level, newfmt, ap2);
				break;
#if USE_PTHREAD
			case LBUFF:
				cnt = vlogf(newfmt, ap3);
				break;
#endif
			default:
				break;
		}
		i <<= 1;
	}

	va_end(ap2);
#if USE_PTHREAD
	va_end(ap3);
#endif
	return cnt;
}

int
log_critical(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	int ret = vlog_xxx("Critical: ", LOG_CRIT, fmt, ap);
	va_end(ap);
	return ret;
}

int
log_err(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	int ret = vlog_xxx("Error: ", LOG_ERR, fmt, ap);
	va_end(ap);
	return ret;
}

int
log_warning(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	int ret = vlog_xxx("Warning: ", LOG_WARNING, fmt, ap);
	va_end(ap);
	return ret;
}

int
log_notice(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	int ret = vlog_xxx("Notice: ", LOG_NOTICE, fmt, ap);
	va_end(ap);
	return ret;
}

int
log_info(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	/* 
	 * LOG_INFO wouldn't log on Leopard
	 * due to the setting in /etc/syslog.conf
	 */
	int ret = vlog_xxx("Info: ", LOG_NOTICE, fmt, ap);
	va_end(ap);
	return ret;
}

int
log_debug(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	int ret = vlog_xxx("Debug: ", LOG_DEBUG, fmt, ap);
	va_end(ap);
	return ret;
}


int
log_hex(const void *data, size_t len)
{
	size_t bufflen = len * 3 + len / 16 + 1;	// alloc ONE more: \0
	char *buff = (char *)malloc(bufflen);
	if (buff == NULL) {
		log_perror("[log_hex] malloc");
		return -1;
	}
	int rval = hex2ascii(buff, bufflen, data, len);

	int i = 1;
	while (i != LMAX) {
		switch (log_type & i) {
			case LCONSOLE:
				fprintf(stderr, "%s\n", buff);
				break;
			case LDAEMON:
				syslog(LOG_DEBUG, buff);
				break;
#if USE_PTHREAD
			case LBUFF:
				log_log("%s\n", buff);
				break;
#endif
			default:
				break;
		}
		i <<= 1;
	}

	return rval;
}

/*
 * my_strcpy:
 * Copy no more than n byte long characters from src to dst,
 * dst string is then ended with '\0' character
 * return bytes copied, not including '\0', ie, return value is always less than n
 */
size_t
my_strcpy(char *dst, const char *src, size_t n)
{
	size_t i = 0;
	while (++i < n && *src != '\0')
		*dst++ = *src++;

	*dst = '\0';
	return i - 1;
}
