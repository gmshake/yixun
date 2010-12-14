/*
 *  commen_logs.c
 *  YiXun
 *
 *  Created by Summer Town on 10/3/10.
 *  Copyright 2010 __MyCompanyName__. All rights reserved.
 *
 */

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <syslog.h>
#include <pthread.h>
#include <errno.h>

#include "common_macro.h"
#include "print_hex.h"

//消息缓冲区大小 4KB + 1
#ifndef INFO_BUF_LEN
#define INFO_BUF_LEN 4097
#endif

#ifndef LCONSOLE
#define LCONSOLE 0
#endif

#ifndef LDAEMON
#define LDAEMON 1
#endif

#ifndef LBUFF
#define LBUFF 2
#endif

void set_log_type(int flag);
int get_log_type();

int log_perror(const char *fmt, ...);
int log_critical(const char *fmt, ...);
int log_err(const char *fmt, ...);
int log_warning(const char *fmt, ...);
int log_notice(const char *fmt, ...);
int log_info(const char *fmt, ...);
int log_debug(const char *fmt, ...);

int log_hex(const void *data, size_t cnt);

void print_info();
void trunc_info();
char * copy_info(char outbuff[], size_t n);
char * copy_info_trunc(char outbuff[], size_t n);

static int log_type = LCONSOLE;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

static char msg_buff[INFO_BUF_LEN];  //消息缓冲区
static const char * msg_buff_end = msg_buff + sizeof(msg_buff);
static char *head = msg_buff, *tail = msg_buff; //消息头、尾指针

static int vlogf(const char *fmt, va_list args); //Log formated

static void append_msg(const char *msg); //往消息缓冲区放新信息 Thread safe
static char * get_msg();            //从缓冲区取信息 not thread safe
inline static void trunc_buff();           //清空缓冲区(修改头指针和尾指针)
inline static int buff_not_empty();
static size_t my_strcpy(char *dst, const char *src, size_t n);

void set_log_type(int flag)
{
    if (pthread_mutex_trylock(&mutex)) pthread_mutex_lock(&mutex);
    log_type = flag;
    pthread_mutex_unlock(&mutex);
}

int get_log_type()
{
    if (pthread_mutex_trylock(&mutex)) pthread_mutex_lock(&mutex);
    int flag = log_type;
    pthread_mutex_unlock(&mutex);
    return flag;
}

int log_log(const char *fmt, ...)
{
    int cnt = 1;
    va_list args;
    va_start(args, fmt);
    
    switch (log_type)
    {
        case LDAEMON:
            vsyslog(LOG_NOTICE, fmt, args);
            break;
        case LCONSOLE:
            cnt = vfprintf(stdout, fmt, args);
            break;
        case LBUFF:
            cnt = vlogf(fmt, args);
            break;
        default:
            break;
    }
    
    va_end(args);
    return cnt;
}

int log_perror(const char *fmt, ...)
{
    int cnt;
    va_list args;
    va_start(args, fmt);
    
    char buff[INFO_BUF_LEN];
    cnt = my_strcpy(buff, "Error:", sizeof(buff));
    if (cnt < sizeof(buff))
        cnt += vsnprintf(buff + cnt, sizeof(buff) - cnt, fmt, args);
    if (cnt < sizeof(buff))
        cnt += snprintf(buff + cnt, sizeof(buff) - cnt, ":%s", strerror(errno));
    
    va_end(args);
    
    switch (log_type)
    {
        case LDAEMON:
            syslog(LOG_ERR, buff);
            break;
        case LCONSOLE:
            cnt = fprintf(stdout, "%s\n", buff);
            break;
        case LBUFF:
            cnt += snprintf(buff + cnt, sizeof(buff) - cnt, "\n");
            append_msg(buff);
            break;
        default:
            break;
    }
        
    return cnt;
}

int log_critical(const char *fmt, ...)
{
    int cnt;
    va_list args;
    va_start(args, fmt);
    
    char newfmt[INFO_BUF_LEN];
    cnt = my_strcpy(newfmt, "Critical:", sizeof(newfmt));
    if (cnt < sizeof(newfmt))
        cnt += my_strcpy(newfmt + cnt, fmt, sizeof(newfmt) - cnt);
        
    switch (log_type)
    {
        case LDAEMON:
            vsyslog(LOG_CRIT, newfmt, args);
            break;
        case LCONSOLE:
            cnt = vfprintf(stdout, newfmt, args);
            break;
        case LBUFF:
            cnt = vlogf(newfmt, args);
            break;
        default:
            break;
    }
    
    va_end(args);
    return cnt;
}

int log_err(const char *fmt, ...)
{
    int cnt;
    va_list args;
    va_start(args, fmt);
    
    char newfmt[INFO_BUF_LEN];
    cnt = my_strcpy(newfmt, "Error:", sizeof(newfmt));
    if (cnt < sizeof(newfmt))
        cnt += my_strcpy(newfmt + cnt, fmt, sizeof(newfmt) - cnt);
    
    switch (log_type)
    {
        case LDAEMON:
            vsyslog(LOG_ERR, newfmt, args);
            break;
        case LCONSOLE:
            cnt = vfprintf(stdout, newfmt, args);
            break;
        case LBUFF:
            cnt = vlogf(newfmt, args);
            break;
        default:
            break;
    }
    
    va_end(args);
    return cnt;
}

int log_warning(const char *fmt, ...)
{
    int cnt;
    va_list args;
    va_start(args, fmt);
    
    char newfmt[INFO_BUF_LEN];
    cnt = my_strcpy(newfmt, "Warning:", sizeof(newfmt));
    if (cnt < sizeof(newfmt))
        cnt += my_strcpy(newfmt + cnt, fmt, sizeof(newfmt) - cnt);
    
    switch (log_type)
    {
        case LDAEMON:
            vsyslog(LOG_WARNING, newfmt, args);
            break;
        case LCONSOLE:
            cnt = vfprintf(stdout, newfmt, args);
            break;
        case LBUFF:
            cnt = vlogf(newfmt, args);
            break;
        default:
            break;
    }
    
    va_end(args);
    return cnt;
}

int log_notice(const char *fmt, ...)
{
    int cnt;
    va_list args;
    va_start(args, fmt);
    
    char newfmt[INFO_BUF_LEN];
    cnt = my_strcpy(newfmt, "Notice:", sizeof(newfmt));
    if (cnt < sizeof(newfmt))
        cnt += my_strcpy(newfmt + cnt, fmt, sizeof(newfmt) - cnt);
    
    switch (log_type)
    {
        case LDAEMON:
            vsyslog(LOG_NOTICE, newfmt, args);
            break;
        case LCONSOLE:
            cnt = vfprintf(stdout, newfmt, args);
            break;
        case LBUFF:
            cnt = vlogf(newfmt, args);
            break;
        default:
            break;
    }
    
    va_end(args);
    return cnt;
}

int log_info(const char *fmt, ...)
{
    int cnt;
    va_list args;
    va_start(args, fmt);
    
    char newfmt[INFO_BUF_LEN];
    cnt = my_strcpy(newfmt, "Info:", sizeof(newfmt));
    if (cnt < sizeof(newfmt))
        cnt += my_strcpy(newfmt + cnt, fmt, sizeof(newfmt) - cnt);
    
    switch (log_type)
    {
        case LDAEMON:
            //vsyslog(LOG_INFO, newfmt, args); LOG_INFO wouldn't log on Leopard due to the setting in /etc/syslog.conf
            vsyslog(LOG_NOTICE, newfmt, args);
            break;
        case LCONSOLE:
            cnt = vfprintf(stdout, newfmt, args);
            break;
        case LBUFF:
            cnt = vlogf(newfmt, args);
            break;
        default:
            break;
    }
    
    va_end(args);
    return cnt;
}

int log_debug(const char *fmt, ...)
{
    int cnt;
    va_list args;
    va_start(args, fmt);
    
    char newfmt[INFO_BUF_LEN];
    cnt = my_strcpy(newfmt, "Debug:", sizeof(newfmt));
    if (cnt < sizeof(newfmt))
        cnt += my_strcpy(newfmt + cnt, fmt, sizeof(newfmt) - cnt);
    
    switch (log_type)
    {
        case LDAEMON:
            vsyslog(LOG_DEBUG, newfmt, args);
            break;
        case LCONSOLE:
#ifdef DEBUG
            cnt = vfprintf(stderr, newfmt, args);
#else
            cnt = 0;
#endif
            break;
        case LBUFF:
#ifdef DEBUG
            cnt = vlogf(newfmt, args);
#else
            cnt = 0;
#endif
            break;
        default:
            break;
    }
    
    va_end(args);
    return cnt;
}


int log_hex(const void *data, size_t cnt)
{
    size_t bufflen = sizeof(char) * (cnt * 3 + cnt / 16 + 1); // alloc ONE more: \0
    char *buff = (char *)malloc(bufflen);
    if (buff == NULL)
    {    
        log_perror("[log_hex] malloc");
        return -1;
    }
    int rval = hex_to_ascii(buff, bufflen, data, cnt);
    
    switch (log_type)
    {
        case LDAEMON:
            syslog(LOG_DEBUG, buff);
            break;
        case LCONSOLE:
            fprintf(stderr, "%s\n", buff);
            break;
        case LBUFF:
            log_log("%s\n", buff);
            break;
        default:
            break;
    }
    
    return rval;
}

void print_info()
{
    switch (log_type)
    {
        case LDAEMON:
            break;
        case LCONSOLE:
            fflush(stdout);
            break;
        case LBUFF:
            if (pthread_mutex_trylock(&mutex)) pthread_mutex_lock(&mutex);
            if (buff_not_empty())
            {
                fprintf(stdout, get_msg());
                trunc_buff();
                fflush(stdout);
            }
            pthread_mutex_unlock(&mutex);
            break;
        default:
            break;
    }
}


char * copy_info(char outbuff[], size_t n)
{
	if (pthread_mutex_trylock(&mutex)) pthread_mutex_lock(&mutex);
    my_strcpy(outbuff, get_msg(), n);
	pthread_mutex_unlock(&mutex);
	return outbuff;
}

char * copy_info_trunc(char outbuff[], size_t n)
{
	if (pthread_mutex_trylock(&mutex)) pthread_mutex_lock(&mutex);
    my_strcpy(outbuff, get_msg(), n);
    trunc_buff();
    pthread_mutex_unlock(&mutex);
	return outbuff;
}

void trunc_info()
{
	if (pthread_mutex_trylock(&mutex)) pthread_mutex_lock(&mutex);
	trunc_buff();
	pthread_mutex_unlock(&mutex);
}


void free_print_info_locks()
{
	pthread_mutex_destroy(&mutex);
}


// Notice: Thread safe
static void append_msg(const char *msg) 
{
    // 只保存最后一段
    if (strlen(msg) > sizeof(msg_buff) - 1)
        msg += strlen(msg) - (sizeof(msg_buff) - 1);

    if (pthread_mutex_trylock(&mutex)) pthread_mutex_lock(&mutex);

    int cnt = my_strcpy(tail, msg, msg_buff_end - tail);
    if (tail >= head)
    {
        tail += cnt;
        if (tail + 1 >= msg_buff_end)
        {
            msg += cnt;
            cnt = my_strcpy(msg_buff, msg, head - tail);
            tail = msg_buff + cnt;
            if (tail >= head)
                head = tail + 1;
        }
    }
    else
    {
        tail += cnt;
        if (tail >= head)
        {
            if (tail + 1 >= msg_buff_end) // reach end
            {
                msg += cnt;
                cnt = my_strcpy(msg_buff, msg, head - tail);
                tail = msg_buff + cnt;
                head = tail + 1;
            }
            else
            {
                head = tail + 1;
            }
        }
    }
    pthread_mutex_unlock(&mutex);
}


// Notice: not thread safe
static char * get_msg()
{
    static char buff[INFO_BUF_LEN];
    if (tail >= head)
        my_strcpy(buff, head, tail - head + 1);
    else
    {
        char *p = buff;
        p += my_strcpy(p, head, msg_buff_end - head);
        my_strcpy(p, msg_buff, tail - msg_buff + 1);
    }
    return buff;
}


inline static int buff_not_empty()
{
    return tail != head;
}

inline static void trunc_buff()
{
    tail = head;
    *head = '\0';
}

/* va_list log format */
static int vlogf(const char *fmt, va_list args)
{
    char buff[INFO_BUF_LEN];
    int cnt = vsnprintf(buff, sizeof(buff), fmt, args);
    append_msg(buff);
    return cnt;
}

/*
 * my_strcpy:
 * Copy no more than n byte long characters from src to dst,
 * dst string is then ended with '\0' character
 * return bytes copied, not including '\0', ie, return value is always less than n
 */
static size_t my_strcpy(char *dst, const char *src, size_t n)
{
    size_t i = 0;
    while (++i < n && *src != '\0')
    {
        *dst++ = *src++;
    }
    *dst = '\0';
    return i - 1;
}
