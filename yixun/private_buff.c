/*
 *  private_buff.c
 *  yixun
 *
 *  Created by Summer Town on 3/18/11.
 *  Copyright 2011 __MyCompanyName__. All rights reserved.
 *
 */

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <syslog.h>
#include <pthread.h>
#include <errno.h>

#include "log_xxx.h"
#include "print_hex.h"
#include "common_macro.h"

//消息缓冲区大小 4KB + 1
#ifndef INFO_BUF_LEN
#define INFO_BUF_LEN 4097
#endif


void print_info();
void trunc_info();
char * copy_info(char outbuff[], size_t n);
char * copy_info_trunc(char outbuff[], size_t n);

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

static char msg_buff[INFO_BUF_LEN];  //消息缓冲区
static const char * msg_buff_end = msg_buff + sizeof(msg_buff);
static char *head = msg_buff, *tail = msg_buff; //消息头、尾指针

static int vlogf(const char *fmt, va_list args); //Log formated

static void append_msg(const char *msg); //往消息缓冲区放新信息 Thread safe
static char * get_msg();            //从缓冲区取信息 not thread safe
inline static void trunc_buff();           //清空缓冲区(修改头指针和尾指针)
inline static int buff_not_empty();


void print_info()
{
    switch (get_log_type()) {
        case LDAEMON:
            break;
        case LCONSOLE:
            fflush(stdout);
            break;
        case LBUFF:
            if (pthread_mutex_trylock(&mutex)) pthread_mutex_lock(&mutex);
            if (buff_not_empty()) {
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
    if (tail >= head) {
        tail += cnt;
        if (tail + 1 >= msg_buff_end) {
            msg += cnt;
            cnt = my_strcpy(msg_buff, msg, head - tail);
            tail = msg_buff + cnt;
            if (tail >= head)
                head = tail + 1;
        }
    } else {
        tail += cnt;
        if (tail >= head) {
            if (tail + 1 >= msg_buff_end) {// reach end
                msg += cnt;
                cnt = my_strcpy(msg_buff, msg, head - tail);
                tail = msg_buff + cnt;
                head = tail + 1;
            } else {
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
    else {
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




