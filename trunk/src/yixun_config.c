/*
 * yixun_config.c
 *
 * by Summer Town
 * 2011.04.26
 */

#include <sys/types.h>

#ifndef CONF_LEN
#define CONF_LEN 32
#endif

char username[CONF_LEN];
char password[CONF_LEN];
char hwaddr[CONF_LEN];
char regip[CONF_LEN];

char authserver[CONF_LEN];
char msgserver[CONF_LEN];

unsigned int listenport;

time_t conn_timeout;
time_t snd_timeout;
time_t rcv_timeout;
time_t heart_beat_timeout;

int pre_config_done;

