/*
 * yixun_config.h
 *
 * by Summer Town
 * 2011.04.26
 */

#ifndef YIXUN_CONFIG_H
#define YIXUN_CONFIG_H

#ifndef CONF_LEN
#define CONF_LEN 32
#endif

extern char username[CONF_LEN];
extern char password[CONF_LEN];
extern char hwaddr[CONF_LEN];
extern char regip[CONF_LEN];

extern char authserver[CONF_LEN];
extern char msgserver[CONF_LEN];

extern unsigned int listenport;

extern time_t conn_timeout;
extern time_t snd_timeout;
extern time_t rcv_timeout;
extern time_t heart_beat_timeout;

extern int pre_config_done;


#endif	/* YIXUN_CONFIG_H */

