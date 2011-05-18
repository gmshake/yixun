/*
 * server.c
 *
 * By Summer Town
 * 2011.04.26
 */

#include <sys/types.h>
#include <sys/socket.h>		/* socket(), setsockopt(), bind(), listen()... */
#include <sys/select.h>		/* select() */
#include <unistd.h>			/* close() */
#include <strings.h>
#include <errno.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "log_xxx.h"
#include "common_macro.h"
#include "yixun_config.h"
#include "radius.h"

#define MAX_CLIENT 10
#define R_BUF_LEN 1024

static int sock_listen;
static int is_listening;

extern int act_on_info(void *buff, int sockfd);

/*
 * start_listen(), start listen on Radius port
 * return 0 on success, otherwise -1;
 */
int
start_listen(void)
{
	if (is_listening)
		return 0;
	if ((sock_listen = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		log_perror("%s: socket()", __FUNCTION__);
		return -1;
	}

	int opt = 1;
	if (setsockopt(sock_listen, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
		log_perror("%s: setsockopt(SO_REUSEADDR)", __FUNCTION__);
		goto ERROR;
	}
	struct sockaddr_in local;
	bzero(&local, sizeof(local));
	local.sin_addr.s_addr = INADDR_ANY; /* listen on 0.0.0.0 is NOT a good idea*/
	local.sin_family = AF_INET;
	local.sin_port = htons(listenport);

	if (bind(sock_listen, (struct sockaddr *)&local, sizeof(local)) != 0) {
		log_perror("%s: bind(%s)", __FUNCTION__, inet_ntoa(local.sin_addr));
		goto ERROR;
	}
	if (listen(sock_listen, MAX_CLIENT) != 0) {
		log_perror("%s: listen(%s)", __FUNCTION__, inet_ntoa(local.sin_addr));
		goto ERROR;
	}
	is_listening = -1;
	return 0;
ERROR:
	close(sock_listen);
	is_listening = 0;
	return -1;
}

/*
 * stop_listen(), stop listen on Radius port
 * return 0
 */
int
stop_listen(void)
{
	if (is_listening) {
		close(sock_listen);
		is_listening = 0;
	}
	return 0;
}

/*
 * wait_msg(), to receive server side infomation
 * return 0 on success, otherwise return none-zero
 */
int
wait_msg(void)
{
	static int select_timeout = 1;
	fd_set rfds;
	struct timeval tv;

	tv.tv_sec = select_timeout;
	tv.tv_usec = 0;
	FD_ZERO(&rfds);
	FD_SET(sock_listen, &rfds);

	switch (select(sock_listen + 1, &rfds, NULL, NULL, &tv)) {
		case -1:
			if (errno != EINTR)
				log_perror("%s: select()", __FUNCTION__);
			return 0;
		case 0:
			if (select_timeout < 16)
				select_timeout <<= 1;
			return 0;
		default:
			if (! FD_ISSET(sock_listen, &rfds))
				return 0;
			select_timeout = 1;
			break;
	}

	BUFF_ALIGNED(r_buff, R_BUF_LEN);
	struct sockaddr_in r_client;
	socklen_t len = sizeof(r_client);
	int sock_client = accept(sock_listen, (struct sockaddr *)&r_client, &len);
	if (sock_client < 0) {
		log_perror("%s: accept()", __FUNCTION__);
		return -1;
	}

	if (msg_server != 0 && msg_server != r_client.sin_addr.s_addr) {
		log_notice("%s: %s attempt to connect\n", \
				__FUNCTION__, inet_ntoa(r_client.sin_addr));
		close(sock_client);
		return 0;
	}

	log_info("%s: accept: %s\n", __FUNCTION__, inet_ntoa(r_client.sin_addr));

	tv.tv_sec = rcv_timeout;
	tv.tv_usec = 0;
	if (setsockopt(sock_client, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
		log_perror("%s: setsockopt(SO_RCVTIMEO)", __FUNCTION__);

	switch (recv(sock_client, r_buff, R_BUF_LEN, 0)) {
		case -1:
			if (errno == EAGAIN)
				log_err("%s: recv(): time out\n", __FUNCTION__);
			else
				log_perror("%s: recv()", __FUNCTION__);
			break;
		case 0:
			log_perror("%s: recv(): Client %s has closed its half side of the connection\n",	__FUNCTION__, inet_ntoa(r_client.sin_addr));
			break;
		default:
			if (act_on_info(r_buff, 0) < 0)
				close(sock_client);
			return 0;
	}

	close(sock_client);
	return -1;
}


