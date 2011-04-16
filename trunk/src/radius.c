/*
 *  radius.c
 *  YiXun
 *
 *  Created by Summer Town on 1/1/11.
 *  Copyright 2010 __MyCompanyName__. All rights reserved.
 *
 */

#include <stdio.h>
#include <stdint.h>		/* uint8_t */
#include <stdlib.h>		/* malloc(), calloc() */
#include <unistd.h>

#include <sys/types.h>
#include <string.h>		/* strcpy()... */
#include <strings.h>		/* bzero() */

#include <arpa/inet.h>		/* inet_addr() */
#include <netinet/in.h>		/* in_addr_t sockaddr_in INADDR_ANY */
#include <sys/socket.h>		/* PF_INET, AF_INET, sockaddr, bind(), connect()... */

#include "log_xxx.h"

#if USE_PTHREAD
#include <pthread.h>
#endif

#include <fcntl.h>
#include <errno.h>

#include "rds_types.h"
#include "yixun_config.h"
#include "convert_code.h"
#include "encode_password.h"
#include "get_ip_mac.h"
#include "radius.h"
#include "common_macro.h"

#ifdef DEBUG
#include "hexdump.h"
#endif


static int sockListen;
static int is_listening;

void print_config(const struct mcb *mcb);

static int pre_config(struct mcb *mcb);
static int yixun_log_op(int op, struct mcb *mcb);


/* 返回 0 表示无错， 返回正数，表示出错原因(e_user, e_pwd ....) */
static int act_on_info(void *buff, struct mcb *mcb, int sockfd);

/* 认证通过后，获取接入服务器给的参数 */
static int get_parameters(const void *buff, struct mcb *mcb);

/* 生成一个发送包（包头） */
static struct rds_packet_header *make_rds_packet(void *buff, enum rds_header_type type);

/* 为发送包添加相应字段 */
static void add_segment(void *buff, enum rds_segment_type type, uint8_t length, uint8_t content_len, const void *content);

/* 带连接超时的connect */
static int connect_tm(int socket, const struct sockaddr *addr, socklen_t addr_len, struct timeval *timeout);


/*
 * pre_config(), pre-config necessary infomation, check username, pwd etc.
 * @param mcb, in/out
 * return 0 on success, otherwise -1;
 */
static int
pre_config(struct mcb *mcb)
{
	if (mcb->username == NULL) {
		log_err("[%s] Require username\n", __FUNCTION__);
		return -1;
	}
	if (mcb->clientip) {
		mcb->gre_src = inet_addr(mcb->clientip);
		if (mcb->gre_src == 0 || mcb->gre_src == 0xffffffff)
			log_err("[%s] Invalid ip address:%s\n", __FUNCTION__, mcb->clientip);
	}
	if (mcb->mac) {
		if (string_to_lladdr(mcb->eth_addr, mcb->mac) < 0)
			log_err("[%s] Invalid lladdr:%s\n", __FUNCTION__, mcb->mac);
	}
	if (mcb->serverip) {
		char tmp[64];
		strncpy(tmp, mcb->serverip, sizeof(tmp));
		tmp[sizeof(tmp) - 1] = '\0';
		char *args[2] = { NULL };
		char *instr = tmp;
		args[0] = strsep(&instr, "/");
		args[1] = strsep(&instr, "/");
		mcb->auth_server = inet_addr(args[0]);
		if (args[1] != NULL) {
			sscanf(args[1], "%u", &mcb->auth_server_maskbits);
			if (mcb->auth_server_maskbits > 32)
				mcb->auth_server_maskbits = 32;
		}
	} else {
		mcb->auth_server = inet_addr(AUTH_SERVER);
		mcb->auth_server_maskbits = AUTH_SERVER_MASKBITS;
	}
	mcb->select_timeout = 1;

	return 0;
}

/*
 * yixun_log_op(), make && send proper packet indicated by op
 * @op, which type of packet
 * @param mcb, in/out
 * return 0 on success, otherwise none-zero;
 */

#define LOGIN 0x01
#define LOGOUT 0x02
#define KEEPALIVE 0x03
static int
yixun_log_op(int op, struct mcb *mcb)
{
	int rval = 0;
	if (!mcb->pre_config_done) {
		if (pre_config(mcb) < 0)
			return -1;
		mcb->pre_config_done = -1;
	}
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		log_perror("[%s] socket", __FUNCTION__);
		return -1;
	}
	struct timeval tv;
	tv.tv_sec = CONNECTION_TIMEOUT;
	tv.tv_usec = 0;

	struct sockaddr_in auth_server;
	bzero(&auth_server, sizeof(struct sockaddr_in));
	auth_server.sin_family = AF_INET;
	auth_server.sin_port = htons(RADIUS_PORT);
	auth_server.sin_addr.s_addr = mcb->auth_server;

	if (connect_tm(sockfd, (struct sockaddr *)&auth_server, sizeof(struct sockaddr_in), &tv) < 0) {
		log_perror("connect to %s", inet_ntoa(auth_server.sin_addr));
		rval = -1;
		goto ERROR;
	}
	/*
	 * when op is same as the last op, then there is no\ need to re-make a same send packet
	 */
	if (op != mcb->last_op) {
		if (get_ip_mac_by_socket(sockfd, &mcb->gre_local, mcb->mac ? NULL : mcb->eth_addr) < 0) {
			log_err("[%s] get ip address and eth_addr\n", __FUNCTION__);
			rval = -1;
			goto ERROR;
		}
		if (mcb->clientip == NULL || mcb->gre_src == 0 || mcb->gre_src == 0xffffffff)
			mcb->gre_src = mcb->gre_local;

		bzero(mcb->s_buff, sizeof(mcb->s_buff));
		switch (op) {
			case LOGIN:
			{
				uint8_t version[4] = { 0x03, 0x00, 0x00, 0x06 };	/* hack: sigh... */
				uint8_t zeros[4] = { 0x00, 0x00, 0x00, 0x00 };

				uint8_t *sec_pwd = (uint8_t *) malloc(sizeof(uint8_t) * (strlen(mcb->password) + 2));
				if (sec_pwd == NULL) {
					log_perror("[%s] malloc\n", __FUNCTION__);
					rval = -1;
					goto ERROR;
				}
				encode_pwd_with_ip(sec_pwd, mcb->password, mcb->gre_src);

				make_rds_packet(mcb->s_buff, u_login);
				add_segment(mcb->s_buff, c_mac, 6, sizeof(mcb->eth_addr), (char *)mcb->eth_addr);
				add_segment(mcb->s_buff, c_ip, sizeof(in_addr_t), sizeof(in_addr_t), (char *)&mcb->gre_src);
				/* Hack:用户名有长度限制 */
				add_segment(mcb->s_buff, c_user, MAX_USER_NAME_LEN, strlen(mcb->username), (char *)mcb->username);
				add_segment(mcb->s_buff, c_pwd, strlen((char *)sec_pwd), strlen((char *)sec_pwd), (char *)sec_pwd);
				add_segment(mcb->s_buff, c_ver, 4, sizeof(version), (char *)version);
				add_segment(mcb->s_buff, c_pad, 4, sizeof(zeros), (char *)zeros);

				free(sec_pwd);
				break;
			}
			case LOGOUT:
				/* Hack:退出登录和保持活动连接只有packet_type有差别 */
				make_rds_packet(mcb->s_buff, u_logout);
				goto LOGOUT_KEEPALIVE;
			case KEEPALIVE:
				make_rds_packet(mcb->s_buff, u_keepalive);
LOGOUT_KEEPALIVE:
				add_segment(mcb->s_buff, c_ip, sizeof(in_addr_t), sizeof(in_addr_t), (char *)&mcb->gre_src);
				add_segment(mcb->s_buff, c_user, MAX_USER_NAME_LEN, strlen(mcb->username), (char *)mcb->username);
				break;
			default:
#ifdef DEBUG
				log_err("[%s] unkown op %d\n", __FUNCTION__, op);
#endif
				rval = -2;
				goto ERROR;
		}
		mcb->s_buff_len = RDS_PACKET_LEN(mcb->s_buff);
		mcb->last_op = op;
	}
	tv.tv_sec = SND_TIMEOUT;
	tv.tv_usec = 0;
	if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
		log_perror("[%s] setsockopt", __FUNCTION__);
		rval = -3;
		goto ERROR;
	}
	if (send(sockfd, mcb->s_buff, mcb->s_buff_len, 0) < 0) {
		log_perror("[%s] send to %s", __FUNCTION__, inet_ntoa(auth_server.sin_addr));
		rval = -1;
		goto ERROR;
	}
	switch (op) {
		case LOGIN:
		{
			/* receive buffer */
			BUFF_ALIGNED(r_buff, R_BUF_LEN);
#ifdef DEBUG
			log_info("address of r_buff is %p\n", &r_buff);
#endif

			tv.tv_sec = RCV_TIMEOUT;
			tv.tv_usec = 0;
			if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
				log_perror("[%s] setsockopt", __FUNCTION__);
				rval = -3;
				goto ERROR;
			}
			ssize_t ret = recv(sockfd, r_buff, R_BUF_LEN, 0);
			if (ret <= 0) {
				if (ret == 0) {
					log_err("[%s] receive: Auth server %s \
								has closed its half side of the connection\n", __FUNCTION__, inet_ntoa(auth_server.sin_addr));
				} else {
					if (errno == EAGAIN)
						log_err("[%s] recv: time out\n", __FUNCTION__);
					else
						log_perror("[%s] recv", __FUNCTION__);
				}

				rval = -1;
				goto ERROR;
			}
			if ((rval = act_on_info(r_buff, mcb, sockfd)) != 0)
				goto ERROR;

			break;
		}
		case LOGOUT:
		case KEEPALIVE:
			break;
		default:
#ifdef DEBUG
			log_err("[%s] unkown op %d\n", __FUNCTION__, op);
#endif
			rval = -1;
			break;
	}

ERROR:
	close(sockfd);
	return rval;
}

/*
 * login(), send login packet
 * @param mcb, in/out
 * return 0 on success, otherwise -1;
 */
int
login(struct mcb *mcb)
{
	int rval = yixun_log_op(LOGIN, mcb);
	if (rval == 0)
		print_config(mcb);
	return rval;
}

/*
 * logout(), send logout packet
 * @param mcb, in
 * return 0 on success, otherwise -1;
 */
int
logout(struct mcb *mcb)
{
	return yixun_log_op(LOGOUT, mcb);
}

/*
 * keep_alive(), send keep alive packet
 * @param mcb, in
 * return 0 on success, otherwise -1;
 */
int
keep_alive(struct mcb *mcb)
{
	return yixun_log_op(KEEPALIVE, mcb);
}

/*
 * start_listen(), start listen on Radius port
 * return 0 on success, otherwise -1;
 */
int
start_listen()
{
	if (is_listening)
		return sockListen;
	if ((sockListen = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		log_perror("[%s] socket", __FUNCTION__);
		return -1;
	}
	int opt = 1;
	if (setsockopt(sockListen, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
		log_perror("[%s] setsockopt", __FUNCTION__);
		goto ERROR;
	}
	struct sockaddr_in local;
	bzero(&local, sizeof(local));
	local.sin_addr.s_addr = INADDR_ANY;
	local.sin_family = AF_INET;
	local.sin_port = htons(RADIUS_PORT);

	if (bind(sockListen, (struct sockaddr *)&local, sizeof(local)) != 0) {
		log_perror("[%s] Bind", __FUNCTION__);
		goto ERROR;
	}
	if (listen(sockListen, MAX_CLIENT) != 0) {
		log_perror("[%s] Listen", __FUNCTION__);
		goto ERROR;
	}
	is_listening = -1;
	return 0;
ERROR:
	close(sockListen);
	is_listening = 0;
	return -1;
}

/*
 * stop_listen(), stop listen on Radius port
 * return 0
 */
int
stop_listen()
{
	if (is_listening) {
		close(sockListen);
		is_listening = 0;
	}
	return 0;
}

/*
 * wait_mcb(), to receive server side infomation
 * @param mcb, in
 * return 0 on success, otherwise return none-zero
 */
int
wait_msg(struct mcb *mcb)
{
	fd_set rfds;
	struct timeval tv;

#if USE_PTHREAD
	pthread_testcancel();
#endif

	tv.tv_sec = mcb->select_timeout;
	tv.tv_usec = 0;
	FD_ZERO(&rfds);
	FD_SET(sockListen, &rfds);

	switch (select(sockListen + 1, &rfds, NULL, NULL, &tv)) {
		case -1:
			if (errno != EINTR)
				log_perror("[%s] select", __FUNCTION__);
			return 0;
		case 0:
			mcb->select_timeout++;
			return 0;
		default:
			if (!FD_ISSET(sockListen, &rfds))
				return 0;
			break;
	}
#if USE_PTHREAD
	pthread_testcancel();
#endif

	BUFF_ALIGNED(r_buff, R_BUF_LEN);
	struct sockaddr_in r_client;
	socklen_t len = sizeof(r_client);
	int sock_client = accept(sockListen, (struct sockaddr *)&r_client, &len);
	if (sock_client < 0) {
		log_perror("[%s] accept", __FUNCTION__);
		return -1;
	}
	/* 当对方的IP地址不在接入服务器IP地址段时断开连接（防止攻击） */
	if ((ntohl(r_client.sin_addr.s_addr) ^ ntohl(mcb->auth_server)) >> (32 - mcb->auth_server_maskbits) != 0) {
		log_notice("[%s]: %s attempt to connect\n", __FUNCTION__, inet_ntoa(r_client.sin_addr));
		close(sock_client);
		return 0;
	}
	if (mcb->msg_server == 0)
		mcb->msg_server = r_client.sin_addr.s_addr;

	log_info("[%s] accept: %s\n", __FUNCTION__, inet_ntoa(r_client.sin_addr));

	tv.tv_sec = RCV_TIMEOUT;
	tv.tv_usec = 0;
	if (setsockopt(sock_client, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
		log_perror("[%s] setsockopt", __FUNCTION__);

	ssize_t ret = recv(sock_client, r_buff, R_BUF_LEN, 0);
	if (ret > 0) {
		if (act_on_info(r_buff, mcb, 0) < 0)
			close(sock_client);
		return 0;
	}
	if (ret == 0) {
		log_perror("[%s] recv: Client %s has closed its half side of the connection\n", __FUNCTION__, inet_ntoa(r_client.sin_addr));
	} else {
		if (errno == EAGAIN)
			log_err("[%s] recv: time out\n", __FUNCTION__);
		else
			log_perror("[%s] recv", __FUNCTION__);
	}
	return -1;
}


/*
 * print_config(), print configuration from returned by server
 * @mcb,    in
 */
void
print_config(const struct mcb *mcb)
{
	log_notice("src IP address:    %s\n", inet_itoa(mcb->gre_src));
	log_notice("dst IP address:    %s\n", inet_itoa(mcb->gre_dst));
	log_notice("Local IP address:  %s\n", inet_itoa(mcb->gre_local));
	log_notice("Remote IP address: %s\n",inet_itoa(mcb->gre_remote));
	log_notice("P-t-P Netmask:     %s\n", inet_itoa(mcb->gre_netmask));
	log_notice("Upload band:       %ukbps\n", mcb->upload_band);
	log_notice("Download band:     %ukbps\n", mcb->download_band);
#ifdef DEBUG
	log_notice("Heart beat:\t%u\n", mcb->timeout);
#endif
}

/*
 * act_on_info(), act on receiving server packet
 * @param buff, server side packet
 * @mcb,    out
 * @sockfd, send yixun user ack from which
 * on success, return 0, otherwise return none-zero
 */
static int
act_on_info(void *buff, struct mcb *mcb, int sockfd)
{
	/*
	 * hack: due to problem caused by memory alignment, we sugguest that buff
	 * is aligned to 4 bytes, then we will not encounter the annoying
	 * bus-error problem on MIPS/ARM/PowerPC/SPARC, or the worse performence
	 * on X86-64
	 */
#ifdef DEBUG
	if ((size_t) buff % sizeof(int) != 0)
		log_warning("[%s] buffer(%p) is not aligned to %d bytes\n", __FUNCTION__, buff, sizeof(int));
#endif
	struct rds_packet_header *hd = (struct rds_packet_header *)buff;
	if (hd->flag != RADIUS_HEADER_FLAG) {
		log_err("Error: Invalid server package flag:0x%02x\n", hd->flag);
#ifdef DEBUG
		hexdump(buff, 32);
#endif
		return -1;
	}
	switch (hd->type) {
		case s_accept:
		{
			log_info("Server accepted...\n");
			if (start_listen() < 0)
				return -1;

			BUFF_ALIGNED(packet, sizeof(struct rds_packet_header));
			make_rds_packet(packet, u_ack);
			if (send(sockfd, packet, sizeof(struct rds_packet_header), 0) < 0) {
				log_perror("[%s] send", __FUNCTION__);
				stop_listen();
				return -1;
			}
			wait_msg(mcb);

			if (get_parameters(buff, mcb) < 0) {
				log_err("[%s] Cannot get parameters\n", __FUNCTION__);
				stop_listen();
				return -1;
			}
			if (mcb->timeout > KEEP_ALIVE_TIMEOUT) {
				log_notice("Server side timeout is too long:%u, use %u instead\n", mcb->timeout, KEEP_ALIVE_TIMEOUT);
				mcb->timeout = KEEP_ALIVE_TIMEOUT;
			}
			break;
		}
		case s_info:
			get_parameters(buff, mcb);
			log_info(mcb->server_info);
			break;
		case s_error:
		{
			int rval = get_parameters(buff, mcb);
			log_err(mcb->server_info);
			return rval ? rval : -1;
		}
		case s_keepalive:
			log_warning("server send keepalive\n  Keep-alive thread fail???\n");
			break;
		default:
			log_err("[%s] Unkown msg type: 0x%02x\n", __FUNCTION__, hd->type);
			break;
	}
	return 0;
}

/*
 * get_parameters(), get infomation from server side packet
 * @param buff, server size packet
 * @mcb,    out
 * on success, return 0, otherwise return none-zero
 */
static int
get_parameters(const void *buff, struct mcb *mcb)
{
	/*
	 * hack: due to problem caused by memory alignment, we sugguest that buff
	 * is aligned to 4 bytes, then we will not encounter the annoying
	 * bus-error problem on MIPS/ARM/PowerPC/SPARC, or the worse performence
	 * on X86-64
	 */
#ifdef DEBUG
	if ((size_t) buff % sizeof(int) != 0)
		log_warning("[%s] buffer(%p) is not aligned to %d bytes\n", __FUNCTION__, buff, sizeof(int));
#endif
	struct rds_packet_header *hd = (struct rds_packet_header *)buff;
	buff = hd->extra;	/* first segment */

	/* the end of segment */
	const void *end = buff + ntohs(hd->length);
	while (buff < end) {
		const struct rds_segment *p = (const struct rds_segment *)buff;
		if (p->flag != SERVER_SEGMENT_FLAG) {
			log_err("[%s] Invalid segment flag:0x%02x\n", __FUNCTION__, p->flag);
#ifdef DEBUG
			hexdump(p, 64);
#endif
			return -1;
		}
#ifdef DEBUG
		if ((p->type == s_gre_d ||
		     p->type == s_gre_l ||
		     p->type == s_gre_r ||
		     p->type == s_timeout || p->type == s_mask || p->type == s_upband || p->type == s_downband) && (size_t) & p->content % sizeof(int) != 0)
			log_warning("[%s] line:%d buffer(%p) is not aligned to %d bytes\n", __FUNCTION__, __LINE__, &p->content, sizeof(int));
#endif
		switch (p->type) {
			case s_gre_d:
				mcb->gre_dst = *((in_addr_t *) p->content);
				break;
			case s_gre_l:
				/*
				 * hack: 这里服务器返回的IP地址是10.0.x.x 从GRE tunnel看来，这个是正确的，不过 实际上，如果使用10.0.x.x作为GRE tunnel local端IP的话，网络反而是不通的，原因是 陕西某某公司做的服务端并未添加 route 表 项到10.0.x.x(tunnel)，因此，从客户端 可以发包出去，却收不到回来的包，因此，这里 的参数忽略
				 */
				if (mcb->gre_local == 0)
					mcb->gre_local = *((in_addr_t *) p->content);
				break;
			case s_gre_r:
				mcb->gre_remote = *((in_addr_t *) p->content);
				break;
			case s_timeout:
				mcb->timeout = ntohl(*((uint32_t *) p->content));
				break;
			case s_rule:
#ifdef DEBUG
				hexdump(p, 64);
#endif
				break;
			case s_mask:
				mcb->gre_netmask = *((in_addr_t *) p->content);
				break;
			case s_pad:
				break;
			case s_upband:
				mcb->upload_band = ntohl(*((uint32_t *) p->content));
				break;
			case s_downband:
				mcb->download_band = ntohl(*((uint32_t *) p->content));
				break;
			case s_sinfo:
			{
				bzero(mcb->server_info, sizeof(mcb->server_info));
				size_t len = p->length - sizeof(struct rds_segment) < sizeof(mcb->server_info) ?
				    p->length - sizeof(struct rds_segment) - 2 : sizeof(mcb->server_info) - 2;

				convert_code("GB18030", "UTF-8",
							p->content, strlen(p->content),
							mcb->server_info, len);

				strcat(mcb->server_info, "\n");

				const struct str_err *p = error_info;
				while (p->info) {
					if (strcasestr(mcb->server_info, p->info) != NULL)
						return p->error;
					p++;
				}
				break;
			}
			default:
#ifdef DEBUG
				fprintf(stderr, "%s: Unkown segment type:0x%02x\n", __FUNCTION__, p->type);
#endif
				break;
		}
		buff += p->length;
	}
	return 0;
}

/*
 * make_rds_packet(), fill packet with necessary infomation, ie packet_flag, packet_type and zeros
 * @param packet, packet buffer
 * @param type, which rds_segment_type
 * @param length, extra content length, the segment len is length + sizeof(struct rds_segment)
 * @param content_len, real content length. if content_len is larger than length, copy length data at most
 * @param content, data to be copied
 */
static struct rds_packet_header *
make_rds_packet(void *buff, enum rds_header_type type)
{
	/*
	 * hack: due to problem caused by memory alignment, we sugguest that buff
	 * is aligned to 4 bytes, then we will not encounter the annoying
	 * bus-error problem on MIPS/ARM/PowerPC/SPARC, or the worse performence
	 * on X86-64
	 */
#ifdef DEBUG
	if ((size_t) buff % sizeof(int) != 0)
		log_warning("[%s] buffer(%p) is not aligned to %d bytes\n", __FUNCTION__, buff, sizeof(int));
#endif
	struct rds_packet_header *p = (struct rds_packet_header *)buff;
	p->flag = RADIUS_HEADER_FLAG;	/* Always be 0x5f */
	p->type = (uint8_t) type;
	p->pad = 0;
	return p;
}


/*
 * add_segment(), add extra data to rds_packet
 * @param packet, packet buffer
 * @param type, which rds_segment_type
 * @param length, extra content length, the segment len is length + sizeof(struct rds_segment)
 * @param content_len, real content length. if content_len is larger than length, copy length data at most
 * @param content, data to be copied, NULL indicates skip length packet, ie, leave length packet unchanged
 */
static void
add_segment(void *buff, enum rds_segment_type type, uint8_t length, uint8_t content_len, const void *content)
{
	/*
	 * hack: due to problem caused by memory alignment, we sugguest that buff
	 * is aligned to 4 bytes, then we will not encounter the annoying
	 * bus-error problem on MIPS/ARM/PowerPC/SPARC, or the worse performence
	 * on X86-64
	 */
#ifdef DEBUG
	if ((size_t) buff % sizeof(int) != 0)
		log_warning("[%s] buffer(%p) is not aligned to %d bytes\n", __FUNCTION__, buff, sizeof(int));
#endif
	struct rds_packet_header *p = (struct rds_packet_header *)buff;
	struct rds_segment *s = (struct rds_segment *)(p->extra + ntohs(p->length));
	/* bzero(&s, sizeof(struct rds_segment)); */

	if (length + sizeof(struct rds_segment) > SEGMENT_MAX_LEN)
		length = SEGMENT_MAX_LEN - sizeof(struct rds_segment);

	s->flag = CLINET_SEGMENT_FLAG;
	s->type = type;
	/* 包含segment头的长度 */
	s->length = length + sizeof(struct rds_segment);
	s->pad = 0;

	if (content_len > length)
		content_len = length;

	if (content && content_len > 0)
		bcopy(content, s->content, content_len);

	/* 包的长度按网络序存储 */
	p->length = htons(ntohs(p->length) + s->length);
}


/*
 * connect_with_timeout
 * wrapper for connect(), add timeout option
 * @param socket
 * @param sockaddr
 * @param address_len
 * @param timeout
 * on success, return 0, otherwise return -1
 */
static int
connect_tm(int socket, const struct sockaddr *addr, socklen_t addr_len, struct timeval *timeout)
{
	int rval;
	int sock_flag;
	int sock_err;
	struct timeval tv;
	fd_set fd;

	int sock_is_blocking = 0;

	/* Set non-blocking */
	if ((sock_flag = fcntl(socket, F_GETFL, NULL)) < 0)
		return -1;
	if ((sock_flag & O_NONBLOCK) == 0) {
		sock_is_blocking = 1;
		sock_flag |= O_NONBLOCK;
		if (fcntl(socket, F_SETFL, sock_flag) < 0)
			return -1;
	}
	/* connect */
	rval = connect(socket, addr, addr_len);
	if (rval < 0) {
		if (errno == EINPROGRESS) {
			do {
				tv.tv_sec = timeout->tv_sec;
				tv.tv_usec = timeout->tv_usec;
				FD_ZERO(&fd);
				FD_SET(socket, &fd);
				rval = select(socket + 1, NULL, &fd, NULL, &tv);
				if (rval < 0 && errno != EINTR) {
					dprintf("%s: Error connecting %d - %s\n", __FUNCTION__, errno, strerror(errno));
					return -1;
				} else if (rval > 0) {
					/* Socket selected for write */
					socklen_t len = sizeof(int);
					if (getsockopt(socket, SOL_SOCKET, SO_ERROR, (void *)(&sock_err), &len) < 0) {
						dprintf("%s: Error getsockopt() %d - %s\n", __FUNCTION__, errno, strerror(errno));
						return -1;
					}
					/* Check the value returned... */
					if (sock_err) {
						dprintf("%s: Error in delayed connection() %d - %s\n", __FUNCTION__, sock_err, strerror(sock_err));
						return -1;
					}
					break;
				} else {
					dprintf("%s: Timeout in select() - Cancelling!\n", __FUNCTION__);
					errno = ETIMEDOUT;
					return -1;
				}
			} while (1);
		} else {
			dprintf("%s: Error connecting %d - %s\n", __FUNCTION__, errno, strerror(errno));
			return -1;
		}
	}
	/* Set to blocking mode, if the socket is blocking mode before */
	if (sock_is_blocking) {
		sock_flag &= (~O_NONBLOCK);
		if (fcntl(socket, F_SETFL, sock_flag) < 0)
			return -1;
	}
	return 0;
}
