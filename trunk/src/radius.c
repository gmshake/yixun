/*
 *  radius.c
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

#if defined(__linux__)	/* Linux stuff...*/
#define __USE_GNU
#include <string.h>		/* strcpy(), strcasestr()... */
#undef __USE_GNU
#else
#include <string.h>
#endif

#include <strings.h>		/* bzero() */

#include <sys/socket.h>		/* PF_INET, AF_INET, sockaddr, bind(), connect()... */
#include <arpa/inet.h>		/* inet_addr() */
#include <netinet/in.h>		/* in_addr_t sockaddr_in INADDR_ANY */

#include "log_xxx.h"

#include <fcntl.h>
#include <errno.h>

#include "rds_types.h"
#include "yixun_config.h"
#include "convert_code.h"
#include "encode_password.h"
#include "get_ip_mac.h"
#include "radius.h"
#include "server.h"
#include "common_macro.h"

#ifdef DEBUG
#include "hexdump.h"
#endif

#ifndef MAX_USER_NAME_LEN
#define MAX_USER_NAME_LEN 20
#endif
#ifndef MAX_CLIENT
#define MAX_CLIENT 10
#endif
#ifndef R_BUF_LEN
#define R_BUF_LEN 1024
#endif
#ifndef S_BUF_LEN
#define S_BUF_LEN 512
#endif
#ifndef SEGMENT_MAX_LEN
#define SEGMENT_MAX_LEN 256
#endif

enum login_state login_state = offline;

uint8_t eth_addr[ETHER_ADDR_LEN];
struct sockaddr_in auth_server;
uint32_t auth_server_maskbits;
in_addr_t msg_server;

/* out parameters */
in_addr_t gre_src;
in_addr_t gre_dst;
in_addr_t gre_local;
in_addr_t gre_remote;
in_addr_t gre_netmask;
uint32_t gre_timeout;
uint32_t gre_upload_band;
uint32_t gre_download_band;

static size_t s_buff_len;
static char s_buff[S_BUF_LEN];
static char server_info[SEGMENT_MAX_LEN + (SEGMENT_MAX_LEN >> 1)];

void print_server_config(void);

static int yixun_log_op(int op);


/* 返回 0 表示无错， 返回正数，表示出错原因(e_user, e_pwd ....) */
int act_on_info(void *buff, int sockfd);

/* 认证通过后，获取接入服务器给的参数 */
static int get_parameters(const void *buff);

/* 生成一个发送包（包头） */
static struct rds_packet_header *make_rds_packet(void *buff, enum rds_header_type type);

/* 为发送包添加相应字段 */
static void add_segment(void *buff, enum rds_segment_type type, uint8_t length, uint8_t content_len, const void *content);

/* 带连接超时的connect */
static int connect_tm(int socket, const struct sockaddr *addr, socklen_t addr_len, struct timeval *timeout);


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
yixun_log_op(int op)
{
	static int last_op = 0;
	int rval = 0;
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		log_perror("[%s] socket", __FUNCTION__);
		return -1;
	}
	struct timeval tv;
	tv.tv_sec = conn_timeout;
	tv.tv_usec = 0;

	if (connect_tm(sockfd, (struct sockaddr *)&auth_server, sizeof(struct sockaddr_in), &tv) < 0) {
		log_perror("connect to %s", inet_ntoa(auth_server.sin_addr));
		rval = -1;
		goto ERROR;
	}
	/*
	 * when op is same as the last op, then there is no\ need to re-make a same send packet
	 */
	if (op != last_op) {
		if (get_ip_mac_by_socket(sockfd, &gre_local, hwaddr[0] ? NULL : eth_addr) < 0) {
			log_err("[%s] get ip address and eth_addr\n", __FUNCTION__);
			rval = -1;
			goto ERROR;
		}
		if (regip[0] == '\0' || gre_src == 0 || gre_src == 0xffffffff)
			gre_src = gre_local;

		bzero(s_buff, sizeof(s_buff));
		switch (op) {
			case LOGIN:
			{
				uint8_t version[4] = { 0x03, 0x00, 0x00, 0x06 };	/* hack: sigh... */
				uint8_t zeros[4] = { 0x00, 0x00, 0x00, 0x00 };

				uint8_t *sec_pwd = (uint8_t *) malloc(sizeof(uint8_t) * (strlen(password) + 2));
				if (sec_pwd == NULL) {
					log_perror("%s: malloc(%u)\n", __FUNCTION__, sizeof(uint8_t) * (strlen(password) + 2));
					rval = -1;
					goto ERROR;
				}
				encode_pwd_with_ip(sec_pwd, password, gre_src);

				make_rds_packet(s_buff, u_login);
				add_segment(s_buff, c_mac, 6, sizeof(eth_addr), (char *)eth_addr);
				add_segment(s_buff, c_ip, sizeof(in_addr_t), sizeof(in_addr_t), (char *)&gre_src);
				/* Hack:用户名有长度限制 */
				add_segment(s_buff, c_user, MAX_USER_NAME_LEN, strlen(username), (char *)username);
				add_segment(s_buff, c_pwd, strlen((char *)sec_pwd), strlen((char *)sec_pwd), (char *)sec_pwd);
				add_segment(s_buff, c_ver, 4, sizeof(version), (char *)version);
				add_segment(s_buff, c_pad, 4, sizeof(zeros), (char *)zeros);

				free(sec_pwd);
				break;
			}
			case LOGOUT:
				/* Hack:退出登录和保持活动连接只有packet_type有差别 */
				make_rds_packet(s_buff, u_logout);
				goto LOGOUT_KEEPALIVE;
			case KEEPALIVE:
				make_rds_packet(s_buff, u_keepalive);
LOGOUT_KEEPALIVE:
				add_segment(s_buff, c_ip, sizeof(in_addr_t), sizeof(in_addr_t), (char *)&gre_src);
				add_segment(s_buff, c_user, MAX_USER_NAME_LEN, strlen(username), (char *)username);
				break;
			default:
#ifdef DEBUG
				log_err("[%s] unkown op %d\n", __FUNCTION__, op);
#endif
				rval = -2;
				goto ERROR;
		}
		s_buff_len = RDS_PACKET_LEN(s_buff);
		last_op = op;
	}
	tv.tv_sec = snd_timeout;
	tv.tv_usec = 0;
	if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
		log_perror("%s: setsockopt(SO_SNDTIMEO)", __FUNCTION__);
		rval = -3;
		goto ERROR;
	}
	if (send(sockfd, s_buff, s_buff_len, 0) < 0) {
		log_perror("%s: send to %s", __FUNCTION__, inet_ntoa(auth_server.sin_addr));
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

			tv.tv_sec = rcv_timeout;
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
			if ((rval = act_on_info(r_buff, sockfd)) != 0)
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
	login_state = rval == 0 ? online : offline;
	return rval;
}

/*
 * login(), send login packet
 * return 0 on success, otherwise -1;
 */
int
login(void)
{
	if (login_state != offline)
		return -1;

	int rval = yixun_log_op(LOGIN);
	if (rval == 0) {
		login_state = online;
		print_server_config();
	}
	return rval;
}

/*
 * logout(), send logout packet
 * return 0 on success, otherwise -1;
 */
int
logout(void)
{
	if (login_state == offline)
		return 0;
	login_state = disconnecting;
	if (yixun_log_op(LOGOUT) == 0) {
		login_state = offline;
		return 0;
	} else 
		return -1;
}

/*
 * keep_alive(), send keep alive packet
 * return 0 on success, otherwise -1;
 */
int
keep_alive(void)
{
	if (login_state != online)
		return -1;

	int retry = 3;
	do {
		/* try to re-send hear-beat packet */
		if (yixun_log_op(KEEPALIVE) == 0)
			break;
		else
			sleep(1);
	} while (--retry > 0);

	if (retry == 0) {
		login_state = offline;
		return -1;
	} else
		return 0;
}


/*
 * print_server_config(), print configuration from returned by server
 */
void
print_server_config(void)
{
	log_notice("src IP address:    %s\n", inet_itoa(gre_src));
	log_notice("dst IP address:    %s\n", inet_itoa(gre_dst));
	log_notice("Local IP address:  %s\n", inet_itoa(gre_local));
	log_notice("Remote IP address: %s\n", inet_itoa(gre_remote));
	log_notice("P-t-P Netmask:     %s\n", inet_itoa(gre_netmask));
	log_notice("Upload band:       %ukbps\n", gre_upload_band);
	log_notice("Download band:     %ukbps\n", gre_download_band);
#ifdef DEBUG
	log_notice("Heart beat:\t%u\n", gre_timeout);
#endif
}

/*
 * act_on_info(), act on receiving server packet
 * @param buff, server side packet
 * @sockfd, send yixun user ack from which
 * on success, return 0, otherwise return none-zero
 */
int
act_on_info(void *buff, int sockfd)
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
			wait_msg();

			if (get_parameters(buff) < 0) {
				log_err("[%s] Cannot get parameters\n", __FUNCTION__);
				stop_listen();
				return -1;
			}
			if (gre_timeout > heart_beat_timeout) {
				log_notice("Server side timeout is too long:%u, use %u instead\n", gre_timeout, heart_beat_timeout);
				gre_timeout = heart_beat_timeout;
			}
			break;
		}
		case s_info:
			get_parameters(buff);
			log_info(server_info);
			break;
		case s_error:
		{
			int rval = get_parameters(buff);
			log_err(server_info);
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
 * on success, return 0, otherwise return none-zero
 */
static int
get_parameters(const void *buff)
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
				gre_dst = *((in_addr_t *) p->content);
				break;
			case s_gre_l:
				/*
				 * hack: 这里服务器返回的IP地址是10.0.x.x 从GRE tunnel看来，这个是正确的，不过 实际上，如果使用10.0.x.x作为GRE tunnel local端IP的话，网络反而是不通的，原因是 陕西某某公司做的服务端并未添加 route 表 项到10.0.x.x(tunnel)，因此，从客户端 可以发包出去，却收不到回来的包，因此，这里 的参数忽略
				 */
				if (gre_local == 0)
					gre_local = *((in_addr_t *) p->content);
				break;
			case s_gre_r:
				gre_remote = *((in_addr_t *) p->content);
				break;
			case s_timeout:
				gre_timeout = ntohl(*((uint32_t *) p->content));
				break;
			case s_rule:
#ifdef DEBUG
				hexdump(p, 64);
#endif
				break;
			case s_mask:
				gre_netmask = *((in_addr_t *) p->content);
				break;
			case s_pad:
				break;
			case s_upband:
				gre_upload_band = ntohl(*((uint32_t *) p->content));
				break;
			case s_downband:
				gre_download_band = ntohl(*((uint32_t *) p->content));
				break;
			case s_sinfo:
			{
				bzero(server_info, sizeof(server_info));
				size_t len = p->length - sizeof(struct rds_segment) < sizeof(server_info) ?
				    p->length - sizeof(struct rds_segment) - 2 : sizeof(server_info) - 2;

				convert_code("GB18030", "UTF-8",
							p->content, strlen(p->content),
							server_info, len);

				strcat(server_info, "\n");

				const struct str_err *p = error_info;
				while (p->info) {
					if (strcasestr(server_info, p->info) != NULL)
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
		memcpy(s->content, content, content_len);

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
