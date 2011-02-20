/*
 *  radius.c
 *  YiXun
 *
 *  Created by Summer Town on 1/1/11.
 *  Copyright 2010 __MyCompanyName__. All rights reserved.
 *
 */

#include <stdio.h>
#include <stdint.h> // uint8_t
#include <stdlib.h> // malloc(), calloc()
#include <unistd.h>

#include <sys/types.h>
#include <string.h> // memcpy()
#include <strings.h> //  bzero()

#include <arpa/inet.h>  // inet_addr()
#include <netinet/in.h> // in_addr_t sockaddr_in INADDR_ANY
#include <sys/socket.h> // PF_INET, AF_INET, sockaddr, bind(), connect()...

#include <errno.h>
#include <pthread.h>

#include <fcntl.h>

#include "common_macro.h"
#include "common_logs.h"
#include "rds_types.h"
#include "yixun_config.h"
#include "convert_code.h"
#include "encode_password.h"
#include "get_ip_mac.h"
#include "radius.h"

#ifdef DEBUG
#include "print_hex.h"
#endif

const static uint8_t version[4] = {0x03, 0x00, 0x00, 0x06};
const static uint8_t zeros[4] = {0x00, 0x00, 0x00, 0x00};

static int sockListen;
static int is_listening;


void print_config(struct yixun_msg *msg);

static int pre_config(struct yixun_msg *msg);
static int yixun_log_op(int op, struct yixun_msg *msg);
static int do_with_server_info(char buff[], struct yixun_msg *msg, int sockfd);  //返回0表示无错，返回正数，表示出错原因(e_user, e_pwd ....)
static int get_parameters(char *buff, struct yixun_msg *msg); //认证通过后，获取接入服务器给的参数

static struct rds_packet_header * make_rds_packet(char packet[], enum rds_header_type type); //生成一个发送包（包头）

//为发送包添加相应字段
static void add_segment(char packet[], enum rds_segment_type type, uint8_t length, uint8_t content_len, const char *content);

// 带连接超时的connect
static int connect_tm(int socket, const struct sockaddr *addr, socklen_t addr_len, struct timeval *timeout);


/*
 * pre_config(), pre-config necessary infomation, check username, pwd etc.
 * @param msg, in/out
 * return 0 on success, otherwise -1;
 */
static int pre_config(struct yixun_msg *msg)
{
    if (msg->username == NULL) {
        log_err("[%s] Require username\n", __FUNCTION__);
        return -1;
    }
    
    if (msg->clientip) {
        msg->gre_src = inet_addr(msg->clientip);
        if (msg->gre_src == 0 || msg->gre_src == 0xffffffff)
            log_err("[%s] Invalid ip address:%s\n", __FUNCTION__, msg->clientip);
    }
    
    if (msg->mac) {
        if (string_to_lladdr(msg->eth_addr, msg->mac) < 0)
            log_err("[%s] Invalid lladdr:%s\n", __FUNCTION__, msg->mac);
    }
    
    if (msg->serverip) {
        char tmp[64];
        strncpy(tmp, msg->serverip, sizeof(tmp));
        tmp[sizeof(tmp) - 1] = '\0';
        char * args[2] = {NULL};
        char *instr = tmp;
        args[0] = strsep(&instr, "/");
        args[1] = strsep(&instr, "/");
        msg->auth_server = inet_addr(args[0]);
        if (args[1] != NULL) {
            sscanf(args[1], "%u", &msg->auth_server_maskbits);
            if (msg->auth_server_maskbits > 32)
                msg->auth_server_maskbits = 32;
        }
    } else {
        msg->auth_server = inet_addr(AUTH_SERVER);
        msg->auth_server_maskbits = AUTH_SERVER_MASKBITS;
    }
    
    return 0;
}

/*
 * yixun_log_op(), make && send proper packet indicated by op
 * @op, which type of packet
 * @param msg, in/out
 * return 0 on success, otherwise none-zero;
 */

#define LOGIN 0x01
#define LOGOUT 0x02
#define KEEPALIVE 0x03
static int yixun_log_op(int op, struct yixun_msg *msg)
{
    int rval = 0;
    /* 重置发送缓冲区信息 */
    if (op != msg->last_op) {
        msg->last_op = op;
        msg->make_send_buff_done = 0;
        bzero(msg->s_buff, sizeof(msg->s_buff));
    }
    
    if (!msg->pre_config_done) {
        if (pre_config(msg) < 0)
            return -1;
        msg->pre_config_done = -1;
    }
    
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
        log_perror("[%s] socket", __FUNCTION__);
        return -1;
    }
    
    struct timeval tv;
    tv.tv_sec = CONNECTION_TIME_OUT;
    tv.tv_usec = 0;
    
    struct sockaddr_in auth_server;
    bzero(&auth_server, sizeof(struct sockaddr_in));
    auth_server.sin_family = AF_INET;
    auth_server.sin_port = htons(RADIUS_PORT);
    auth_server.sin_addr.s_addr = msg->auth_server;
    
    if (connect_tm(sockfd, (struct sockaddr *)&auth_server, sizeof(struct sockaddr_in), &tv) < 0) {
        log_perror("[%s] connect %s", __FUNCTION__, inet_ntoa(auth_server.sin_addr));
        rval = -1;
        goto ERROR;
    }      

    if (!msg->make_send_buff_done) {
        if (get_ip_mac_by_socket(sockfd, &msg->gre_local, msg->mac ? NULL : msg->eth_addr) < 0) {
            log_err("[%s] get ip address and eth_addr\n", __FUNCTION__);
            rval = -1;
            goto ERROR;
        }
        if (msg->clientip == NULL || msg->gre_src == 0 || msg->gre_src == 0xffffffff)
            msg->gre_src = msg->gre_local;
        
        switch (op) {
            case LOGIN:
            {
                uint8_t *sec_pwd = (uint8_t *)malloc(sizeof(uint8_t) * (strlen(msg->password) + 2));
                if (sec_pwd == NULL) {
                    log_perror("[%s] malloc\n", __FUNCTION__);
                    rval = -1;
                    goto ERROR;
                }
                encode_pwd_with_ip(sec_pwd, msg->password, msg->gre_src);
                
                make_rds_packet(msg->s_buff, u_login);
                add_segment(msg->s_buff, c_mac, 6, sizeof(msg->eth_addr), (char *)msg->eth_addr);
                add_segment(msg->s_buff, c_ip, sizeof(in_addr_t), sizeof(in_addr_t), (char *)&msg->gre_src);
                add_segment(msg->s_buff, c_user, MAX_USER_NAME_LEN, strlen(msg->username), (char *)msg->username); //Hack:用户名有长度限制
                add_segment(msg->s_buff, c_pwd, strlen((char *)sec_pwd), strlen((char *)sec_pwd), (char *)sec_pwd);
                add_segment(msg->s_buff, c_ver, 4, sizeof(version), (char *)version);
                add_segment(msg->s_buff, c_pad, 4, sizeof(zeros), (char *)zeros);
                
                free(sec_pwd);
                break;
            }
            case LOGOUT:
                make_rds_packet(msg->s_buff, u_logout); //Hack:退出登录和保持活动连接只有这一个地方有差别
                add_segment(msg->s_buff, c_ip, sizeof(in_addr_t), sizeof(in_addr_t), (char *)&msg->gre_src);
                add_segment(msg->s_buff, c_user, MAX_USER_NAME_LEN, strlen(msg->username), (char *)msg->username);
                break;
            case KEEPALIVE:
                make_rds_packet(msg->s_buff, u_keepalive);
                add_segment(msg->s_buff, c_ip, sizeof(in_addr_t), sizeof(in_addr_t), (char *)&msg->gre_src);
                add_segment(msg->s_buff, c_user, MAX_USER_NAME_LEN, strlen(msg->username), (char *)msg->username);
                break;
            default:
#ifdef DEBUG
                log_err("[%s] unkown op %d\n", __FUNCTION__, op);
#endif
                rval = -2;
                goto ERROR;
        }
        msg->s_buff_len = RDS_PACKET_LEN(msg->s_buff);
        msg->make_send_buff_done = -1;
    }
    
    tv.tv_sec = SND_RCV_TIME_OUT;
    tv.tv_usec = 0;
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
        log_perror("[%s] setsockopt", __FUNCTION__);
        rval = -3;
        goto ERROR;
    }

    if (send(sockfd, msg->s_buff, msg->s_buff_len, 0) < 0) {
        log_perror("[%s] send to %s", __FUNCTION__, inet_ntoa(auth_server.sin_addr));
        rval = -1;
        goto ERROR;
    }
	
    switch (op) {
        case LOGIN:
        {
            char r_buff[R_BUF_LEN]; // receive buffer
            
            tv.tv_sec = SND_RCV_TIME_OUT;
            tv.tv_usec = 0;
            if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
                log_perror("[%s] setsockopt", __FUNCTION__);
                rval = -3;
                goto ERROR;
            }
            
            ssize_t ret = recv(sockfd, r_buff, R_BUF_LEN, 0);
            if (ret <= 0) {
                if (ret == 0) {
                    log_err("[%s] receive: Auth server %s has closed its half side of the connection\n", __FUNCTION__, inet_ntoa(auth_server.sin_addr));
                } else {
                    if (errno == EAGAIN)
                        log_err("[%s] recv: time out\n", __FUNCTION__);
                    else
                        log_perror("[%s] recv", __FUNCTION__);
                }

                rval = -1;
                goto ERROR;
            }
            if ((rval = do_with_server_info(r_buff, msg, sockfd)) != 0)
                goto ERROR;
            
            break;
        }
        case LOGOUT:
            break;
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
 * log_in(), send login packet
 * @param msg, in/out
 * return 0 on success, otherwise -1;
 */
int log_in(struct yixun_msg *msg)
{
    int rval = yixun_log_op(LOGIN, msg);
    if (rval == 0)
        print_config(msg);
    return rval;
}

/*
 * log_out(), send logout packet
 * @param msg, in
 * return 0 on success, otherwise -1;
 */
int log_out(struct yixun_msg *msg)
{
    return yixun_log_op(LOGOUT, msg);
}

/*
 * keep_alive(), send keep alive packet
 * @param msg, in
 * return 0 on success, otherwise -1;
 */
int keep_alive(struct yixun_msg *msg)
{
    return yixun_log_op(KEEPALIVE, msg);
}

/*
 * start_listen(), start listen on Radius port
 * return 0 on success, otherwise -1;
 */
int start_listen()
{
    if (is_listening) return sockListen;
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
int stop_listen()
{
    if (is_listening) {
        close(sockListen);
        is_listening = 0;
    }
	return 0;
}

/*
 * accept_client(), to receive server side infomation
 * @param msg, in
 * return 0 on success, otherwise return none-zero
 */
int accept_client(struct yixun_msg *msg)
{
    static fd_set rfds;
    static struct timeval tv;

    pthread_testcancel();

    tv.tv_sec = 1;
    tv.tv_usec = 0;
    FD_ZERO(&rfds);
    FD_SET(sockListen, &rfds);
    int cnt = select(sockListen + 1, &rfds, NULL, NULL, &tv);
    if (cnt <= 0) {
        if (cnt < 0 && errno != EINTR)
            log_perror("[%s] select", __FUNCTION__);
        return 0;
    }
    
    pthread_testcancel();
    if (FD_ISSET(sockListen, &rfds)) {
        char r_buff[R_BUF_LEN];
        struct sockaddr_in r_client;
        socklen_t len = sizeof(r_client);
        int sock_client = accept(sockListen, (struct sockaddr *)&r_client, &len);
        if (sock_client < 0) {
            log_perror("[%s] accept", __FUNCTION__);
            return -1;
        }
        /*
         in_addr_t ui = ntohl(r_client.sin_addr.s_addr);
         ui &= ~((1 << (32 - auth_server_maskbits)) - 1);
         ui = htonl(ui);
         */
        /*
         if (strcmp(inet_ntoa(r_client.sin_addr), AUTH_SERVER) != 0 && \
         strcmp(inet_ntoa(r_client.sin_addr), BRAS_SERVER) != 0) // 当对方的IP地址不是服务器IP地址时断开连接（防止攻击）
         */
        //if (ui != auth_server_addrs) // 当对方的IP地址不在接入服务器IP地址段时断开连接（防止攻击）
        if ((ntohl(r_client.sin_addr.s_addr) ^ ntohl(msg->auth_server)) >> (32 - msg->auth_server_maskbits) != 0) {
            log_notice("[%s]: %s attempt to connect\n", __FUNCTION__, inet_ntoa(r_client.sin_addr));
            close(sock_client);
            return 0;
        }
        
        if (msg->msg_server == 0)
            msg->msg_server = r_client.sin_addr.s_addr;
        
        log_info("[%s] accept: %s\n", __FUNCTION__, inet_ntoa(r_client.sin_addr));
        
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        if (setsockopt(sock_client, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
            log_perror("[%s] setsockopt", __FUNCTION__);
        
        ssize_t ret = recv(sock_client, r_buff, R_BUF_LEN, 0);
        if (ret <= 0) {
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

        if (do_with_server_info(r_buff, msg, 0) < 0)
            close(sock_client);
    }
    return 0;
}


/*
 * print_config(), print configuration from returned by server
 * @msg,    in
 */
void print_config(struct yixun_msg *msg)
{
    struct in_addr a[5];
    char p1[5][20];
    
    a[0].s_addr = msg->gre_src; a[1].s_addr = msg->gre_dst; a[2].s_addr = msg->gre_local; a[3].s_addr = msg->gre_remote; a[4].s_addr = msg->gre_netmask;
    int i;
    for (i = 0; i < 5; i++) {
        strcpy(p1[i], inet_ntoa(a[i]));
    }
    
    log_notice("gre_src:%s gre_dst:%s gre_local:%s gre_remote:%s netmask:%s\n", p1[0], p1[1], p1[2], p1[3], p1[4]);
    log_notice("timeout:%u upload_band:%u download_band:%u\n", msg->timeout, msg->upload_band, msg->download_band);
}

/*
 * do_with_server_info(), act on receiving server packet
 * @param buff, server side packet
 * @msg,    out
 * @sockfd, send yixun user ack from which
 * on success, return 0, otherwise return none-zero
 */
static int do_with_server_info(char buff[], struct yixun_msg *msg, int sockfd)
{
    struct rds_packet_header *hd = (struct rds_packet_header *)buff;
    if (hd->flag != RADIUS_HEADER_FLAG) {
        log_err("Error: Invalid server package flag:0x%02x\n", hd->flag);
#ifdef DEBUG
        print_hex(buff, 32);
#endif
        return -1;
    }
    switch (hd->type) {
        case s_accept:
        {
            log_info("Server accepted...\n");
            if (start_listen() < 0)
                return -1;
            
            char packet[sizeof(struct rds_packet_header)];
            make_rds_packet(packet, u_ack);
            if (send(sockfd, packet, sizeof(packet), 0) < 0) {
                log_perror("[%s] send", __FUNCTION__);
                stop_listen();
                return -1;
            }
            
            accept_client(msg);
            
            if (get_parameters(buff, msg) < 0) {
                log_err("[%s] Cannot get parameters\n", __FUNCTION__);
                stop_listen();
                return -1;
            }
            
            if (msg->timeout > MAX_TIME_OUT) {
                log_notice("Server side timeout to long:%u\n  use %u instead\n", msg->timeout, MAX_TIME_OUT);
                msg->timeout = MAX_TIME_OUT;
            }
            
            break;
        }
        case s_info:
            get_parameters(buff, msg);
            log_info(msg->server_info);
            break;
        case s_error:
        {
            int rval = get_parameters(buff, msg);
            log_err(msg->server_info);
            return rval ? rval : -1;
        }
        case s_keepalive:
            log_warning("server send keepalive\n  Keep-alive thread fail???\n");
            break;
        default:
            log_err("[%s] Unkown msg type: 0x%02x\n", __FUNCTION__, hd->type);
    }
    return 0;
}

/*
 * get_parameters(), get infomation from server side packet
 * @param buff, server size packet
 * @msg,    out
 * on success, return 0, otherwise return none-zero
 */
static int get_parameters(char *buff, struct yixun_msg *msg)
{
	struct rds_packet_header *hd = (struct rds_packet_header *)buff;
	buff = hd->extra; // first segment
	
	char *end = buff + ntohs(hd->length);	// the end of segment
	while (buff < end) {
		struct rds_segment *p = (struct rds_segment *)buff;
		if (p->flag != SERVER_SEGMENT_FLAG) {
			log_err("[%s] Invalid segment flag:0x%02x\n", __FUNCTION__, p->flag);
#ifdef DEBUG
			print_hex(p, 64);
#endif
			return -1;
		}
		switch (p->type) {
			case s_gre_d:
				msg->gre_dst = *((in_addr_t *)p->content);
				break;
			case s_gre_l:
                if (msg->gre_local == 0)    /* hack: 陕西的某某公司做的那个客户端在这里有些出入，\
                                            * 本来应该在接入服务器加上一条到gre_local的路由信息的，
                                            * 不知是出于什么目的没有这样做，导致实际的实现，客户端对发出的包作封包，\
                                            * 而接入服务器(路由器)却不对流向客户端这边的包作GRE封包处理，所以，\
                                            * 实际上，这里的信息是被忽略了的，如果不忽略，反而连接不上
                                            */
                    msg->gre_local = *((in_addr_t *)p->content);
				break;
			case s_gre_r:
				msg->gre_remote = *((in_addr_t *)p->content);
				break;
            case s_timeout:
				msg->timeout = ntohl(*((uint32_t *)p->content));
				break;
            case s_rule:
#ifdef DEBUG
                print_hex(p, 64);
#endif
                break;
            case s_mask:
				msg->gre_netmask = *((in_addr_t *)p->content);
				break;
            case s_pad:
                break;
			case s_upband:
				msg->upload_band = ntohl(*((uint32_t *)p->content));
				break;
			case s_downband:
				msg->download_band = ntohl(*((uint32_t *)p->content));
				break;
            case s_sinfo:
            {
                bzero(msg->server_info, sizeof(msg->server_info));
                size_t len = p->length - sizeof(struct rds_segment) < sizeof(msg->server_info) ? \
                    p->length - sizeof(struct rds_segment) - 2 : sizeof(msg->server_info) - 2;
                
                int rval = convert_code("GB18030", "UTF-8", \
                                        p->content, strlen(p->content), \
                                        msg->server_info, len);
                if (rval != 0) dprintf("Warning, convert_code returned %d\n", rval);
                
                strcat(msg->server_info, "\n");
                
                const struct str_err *p = error_info;
                while(p->info) {
                    if (strstr(msg->server_info, p->info) != NULL)
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
make_rds_packet(char packet[], enum rds_header_type type)
{
    struct rds_packet_header *p = (struct rds_packet_header *)packet;
    p->flag = RADIUS_HEADER_FLAG; //Always be 0x5f
    p->type = (uint8_t)type;
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
add_segment(char packet[], enum rds_segment_type type, uint8_t length, uint8_t content_len, const char *content)
{
    struct rds_packet_header *p = (struct rds_packet_header *)packet;
    struct rds_segment *s = (struct rds_segment *)(p->extra + ntohs(p->length));
	//bzero(&s, sizeof(struct rds_segment));
    
	if (length + sizeof(struct rds_segment) > SEGMENT_MAX_LEN)
        length = SEGMENT_MAX_LEN - sizeof(struct rds_segment);
	
    s->flag = CLINET_SEGMENT_FLAG;
    s->type = type;
    s->length = length + sizeof(struct rds_segment); //包含segment头的长度
    s->pad = 0;
    
    if (content_len > length)
        content_len = length;
    
    if (content && content_len > 0)
        bcopy(content, s->content, content_len);
        
    p->length = htons(ntohs(p->length) + s->length); //包的长度按网络序存储
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
static int connect_tm(int socket,
                      const struct sockaddr *addr,
                      socklen_t addr_len,
                      struct timeval *timeout)
{
    int     rval;
    int     sock_flag;
    int     sock_err;
    struct  timeval tv;
    fd_set  fd;
    
    int sock_is_blocking = 0;
    
    // Set non-blocking 
    if ((sock_flag = fcntl(socket, F_GETFL, NULL)) < 0)
        return -1;
    if ((sock_flag & O_NONBLOCK) == 0) {
        sock_is_blocking = 1;
        sock_flag |= O_NONBLOCK;
        if (fcntl(socket, F_SETFL, sock_flag) < 0)
            return -1;
    }
    
    // connect
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
                    // Socket selected for write
                    socklen_t len = sizeof(int);
                    if (getsockopt(socket, SOL_SOCKET, SO_ERROR, (void*)(&sock_err), &len) < 0) {
                        dprintf("%s: Error getsockopt() %d - %s\n", __FUNCTION__, errno, strerror(errno));
                        return -1;
                    }
                    // Check the value returned... 
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
    
    // Set to blocking mode, if the socket is blocking mode before
    if (sock_is_blocking) {
        sock_flag &= (~O_NONBLOCK);
        if (fcntl(socket, F_SETFL, sock_flag) < 0)
            return -1;
    }
    
    return 0;
}

