/*
 *  Radius.c
 *  YiXun
 *
 *  Created by Summer Town on 9/14/10.
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


#include "common_macro.h"
#include "common_logs.h"
#include "rds_types.h"
#include "yixun_config.h"
#include "convert_code.h"
#include "encode_password.h"
#include "get_ip_mac.h"

#include "print_hex.h" // for debug
//#include "listen_thread.h"
#include "login_state.h"

#ifndef RDS_PACKET_LEN
#define RDS_PACKET_LEN(p) (ntohs((p)->length) + 8)
#endif

in_addr_t gre, gre_client_ip, gateway_ip, net_mask;  //out parameters
uint32_t timeout, upload_band, download_band;		// out

unsigned auth_server_maskbits = 0; // Auth server netmask bits
//in_addr_t auth_server_addrs = 0;  // Auth server ip
in_addr_t clientip = 0;			// IP address

int start_listen();
int stop_listen();
int accept_client();

static int sockListen;
static int is_listening;

static char uname[MAX_USER_NAME_LEN];	// user name
static char pwd[MAX_PWD_LEN];			// user pwd
static uint8_t eth_addr[6];				// Ethernet address

static struct sockaddr_in auth_server;  //radius server 10.0.100.2

const static uint8_t version[4] = {0x03, 0x00, 0x00, 0x06};
const static uint8_t padding[4] = {0x00, 0x00, 0x00, 0x00};

static int settingChanged = 0;
static int opt_clientip = 0;
static int opt_lladdr = 0;

static int get_server_info(void *buff);
static int do_with_server_info(uint8_t buff[], int sockfd);  //返回0表示无错，返回正数，表示出错原因(e_user, e_pwd ....)
static rds_packet * make_rds_packet(enum rds_head_type tp);  //生成一个发送包（包头）
static void free_rds_packet(rds_packet *);	//释放内存

static void add_segment(rds_packet *p, enum segment_type type, uint16_t length, \
						uint16_t content_len, const uint8_t *content); //为发送包添加相应字段
static void make_send_buff(void *buff, rds_packet *p);	//将生成的发送包内容放到发送缓冲区

static int get_parameters(uint8_t *buff, \
						  in_addr_t *gre, in_addr_t *gre_client_ip, in_addr_t *gateway_ip, in_addr_t *net_mask, \
						  uint32_t *timeout, uint32_t *upload_band, uint32_t *download_band); //认证通过后，获取接入服务器给的参数


//int set_config(const char *ifname, const char *username, const char *password)
//int set_config(const char *username, const char *password, const char *ipaddr, const char *lladdr)
int set_config(const char *username, const char *password, const char *sip, const char *cip, const char *mac)
{ 
    //if (username == NULL || password == NULL) return -1;
    if (username == NULL) return -1;
	
	if (strcmp(username, uname) != 0)
    {
        strncpy(uname, username, sizeof(uname) - 1); uname[sizeof(uname) - 1] = '\0'; // 保存用户名
        settingChanged = -1;
    }
    if (password != NULL && strcmp(password, pwd) != 0)
    {
        strncpy(pwd, password, sizeof(pwd) - 1); pwd[sizeof(pwd) - 1] = '\0';	// 保存密码
        settingChanged = -1;
    }
    
    if (cip != NULL)
    {
        clientip = inet_addr(cip);
        if (clientip != (in_addr_t)0 && clientip != (in_addr_t)-1)
            opt_clientip = -1;
        else
            log_err("[set_config] Invalid ip address:%s\n", clientip);
    }
    
    if (mac != NULL)
    {
        opt_lladdr = string_to_lladdr(eth_addr, mac);
        if (opt_lladdr == 0) log_err("[set_config] Invalid lladdr:%s\n", mac);
    }
    
    bzero(&auth_server, sizeof(auth_server));
    auth_server.sin_family = AF_INET;
    auth_server.sin_port = htons(RADIUS_PORT);
    
    if (sip != NULL)
    {
        char tmp[64];
        strncpy(tmp, sip, sizeof(tmp) - 1);
        tmp[sizeof(tmp) - 1] = '\0';
        char * args[2] = {NULL};
        char *instr = tmp;
        args[0] = strsep(&instr, "/");
        args[1] = strsep(&instr, "/");
        auth_server.sin_addr.s_addr = inet_addr(sip);
        if (args[1] != NULL)
        {
            sscanf(args[1], "%u", &auth_server_maskbits);
            if (auth_server_maskbits > 32) auth_server_maskbits = 32;
        }
    }
    else
    {
        auth_server.sin_addr.s_addr = inet_addr(AUTH_SERVER);
        auth_server_maskbits = AUTH_SERVER_MASKBITS;
    }
/*
    auth_server_addrs = ntohl(auth_server.sin_addr.s_addr);
    auth_server_addrs &=  ~((1 << (32 - auth_server_maskbits)) - 1);
    auth_server_addrs = htonl(auth_server_addrs);
*/    
    /*
    if (inet_pton(AF_INET, AUTH_SERVER, &auth_server.sin_addr) <= 0)
    {
        log_perror("[set_config]:%s\n", AUTH_SERVER);
        return -4;
    }
	*/
    return 0;
}

int log_in()
{
    int rval = -1;
    set_login_state(connecting);
	static uint8_t s_buff[S_BUF_LEN];
	static size_t len;
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0)
    {
        log_perror("[log_in] socket");
        goto ERROR;
    }
    /*
    struct timeval tv;
    tv.tv_sec = CONNECTION_TIME_OUT;
    tv.tv_usec = 0;
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0)
    {
        log_perror("[log_in] setsockopt");
        goto ERROR;
    }
    tv.tv_sec = CONNECTION_TIME_OUT;
    tv.tv_usec = 0;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
    {
        log_perror("[log_in] setsockopt");
        goto ERROR;
    }
    */
    if (connect(sockfd, (struct sockaddr *)&auth_server, sizeof(struct sockaddr_in)) < 0)
    {
        log_perror("[log_in] connect %s", inet_ntoa(auth_server.sin_addr));
        goto ERROR;
    }
	
	if (settingChanged)
	{
        if (!opt_clientip && get_ip_mac_by_socket(sockfd, &clientip, opt_lladdr ? NULL : eth_addr) < 0)
        {
            log_err("[log_in] get ip address and eth_addr");
            goto ERROR;
        }
		
        uint8_t *sec_pwd = (uint8_t *)malloc(sizeof(uint8_t) * (strlen(pwd) + 2));
		encode_pwd_with_ip(sec_pwd, pwd, clientip);

		rds_packet *packet = make_rds_packet(u_login);

		add_segment(packet,  c_mac, 6, 6, eth_addr);
		add_segment(packet,  c_ip, 4, 4, (uint8_t *)&clientip);
		add_segment(packet,  c_user, MAX_USER_NAME_LEN, strlen(uname), (uint8_t *)uname); //***Hack,用户名最长为20***
		add_segment(packet,  c_pwd, strlen((char *)sec_pwd), strlen((char *)sec_pwd), sec_pwd);
		add_segment(packet,  c_ver, 4,4, version);
		add_segment(packet,  c_pad, 4,4, padding);
		
		free(sec_pwd);
		
		len = RDS_PACKET_LEN(packet);
		
		make_send_buff(s_buff, packet);
		free_rds_packet(packet);
		
		settingChanged = 0;
    }
		
    int ret = send(sockfd, s_buff, len, 0);

    if (ret < 0)
    {
        log_perror("[log_in] send to %s", inet_ntoa(auth_server.sin_addr));
        goto ERROR;
    }
	
	uint8_t r_buff[R_BUF_LEN];

    ret = recv(sockfd, r_buff, R_BUF_LEN, 0);
    if (ret > 0)
    {
        rval = do_with_server_info(r_buff, sockfd);
        if (rval != 0)
            goto ERROR;
    }
    else
    {
		if (ret == 0)
			log_err("[log_in] receive: Auth server %s has closed its half side of the connection\n", inet_ntoa(auth_server.sin_addr));
		else
			log_perror("[log_in] receive");
        
		goto ERROR;
    }
    
    set_login_state(connected);
    return 0;
ERROR:
    set_login_state(not_login);
    return rval;
}


int send_keep_alive()
{
	static uint8_t s_buff[S_BUF_LEN];
	
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0)
    {
        log_perror("[send_keep_alive] create socket");
        goto ERROR;
    }
    
    if (connect(sockfd, (struct sockaddr *)&auth_server, sizeof(struct sockaddr_in)) < 0)
    {
        log_perror("[send_keep_alive] connect %s", inet_ntoa(auth_server.sin_addr));
        goto ERROR;
    }
	
	if(s_buff[0] == 0) //因为这个发送包的内容是固定的，因此没有必要每次都重新再做这个包
	{
        if (!opt_clientip && get_ip_mac_by_socket(sockfd, &clientip, NULL) < 0)
        {
            log_perror("[send_keep_alive] get ip address and eth_addr");
            goto ERROR;
        }
		rds_packet *packet = make_rds_packet(u_keepalive);
		
		add_segment(packet, c_ip, 4, 4, (uint8_t *)&clientip);
		add_segment(packet, c_user, MAX_USER_NAME_LEN, strlen(uname), (uint8_t *)uname); //***Hack,用户名最长为20***

		make_send_buff(s_buff, packet);
		free_rds_packet(packet);
	}
	
    if (send(sockfd, s_buff, sizeof(s_buff), 0) < 0) // Hack:发送包是固定的512字节
    {
        log_perror("[send_keep_alive] send");
        goto ERROR;
    }
	
    return 0;
ERROR:
    set_login_state(not_login);
    return -1;
}


int log_out()
{
	static uint8_t s_buff[S_BUF_LEN];
	
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0)
    {
        log_perror("[log_out] create socket");
        goto ERROR;
    }
    
    if (connect(sockfd, (struct sockaddr *)&auth_server, sizeof(struct sockaddr_in)) < 0)
    {
        log_perror("[log_out] connect");
        goto ERROR;
    }
	
	if(s_buff[0] == 0) //因为这个发送包的内容是固定的，因此没有必要每次都重新再做这个包
	{
        if (!opt_clientip && get_ip_mac_by_socket(sockfd, &clientip, NULL) < 0)
        {
            log_err("[log_out] get ip address and eth_addr\n");
            goto ERROR;
        }
        
		rds_packet *packet = make_rds_packet(u_logout); //Hack:退出登录和保持活动连接只有这一个地方有差别
		
		add_segment(packet, c_ip, 4, 4, (uint8_t *)&clientip);
		add_segment(packet, c_user, MAX_USER_NAME_LEN, strlen(uname), (uint8_t *)uname); //***Hack,用户名最长为20***
		
		make_send_buff(s_buff, packet);
		free_rds_packet(packet);
	}
	
    if (send(sockfd, s_buff, sizeof(s_buff), 0) < 0) // Hack:发送包是固定的512字节
    {
        log_perror("[log_out] send");
        goto ERROR;
    }

    stop_listen();
    set_login_state(not_login);
    return 0;
ERROR:
    stop_listen();
    set_login_state(not_login);
    return -1;
}

int start_listen()
{
	if (is_listening) return sockListen;
	if ((sockListen = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		log_perror("[start_listen] socket");
		return -1;
	}
	
	int opt = 1;
	if (setsockopt(sockListen, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
	{
		log_perror("[start_listen] setsockopt");
		goto ERROR;
	}
	
	struct sockaddr_in local;
	bzero(&local, sizeof(local));
	local.sin_addr.s_addr = INADDR_ANY;
	local.sin_family = AF_INET;
	local.sin_port = htons(RADIUS_PORT);
	
	if (bind(sockListen, (struct sockaddr *)&local, sizeof(local)) != 0)
	{
		log_perror("[start_listen] Bind");
		goto ERROR;
	}
	
	if (listen(sockListen, MAX_CLIENT) != 0)
	{
		log_perror("[start_listen] Listen");
		goto ERROR;
	}
	is_listening = -1;
	return 0;
ERROR:
    close(sockListen);
    is_listening = 0;
    return -1;
}

int stop_listen()
{
	if (!is_listening) return 0;
	close(sockListen);
	is_listening = 0;
	return 0;
}

int accept_client()
{
    static fd_set rfds;
    static struct timeval tv;
/*	do
	{
*/      pthread_testcancel();
        /*
        tv.tv_sec = 0;
        tv.tv_usec = 500000; // 0.5 second
        */
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        FD_ZERO(&rfds);
        FD_SET(sockListen, &rfds);
        int cnt = select(sockListen + 1, &rfds, NULL, NULL, &tv);
        if (cnt <= 0)
        {
            if (cnt < 0 && errno != EINTR)
                log_perror("[accept_client] select");
            return 0;
        }
        
        pthread_testcancel();
        if (FD_ISSET(sockListen, &rfds))
        {
            uint8_t r_buff[R_BUF_LEN];
            struct sockaddr_in r_client;
            socklen_t len = sizeof(r_client);
            int sock_client = accept(sockListen, (struct sockaddr *)&r_client, &len);
            if (sock_client < 0)
            {
                log_perror("[accept_client] accept");
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
            if ((ntohl(r_client.sin_addr.s_addr) ^ ntohl(auth_server.sin_addr.s_addr)) >> (32 - auth_server_maskbits) != 0)
            {
                log_notice("[accept_client]: %s attempt to connect\n", inet_ntoa(r_client.sin_addr));
                close(sock_client);
                return 0;
            }
            
            log_info("[accept_client] accept: %s\n", inet_ntoa(r_client.sin_addr));
                        
            tv.tv_sec = 1;
            tv.tv_usec = 0;
            if (setsockopt(sock_client, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
                log_perror("[accept_client] setsockopt");
            
            int ret = recv(sock_client, r_buff, R_BUF_LEN, 0);
            if (ret <= 0)
            {
                if (ret == 0)
                    log_perror("[accept_client] receive: Client %s has closed its half side of the connection\n", inet_ntoa(r_client.sin_addr));
                else
                    log_perror("[accept_client] receive");
                return 0;
            }
            ret = do_with_server_info(r_buff, 0);
            if (ret) close(sock_client);

            //print_info();
        }
//	}while(flag);
    return 0;
}

static int do_with_server_info(uint8_t buff[], int sockfd)
{
    rds_packet *hd = (rds_packet *)buff;
    if (hd->flag != RADIUS_HEADER_FLAG)
    {
        log_err("Error: Invalid server package flag:0x%02x\n", hd->flag);
        debug_print_hex(buff, 32);
        return -1;
    }
    switch (hd->type)
    {
        case s_accept:
        {

            log_info("Server accepted...\n");
            if (start_listen() < 0)
                return -1;

            rds_packet *packet = make_rds_packet(u_ack);
            int err = send(sockfd, packet, 8, 0);
            free_rds_packet(packet);
            
            if (err < 0)
            {
                log_perror("[do_with_server_info] send");
                stop_listen();
                return -1;
            }
            
            accept_client();
 
            if (get_parameters(buff, &gre, &gre_client_ip, &gateway_ip, &net_mask, &timeout, &upload_band, &download_band) < 0)
            {
                log_err("[do_with_server_info] Cannot get parameters\n");
                stop_listen();
                return -1;
            }
            if (timeout > MAX_TIME_OUT)
            {
                log_notice("Server side time out to long:%u\n  use %u instead\n", timeout, MAX_TIME_OUT);
                timeout = MAX_TIME_OUT;
            }
                      
            struct in_addr a[4];
            char p1[4][20];
            
            a[0].s_addr = gre; a[1].s_addr = gre_client_ip; a[2].s_addr = gateway_ip; a[3].s_addr = net_mask;
            int i;
            for (i = 0; i < 4; i++) {
                strcpy(p1[i], inet_ntoa(a[i]));
            }
            
            log_notice("gre:%s clientip:%s gateway:%s netmask:%s\n", p1[0], p1[1], p1[2], p1[3]);
            log_notice("timeout:%u upload_band:%u download_band:%u\n", timeout, upload_band, download_band);

            break;
        }
        case s_info:
            get_server_info(buff);
            break;
        case s_error:
            return get_server_info(buff);
        case s_keepalive:
            log_warning("server send keepalive\n  Keep-alive thread fail???\n");
            break;
        default:
            log_err("[do_with_server_info] Unkown msg type: 0x%02x\n", hd->type);
    }
    return 0;
}

static int get_parameters(uint8_t *buff, \
				   in_addr_t *gre, in_addr_t *gre_client_ip, in_addr_t *gateway_ip, in_addr_t *net_mask, \
				   uint32_t *timeout, uint32_t *upload_band, uint32_t *download_band)
{
	rds_packet *hd = (rds_packet *)buff;
	buff += 8; // offset 8 is first segment
	
	uint8_t *end = buff + ntohs(hd->length);	// the end of segment
	while (buff < end)
	{
		rds_segment *p = (rds_segment *)buff;
		if (p->flag != SERVER_SEGMENT_FLAG)
		{
			log_err("[get_parameters] Invalid segment flag:0x%02x\n", p->flag);
			debug_print_hex(p, 64);
			return -1;
		}
		switch (p->type) {
			case s_gre:
				*gre = *((in_addr_t *)p->content);
				break;
			case s_cip:
				*gre_client_ip = *((in_addr_t *)p->content);
				break;
			case s_gip:
				*gateway_ip = *((in_addr_t *)p->content);
				break;
			case s_mask:
				*net_mask = *((in_addr_t *)p->content);
				break;
			case s_timeout:
				*timeout = ntohl(*((uint32_t *)p->content));
				break;
			case s_upband:
				*upload_band = ntohl(*((uint32_t *)p->content));
				break;
			case s_downband:
				*download_band = ntohl(*((uint32_t *)p->content));
				break;
			default:
				break;
		}
		buff += p->length;
	}
	return 0;
}

static int get_server_info(void *buff)
{
    rds_packet *hd = (rds_packet *)buff;
    
    buff += 12; //信息位置
    char tmpbuff[2048];
    int rval = convert_code("GB18030", "UTF-8", (char *)buff, strlen((char*)buff), tmpbuff, sizeof(tmpbuff) - 1);
    tmpbuff[sizeof(tmpbuff) - 1] = '\0';
    int len = strlen(tmpbuff);
    //tmpbuff[len] = '\n';
    //tmpbuff[len + 1] = '\0';
    
    snprintf(tmpbuff + len, sizeof(tmpbuff) - len, "\n");
    //dprintf("tmpbuff:%s", tmpbuff);
    
    if (hd->type == s_info)
        log_info(tmpbuff);
    else if(hd->type == s_error)
        log_err(tmpbuff);
    else
        log_debug(tmpbuff);
    
    if (rval != 0) dprintf("Warning, convert_code returned %d\n", rval);
    
    int i = 0;
    while(error_info_str[i] != NULL)
    {
        if (strnstr(tmpbuff, error_info_str[i], sizeof(tmpbuff)) != NULL)
            return e_user + i;
        i++;
    }
    
	return hd->type == s_error ? -1 : 0;
}


static rds_packet * make_rds_packet(enum rds_head_type tp)
{
    rds_packet *p = (rds_packet *)calloc(sizeof(rds_packet), 1);
    if (!p)
    {
        log_perror("[make_rds_packet] calloc");
        return NULL;
    }
    
    p->flag = RADIUS_HEADER_FLAG; //Always be 0x5f
    p->type = (uint8_t)tp;
    return p;
}


static void add_segment(rds_packet *p, enum segment_type type, uint16_t length, uint16_t content_len, const uint8_t *content)
{
    rds_segment *s = calloc(sizeof(rds_segment), 1);
    if (!s)
    {
        log_perror("[add_segment] calloc");
        return;
    }
	
	if (length + 4 > SEGMENT_MAX_LEN) length = SEGMENT_MAX_LEN - 4;
	
    s->flag = CLINET_SEGMENT_FLAG;
    s->type = type;
    s->length = length + 4; //包含segment头的长度4
    
    if (content_len > length) content_len = length;
    memcpy(s->content, content, content_len);
    
    if (p->extra == NULL)
    {
        p->extra = s;
    }
    else
    {
        rds_segment *t = p->extra;
        while (t->next) {
            t = t->next;
        }
        t->next = s;
    }
    p->length = htons(ntohs(p->length) + s->length); //修正包的长度
}

static void make_send_buff(void *buff, rds_packet *p)
{
    memcpy(buff, p, 8); //拷贝包头（8个字节）
    uint8_t *t = (uint8_t *)buff + 8;
    rds_segment *s = p->extra;
    while(s)
    {
        memcpy(t, s, 4); //segment head size = 4
        t += 4;
        size_t len = s->length - 4;
        if (s->length > 4) memcpy(t, s->content, len);
        s = s->next;
        t += len;
    }
    return;
}

static void free_rds_packet(rds_packet *p)
{
    if (p == NULL) 
    {
        log_warning("[free_rds_packet] Free Null pointer\n");
        return;
    }
    rds_segment *t = p->extra;
    free(p);
    
    while(t)
    {
        rds_segment *s = t;
        t = t->next;
        free(s);
    }
}
