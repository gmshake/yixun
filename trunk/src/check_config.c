#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <fcntl.h>

#include <arpa/inet.h>

#include "defconfig.h"
#include "yixun_config.h"
#include "log_xxx.h"
#include "radius.h"
#include "get_ip_mac.h"


/*
 * check sanity of config file
 * @fd,		file discription
 *
 * @return	success 0, error -1, others
 * 0x0001, server-ip missing
 * 0x0002, username missing
 * 0x0004, password missing
 */
int
sanity_check(int fd)
{
	printf("%s: **** TODO ****\n", __FUNCTION__);
	return 0xffff;
}


/*
 * check configuration file
 * @conf, in, user defined file, NULL to indicates use default conf file
 * 
 * on sucess, return 0;
 * on synatx error, return -1;
 * other error, error code can be combined
 * 0x0001, server-ip missing
 * 0x0002, username missing
 * 0x0004, password missing
 */
int
check_conf_file(const char *conf)
{
	int fd;

	if (conf) {
		if ((fd = open(conf, O_RDONLY, 0)) < 0) {
			fprintf(stderr, "error open %s: %s\n", conf, strerror(errno));
			return -1;
		}

		int err = sanity_check(fd);
		close(fd);

		return err;

	} else {
		fprintf(stderr, "%s: **** TODO ****\n", __FUNCTION__);
		fputs("    ***  check /etc/yixun.conf  ****\n", stderr);
		fputs("    ***  check ~/.yixun_conf    ****\n", stderr);
		return sanity_check(0);
	}

}

void
load_default(void)
{
	if (serverport == 0)
		serverport = SERVER_PORT;

	if (listenport == 0)
		listenport = LISTEN_PORT;

	if (authserver[0] == '\0')
		strlcpy(authserver, AUTH_SERVER, sizeof(authserver));

	if (msgserver[0] == '\0')
		strlcpy(msgserver, MSG_SERVER, sizeof(msgserver));

	if (conn_timeout == 0)
		conn_timeout = CONNECTION_TIMEOUT;

	if (snd_timeout == 0)
		snd_timeout = SND_TIMEOUT;

	if (rcv_timeout == 0)
		rcv_timeout = RCV_TIMEOUT;

	if (heart_beat_timeout == 0)
		heart_beat_timeout = HEART_BEAT_TIMEOUT;
}

/*
 * check_config(), check necessary infomation, username, pwd etc.
 * return 0 on success, otherwise -1;
 */
int
check_config(void)
{
	if (username[0] == '\0') {
		log_err("%s: require username\n", __FUNCTION__);
		return -1;
	}
	if (password[0] == '\0') {
		log_err("%s: require password\n", __FUNCTION__);
		return -1;
	}
	if (regip[0]) {
		gre_src = inet_addr(regip);
		if (gre_src == 0 || gre_src == 0xffffffff)
			log_err("%s: invalid ip address:%s\n", __FUNCTION__, regip);
	}
	if (hwaddr[0]) {
		if (string_to_lladdr(eth_addr, hwaddr) < 0)
			log_err("%s: invalid lladdr:%s\n", __FUNCTION__, hwaddr);
	}
	if (serverport == 0 || serverport > 65535) {
		log_err("%s: server port out of range: %u\n", __FUNCTION__, serverport);
		return -1;
	}
	if (listenport == 0 || listenport > 65535) {
		log_err("%s: listen port out of range: %u\n", __FUNCTION__, listenport);
		return -1;
	}

	bzero(&auth_server, sizeof(auth_server));
	auth_server.sin_family = AF_INET;
	auth_server.sin_port = htons(serverport);

	if (authserver[0] == '\0') {
		log_err("%s: require auth server ip\n", __FUNCTION__);
		return -1;
	}

	char tmp[64];
	strlcpy(tmp, authserver, sizeof(tmp));
	char *args[2] = { NULL };
	char *instr = tmp;
	args[0] = strsep(&instr, "/");
	args[1] = strsep(&instr, "/");
	auth_server.sin_addr.s_addr = inet_addr(args[0]);
	if (args[1] != NULL) {
		sscanf(args[1], "%u", &auth_server_maskbits);
		if (auth_server_maskbits > 32)
			auth_server_maskbits = 32;
	}

	if (conn_timeout < 1) {
		log_err("%s: connect timeout too short:%u\n", __FUNCTION__, conn_timeout);
		return -1;
	}
	if (snd_timeout < 1) {
		log_err("%s: send timeout too short:%u\n", __FUNCTION__, snd_timeout);
		return -1;
	}
	if (rcv_timeout < 1) {
		log_err("%s: receive timeout too short:%u\n", __FUNCTION__, rcv_timeout);
		return -1;
	}

	return 0;
}


