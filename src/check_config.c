#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>		/* AF_INET */
#include <sys/param.h>		/* MAXPATHLEN */
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>			/* fopen(), fclose(), fgetln(), getenv() */
#include <errno.h>
#include <string.h>			/* strsep(), memcpy() */
#include <strings.h>		/* bzero() */
#include <stdbool.h>

#include <fcntl.h>

#include <arpa/inet.h>		/* inet_addr(), htons() */

#include "defconfig.h"
#include "yixun_config.h"
#include "log_xxx.h"
#include "radius.h"
#include "get_ip_mac.h"

#ifdef DEBUG 
#include "hexdump.h"
#endif

#define CONF_FILE "/etc/yixun.conf"
#define PRIV_CONF_FILE ".yixun_conf"

#define SLOT_CNT 31

extern bool flag_verbose;
extern bool flag_quiet;

enum key_type {
	ch,
	in,
	ui
};

struct key {
	const char *parm;
	unsigned int hash;
	void * data;
	enum key_type type;
	struct key *next;
};

struct key keys[] = {
	{"username",	0,	username,	ch},
	{"password",	0,	password,	ch},
	{"hwaddr",		0,	hwaddr,		ch},
	{"regip",		0,	regip,		ch},
	{"authserver",	0,	authserver,	ch},
	{"msgserver",	0,	msgserver,	ch},
	{"serverport",	0,	&serverport,	ui},
	{"listenport",	0,	&listenport,	ui},
	{"conn_timeout",	0,	&conn_timeout,	in},
	{"snd_timeout",	0,	&snd_timeout,	in},
	{"rcv_timeout",	0,	&rcv_timeout,	in},
	{"heart_beat_timeout",	0,	&heart_beat_timeout,	in},
	{NULL,			0,	NULL,		0}
};

struct key *key_pcb[SLOT_CNT] = {NULL};

/* DJB Hash */
static unsigned int
hash(const char *s)
{
	unsigned int h = 5381;
	while (*s) {
		h += (h << 5) + *s++;
	}
	return h & 0x7fffffff;
}

static void
init_keys(struct key *k)
{
#ifdef DEBUG 
	fprintf(stderr, "dump key_pcb...\n");
	hexdump(key_pcb, sizeof(key_pcb));
#endif

	while (k->parm) {
		k->hash = hash(k->parm);
#ifdef DEBUG
		fprintf(stderr, "%s: k->parm = %s, k->hash = %u\n", \
				__FUNCTION__, k->parm, k->hash);
#endif
		k->next = NULL;
		unsigned int slot = k->hash % SLOT_CNT;
		if (key_pcb[slot] == NULL) 
			key_pcb[slot] = k;
		else {

#ifdef DEBUG
		fprintf(stderr, "dump key_pcb[%u]...", slot);
		hexdump(key_pcb[slot], sizeof(key_pcb[slot]));
#endif
			struct key *p = key_pcb[slot];
			while (p->next) p = p->next;
			p->next = k;
		}
		k++;
	}
}

static int
read_conf(const char *key, const char *val)
{
#ifdef DEBUG
	fprintf(stderr, "%s: key: %s, val: %s\n", __FUNCTION__, key, val);
#endif

	unsigned int slot = hash(key) % SLOT_CNT;

	struct key *p = key_pcb[slot];
	for (p = key_pcb[slot]; p; p = p->next) {
		if (strcmp(key, p->parm) == 0) {
			switch (p->type) {
				case ch:
					strlcpy((char *)p->data, val, CONF_LEN);
					break;
				case in:
					sscanf(val, "%i", (int *)p->data);
					break;
				case ui:
					sscanf(val, "%u", (unsigned int *)p->data);
					break;
				default:
					/* should never happen */
					fprintf(stderr, "unkown key type %d\n", p->type);
			}
			return 0;
		}
	}

	fprintf(stderr, "unknown option %s\n", key);
	return -1;
}


char *
skip_blanks(char *s)
{
	if (s == NULL)
		return NULL;

	while (*s) {
		switch (*s) {
			case ' ':
			case '\t':
			case '\r':
			case '\n':
				s++;
				break;
			default:
				return s;
		}
	}
	return NULL;
}

int
get_params(char *buff, size_t len, char *par1, size_t par1_len, char *par2, size_t par2_len)
{
	int i;
	int l1 = 0, l2 = 0;
	int has_equal = 0;
	for (i = 0; i < len && buff[i]; i++) {
		if (buff[i] == '=') {
			has_equal = 1;
			break;
		}
		switch (buff[i]) {
			case ' ':
			case '\t':
			case '\r':
			case '\n':
				continue;
			default:
				if (l1 < par1_len)
					par1[l1++] = buff[i];
		}
	}

	par1[l1] = '\0';

	/* check if is empty line */
	if (! has_equal)
		return l1 == 0 ? 0 : -1;

	/* = bar , missing "foo" */
	if (l1 == 0)
		return -1;

	/* foo, missing "=" and "bar" */

	for (i++; i < len && buff[i]; i++) {
		switch (buff[i]) {
			case ' ':
			case '\t':
			case '\r':
			case '\n':
				continue;
			default:
				if (l2 < par2_len)
					par2[l2++] = buff[i];
		}
	}

	par2[l2] = '\0';

	/* foo = , missing "bar" */
	if (l2 == 0)
		return -1;

	return 1;
}


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
 * on error, return -1;
 * on syntax error, return syntax error count;
 */
int
check_conf_file(const char *conf)
{
	static int keys_inited = 0;
	if (!keys_inited) {
		init_keys(keys);
		keys_inited = 1;
	}

	if (conf) {
		FILE * fp;
		if ((fp = fopen(conf, "r")) == NULL) {
			fprintf(stderr, "cannot open %s: %s\n", conf, strerror(errno));
			return -1;
		}

		int errcnt = 0; /* syntax error count */

		char *buff;
		size_t len;
		int line = 0;

		while ((buff = fgetln(fp, &len))) {
			line++;
			char s[80], t[80];
			switch (get_params(buff, len, s, sizeof(s), t, sizeof(t))) {
				case -1:
					/* error */
					fprintf(stderr, "Syntax error in %s at line %d\n", \
							conf, line);
					errcnt++;
					break;
				case 0:
					/* empty line */
					break;
				default:
					/* get a line */
					if (read_conf(s, t) < 0)
						goto DONE;
			}
		}
DONE:
		if (fclose(fp) == EOF) {
			fprintf(stderr, "fclose(%s): %s\n", conf, strerror(errno));
			return -1;
		}

		return errcnt;
	} else {
		char *p = getenv("HOME");
		if (p) {
			char priv_conf[MAXPATHLEN];
			snprintf(priv_conf, sizeof(priv_conf), "%s/%s", p, PRIV_CONF_FILE);
			if (chmod(priv_conf, 0644) == 0) {
				int err = check_conf_file(priv_conf);
				if (err)
					return err;
			}
		} else
			fprintf(stderr, "warnning: $HOME not set\n");

		if (chmod(CONF_FILE, 0644) == 0) {
			int err = check_conf_file(CONF_FILE);
			if (err)
				return err;
		}

		return 0;
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
		log_err("require username\n");
		return -1;
	}
	if (password[0] == '\0') {
		log_err("require password\n");
		return -1;
	}
	if (regip[0]) {
		gre_src = inet_addr(regip);
		if (gre_src == 0 || gre_src == 0xffffffff)
			log_err("invalid ip address:%s\n", regip);
	}
	if (hwaddr[0]) {
		if (string_to_lladdr(eth_addr, hwaddr) < 0)
			log_err("invalid lladdr:%s\n", hwaddr);
	}
	if (serverport == 0 || serverport > 65535) {
		log_err("server port out of range: %u\n", serverport);
		return -1;
	}
	if (listenport == 0 || listenport > 65535) {
		log_err("listen port out of range: %u\n", listenport);
		return -1;
	}

	bzero(&auth_server, sizeof(auth_server));
	auth_server.sin_family = AF_INET;
	auth_server.sin_port = htons(serverport);

	if (authserver[0] == '\0') {
		log_err("require auth server ip\n");
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
		log_err("connect timeout too short:%u\n", conn_timeout);
		return -1;
	}
	if (snd_timeout < 1) {
		log_err("send timeout too short:%u\n", snd_timeout);
		return -1;
	}
	if (rcv_timeout < 1) {
		log_err("receive timeout too short:%u\n", rcv_timeout);
		return -1;
	}

	return 0;
}


