#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>		/* AF_INET */
#include <sys/param.h>		/* MAXPATHLEN */
#include <unistd.h>
#include <stdio.h>			/* BUFSIZ */
#include <stdlib.h>			/* fopen(), fclose(), getenv() */
#include <errno.h>

#if defined(__linux__)  /* Linux stuff...*/
#define __USE_GNU
#include <string.h>         /* strsep(), memcpy(), strcasecmp()... */
#undef __USE_GNU
#else
#include <string.h>
#endif

#include <strings.h>		/* bzero() */
#include <stdbool.h>

#include <fcntl.h>

#include <arpa/inet.h>		/* inet_addr(), htons() */

#include "defconfig.h"
#include "yixun_config.h"
#include "log_xxx.h"
#include "radius.h"
#include "get_ip_mac.h"
#include "parse_args.h"

#ifdef DEBUG 
#include "hexdump.h"
#endif

#define CONF_FILE "/etc/yixun.conf"
#define PRIV_CONF_FILE ".yixun_conf"

#define SLOT_CNT 31

extern bool flag_verbose;
extern bool flag_quiet;

enum key_type {
	st,	/* string */
	in,	/* interger */
	ui,	/* unsigned interger */
	bo	/* boolean */
};

struct key {
	const char *key;
	void *val;
	enum key_type type;
	unsigned int hash;
	struct key *next;
};

/* known keys and key type */
static struct key keys[] = {
	{"username",		username,		st},
	{"password",		password,		st},
	{"hwaddr",			hwaddr,			st},
	{"regip",			regip,			st},
	{"auth-server",		authserver,		st},
	{"msg-server",		msgserver,		st},
	{"listen-port",		&listenport,	ui},
	{"conn-timeout",	&conn_timeout,	in},
	{"snd-timeout",		&snd_timeout,	in},
	{"rcv-timeout",		&rcv_timeout,	in},
	{"heart-beat-timeout",		&heart_beat_timeout,	in},
	{NULL,				NULL,			0}
};

/* hash table */
static struct key *key_pcb[SLOT_CNT];

/* DJB Hash */
static unsigned int
hash(const char *s)
{
	unsigned int h = 5381;
	while (*s) {
		h += (h << 5) + *s++;
	}
	return h;
}

/* calculate key hash, put key into the hash table key_pcb */
static void
init_keys(struct key *p)
{
	for (; p->key; p++) {
		p->hash = hash(p->key);

		/* simpler policy, just INSERT */
		unsigned int slot = p->hash % SLOT_CNT;
		p->next = key_pcb[slot];
		key_pcb[slot] = p;
	}
}

static int
read_key_val(const char *key, const char *val)
{
	unsigned int h = hash(key);
	unsigned int slot = h % SLOT_CNT;

	struct key *p = key_pcb[slot];
	for (p = key_pcb[slot]; p; p = p->next) {
		if (p->hash == h && strcmp(key, p->key) == 0) {
			switch (p->type) {
				case st:
					strlcpy((char *)p->val, val, CONF_LEN);
					break;
				case in:
					sscanf(val, "%i", (int *)p->val);
					break;
				case ui:
					sscanf(val, "%u", (unsigned int *)p->val);
					break;
				case bo:
					if (strcasecmp(val, "yes") == 0)
						*(bool *)p->val = true;
					else if (strcasecmp(val, "no") == 0)
						*(bool *)p->val = false;
					else {
						fprintf(stderr, "option %s: %s should be `yes' or `no'\n", key, val);
						return -1;
					}
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

static void
load_default_conf(void)
{
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

static const char *
skip_blanks(const char *s)
{
	if (s == NULL) {
#ifdef DEBUG
		fprintf(stderr, "%s: warnning: Null string\n", __FUNCTION__);
#endif
		return NULL;
	}

	for(;;) {
		switch (*s) {
			case ' ':
			case '\t':
			case '\r':
			case '\n':
				s++;
				continue;
			default:
				break;
		}
		break;
	}

	return s;
}

static const char *
copy_key(const char *buff, char *key, size_t len)
{
	int i;
	const char *p;
	for (i = 0, p = buff; *p; p++) {
		switch (*p) {
			case ' ':
			case '\t':
			case '\r':
			case '\n':
				break;
			default:
				if (i < len)
					key[i++] = *p;
				continue;
		}
		break;
	}

	if (i < len)
		key[i] = '\0';
	else if (len > 0)
		key[len - 1] = '\0';

	return p;
}

static const char *
copy_escape_val(const char *buff, char *val, size_t len)
{
	int i;
	const char *p;

	if (*buff != '"')
		return buff;
	for (i = 0, p = buff + 1; *p; p++) {
		switch (*p) {
			case '\\':
				p++;
				if (*p != '\\' && \
						*p != '"')
					break;
				if (i < len)
					val[i++] = *p;
				continue;
			default:
				if (*p == '"') {
					p++;
					break;
				}
				if (i < len)
					val[i++] = *p;
				continue;
		}
		break;
	}

	if (i < len)
		val[i] = '\0';
	else if (len > 0)
		val[len - 1] = '\0';

	return p;
}


static const char *
copy_val(const char *buff, char *val, size_t len)
{
	int i;
	const char *p;
	for (i = 0, p = buff; *p; p++) {
		switch (*p) {
			case ' ':
			case '\t':
			case '\r':
			case '\n':
				break;
			default:
				if (i < len)
					val[i++] = *p;
				continue;
		}
		break;
	}

	if (i < len)
		val[i] = '\0';
	else if (len > 0)
		val[len - 1] = '\0';

	return p;
}

/*
 * we support these val types:
 * 1: key val
 * 2: key "val"
 * 3: key "some val"
 * 4: key " \\ \" some other "
 * 5: key val #with comments
 * 6: key "some val" #with comments
 */
static int
get_key_val(const char *buff, char *key, size_t key_len, char *val, size_t val_len)
{
	if (key_len == 0 || val_len == 0) {
#ifdef DEBUG
		fprintf(stderr, "key_len:%u val_len:%u\n", key_len, val_len);
#endif
		return 0;
	}

	/* parse key */
	buff = skip_blanks(buff);
	switch (*buff) {
		/* empty line */
		case '\0':
			/* start with '#', comment */
		case '#':
			return 0;
		default:
			buff = copy_key(buff, key, key_len);
	}

	/* parse value */
	buff = skip_blanks(buff);
	switch (*buff) {
		/* foo without bar */
		case '\0':
		case '#':
			return -1;
		case '"':
			buff = copy_escape_val(buff, val, val_len);
			break;
		default:
			buff = copy_val(buff, val, val_len);
	}

	if (val[0] == '\0')
		/* foo, missing bar */
		return -1;

	buff = skip_blanks(buff);
	switch (*buff) {
		case '\0':
		case '#':
			/* done */
			break;
		default:
			return -2;
	}

	return 1;
}


/*
 * real load conf file
 */
static int
_load_conf_file(const char *fl)
{
	FILE * fp;
	if ((fp = fopen(fl, "r")) == NULL)
		return -1;

	int errcnt = 0; /* syntax error count */

	char buff[BUFSIZ];
	int line = 0;
	while ((fgets(buff, sizeof(buff), fp))) {
		line++;
		char k[80], v[80];
		switch (get_key_val(buff, k, sizeof(k), v, sizeof(v))) {
			case -2:
				/* error near val */
				fprintf(stderr, "Syntax error in %s at line %d near `%s'\n", \
						fl, line, v);
				errcnt++;
				continue;
			case -1:
				/* error near key */
				fprintf(stderr, "Syntax error in %s at line %d near `%s'\n", \
						fl, line, k);
				errcnt++;
				continue;
			case 0:
				/* empty line, or comments */
				continue;
			default:
				/* get a line */
				if (read_key_val(k, v) < 0) {
					errcnt++;
					break;
				}
				continue;
		}
		break;
	}
	if (fclose(fp) == EOF) {
		fprintf(stderr, "fclose(%s): %s\n", fl, strerror(errno));
		return 0;
	}

	return errcnt;
}
/*
 * check configuration file
 * @conf, in, user defined file, NULL to indicates use default conf file
 * 
 * on sucess, return 0;
 * on error, return -1;
 * on syntax error, return syntax error count;
 */
static int
load_conf_file(const char *conf)
{
	int err;

	if (conf) {
		if ((err = _load_conf_file(conf)) < 0)
			fprintf(stderr, "can not open %s: %s\n", conf, strerror(errno));

		return err;
	} else {
		/* if the CONF_FILE does not exist, continue next conf file */
		if ((err = _load_conf_file(CONF_FILE)) > 0)
			return err;

		char *p = getenv("HOME");
		if (p) {
			char priv_conf[MAXPATHLEN];
			snprintf(priv_conf, sizeof(priv_conf), "%s/%s", p, PRIV_CONF_FILE);
			if ((err = _load_conf_file(priv_conf)) > 0)
				return err;
		} else
			fprintf(stderr, "warnning: $HOME not set\n");

		return 0;
	}
}

/*
 * parsing cmd config, this will override
 * existing config from config file
 */
static void
load_cmd_conf(void)
{
	if (arg_username)
		strlcpy(username, arg_username, sizeof(username));
	if (arg_password)
		strlcpy(password, arg_password, sizeof(password));
	if (arg_authserver)
		strlcpy(authserver, arg_authserver, sizeof(authserver));
	if (arg_regip)
		strlcpy(regip, arg_regip, sizeof(regip));
	if (arg_hwaddr)
		strlcpy(hwaddr, arg_hwaddr, sizeof(hwaddr));
}

static int
ato_addr_port(const char *cp, struct sockaddr_in *s)
{
	char buff[64];
	char *args[2];
	char *instr;
	in_addr_t addr;
	unsigned int port = SERVER_PORT;	/* default server port here */

	strlcpy(buff, cp, sizeof(buff));
	instr = buff;
	args[0] = strsep(&instr, ":");
	args[1] = strsep(&instr, ":");

	if ((addr = inet_addr(args[0])) == INADDR_NONE) {
		log_err("invalid ip addr: %s\n", args[0]);
		return -1;
	}

	if (args[1]) {
		sscanf(args[1], "%u", &port);
		if (port == 0 || port > 65535) {
			log_err("port out of range: %u\n", port);
			return -1;
		}
	}

	bzero(s, sizeof(*s));
	s->sin_family = AF_INET;
	s->sin_addr.s_addr = addr;
	s->sin_port = htons(port);

	return 0;
}
	
/*
 * check_config(), check necessary infomation, username, pwd etc.
 * return 0 on success, otherwise -1;
 */
static int
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

	if (authserver[0] == '\0') {
		log_err("require auth server ip\n");
		return -1;
	}

	if (ato_addr_port(authserver, &auth_server) < 0)
		return -1;

	if (listenport == 0 || listenport > 65535) {
		log_err("listen port out of range: %u\n", listenport);
		return -1;
	}

	msg_server = inet_addr(msgserver);

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

int
load_config(void)
{
	static int keys_inited = 0;

	load_default_conf();

	if (!keys_inited) {
		init_keys(keys);
		keys_inited = 1;
	}

	switch (load_conf_file(arg_conf_file)) {
		case -1:
			return -1;
		case 0:
			break;
		default:
			/* there must be some syntax error in config file */
			log_info("Syntax check failed\n");
			return -1;
	}
	load_cmd_conf();

	if (check_config() < 0)
		return -1;
	return 0;
}

void
print_config(void)
{
	printf("username:         %s\n", username);
	printf("password:         %s\n", password);
	printf("auth server ip:   %s\n", inet_ntoa(auth_server.sin_addr));
	printf("auth server port: %u\n", ntohs(auth_server.sin_port));
	printf("msg server ip:    %s\n", inet_ntoa(*(struct in_addr *)&msg_server));
	printf("listen port:      %u\n", listenport);
	printf("connect timeout:  %ld\n", (long)conn_timeout);
	printf("send timeout:     %ld\n", (long)snd_timeout);
	printf("receive timeout:  %ld\n", (long)rcv_timeout);
}

