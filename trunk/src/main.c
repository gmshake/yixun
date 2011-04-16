/*
 * Copyright (c) 2010, 2011 SummerTown
 *
 * @yixun main() routine
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdbool.h>	/* bool */
#include <unistd.h>		/* ftruncate() */
#include <stdlib.h>		/* for daemon() */
#include <string.h>		/* bzero() strlen() ... */
#include <stdio.h>
#include <getopt.h>		/* getopt_long() */
#include <errno.h>

#include <fcntl.h>
#include <signal.h>
#include <syslog.h>		/* openlog() */

#include <arpa/inet.h>		/* inet_addr() inet_ntoa */
#include <net/if_var.h>

#include "radius.h"
#include "log_xxx.h"
#include "common_macro.h"
#include "route_op.h"
#include "gre_module.h"
#include "gre_tunnel.h"

#ifdef YIXUN_PID
#define LOCKFILE YIXUN_PID
#else
#define LOCKFILE "/var/tmp/yixun.pid"
#endif

static int lockfd;		/* lockfile file description */
//static char *progname;

static bool flag_changeroute = false;
static bool flag_daemon = true;
static bool flag_test = false;
static bool flag_etest = false;
static bool flag_verbose = false;
static bool flag_quiet = false;
static bool flag_exit = false;

static bool log_opened = false;
static bool connected = false;
static bool flag_gre_if_isset = false;

static in_addr_t default_route = 0;

static struct mcb mcb;

static char *conf_file;

static int extr_argc;
static char *const *extr_argv;

void usage(int status);
void version(void);
void parse_args(int argc, char *const argv[]);
int check_conf_file(const char *conf);
int sanity_check(int fd);
void process_signals(int sig);
int quit_daemon(void);
int set_tunnel(in_addr_t src, in_addr_t dst, in_addr_t local, in_addr_t remote, in_addr_t netmask);
int remove_tunnel(in_addr_t src, in_addr_t dst, in_addr_t local, in_addr_t remote);
int open_pid_file(void);
int write_pid(int fd);
int close_pid_file(int fd);

void cleanup(void);

#if ! HAVE_STPCPY
static char *
stpcpy(char *to, char *from)
{
	for (; (*to = *from); ++from, ++to);
	return to;
}
#endif

int
main(int argc, char *const argv[])
{
	parse_args(argc, argv);	/* process args */

	/* sanity check done */
	if (flag_test)
		return EXIT_SUCCESS;

	if (flag_quiet)
		set_log_type(LNONE);
	else if (!flag_daemon)
		set_log_type(LCONSOLE);
	else {
		openlog(PACKAGE, LOG_PID | LOG_CONS, LOG_USER);
		log_opened = true;
		setlogmask(LOG_UPTO(LOG_INFO));
#ifdef DEBUG
		setlogmask(LOG_UPTO(LOG_DEBUG));
#endif
		set_log_type(LCONSOLE | LDAEMON);
	}

	if (flag_exit)
		return quit_daemon();

	/* try to lock */
	if (flag_daemon && (lockfd = open_pid_file()) < 0)
		return EXIT_FAILURE;

	if (atexit(cleanup) < 0) {
		log_perror("atexit()");
		return EXIT_FAILURE;
	}

	int retry_count = 4;
	do {
		int rval = login(&mcb);
		if (rval == 0)
			break;
		else if (rval > 0)
			/* Username or password error, do not retry */
			return EXIT_FAILURE;
		sleep(1);
	} while (retry_count-- > 0);

	if (retry_count <= 0) {
		log_err("Can not log in\n");
		return EXIT_FAILURE;
	}

	if (flag_daemon) {
		if (daemon(0, 0) < 0) {
			log_perror("daemon");
			return EXIT_FAILURE;
		}
		set_log_type(LDAEMON);

		if (write_pid(lockfd) < 0)
			return EXIT_FAILURE;
	}
	
	connected = true;

	/* Extended test done */
	if (flag_etest)
		return EXIT_SUCCESS;

	if (set_tunnel(mcb.gre_src, mcb.gre_dst, mcb.gre_local, mcb.gre_remote, mcb.gre_netmask) < 0) {
		log_perror("Can not set gre interface");
		return EXIT_FAILURE;
	}
	flag_gre_if_isset = true;

	signal(SIGINT, process_signals);
	signal(SIGTERM, process_signals);
	signal(SIGHUP, process_signals);
	signal(SIGQUIT, process_signals);
	signal(SIGALRM, process_signals);

	alarm(mcb.timeout);

	/* if not extended test, loop forever */
	while(1) {
		wait_msg(&mcb);
	}

	return EXIT_SUCCESS;
}

void
parse_args(int argc, char *const argv[])
{
//	progname = argv[0];
	int ch;

	const struct option opts[] = {
		{"config",		required_argument,	NULL,	'f'},
		{"username",	required_argument,	NULL,	'u'},
		{"password",	required_argument,	NULL,	'p'},
		{"server-ip",	required_argument,	NULL,	's'},
		{"client-ip",	required_argument,	NULL,	'c'},
		{"mac-addr",	required_argument,	NULL,	'm'},
		{"no-daemon",	no_argument,		NULL,	'D'},
		{"verbose",		no_argument,		NULL,	'V'},
		{"version",		no_argument,		NULL,	'v'},
		{"quiet",		no_argument,		NULL,	'q'},
		{"test",		no_argument,		NULL,	't'},
		{"ex-test",		no_argument,		NULL,	'T'},
		{"help",		no_argument,		NULL,	'h'},
		{NULL,			0,					NULL,	0}
	};

	while ((ch = getopt_long(argc, argv, "u:p:i:m:f:ADTVtvqxh", opts, NULL)) != -1) {
		switch (ch) {
			case 'u':
				mcb.username = optarg;
				break;
			case 'p':
				mcb.password = optarg;
				break;
			case 's':
				mcb.serverip = optarg;
				break;
			case 'i':
				mcb.clientip = optarg;
				break;
			case 'm':
				mcb.mac = optarg;
				break;
			case 'f':
				conf_file = optarg;
				break;
			case 'A':
				flag_changeroute = true;
				break;
			case 'D':
				flag_daemon = false;
				break;
			case 't':
				flag_test = true;
				break;
			case 'T':
				flag_etest = true;
				break;
			case 'V':
				flag_verbose = true;
				break;
			case 'q':
				flag_quiet = true;
				break;
			case 'x':
				flag_exit = true;
				break;
			case 'v':
				version();
				exit(EXIT_SUCCESS);
				break;
			case 'h':
				usage(EXIT_SUCCESS);
				break;
			default:
				//fprintf(stderr, "%s: invalid option -- %c\n", PACKAGE, ch);
				usage(EXIT_FAILURE);
		}
	}
	argc -= optind;
	argv += optind;

	extr_argc = argc;
	extr_argv = argv;

	/*
	 * if do not use configure file, username and password are
	 * required
	 */

	if (flag_etest || flag_exit)
		flag_daemon = false;

	if (flag_exit)
		return;

	int err = check_conf_file(conf_file);

	switch (err) {
		case 0:
			break;
		case -1:
			fprintf(stderr, "sanity check error\n");
			exit(EXIT_FAILURE);
			break;
		default:
			{
				/*
				if (err & 0x0001 && mcb.serverip == NULL)
					fputs("require server-ip\n", stderr);
					*/
				if (err & (0x02 | 0x04)) {
					if (err & 0x0002 && mcb.username == NULL) {
						fputs("require username\n", stderr);
						if (err & 0x0004 && mcb.password == NULL)
							fputs("require password\n", stderr);
						usage(EXIT_FAILURE);
					}
				}
			}
	}
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
 * @param op, T_SET, T_REMOVE
 * @param flag, 0 indicates not to change route
 *              1, change default gateway and routes followed
 *              2, revert the changes
 */
#define FLAG_SET 0x01
#define FLAG_CROUTE 0x02
static int
gre_if_op(int flag, struct mcb *mcb, int argc, char *const argv[])
{
	char cmd[512];
	char *p = cmd;
	p = stpcpy(p, "/usr/local/bin/gre-config");
	if ((flag & FLAG_SET) == 0)
		p = stpcpy(p, " -u");

	p += sprintf(p, " -s%s", inet_itoa(mcb->gre_src));
	p += sprintf(p, " -d%s", inet_itoa(mcb->gre_dst));
	p += sprintf(p, " -l%s", inet_itoa(mcb->gre_local));
	p += sprintf(p, " -r%s", inet_itoa(mcb->gre_remote));

	if (flag & FLAG_SET)
		p += sprintf(p, " -n%s", inet_itoa(mcb->gre_netmask));

	if (flag & FLAG_CROUTE) {
		if (default_route == 0) {
			in_addr_t dst = 0, mask = 0;
			/* get default route */
			if (route_get(&dst, &mask, &default_route, NULL) < 0) {
				mask = 0xffffffff;
				dst = mcb->auth_server;
				/* get route to authorize server */
				if (route_get(&dst, &mask, &default_route, NULL) < 0)
					return -1;	/* joking me ??? */
			}
		}
		p += sprintf(p, " -C%s ", inet_itoa(default_route));

		p = stpcpy(p, inet_itoa(mcb->auth_server));
		if (mcb->msg_server != 0)
			p += sprintf(p, " %s", inet_itoa(mcb->msg_server));
		if (mcb->gre_dst != mcb->msg_server)
			p += sprintf(p, " %s", inet_itoa(mcb->gre_dst));

		int i;
		for (i = 0; i < argc; i++) {
			if (argv[i] == NULL || p + strlen(argv[i]) + 1 >= cmd + sizeof(cmd))
				break;
			else
				p += sprintf(p, " %s", argv[i]);
		}
	}
#ifdef DEBUG
	fprintf(stderr, "cmd:%s\n", cmd);
#endif
	return system(cmd);
}

int
set_tunnel(in_addr_t src, in_addr_t dst, in_addr_t local, in_addr_t remote, in_addr_t netmask)
{
	//return gre_if_op(flag_changeroute ? FLAG_SET | FLAG_CROUTE : FLAG_SET, &mcb, extr_argc, extr_argv);

	/*
	 *  load needed module
	 *  On OSX, that is /Library/Extensions/GRE.kext, by SummerTown
	 *  On FreeBSD, that is if_gre.ko
	 *  On linux, it would be ip_gre.*
	 */
	if (load_gre_module() < 0)
		return -1;

	char ifname[IFNAMSIZ];
	if (gre_find_tunnel_with_addr(ifname, src, dst, local, remote) == 0) {
		fprintf(stderr, "tunnel already exists\n");
		return 0;
	}

	if (gre_find_unused_tunnel(ifname) < 0) {
		fprintf(stderr, "unable to find unused gre interface.\n");
		return -1;
	}

	if (gre_set_tunnel_addr(ifname, src, dst) < 0) {
		fprintf(stderr, "error set tunnel address of %s\n", ifname);
		return -1;
	}

	if (gre_set_if_addr(ifname, local, remote, netmask) < 0) {
		fprintf(stderr, "error set address of %s\n", ifname);
		return -1;
	}

	/*
	 * hack: if tunnel remote is the same as tunnel interface dst, as we have no 
	 * opportunity to access route directly(Apple has not addressed it to the developer)
	 * , we delete the loopback route. 
	 */
	if (remote == dst) {
		in_addr_t tmp_dst = remote;
		in_addr_t tmp_mask = 0xffffffff;
		if (route_get(&tmp_dst, &tmp_mask, NULL, NULL) == 0 && tmp_dst == remote && tmp_mask == 0xffffffff)
			route_delete(remote, 0xffffffff);
	}

	if (flag_changeroute) {

		route_change(0, 0, remote, ifname);
		/*
		   route_delete(0, 0);
		   route_add(0, 0, remote, ifname);
		   */
	}


}

int
remove_tunnel(in_addr_t src, in_addr_t dst, in_addr_t local, in_addr_t remote)
{
	//return gre_if_op(flag_changeroute ? FLAG_CROUTE : 0, &mcb, extr_argc, extr_argv);
	
	char ifname[IFNAMSIZ];
	if (gre_find_tunnel_with_addr(ifname, src, dst, local, remote) < 0) {
		fprintf(stderr, "find_if_with_addr(): unable to find gre interface.\n");
		return -1;
	}

	if (gre_delete_if_tunnel_addr(ifname) < 0) {
		fprintf(stderr, "delete_if_addr_tunnel(): unable to delete address of %s\n", ifname);
		return -1;
	}

	if (flag_changeroute) {
		/*
		if (gateway)
			route_add(0, 0, gateway, NULL);
		else {
			in_addr_t tmp_dst = dst;
			in_addr_t tmp_mask = 0xffffffff;
			in_addr_t tmp_gateway = 0;
			if (route_get(&tmp_dst, &tmp_mask, &tmp_gateway, ifp) == 0)
				route_add(0, 0, tmp_gateway, tmp_gateway ? NULL : ifp);
			else
				fprintf(stderr, "route_get: error get ori gateway\n");
		}
		*/
	}

	return 0;
}

int
quit_daemon(void)
{
	int fd = open(LOCKFILE, O_RDONLY);
	if (fd < 0) {
		log_perror("%s: open(%s)", __FUNCTION__, LOCKFILE);
		return -1;
	}
	/* A running daemon won't let us succeed in locking fd exclusively */
	if (flock(fd, LOCK_EX | LOCK_NB) == 0) {
		log_err("%s: No daemons found\n", __FUNCTION__);
		return 0;
	}
	char fbuff[32];
	read(fd, fbuff, sizeof(fbuff) - 1);
	close(fd);

	fbuff[sizeof(fbuff) - 1] = '\0';
	long pid;
	sscanf(fbuff, "%ld", &pid);

	if (kill(pid, SIGTERM) < 0) {
		log_perror("%s: kill(%ld)", __FUNCTION__, pid);
		return -1;
	}
	return 0;
}

int
open_pid_file(void)
{
	int fd = open(LOCKFILE, O_RDWR | O_CREAT, 0640);
	if (fd < 0) {
		log_perror("%s: open(%)s", __FUNCTION__, LOCKFILE);
		return -1;
	}
	if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
		log_perror("%s: flock(%s)", __FUNCTION__, LOCKFILE);
		return -1;
	}
	return fd;
}

int
write_pid(int fd)
{
	if (ftruncate(fd, 0) < 0) {
		log_perror("%s: unable to ftruncate(%s)", __FUNCTION__, LOCKFILE);
		return -1;
	}
	char fbuff[32];
	snprintf(fbuff, sizeof(fbuff), "%ld", (long)getpid());

	if (write(fd, fbuff, strlen(fbuff)) < 0) {
		log_perror("%s: write(%s)", __FUNCTION__, LOCKFILE);
		return -2;
	}
	return 0;
}

int
close_pid_file(int fd)
{
	if (flock(fd, LOCK_UN) < 0)
		log_perror("%s: flock()", __FUNCTION__);
	if (close(lockfd) < 0)
		log_perror("%s: close()", __FUNCTION__);
	return 0;
}
void
usage(int status)
{
	if (status != 0)
		fprintf(stderr, "Try `%s --help' for more information.\n", PACKAGE);
	else {
		fprintf(stderr, "Usage: %s [options]...\n", PACKAGE);
		fputs(\
"Operration modes:\n\
    -h, --help        display this help and exit\n\
    -v, --version     output version information and exit\n\
    -f FILE, --config=FILE\n\
                      choose a alternative config file\n\
                      the default is /etc/yixun.conf and \n\
                      ~/.yixun.conf\n\
    -u USERNAME, --username=USERNAME\n\
                      username to authorise\n\
    -p PASSWORD, --password=PASSWORD\n\
                      password to authorise\n\
    -s SERVERIP, --server-ip=SERVERIP\n\
                      Auth server IP\n\
    -c CLIENTIP, --client-ip=CLIENTIP\n\
                      Use CLIENTIP to authorise\n\
    -m MACADDR,  --mac-addr=MACADDR\n\
                      Use MACADDR to authorise\n\
    -D, --no-daemon   Does not become a daemon\n\
    -V, --verbose     Verbose mode. show extra infomation\n\
    -q, --quiet       Quiet mode. Nothing is sent to the system log.\n\
    -t, --test        Test mode. Only check the validity of the \n\
                      configuration file and sanity of the keys.\n\
    -T, --ex-test     Extended test mode. Check the validity of the \n\
                      configuration file, sanity of the keys. Then try \n\
                      to connect to auth-server, disconnect on success.\n\
                      This will not create any tunnels between host and\n\
					  server\n\
    -A                Send all traffic over tunnel.\n\
", stdout);
	}

	exit(status);

/*
	fputs("\t-u <username>\tUser name used to authorise\n", stderr);
	fputs("\t-p <password>\tPassword used to authorise\n", stderr);
	fputs("\t-s <Server IP>\tAuth server IP used to authorise\n", stderr);
	fputs("\t-i <Client IP>\tClient IP used to authorise\n", stderr);
	fputs("\t-m <MAC>\tMAC address used to authorise\n", stderr);
*/	/*
	 * fputs("\t-f <file>\tConfigure file used to authorise. \ If -f and
	 * -u or -p supplied at same time, \ use -u or -p instead of the
	 * parameters in config file\n", stderr);
	 */
/*	fputs("\t-A\t\tPass all traffic over gre interface\n", stderr);
	fputs("\t-D\t\tRun as daemon\n", stderr);
	fputs("\t-T\t\tTest mode, do NOT set gre tunnel and address\n", stderr);
	fputs("\t-v\t\tVerbose mode\n", stderr);
	fputs("\t-q\t\tQuit daemon\n", stderr);
*/
}

void
version(void)
{
	printf("%s\n", PACKAGE_STRING);
	fputs("Homepage: http://yixun.googlecode.com\n\n", stdout);
	fputs("Written by Summer Town.\n", stdout);
}

void
process_signals(int sig)
{
	switch (sig) {
		case SIGALRM:
			if (keep_alive(&mcb) < 0) {
				sleep(1);
				if (keep_alive(&mcb) < 0) {	/* unable to send keep
								 * alive to BRAS */
					log_warning("Failed sending keep-alive packets.");
					stop_listen();
					connected = false;
					exit(EXIT_SUCCESS);
				}
			}
			alarm(mcb.timeout);
			break;
		case SIGHUP:
		case SIGINT:
			log_notice("%s: user interupted\n", __FUNCTION__);
		case SIGQUIT:
		case SIGTERM:
			exit(EXIT_SUCCESS);
			break;
		default:
			log_warning("%s: Unkown signal %d", __FUNCTION__, sig);
			break;
	}
	signal(sig, process_signals);	/* let signal be caught again */
}

void
cleanup(void)
{
	if (flag_daemon)
		close_pid_file(lockfd);
	if (flag_gre_if_isset)
		remove_tunnel(mcb.gre_src, mcb.gre_dst, mcb.gre_local, mcb.gre_remote);
	if (connected)
		logout(&mcb);
	if (flag_daemon)
		log_notice("Daemon ended.");
	if (log_opened)
		closelog();
}
