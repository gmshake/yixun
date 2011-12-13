/*
 * Copyright (c) 2010, 2011 SummerTown
 *
 * @yixun main() routine
 *
 */

#include <config.h>

#include <unistd.h>		/* sleep(), */
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>	/* bool */
#include <string.h>
#include <errno.h>
#include <syslog.h>		/* openlog() */

#include <fcntl.h>		/* open() */
#include <sys/file.h>	/* flock() */

#include <signal.h>

#include "sys.h"
#include "parse_args.h"
#include "lock_file.h"
#include "tunnel.h"
#include "radius.h"
#include "server.h"
#include "log_xxx.h"
#include "check_config.h"
#include "common_macro.h"
#include "yixun_config.h"

#define LOCKFILE "/var/run/yixun.pid"

const char *pidfile = LOCKFILE;
bool flag_changeroute = false;
bool flag_daemon = true;
bool flag_test = false;
bool flag_etest = false;
bool flag_verbose = false;
bool flag_quiet = false;
bool flag_exit = false;

static int lockfd;		/* lockfile file description */
static bool log_opened = false;
static bool connected = false;

static in_addr_t default_route = 0;

static int start_login(void);
static void handle_signals(int sig);
static int quit_daemon(void);
static void cleanup(void);

int
main(int argc, char *const argv[])
{
	parse_args(argc, argv);	/* process args */

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

	signal(SIGHUP, SIG_IGN);
	if (load_config() != 0)
		return EXIT_FAILURE;

	if (flag_verbose)
		print_config();

	/* sanity check done */
	if (flag_test) {
		printf("Syntax OK\n");
		return EXIT_SUCCESS;
	}

	/* try to lock */
	if (flag_daemon && (lockfd = open_lock_file(pidfile)) < 0)
		return EXIT_FAILURE;

	if (atexit(cleanup) < 0) {
		log_perror("atexit()");
		return EXIT_FAILURE;
	}

	if (start_login() < 0)
		return EXIT_FAILURE;

	if (flag_daemon) {
		if (daemon(0, 0) < 0) {
			log_perror("daemon");
			return EXIT_FAILURE;
		}
		set_log_type(LDAEMON);

		if (write_pid(lockfd) < 0)
			return EXIT_FAILURE;
	}

	/* Extended test done */
	if (flag_etest) {
		printf("Syntax OK\n");
		return EXIT_SUCCESS;
	}

	if (set_tunnel() < 0) {
		log_perror("Can not set gre interface");
		return EXIT_FAILURE;
	}

	signal(SIGHUP, handle_signals);
	signal(SIGINT, handle_signals);
	signal(SIGQUIT, handle_signals);
	signal(SIGALRM, handle_signals);
	signal(SIGTERM, handle_signals);

	alarm(gre_timeout);

	/* if not extended test, loop forever */
	while(1) {
		wait_msg();
	}

	return EXIT_SUCCESS;
}

static int
start_login(void)
{
	int trys = 3;
	do {
		int rval = login();
		if (rval == 0)
			break;
		else if (rval > 0)
			/* 
			 * Username, password, mac bind or ip addr bind error
			 * do not retry
			 */
			return -1;
		sleep(1);
	} while (--trys > 0);

	if (trys <= 0) {
		log_err("Can not log in\n");
		return -1;
	}

	connected = true;
	return 0;
}

int
quit_daemon(void)
{
	int fd = open(pidfile, O_RDONLY);
	if (fd < 0) {
		log_perror("%s: open(%s)", __FUNCTION__, pidfile);
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

void
handle_signals(int sig)
{
	switch (sig) {
		case SIGHUP:
			log_notice("reload config...\n");

			remove_tunnel();
			stop_listen();

			if (connected) {
				logout();
				connected = false;
			}

			if (load_config() < 0)
				exit(EXIT_FAILURE);

			log_notice("reload done\n");

			if (start_login() < 0)
				exit(EXIT_FAILURE);

			if (set_tunnel() < 0) {
				log_perror("Can not set gre interface");
				exit(EXIT_FAILURE);
			}

			break;
		case SIGINT:
			log_notice("user interupted\n");
		case SIGQUIT:
			exit(EXIT_SUCCESS);
			break;
		case SIGALRM:
			if (keep_alive() < 0) {
				remove_tunnel();
				connected = false;
				/* unable to send keep alive to BRAS */
				log_warning("Failed sending keep-alive packets.");
				while (retry_count != 0) {
					if (start_login() == 0)
						break;
					if (retry_count > 0)
						--retry_count;
				}
				if (retry_count == 0) {
					stop_listen();
					exit(EXIT_SUCCESS);
				}

				if (set_tunnel() < 0) {
					log_perror("Can not set gre interface");
					exit(EXIT_FAILURE);
				}
			}
			alarm(gre_timeout);
			break;
		case SIGTERM:
			exit(EXIT_SUCCESS);
			break;
		default:
			log_warning("%s: Unkown signal %d", __FUNCTION__, sig);
			return;
	}
#if ! (defined(__FreeBSD__) || defined(__apple__))
	signal(sig, handle_signals);	/* let signal be caught again */
#endif
}

void
cleanup(void)
{
	remove_tunnel();
	if (connected)
		logout();
	if (flag_daemon)
		close_lock_file(lockfd);
	if (flag_daemon)
		log_notice("Daemon ended.");
	if (log_opened)
		closelog();
}

