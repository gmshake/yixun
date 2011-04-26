
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdbool.h>

#include "radius.h"
#include "check_config.h"

extern bool flag_changeroute;
extern bool flag_daemon;
extern bool flag_test;
extern bool flag_etest;
extern bool flag_verbose;
extern bool flag_quiet;
extern bool flag_exit;

extern bool log_opened;
extern bool connected;
extern bool flag_gre_if_isset;

extern struct mcb mcb;

extern char *conf_file;

extern const char *progname;

extern void usage(int status);
extern void version(void);

const static struct option opts[] = {
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


void
parse_args(int argc, char *const argv[])
{
//	progname = argv[0];
	int ch;

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

/*	extr_argc = argc;
	extr_argv = argv;*/

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

