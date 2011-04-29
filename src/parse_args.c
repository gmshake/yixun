
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdbool.h>

#include "yixun_config.h"
#include "check_config.h"

extern bool flag_changeroute;
extern bool flag_daemon;
extern bool flag_test;
extern bool flag_etest;
extern bool flag_verbose;
extern bool flag_quiet;
extern bool flag_exit;

extern char *conf_file;

extern void usage(int status);
extern void version(void);

const char *arg_username;
const char *arg_password;
const char *arg_authserver;
const char *arg_regip;
const char *arg_hwaddr;

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
	int ch;
	while ((ch = getopt_long(argc, argv, "u:p:i:m:f:ADTVtvqxh", opts, NULL)) != -1) {
		switch (ch) {
			case 'u':
				arg_username = optarg;
				break;
			case 'p':
				arg_password = optarg;
				break;
			case 's':
				arg_authserver = optarg;
				break;
			case 'i':
				arg_regip = optarg;
				break;
			case 'm':
				arg_hwaddr = optarg;
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
				usage(EXIT_FAILURE);
		}
	}
	argc -= optind;
	argv += optind;

	if (argc > 0) {
		fprintf(stderr, "unrecognized operand: %s\n", argv[0]);
		usage(EXIT_FAILURE);
	}
}

