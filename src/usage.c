#include <config.h>
#include <stdio.h>
#include <stdlib.h>

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
    -s SERVERIP, --server=SERVERIP\n\
                      Auth server IP\n\
    -i REGIP,    --reg-ip=REGIP\n\
                      Use REGIP to authorise\n\
    -m REGMAC,   --reg-mac=REGMAC\n\
                      Use REGMAC to authorise\n\
    -d DEVICE,   --device=DEVICE\n\
                      Setup DEVICE as tunnel(works only on linux. oops...)\n\
    -P PIDFILE,  --pidfile=PIDFILE\n\
                      Create pid file PIDFILE (default /var/run/yixun.pid)\n\
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
	fputs("\t-A\t\tPass all traffic over gre interface\n", stderr);
	fputs("\t-D\t\tRun as daemon\n", stderr);
	fputs("\t-T\t\tTest mode, do NOT set gre tunnel and address\n", stderr);
	fputs("\t-v\t\tVerbose mode\n", stderr);
	fputs("\t-q\t\tQuit daemon\n", stderr);
*/
}


