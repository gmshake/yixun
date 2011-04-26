#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <fcntl.h>

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


