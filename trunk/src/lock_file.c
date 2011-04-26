#include <unistd.h>		/* ftruncate(), write(), close(), getpid() */
#include <fcntl.h>		/* open() */
#include <stdio.h>		/* snprintf() */
#include <string.h>		/* strlen() */
#include <sys/file.h>	/* flock() */

#include "log_xxx.h"

int
open_lock_file(const char *file)
{
	int fd = open(file, O_RDWR | O_CREAT, 0640);
	if (fd < 0) {
		log_perror("%s: open(%)s", __FUNCTION__, file);
		return -1;
	}
	if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
		log_perror("%s: flock(%s)", __FUNCTION__, file);
		return -1;
	}
	return fd;
}

int
write_pid(int fd)
{
	if (ftruncate(fd, 0) < 0) {
		log_perror("%s: unable to ftruncate()", __FUNCTION__);
		return -1;
	}
	char buff[32];
	snprintf(buff, sizeof(buff), "%ld", (long)getpid());

	if (write(fd, buff, strlen(buff)) < 0) {
		log_perror("%s: write()", __FUNCTION__);
		return -2;
	}
	return 0;
}

int
close_lock_file(int fd)
{
	if (flock(fd, LOCK_UN) < 0)
		log_perror("%s: flock()", __FUNCTION__);
	if (close(fd) < 0)
		log_perror("%s: close()", __FUNCTION__);
	return 0;
}


