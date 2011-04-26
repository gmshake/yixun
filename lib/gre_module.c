
#include <unistd.h>
#include <stdio.h>

#if defined(__FreeBSD__)
#include <sys/param.h>
#include <sys/linker.h>		//kldload()
#include <sys/module.h>		//modfind()
#endif

#if defined(__APPLE__) || defined(__linux__)
#include <sys/wait.h>
#endif

#if defined(__linux__)
#include <string.h>		/* strstr() */
#include <stdlib.h>			//exit()
#include <fcntl.h>			//open()...
#include <netinet/ip.h>		/* struct iphdr */
#include <linux/if.h>			/* IFNAMSIZ */
#include <linux/if_tunnel.h>	//SIOCADDTUNNEL...
#endif

#include <errno.h>

#if defined(__linux__)
#define GRENAME "greyixun"
#endif


int
load_gre_module(void)
{
#if defined(__APPLE__)
	fprintf(stderr, "OSX, kextload GRE.kext\n");
	int pid;
	if ((pid = fork()) < 0)
		return -1;

	if (pid == 0) {
		execle("/sbin/kextload", "kextload", "/Library/Extensions/GRE.kext", NULL, NULL);
		exit(1);
	}

	while (waitpid(pid, 0, 0) < 0) {
		if (errno == EINTR)
			continue;
		return -1;
	}
	return 0;
#else
#if defined(__FreeBSD__)
	if (modfind("if_gre") < 0) {
#ifdef DEBUG
		fprintf(stderr, "FreeBSD, kldload if_gre\n");
#endif
		if (kldload("if_gre") < 0) {
			perror("can't load if_gre");
			return -1;
		}
	}
	return 0;
#else
#if defined(__linux__)
	fprintf(stderr, "Linux, insmod ip_gre\n");
	int fd;
	if ((fd = open("/proc/modules", O_RDONLY)) < 0) {
		perror("open(\"proc/modules\")");
		return -1;
	}
	
	int i;
	char buff[128];
	bzero(buff, sizeof(buff));
	while ((i = read(fd, buff, sizeof(buff) - 1)) > 0) {
		if (strstr(buff, "ip_gre")) {
			close(fd);
			return 0;
		}
		bzero(buff, sizeof(buff));
	}
	close(fd);
	/* module ip_gre not found, try to load ip_gre */
	fprintf(stderr, "load ip_gre...\n");
	int pid;
	if ((pid = fork()) < 0)
		return -1;

	if (pid == 0) {
		execle("/sbin/modprobe", "modprobe", "ip_gre", NULL, NULL);
		execle("/sbin/insmod", "insmod", "ip_gre", NULL, NULL);
		exit(1);
	}

	while (waitpid(pid, 0, 0) < 0) {
		if (errno == EINTR)
			continue;
		return -1;
	}
	return 0;
#else
	fprintf(stderr, "%s: Your OS is not supported yet\n", __FUNCTION__);
	return -1;
#endif
#endif
#endif
}

