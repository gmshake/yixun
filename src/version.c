#include <config.h>
#include <stdio.h>

void
version(void)
{
	printf("%s\n", PACKAGE_STRING);
	printf("Homepage: http://yixun.googlecode.com\n\n");
	printf("Written by Summer Town.\n");
	printf("Build date: " __DATE__ " " __TIME__ "\n");
}


