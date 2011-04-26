#include <config.h>
#include <stdio.h>

void
version(void)
{
	printf("%s\n", PACKAGE_STRING);
	fputs("Homepage: http://yixun.googlecode.com\n\n", stdout);
	fputs("Written by Summer Town.\n", stdout);
}


