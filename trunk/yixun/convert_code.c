/*
 *  ConvertCode.c
 *  YiXun
 *
 *  Created by Summer Town on 9/15/10.
 *  Copyright 2010 __MyCompanyName__. All rights reserved.
 *
 */
#include <string.h>
#include <iconv.h>

#ifdef DEBUG
#include <stdio.h>
#endif

#include "common_logs.h"

int convert_code(char *from_charset, char *to_charset,
				 char *inbuf, size_t inlen, char *outbuf, size_t outlen)
{
    iconv_t cd;
    cd = iconv_open(to_charset,from_charset);
    if (cd==0)
    {
        log_perror("Error iconv_open");
        return -1;
    }
    memset(outbuf,0,outlen);
    if (iconv (cd, &inbuf, &inlen, &outbuf, &outlen) == (size_t)-1)
	{
        log_perror("Error iconv");
		iconv_close(cd);
		return -1;
	}
    iconv_close(cd);
    return 0;
}