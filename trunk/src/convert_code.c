/*
 *  ConvertCode.c
 *  YiXun
 *
 *  Created by Summer Town on 9/15/10.
 *  Copyright 2010 __MyCompanyName__. All rights reserved.
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#if HAVE_ICONV && HAVE_ICONV_H
#include <strings.h>
#include <iconv.h>
#include "log_xxx.h"
#endif

#include <string.h>

int
convert_code(char *from_charset, char *to_charset, char *inbuf, size_t inlen, char *outbuf, size_t outlen)
{
#if HAVE_ICONV && HAVE_ICONV_H
	iconv_t cd;
	cd = iconv_open(to_charset, from_charset);
	if (cd == (iconv_t) (-1)) {
		log_perror("[%s] iconv_open(%s, %s)", __FUNCTION__, to_charset, from_charset);
		log_warning("[%s] pass through charset convert\n", __FUNCTION__);
		strncpy(outbuf, inbuf, inlen < outlen ? inlen : outlen);
		outbuf[outlen - 1] = '\0';
		return -1;
	}

	bzero(outbuf, outlen);
	if (iconv(cd, (char **)&inbuf, &inlen, &outbuf, &outlen) == (size_t) (-1)) {
		log_perror("Error iconv");
		iconv_close(cd);
		return -1;
	}
	iconv_close(cd);
#else
	strncpy(outbuf, inbuf, inlen < outlen ? inlen : outlen);
	outbuf[outlen - 1] = '\0';
#endif
	return 0;
}
