/*
 * sys.h
 * implement functions such as bzero, stpcpy
 * By Summer Town
 * 2011.04.22
 */

#ifndef SYS_H
#define SYS_H

#include <config.h>
#if ! HAVE_BZERO
extern void bzero(void *s, size_t n);
#endif

#if ! HAVE_STRLCPY
extern size_t strlcpy(char *dst, const char *src, size_t size);
#endif

#if ! HAVE_STPCPY
extern char * stpcpy(char *to, const char *from);
#endif

#endif	/* SYS_H */

