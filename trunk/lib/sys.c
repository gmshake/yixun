#include <config.h>
#include <sys/types.h>

#if ! HAVE_BZERO
#include <string.h>

inline void
bzero(void *s, size_t n)
{
	memset(s, 0, n);
}
#endif

#if ! HAVE_STRLCPY
/*
 * Copyright (c) 1998 Todd C. Miller <Todd.Miller@courtesan.com>
 * All rights reserved.
 */

/*
 * Copy src to string dst of size siz.  At most siz-1 characters
 * will be copied.  Always NUL terminates (unless siz == 0).
 * Returns strlen(src); if retval >= siz, truncation occurred.
 */
size_t
strlcpy(char *dst, const char *src, size_t siz)
{
	char *d = dst;
	const char *s = src;
	size_t n = siz;

	if (n != 0 && --n != 0) {
		do {
			if ((*d++ = *s++) == 0)
				break;
		} while (--n != 0);
	}

	if (n == 0) {
		if (siz != 0)
			*d = '\0';
		while (*s++)
			;
	}

	return s - src - 1;
}
#endif

#if ! HAVE_STPCPY
char *
stpcpy(char *to, const char *from)
{
	for (; (*to = *from); ++from, ++to);
	return to;
}
#endif

