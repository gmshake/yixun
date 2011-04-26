#include <config.h>
#include <string.h>

#if ! HAVE_BZERO
inline void
bzero(void *s, size_t n)
{
	memset(s, 0, n);
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

