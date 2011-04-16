#AM_CFLAGS = 

bin_PROGRAMS = yixun
yixun_SOURCES = main.c convert_code.c covert_code.h \
				encode_password.c encode_password.h \
				radius.c radius.h \
				rds_types.h yixun_config.h

INCLUDES = -I$(top_srcdir)/lib
yixun_LDADD = $(top_srcdir)/lib/libyixun.a

#yixun_LDADD = $(INTLLIBS)

#$(PROGRAMS): ../lib/libroute.a ../lib/libtunnel.a ../lib/liblogs.a ../lib/libdumphex.a ../lib/libipmac.a

