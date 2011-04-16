#AM_CFLAGS = 

bin_PROGRAMS = yixun
yixun_SOURCES = main.c convert_code.c convert_code.h \
				encode_password.c encode_password.h \
				radius.c radius.h \
				rds_types.h yixun_config.h

yixun_LDADD = $(top_srcdir)/lib/libyixun.a

INCLUDES = -I$(top_srcdir)/lib

