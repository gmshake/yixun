#AM_CFLAGS = 

bin_PROGRAMS = yixun
yixun_SOURCES = main.c \
				check_config.c check_config.h \
				convert_code.c convert_code.h \
				encode_password.c encode_password.h \
				lock_file.c lock_file.h \
				parse_args.c parse_args.h \
				radius.c radius.h \
				server.c server.h \
				tunnel.c tunnel.h \
				yixun_config.c yixun_config.h \
				usage.c \
				version.c \
				rds_types.h

yixun_LDADD = $(top_srcdir)/lib/libyixun.a

INCLUDES = -I$(top_srcdir)/lib

