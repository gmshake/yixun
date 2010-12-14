#
# tun-gre wrapper for MacOSX
#
# Makefile
#
# (c) 2010 SummerTown
#

# Base install directory
BASE = /usr/local/bin

INC = -I/usr/include -I/usr/local/include
LIBINC = -L/usr/lib -L/usr/local/lib
CC = gcc
CPP = g++
CFLAGS = -O2 -Wall
CCFLAGS = ${CFLAGS}
LIBS = -lpthread
CFLAGS += ${INC}
CCFLAGS += ${INC}

OBJS = main.o change_routes.o common_logs.o print_hex.o process_packet.o tun-dev.o

PROGS = tun-gre

.PHONY:all
all: ${PROGS}

tun-gre: ${OBJS}
	${CC} ${CFLAGS} ${LIBINC} -o $@ ${OBJS} ${LIBS}

install:
	test -d ${BASE} || mkdir -p ${BASE}
	install -m4755 ${PROGS} ${BASE}
uninstall:
	test -f ${BASE}/${PROGS} && rm -f ${BASE}/${PROGS}

libclean:
	-rm -f ${OBJS}
clean:
	-rm -f ${PROGS} ${OBJS}
