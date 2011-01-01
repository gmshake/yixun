#
# yixun for MacOSX
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
LIBS = -liconv -lpthread
CFLAGS += ${INC}
CCFLAGS += ${INC}

OBJS = common_logs.o radius.o convert_code.o encode_password.o get_ip_mac.o login_state.o print_hex.o ../route/route_op.o

PROGS = yixun

.PHONY:all install uninstall libclean clean
all: ${PROGS}

yixun: ${OBJS} main.o
	${CC} ${CFLAGS} ${LIBINC} -o $@ main.o ${OBJS} ${LIBS}
	
install:
	test -d ${BASE} || mkdir -p ${BASE}
	install ${PROGS} ${BASE}

uninstall:
	test -f ${BASE}/${PROGS} && rm -f ${BASE}/${PROGS}

libclean:
	-rm -f main.o ${OBJS}

clean:
	-rm -f ${PROGS} main.o ${OBJS}
