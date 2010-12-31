#
# mac-gre
# wrapper for ifconfig and route
# (c) 2010 SummerTown
#

# Base install derectory
BASE = /usr/local/bin

INC = -I/usr/include
LIBINC = -L/usr/lib
CC = gcc
CPP = g++
CFLAGS = -O2 -Wall
CCFLAGS = ${CFLAGS}
LIBS = 
CFLAGS += ${INC}
CCFLAGS += ${INC}

OBJS = ../route/route_op.o

PROGS = gre-config

.PHONY:all
	all: ${PROGS}

gre-config: ${OBJS} main.o
	${CC} ${CFLAGS} ${LIBINC} -o $@ main.o ${OBJS} ${LIBS}

install:
	test -d ${BASE} || mkdir -p ${BASE}
	install -m4755 ${PROGS} ${BASE}

uninstall:
	test -f ${BASE}/${PROGS} && rm -f ${BASE}/${PROGS}

clean:
	-rm -f ${PROGS} main.o ${OBJS}


