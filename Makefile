all:
	${MAKE} -C yixun
	${MAKE} -C gre-config

clean:
	${MAKE} clean -C yixun
	${MAKE} clean -C gre-config

install:
	${MAKE} install -C yixun
	${MAKE} install -C gre-config

uninstall:
	${MAKE} uninstall -C yixun
	${MAKE} uninstall -C gre-config

