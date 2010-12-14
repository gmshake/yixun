all:
	cd tun-gre && make
	cd yixun && make

clean:
	cd tun-gre && make clean
	cd yixun && make clean

install:
	cd tun-gre && make install
	cd yixun && make install

uninstall:
	cd tun-gre && make uninstall
	cd yixun && make uninstall

