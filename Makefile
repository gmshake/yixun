all:
	cd gre-config && make
	cd yixun && make

clean:
	cd gre-config && make clean
	cd yixun && make clean

install:
	cd gre-config && make install
	cd yixun && make install

uninstall:
	cd gre-config && make uninstall
	cd yixun && make uninstall

