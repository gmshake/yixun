all:
	cd mac-gre && make
	cd yixun && make

clean:
	cd mac-gre && make clean
	cd yixun && make clean

install:
	cd mac-gre && make install
	cd yixun && make install

uninstall:
	cd mac-gre && make uninstall
	cd yixun && make uninstall

