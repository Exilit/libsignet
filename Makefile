include Makefile.common

all:	libraries applications

applications:	libraries
	@echo Building applications...
	make -C app

libraries:
	@echo Building libraries...
	make -C lib

check: libraries
	make -C checks

clean:
	make -C checks clean
	make -C app clean
	make -C lib clean
