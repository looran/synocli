PREFIX=/usr/local
BINDIR=$(PREFIX)/bin

all:
	@echo "Use \"sudo make install\" to install"

install:
	install -m 0755 synocli.py $(BINDIR)/synocli
