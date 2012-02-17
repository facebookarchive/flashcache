#!/usr/bin/make -f
# -*- makefile -*-

PREFIX ?= /usr
MANPAGES := $(patsubst %.mdwn, %.8, $(wildcard *.mdwn))

all: $(MANPAGES)

clean:
	$(RM) $(MANPAGES)

$(MANPAGES):
	pandoc --standalone --to=man --output=$@ $(@:.8=.mdwn)

install: $(MANPAGES)
	install -m0644 $(MANPAGES) $(DESTDIR)${PREFIX}/share/man/man8

