###########################################################################
##
## File:        ./Makefile.am
## Versions:    $Id: Makefile.am,v 1.16 2010/06/14 12:50:57 j-nijhof Exp $
## Created:     2002/06/14
##
###########################################################################
##
## run  automake to generate a Makefile.in
##      Makefile.am \
##      configure.ac >  Makefile.in
##      aclocal.m4  /
##

ACLOCAL_AMFLAGS= -I config

bin_PROGRAMS = nfqueue-test

nfqueue_test_SOURCES = nfqueue-test.c

install-data-hook:
#	@echo === install-data-hook ===
	-rm $(DESTDIR)/$(libdir)/$(module_LTLIBRARIES)

help:
	@echo ""
	@echo "make		- compile sources to a shared library module"
	@echo "make all		- same as above"
	@echo "make install	- copy module and docs to destination"
	@echo "make clean	- cleans out most useless files"
	@echo "make disthelp	- extra help for developers"
	@echo ""

disthelp:
	@echo ""
	@echo "make dist	- creates distribution tarballs"
	@echo "make distclean	- cleans & removes most made files"
	@echo "make maintainer-clean	- cleans even more"
	@echo ""
