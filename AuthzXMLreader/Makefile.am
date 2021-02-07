#######################################################################
## Makefile.am for libAuthzXMLreader.la
##
##
## Version info: $Id: Makefile.am,v 1.5 2007/03/13 14:48:03 apeters Exp $
## Checked in by $Author: apeters $
#######################################################################

AM_CPPFLAGS = $(XML2_INCDIR) $(BASE_INCDIR)
lib_LTLIBRARIES = libAuthzXMLreader.la
noinst_LTLIBRARIES =libConvAuthzXMLreader.la

include_HEADERS = TAuthzXMLreader.h 

libAuthzXMLreader_la_SOURCES = TAuthzXMLreader.cxx TAuthzXMLreader.h
libAuthzXMLreader_la_LIBADD = $(XML2_LIBDIR) $(BASE_LIBDIR) -lxml2
libAuthzXMLreader_la_LDFLAGS = -version-info 1:0:0
libConvAuthzXMLreader_la_SOURCES = TAuthzXMLreader.cxx TAuthzXMLreader.h
libConvAuthzXMLreader_la_LIBADD = $(XML2_LIBDIR) $(BASE_LIBDIR) -lxml2

# this is not portable
rpm:
	rm -f ../$(distdir);
	ln -s ${PWD} ../$(distdir);
	echo "HOME       %{expand:%%(cd; pwd)}" > .rpmmacros 
	echo "%_topdir    %{HOME}/rpm" >> .rpmmacros
	cd ../; tar cvzf ${HOME}/rpm/SOURCES/$(distdir).tar.gz $(distdir)
	cp AuthzXMLreader.spec ${HOME}/rpm/SPECS/
	rpm -ba ${HOME}/rpm/SPECS/AuthzXMLreader.spec
