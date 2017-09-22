#######################################################################
## Makefile.am for libTokenAuthz
##
##
## Version info: $Id: Makefile.am,v 1.9 2006/11/10 13:21:46 apeters Exp $
## Checked in by $Author: apeters $
#######################################################################

SUBDIRS = AuthzXMLreader SealedEnvelope .

CPPFLAGS = -I /usr/kerberos/include -I$(top_srcdir)/SealedEnvelope  -I$(top_srcdir)/AuthzXMLreader \
           $(BASE_INCDIR) $(OPENSSL_INCDIR)

lib_LTLIBRARIES = libTokenAuthz.la
include_HEADERS = TTokenAuthz.h 

libTokenAuthz_la_SOURCES = TTokenAuthz.cxx TTokenAuthz.h


libTokenAuthz_la_LIBADD =  SealedEnvelope/libConvSealedEnvelope.la \
                           AuthzXMLreader/libConvAuthzXMLreader.la \
                           $(LIBPTHREAD)
libTokenAuthz_la_LDFLAGS = -version-info 1:1:0

bin_PROGRAMS = tokenauthztest
tokenauthztest_SOURCES = tokenauthztest.cxx
tokenauthztest_LDADD = -lcrypto -lpthread libTokenAuthz.la


EXTRA_DIST = configure.ac configure bootstrap.sh conf/TkAuthz.Authorization.allow-all \
conf/TkAuthz.Authorization.example \
conf/TkAuthz.Authorization.test \
tokenauthz.spec

rpm:	dist
	mkdir -p ~/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
	cp $(DIST_ARCHIVES) ~/rpmbuild/SOURCES/
	rpmbuild -bb --define "debug_package %{nil}" --define "_rpmdir ./RPMS/" --define "_build_name_fmt %%{NAME}-%%{VERSION}-%%{RELEASE}.%%{ARCH}.rpm" tokenauthz.spec
