AM_CPPFLAGS = $(BASE_INCDIR) $(OPENSSL_INCDIR)

lib_LTLIBRARIES = libSealedEnvelope.la
noinst_LTLIBRARIES = libConvSealedEnvelope.la

include_HEADERS = TSealedEnvelope.h 

libSealedEnvelope_la_SOURCES = TSealedEnvelope.cxx TSealedEnvelope.h \
                               spc_b64.cxx spc_b64.h
libSealedEnvelope_la_LIBADD =  -lz $(OPENSSL_LIBDIR) $(OPENSSL_LIBS) \
                               $(LIBSOCKET) $(LIBNSL) $(LIBPTHREAD) -ldl
libSealedEnvelope_la_LDFLAGS = -version-info 1:0:0

libConvSealedEnvelope_la_SOURCES = TSealedEnvelope.cxx TSealedEnvelope.h \
                                   spc_b64.cxx spc_b64.h
libConvSealedEnvelope_la_LIBADD =  -lz $(OPENSSL_LIBDIR) $(OPENSSL_LIBS) \
                                   $(LIBSOCKET) $(LIBNSL) $(LIBPTHREAD) -ldl

bin_PROGRAMS = encode decode 
encode_SOURCES = encode.cxx
encode_LDADD = libSealedEnvelope.la

decode_SOURCES = decode.cxx
decode_LDADD = libSealedEnvelope.la

## NOTE
## all of the things below are not portable and follow Andreas' old build file.
## I just guarantee the complete rolling of the tarball
EXTRA_DIST = perl/Makefile.PL.in perl/SealedEnvelope.i authzwrite.pl xrdauthz.pl xrdauthz-read.pl xrdauthz-write.pl
##

# currently needed for the linking step of the swig produced library on macos
if APPLEHACK
export MACOSX_DEPLOYMENT_TARGET=10.3
endif

if ENABLE_PERLINT

all-local: perlmodule
install-exec-local: perlmodule-install

## that does not yet work. perl clean is broken
clean-local: perlmodule-clean

perlmodule-all:	perlmodule perlmodule-install

perlmodule:	
		cd perl; $(SWIG) -c++ -perl SealedEnvelope.i
		cd perl; ${PERL} Makefile.PL; make;

perlmodule-install:	
		cd perl; make install;

perlmodule-uninstall:
		cd perl; make uninstall;

perlmodule-clean:
		cd perl; make clean; rm -f SealedEnvelope_wrap.cxx SealedEnvelope.pm

endif


test:
	test -e sealtest || g++ -g -D__MAIN__ -DPACKAGE_VERSION=\"TEST\" -I $(prefix)/include -I/usr/kerberos/include -o sealtest  TSealedEnvelope.cxx -lssl spc_b64.o -lz
	(test -r key.pem && test -r pkey.pem && ./sealtest) || (\
	/usr/bin/openssl genrsa -rand 12938467 -out key.pem 1024 && \
	/usr/bin/openssl req -new -inform PEM -key key.pem -outform PEM -out certreq.pem && \
	/usr/bin/openssl x509 -days 3650 -signkey key.pem -in certreq.pem -req -out cert.pem &&\
	/usr/bin/openssl x509 -pubkey -in cert.pem > pkey.pem && \
	./sealtest; )


rpm:
	rm -f ../$(distdir);
	ln -s ${PWD} ../$(distdir);
	echo "HOME       %{expand:%%(cd; pwd)}" > .rpmmacros 
	echo "%_topdir    %{HOME}/rpm" >> .rpmmacros
	cd ../; tar cvzf ${HOME}/rpm/SOURCES/$(distdir).tar.gz $(distdir)
	cp SealedEnvelope.spec ${HOME}/rpm/SPECS/
	rpm -ba ${HOME}/rpm/SPECS/SealedEnvelope.spec

##install-exec-local: $(PERLMODULEMAKE) 

