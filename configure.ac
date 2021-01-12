AC_PREREQ(2.57)
AC_INIT([tokenAuthz],[1.2.5],[andreas.joachim.peters@cern.ch,derek.feichtinger@cern.ch])
AC_CONFIG_SRCDIR([TTokenAuthz.cxx])
AC_CONFIG_MACRO_DIR([m4])

# detect system type and define some specific settings
AC_CANONICAL_TARGET

SHRLIB_EXT=".so"
case "$target_os" in
    linux*)
    if test -d /usr/kerberos/include ; then
       AC_MSG_NOTICE([found kerberos installation in /usr/kerberos. Adding flags for openssl])
       extra_inc_path="$extra_inc_path /usr/kerberos/include"
       extra_lib_path="$extra_lib_path /usr/kerberos/lib"
    fi
    ;;
    darwin*)
    SHRLIB_EXT=".dylib"
    need_applehack=yes
    ;;
esac
AM_INIT_AUTOMAKE(1.6 foreign subdir-objects)

# It is very ugly that we need to define the shared library extension manually, but there is
# currently no good way for obtaining the information from libtool. We only need it, because
# we depart from the pure autotools build for the SealedEnvelope/perl/Makefile.PL
# This only matters for mac/darwin 
AC_SUBST(SHRLIB_EXT)
# Even uglier, macos currently needs setting a special environment variable set for the
# linking of the swig produced library. APPLEHACK is used in SealedEnvelope/Makefile.am
AM_CONDITIONAL(APPLEHACK, test x"$need_applehack" = xyes)

######################################################################
# OPTIONS PARSING
ACX_WITH_BASEDIR
extra_inc_path="$acx_base_incdir $extra_inc_path"
extra_lib_path="$acx_base_libdir $extra_lib_path"
if test x"$acx_base_bindir" != x ; then
   PATH="$acx_base_bindir":$PATH
fi



# for some tests we need the standard include path (finding and extracting stuff
# from header files):
# We need to add any settings the user may have set via CPPFLAGS
for opt in $CPPFLAGS ; do
   case $opt in
      -I*)
         dir=`expr x"$opt" : 'x-I\(.*\)'`
         std_inc_path="$std_inc_path $dir"
         ;;
      *)
        ;;
   esac
done
std_inc_path="$std_inc_path $extra_inc_path /usr/include"


###################################################################
# LIBXML2 OPTIONS
AC_ARG_WITH([xml2_incdir],
            [  --with-xml2-incdir   directory with libxml/xmlreader.h],
            [searchpath="$withval"],
            [searchpath="$std_inc_path /usr/include/libxml2"]
	    )
AC_SUBST(XML2_INCDIR)

ACX_LOCATEFILE([libxml/xmlreader.h],[$searchpath],
               [XML2_INCDIR="-I$acx_founddir"],
               [AC_MSG_ERROR([could not locate libxml/xmlreader.h in $searchpath])]
              )
AC_MSG_NOTICE([Location of libxml/xmlreader.h: $XML2_INCDIR])

AC_ARG_WITH([xml2_libdir],
            [  --with-xml2-libdir   directory with libxml],
            [XML2_LIBDIR="-L$withval"]
	    )
AC_SUBST(XML2_LIBDIR)
###################################################################




# we need to add the additional path elements to CPPFLAGS and
# LDFLAGS, so that they are used by the tests and in the compilation

# add extra include path elements to CPPFLAGS
for dir in $extra_inc_path ; do
   if test x"$dir" != x ; then
      CPPFLAGS="$CPPFLAGS -I$dir"
   fi
done


# add extra library path elements to LDFLAGS
for dir in $extra_lib_path ; do
   if test x"$dir" != x ; then
      LDFLAGS="$LDFLAGS -L$dir"
   fi
done

AC_MSG_NOTICE([my CPPFLAGS: $CPPFLAGS])
AC_MSG_NOTICE([my LDFLAGS: $LDFLAGS])

# backup these values because we will modify the flags for some of the
# tests
CPPFLAGS_BUP="$CPPFLAGS"
LDFLAGS_BUP="$LDFLAGS"



enable_threads=yes
AC_ARG_ENABLE(threads,
              [  --enable-threads      use threads [[default=yes]] ],
              [],
              [enable_threads=no]
             )
if test x"$enable_threads" = xyes; then
   AC_MSG_NOTICE([Threads are enabled])
   AC_DEFINE(WITHTHREADS)
fi

#########################################################
# Perl interface options
AC_ARG_ENABLE(perlint,
              [  --enable-perlint      build perl interface [[default=no]] ],
              [],[enable_perlint=no]
             )
AM_CONDITIONAL(ENABLE_PERLINT, test x"$enable_perlint" = xyes)

if test x"$enable_perlint" = xyes ; then
  AC_ARG_WITH(perl,
            [  --with-perl=PATH        path to perl executable],
            PERL=$withval,
            PERL=perl)
  AC_SUBST(PERL)
  # get the correct library options and link flags for perl
  AC_MSG_CHECKING([perl libraries and link options])
  perlbuf=`${PERL} -MExtUtils::Embed -e ldopts`
  if test x"$perlbuf" = x
  then
    AC_MSG_ERROR([no result from ${PERL} -MExtUtils::Embed -e ldopts])
  fi
  AC_MSG_RESULT($perlbuf)
  for name in $perlbuf
  do
    case $name in
      -L*)
        PERL_LIBS="${PERL_LIBS} $name"
        ;;
      -l*)
        PERL_LIBS="${PERL_LIBS} $name"
        ;;
       *.a)
        PERL_LIBS="${PERL_LIBS} $name"
        ;;
      *)
        PERL_LDOPTS="${PERL_LDOPTS} $name"
        ;;
    esac
  done
  AC_MSG_NOTICE([perlembed libraries to link: $PERL_LIBS])
  AC_MSG_NOTICE([perlembed link flags: $PERL_LDOPTS])
  PERL_CCOPTS=`${PERL} -MExtUtils::Embed -e ccopts`
  AC_MSG_NOTICE([perlembed cc options: $PERL_CCOPTS])
  AC_SUBST(PERL_LIBS)
  AC_SUBST(PERL_LDOPTS)
  AC_SUBST(PERL_CCOPTS)

fi

AC_ARG_WITH([swig],
           [  --with-swig=PATH  directory containing swig executable],
           [swigtestpath=$withval],
           [swigtestpath="$PATH"]
           )


#############################
# Note: libcrypto on i86 solaris requires linking against libdl, libsocket, libnsl
# we test for the presence of some of this here, before the OpenSSL tests
AC_CHECK_LIB([socket],[connect],
             [
                 AC_SUBST(LIBSOCKET,[-lsocket])
             ])
# this test taken from xrootd configure.ac
AC_CHECK_LIB([nsl],[gethostbyname],
             [AC_SUBST(LIBNSL,[-lnsl])]
            )


#############################
# OpenSSL options

AC_ARG_WITH(openssl-incdir,
            [  --with-openssl-incdir=PATH   dir containing openssl/ header directory],
            [searchpath="$withval"],
            [searchpath="$std_inc_path"]
           )

AC_ARG_WITH(openssl-libdir,
            [  --with-openssl-libdir=PATH    dir containing openssl library (libssl.*)],
            [
              OPENSSL_LIBDIR="-L$withval";
              AC_MSG_NOTICE([openssl library dir set to: ${OPENSSL_LIBDIR}])
            ]
           )
AC_SUBST(OPENSSL_LIBDIR)

OPENSSL_LIBS="-lssl -lcrypto"
AC_ARG_WITH(openssl-libs,
            [  --with-openssl-libs=[-lssl -lcrypto] names of ssl libraries to link (ssl or ssl_gcc32 f.e.)],
            [
              OPENSSL_LIBS="$withval";
              AC_MSG_NOTICE([ssl libraries set to: ${SSL_LIBS}])
            ]
)
AC_SUBST(OPENSSL_LIBS)

ACX_LOCATEFILE([openssl/opensslv.h],[$searchpath],
               [OPENSSL_INCDIR="-I$acx_founddir"
                 OPENSSL_VERSION_TEXT=`grep OPENSSL_VERSION_TEXT "$dir"/openssl/opensslv.h | grep OpenSSL`
                 AC_MSG_NOTICE([openssl header dir set to: $dir ]) ],
                [AC_MSG_ERROR([Could not locate openssl/opensslv.h in $searchpath])]
               )

AC_SUBST(OPENSSL_INCDIR)

# test openssl version
verstr=`expr  x"$OPENSSL_VERSION_TEXT" : '.*\([[0-9]][[0-9]]*\.[[0-9]][[0-9]]*\.[[0-9]][[0-9]]*[[a-z]]*\)'`
AC_MSG_NOTICE([OpenSSL version : $verstr])

vermajor=`expr x"$verstr" : '.*\([[0-9]][[0-9]]*\).[[0-9]][[0-9]]*.[[0-9]][[0-9]]*'`
verminor=`expr x"$verstr" : '.*[[0-9]][[0-9]]*\.\([[0-9]][[0-9]]*\)\.[[0-9]][[0-9]]*'`
verrelease=`expr x"$verstr" : '.*[[0-9]][[0-9]]*\.[[0-9]][[0-9]]*\.\([[0-9]][[0-9]]*\)'`
vernum=`expr 10000 \* 0"$vermajor" + 100 \* 0"$verminor" + 0"$verrelease"`
if test 0"$vernum" -lt 906 ; then
  AC_MSG_ERROR([OpenSSL >= 0.9.6 required (found: $OPENSSL_VERSION_TEXT)])
fi
#AC_MSG_NOTICE([Openssl version: $vermajor  $verminor  $verrelease == $vernum])

# note: -DPERL5 is needed for resolving a clash between unistd.h and
# openssl/des.h regarding the crypt function on some older systems (e.g. RH7.3)
if test 0"$vernum" -lt 907 ; then
  AC_DEFINE(R__SSL_096)
  AC_SUBST(SSLCXXFLAGS,[-DPERL5])
fi

# note: -DR__SSL_GE_098 allows to deal with some differences in ANS1 macros
# introduced in version 0.9.8
#if test 0"$vernum" -ge 908 ; then
#  AC_DEFINE(R__SSL_GE_098)
#fi

# note: openssl may require kerberos5 include files
AC_CHECK_HEADER([openssl/ssl.h])


LDFLAGS="$OPENSSL_LIBDIR $LDFLAGS"
AC_CHECK_LIB([ssl],[SSL_library_init],
             [:],
             [AC_MSG_ERROR([failed to link with libssl])],
             [-lcrypto $LIBSOCKET $LIBNSL -ldl]
            )
 
CPPFLAGS="$CPPFLAGS_BUP"
LDFLAGS=$LDFLAGS_BUP


##############################################################################
# Checks for libraries.

LDFLAGS="$XML2_LIBDIR $BASE_LIBDIR $LDFLAGS"
AC_CHECK_LIB([xml2], [xmlReaderForMemory],
             [:],[ACX_MSG_ERROR([Failed compilation test for libxml2. You need at least version 2.6])])
LDFLAGS="$LDFLAGS_BUP"

# Check for libcurl
AC_CHECK_LIB([curl], [curl_easy_init],
             [
	        AC_SUBST(LIBCURL,[-lcurl])
             ],
             [AC_MSG_ERROR(libcurl not found)])

# pthreads differ on various platforms
AC_CHECK_LIB([pthread],[pthread_join],
             [LIBPTHREAD="-lpthread"])
AC_CHECK_LIB([pthreads],[pthread_join],
             [
             if test x"$LIBPTHREAD" != x; then
               AC_MSG_WARN([found both libpthread and libpthreads. Using -lpthread])
             else
               LIBPTHREAD="-lpthreads"
             fi
             ])
AC_SUBST(LIBPTHREAD)

###############################################################################
# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_LIBTOOL

AC_PATH_PROG([SWIG],[swig],[not_found],[$swigtestpath])
if test x"$enable_perlint" = xyes ; then
   if test x"$SWIG" = xnot_found ; then
      AC_MSG_ERROR([Could not locate swig executable in $swigtestpath])
   fi
fi

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([fcntl.h netinet/in.h stdlib.h string.h strings.h unistd.h])

CPPFLAGS="$XML2_INCDIR $CPPFLAGS"
AC_CHECK_HEADER([libxml/xmlreader.h],
                [],[ACX_MSG_ERROR([Failed include test for libxml/xmlreader.h])])
CPPFLAGS="$CPPFLAGS_BUP"


# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_CONST
AC_TYPE_SIZE_T
AC_HEADER_TIME

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([gettimeofday])

AC_CONFIG_FILES([Makefile
                 AuthzXMLreader/Makefile
                 SealedEnvelope/Makefile
                 SealedEnvelope/perl/Makefile.PL])
AC_OUTPUT
