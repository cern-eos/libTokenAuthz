# Build steps necessary for autotools
/usr/bin/libtoolize --force 
/usr/bin/aclocal
/usr/bin/automake --force-missing --add-missing
/usr/bin/autoconf
./configure 
