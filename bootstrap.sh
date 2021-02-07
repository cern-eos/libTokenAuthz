# Build steps necessary for autotools
libtoolize --force
aclocal
automake --force-missing --add-missing
autoconf
