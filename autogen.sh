#!/bin/sh

echo
echo "Suggested version:"
echo
echo "     autoconf 2.57"
echo "     automake 1.7.x"
echo "     libtool  1.4.x"
echo
echo "Actual version:"
echo
echo "     `autoconf --version | head -n 1`"
echo "     `automake --version | head -n 1`"
echo "     `libtool --version | head -n 1`"
echo

echo "cleaning up config files..."
echo 
rm -f configure
rm -f aclocal.m4
rm -f ltmain.sh
find . -name 'Makefile' -exec rm -f {} \;
find . -name 'Makefile.in' -exec rm -f {} \;

echo "running aclocal"
aclocal
echo "running libtoolize"
libtoolize --force --copy 
echo "running aclocal"
aclocal
echo "running autoheader"
autoheader
echo "running autoconf"
autoconf
echo "running automake"
automake --add-missing --copy

