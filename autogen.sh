#!/bin/sh

echo
echo "Suggested version:"
echo
echo "     autoconf 2.57"
echo "     automake 1.7.x"
echo "     libtool  1.4.x"
echo

echo "cleaning up config files"
rm -f configure
rm -f aclocal.m4
find . -name 'Makefile' -exec rm -f {} \;
find . -name 'Makefile.in' -exec rm -f {} \;

echo "running `aclocal --version | head -n 1`"
aclocal
echo "running `autoheader --version | head -n 1`"
autoheader
echo "running `autoconf --version | head -n 1`"
autoconf
echo "running `automake --version | head -n 1`"
automake

