#!/bin/sh

echo "cleaning up config files"
rm -f configure
rm -f aclocal.m4
find . -name 'Makefile' -exec rm -f {} \;
find . -name 'Makefile.in' -exec rm -f {} \;

echo "running aclocal..."
aclocal
echo "running autoheader..."
autoheader
echo "running autoconf..."
autoconf
echo "running automake..."
automake

