#!/bin/sh

WANT_AUTOMAKE="1.11"
export WANT_AUTOMAKE

echo

if test x`which autoconf` = x; then
   echo "ERROR: autoconf not found"
   exit
fi
if test x`which autoheader` = x; then
   echo "ERROR: autoheader not found"
   exit
fi
if test x`which automake` = x; then
   echo "ERROR: automake not found"
   exit
fi
if test x`which aclocal` = x; then
   echo "ERROR: aclocal not found"
   exit
fi
if test x`which libtoolize` = x; then
   if test x`which glibtoolize` = x; then
      echo "ERROR: libtoolize not found"
      exit
   else
      USEGLIBTOOLIZE=1
   fi
fi
if test x`which pkg-config` = x; then
   echo "ERROR: pkg-config not found"
   exit
fi

echo "Suggested version:"
echo
echo "     autoconf     2.59"
echo "     automake     1.7.x"
echo "     libtool      1.5.x"
echo "     pkg-config   0.15.0"
echo
echo "Actual version:"
echo
echo "     `autoconf --version | head -n 1`"
echo "     `automake --version | head -n 1`"
if test $USEGLIBTOOLIZE; then
   echo "     `glibtoolize --version | head -n 1`"
else
   echo "     `libtoolize --version | head -n 1`"
fi
echo "     pkg-config `pkg-config --version`"
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
if test $USEGLIBTOOLIZE; then
   glibtoolize --force --copy 
else
   libtoolize --force --copy 
fi
echo "running aclocal"
aclocal
echo "running autoheader"
autoheader
echo "running autoconf"
autoconf
echo "running automake"
automake --add-missing --copy

