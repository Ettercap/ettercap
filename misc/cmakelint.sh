#!/bin/sh
# set -xe

# cmakelint.sh -- report style/format issues in CMake files.
# (C) 2018 Ettercap Development Team.

# cmake-lint is a Python tool that checks and reports coding/style issues in
# CMake related build scripts.
#
# Installation:
# https://github.com/richq/cmake-lint
# The recommended version is 1.4, which, at the time of this writing, was not yet
# published on PyPI.
#
# Ettercap uses cmake-lint and this shell script to enforce its consistent,
# portable and up-to-date cmake coding practices. This means that all cmake files
# *contributed* to the project will undergo a series of checks before the build
# configuration phase can begin.
#
# If this script finds any issues, it will exit with a non-zero status and a
# detailed error message. Else it won't output anything and exits with status
# code 0.
#
# Additional information, including on how to use this script as pre-commit
# hook, see Ettercap's Wiki (Etterwiki) at:
# https://github.com/Ettercap/ettercap/wiki
#
# TODO:
# 1. Enforce maximum line length of 80 characters (requires cmake version >= 3)
# 2. Fix (variables passed to std args in) FindGTK3.cmake
# 3. Move the description about this script to Etterwiki

[ -f cmakelint.sh ] && ECROOT=.. || ECROOT=.

FILTERS=\
-linelength,\
-package/stdargs,\
+convention/filename,\
+package/consistency,\
+readability/logic,\
+readability/mixedcase,\
+readability/wonkycase,\
+syntax,\
+whitespace/eol,\
+whitespace/extra,\
+whitespace/indent,\
+whitespace/mismatch,\
+whitespace/newline,\
+whitespace/tabs

CMAKELINT="cmakelint --filter=$FILTERS --quiet --spaces=2"

FIND="$(find $ECROOT \
-name CMakeLists.txt -not -path "$ECROOT/build*/*" -or \
-name *.cmake -not -path "$ECROOT/build*/*")"

$CMAKELINT $FIND