
include $(top_srcdir)/Makefile.am.common

bin_PROGRAMS = lcconvert etterlog

lcconvert_SOURCES = lc-convert.c 

etterlog_SOURCES = el_main.c

lcconvert_CFLAGS = -O2 -funroll-loops -fomit-frame-pointer -Wall
etterlog_CFLAGS = @EC_CFLAGS@

LIBS =
lcconvert_LIBS =
etterlog_LIBS =

CLEANFILES = *.log *.out core* *~

# vim:ts=4:noexpandtab
