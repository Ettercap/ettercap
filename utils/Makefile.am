
include $(top_srcdir)/Makefile.am.common

# do not link ettercap libs
LIBS = 

bin_PROGRAMS = lcconvert etterlog

lcconvert_SOURCES = lc-convert.c 

lcconvert_CFLAGS = -O2 -funroll-loops -fomit-frame-pointer -Wall

lcconvert_LIBS =


etterlog_SOURCES = el_main.c \
                   el_parser.c \
                   el_error.c \
                   el_analyze.c \
                   el_log.c \
                   ../src/ec_inet.c \
                   ../src/ec_format.c

etterlog_CFLAGS = @EC_CFLAGS@

etterlog_LDADD = -lz


CLEANFILES = *.log *.out core* *~

# vim:ts=4:noexpandtab
