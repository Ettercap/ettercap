
include $(top_srcdir)/Makefile.am.common

# do not link ettercap libs
LIBS = 

bin_PROGRAMS = etterlog

etterlog_SOURCES = el_main.c \
                   el_parser.c \
                   el_error.c \
                   el_analyze.c \
                   el_log.c \
                   $(top_srcdir)/src/ec_inet.c \
                   $(top_srcdir)/src/ec_format.c

etterlog_CFLAGS = @EC_CFLAGS@

etterlog_LDADD = -lz


CLEANFILES = *.log *.out core* *~

# vim:ts=4:noexpandtab
