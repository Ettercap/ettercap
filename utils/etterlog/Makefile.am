
include $(top_srcdir)/Makefile.am.common

# do not link ettercap libs
LIBS = 

bin_PROGRAMS = etterlog

etterlog_SOURCES = el_main.c \
                   el_parser.c \
                   el_error.c \
                   el_analyze.c \
                   el_conn.c \
                   el_target.c \
                   el_display.c \
                   el_log.c \
                   el_profiles.c \
                   el_ec_compat.c \
                   $(top_srcdir)/src/ec_fingerprint.c \
                   $(top_srcdir)/src/ec_manuf.c \
                   $(top_srcdir)/src/ec_hash.c \
                   $(top_srcdir)/src/ec_file.c \
                   $(top_srcdir)/src/ec_inet.c \
                   $(top_srcdir)/src/ec_format.c
                   
if MISSING_STRSEP
   etterlog_SOURCES += $(top_srcdir)/src/missing/strsep.c
endif
if MISSING_INET_ATON
   etterlog_SOURCES += $(top_srcdir)/src/missing/inet_aton.c
endif
if MISSING_GETOPT_LONG
   etterlog_SOURCES += $(top_srcdir)/src/missing/getopt.c
endif

etterlog_CFLAGS = @EC_CFLAGS@

etterlog_LDADD = -lz


CLEANFILES = *.log *.out core* *~

# vim:ts=4:noexpandtab
