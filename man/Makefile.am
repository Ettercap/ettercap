
# $Id: Makefile.am,v 1.7 2004/01/04 17:02:43 alor Exp $

include $(top_srcdir)/Makefile.am.common

man_MANS = ettercap.8 ettercap_curses.8 etterlog.8 etterfilter.8 etter.conf.5

if PLUGINS
   man_MANS += ettercap_plugins.8
endif

EXTRA_DIST = $(man_MANS)

CLEANFILES = *.8 *.5

