
# $Id: Makefile.am,v 1.2 2003/10/20 14:41:50 alor Exp $

include $(top_srcdir)/Makefile.am.common

SUBDIRS = widgets

noinst_LIBRARIES = libec_curses.a

libec_curses_a_CFLAGS = @EC_CFLAGS@ -Iwidgets

libec_curses_a_SOURCES = ec_curses.c

# hack to include libwdg.a objects into libec_curses.a
all-am: libec_curses.a 
	@if test libec_curses.a -ot widgets/libwdg.a -o "`ar t libec_curses.a | grep libwdg`" == ""; then \
		$(AR) x widgets/libwdg.a;			\
		$(AR) ru libec_curses.a *wdg*;	\
		echo "Joining libwdg objects into libec_curses..."; \
	fi

# vim:ts=4:noexpandtab

