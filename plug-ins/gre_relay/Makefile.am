
# $Id: Makefile.am,v 1.3 2004/01/03 11:07:43 alor Exp $

include $(top_srcdir)/Makefile.am.common

pkglib_LTLIBRARIES = ec_gre_relay.la

ec_gre_relay_la_CFLAGS = @PL_CFLAGS@ @LNETINC@

ec_gre_relay_la_SOURCES = gre_relay.c

ec_gre_relay_la_LDFLAGS = @PL_LDFLAGS@ -module -avoid-version

LIBS =
ec_gre_relay_la_LIBS = 

# vim:ts=4:noexpandtab

