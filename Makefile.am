
# $Id: Makefile.am,v 1.13 2003/09/24 19:28:41 alor Exp $

include $(top_srcdir)/Makefile.am.common

SUBDIRS = man share include include src utils

if PLUGINS
   SUBDIRS += plug-ins
endif


EXTRA_DIST = AUTHORS \
             BUGS \
             CHANGELOG \
             LICENSE \
             PORTINGS \
             README \
             README.BINARIES \
             README.WIN32 \
             THANKS \
             TODO \
             TODO.TESTING \
             Makefile.am.common \
             shtool \
             doc/*

CLEANFILES = *.log *.out *.cache *.so ettercap etterlog etterfilter

dist-hook:
	rm -rf `find $(distdir)/doc -name CVS`
	cat $(distdir)/Makefile.am.common | sed s/#no/no/g > $(distdir)/Makefile.am.common

test: all
	ln -fs ./src/ettercap ./
	ln -fs ./utils/etterlog/etterlog ./
	ln -fs ./utils/etterfilter/etterfilter ./
	find ./plug-ins -name '*.so' -exec ln -fs {} ./ \;
	./shtool fixperm ./

# vim:ts=4:noexpandtab
