
include $(top_srcdir)/Makefile.am.common

SUBDIRS = man share include include src utils

if PLUGINS
   SUBDIRS += plug-ins
endif


EXTRA_DIST = LICENSE \
             AUTHORS \
             CHANGELOG \
             PORTINGS \
             THANKS \
             TODO \
             TODO.TESTING \
             Makefile.am.common \
             shtool \
             doc/*

CLEANFILES = *.log *.out *.cache *.so ettercap etterlog etterfilter

dist-hook:
	rm -rf `find $(distdir)/doc -name CVS`

test: all
	ln -fs ./src/ettercap ./
	ln -fs ./utils/etterlog/etterlog ./
	ln -fs ./utils/etterfilter/etterfilter ./
	find ./plug-ins -name '*.so' -exec ln -fs {} ./ \;
	./shtool fixperm ./

# vim:ts=4:noexpandtab
