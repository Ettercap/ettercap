
# $Id: Makefile.am,v 1.18 2003/11/26 20:39:10 alor Exp $

include $(top_srcdir)/Makefile.am.common

SUBDIRS = man share include include src utils

if PLUGINS
   SUBDIRS += plug-ins
endif


EXTRA_DIST = AUTHORS \
             BUGS \
             CHANGELOG \
             LICENSE \
             README \
             README.BINARIES \
             README.CVS \
             README.PLATFORMS \
             THANKS \
             TODO \
             TODO.TESTING \
             Makefile.am.common \
             shtool \
             doc/*

CLEANFILES = -R auto4te.cache *~ *.log *.out *.cache *.so ettercap etterlog etterfilter

dist-hook:
	rm -rf `find $(distdir)/doc -name CVS`
	cat $(distdir)/Makefile.am.common | sed s/#no/no/g > $(distdir)/Makefile.am.common

test: all
	rm -f ettercap etterfilter etterlog *.so
	ln -fs ./src/ettercap ./
	ln -fs ./utils/etterlog/etterlog ./
	ln -fs ./utils/etterfilter/etterfilter ./
	find ./plug-ins -name '*.so' -exec ln -fs {} ./ \;
	./shtool fixperm ./

# only for developers
deep-debug:
	@echo Setting root privs for ettercap...
	@export EC_UID=0
	@echo Setting hard checks on heap corruption...
	@export MALLOC_CHECK_=2

# vim:ts=4:noexpandtab

