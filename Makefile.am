
include $(top_srcdir)/Makefile.am.common

SUBDIRS = man src include utils

if PLUGINS
   SUBDIRS += plug-ins
endif


EXTRA_DIST = LICENSE \
             AUTHORS \
             CHANGELOG \
             TODO \
             TODO.TESTING \
             Makefile.am.common \
             shtool \
             doc/* \
             share/* 

CLEANFILES = *.log *.out *.cache *.so ettercap etterlog

test: all
	ln -fs ./src/ettercap ./
	ln -fs ./utils/etterlog/etterlog ./
	find ./plug-ins -name '*.so' -exec ln -fs {} ./ \;
	./shtool fixperm ./

# vim:ts=4: noexpandtab
