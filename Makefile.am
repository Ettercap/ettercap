
include $(top_srcdir)/Makefile.am.common

SUBDIRS = man src include utils plug-ins 

EXTRA_DIST = LICENSE \
             AUTHORS \
             CHANGELOG \
             TODO \
             Makefile.am.common \
             shtool \
             share/* 

CLEANFILES = *.log *.out *.cache *.so ettercap

test: all
	ln -fs ./src/ettercap ./
	find ./plug-ins -name '*.so' -exec ln -fs {} ./ \;
	./shtool fixperm ./

# vim:ts=4: noexpandtab
