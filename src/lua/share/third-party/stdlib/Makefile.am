## Process this file with automake to produce Makefile.in

ACLOCAL_AMFLAGS = -I m4

src_spec = $(abs_srcdir)/src/?.lua

LUA_PATH ?= ;
LUA_ENV  = LUA_PATH="$(src_spec);$(LUA_PATH)"
SPEC_ENV = LUA_PATH="$(src_spec);$(LUA_PATH)"

SPECL_MIN = 3

NOTHING_ELSE =

SOURCES = 				\
	src/base.lua			\
	src/bin.lua			\
	src/debug_ext.lua		\
	src/debug_init.lua		\
	src/fstable.lua			\
	src/getopt.lua			\
	src/io_ext.lua			\
	src/lcs.lua			\
	src/list.lua			\
	src/math_ext.lua		\
	src/mbox.lua			\
	src/modules.lua			\
	src/object.lua			\
	src/package_ext.lua		\
	src/parser.lua			\
	src/set.lua			\
	src/std.lua			\
	src/strbuf.lua			\
	src/strict.lua			\
	src/string_ext.lua		\
	src/table_ext.lua		\
	src/tree.lua			\
	src/xml.lua			\
	$(NOTHING_ELSE)

SPECS =						\
	$(srcdir)/specs/getopt_spec.yaml	\
	$(srcdir)/specs/package_ext_spec.yaml	\
	$(srcdir)/specs/string_ext_spec.yaml	\
	$(srcdir)/specs/table_ext_spec.yaml	\
	$(NOTHING_ELSE)

dist_data_DATA = $(SOURCES)

dist_doc_DATA =				\
	$(top_srcdir)/src/index.html	\
	$(top_srcdir)/src/luadoc.css
filesdir = $(docdir)/files
dist_files_DATA = $(wildcard $(top_srcdir)/src/files/*.html)
modulesdir = $(docdir)/modules
dist_modules_DATA = $(wildcard $(top_srcdir)/src/modules/*.html)

EXTRA_DIST =				\
	src/std.lua.in			\
	GNUmakefile			\
	$(SPECS)			\
	$(NOTHING_ELSE)

DISTCLEANFILES = $(PACKAGE).rockspec

# In order to avoid regenerating std.lua at configure time, which
# causes the documentation to be rebuilt and hence requires users to
# have luadoc installed, put src/std.lua in as a Makefile dependency.
# (Strictly speaking, distributing an AC_CONFIG_FILE would be wrong.)
src/std.lua: src/std.lua.in
	./config.status --file=$@

$(dist_doc_DATA): $(SOURCES)
	cd src && $(LUADOC) *.lua

check-local:
	@v=`specl --version | sed -e 's|^.* ||' -e 1q`;		\
	if test "$$v" -lt "$(SPECL_MIN)"; then			\
	  echo "ERROR: Specl version $$v is too old, please upgrade to at least version $(SPECL_MIN),";\
	  echo "ERROR: and rerun \`make check\`";		\
	  exit 1;						\
	else							\
	  $(SPEC_ENV) specl $(SPECL_OPTS) $(SPECS);		\
	fi
