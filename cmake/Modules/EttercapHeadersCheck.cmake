include(CheckIncludeFile)

check_include_file(sys/poll.h HAVE_SYS_POLL_H)
check_include_file(sys/select.h HAVE_SYS_SELECT_H)
check_include_file(sys/utsname.h HAVE_UTSNAME_H)

check_include_file(stdint.h HAVE_STDINT_H)
check_include_file(getopt.h HAVE_GETOPT_H)
check_include_file(ctype.h HAVE_CTYPE_H)
check_include_file(inttypes.h HAVE_INTTYPES_H)

check_include_file(arpa/nameser.h HAVE_ARPA_NAMESER_H)

check_include_file(ltdl.h HAVE_LTDL_H)
check_include_file(dlfcn.h HAVE_DLFCN_H)
check_include_file(libgen.h HAVE_LIBGEN_H)