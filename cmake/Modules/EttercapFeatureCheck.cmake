include(CMakePushCheckState)
include(CheckSymbolExists)
include(CheckTypeSize)
include(CheckIncludeFile)

# Check for Header files

# XXX - HAVE_POLL_H result is currently unimplemented because according to
# http://pubs.opengroup.org/onlinepubs/009695399/functions/poll.html
# HAVE_POLL_H should be the default.
check_include_file(poll.h HAVE_POLL_H)
check_include_file(sys/poll.h HAVE_SYS_POLL_H)

check_include_file(sys/select.h HAVE_SYS_SELECT_H)
check_include_file(sys/utsname.h HAVE_UTSNAME_H)

check_include_file(stdint.h HAVE_STDINT_H)
check_include_file(getopt.h HAVE_GETOPT_H)
check_include_file(ctype.h HAVE_CTYPE_H)
check_include_file(inttypes.h HAVE_INTTYPES_H)

check_include_file(nameser.h HAVE_NAMESER_H)
check_include_file(arpa/nameser.h HAVE_ARPA_NAMESER_H)

check_include_file(ltdl.h HAVE_LTDL_H)
check_include_file(dlfcn.h HAVE_DLFCN_H)
check_include_file(libgen.h HAVE_LIBGEN_H)

# Check for Symbols

cmake_push_check_state(RESET)

# XXX - This used to turn out as false on linux because we never defined
# _GNU_SOURCE before running the test. See feature_test_macros(7)
# uncomment either in case the build breaks:
# add_definitions(-D_GNU_SOURCE)
# set(EC_DEFINITIONS ${EC_DEFINITIONS} -D_GNU_SOURCE)
set(CMAKE_REQUIRED_DEFINITIONS -D_GNU_SOURCE)
check_symbol_exists(strcasestr
  "string.h" HAVE_STRCASESTR
)
cmake_reset_check_state()
# The memrchr() function is a GNU extension and conforms to no standard.
set(CMAKE_REQUIRED_DEFINITIONS -D_GNU_SOURCE)
check_symbol_exists(memrchr
  "string.h" HAVE_MEMRCHR
)
cmake_reset_check_state()

if(NOT HAVE_POLL_H AND NOT HAVE_SYS_POLL_H AND OS_WINDOWS)
  # XXX - windows: HAVE_WSAPOLL result currently unimplemented because of needed
  # core definitions _WIN32_WINNT=0x0600 & INCL_WINSOCK_API_PROTOTYPES.
  set(CMAKE_REQUIRED_DEFINITIONS
    -D_WIN32_WINNT=0x0600
    -DINCL_WINSOCK_API_PROTOTYPES
  )

  if(OS_MINGW)
    set(CMAKE_REQUIRED_LIBRARIES ws2_32)
  else()
    set(CMAKE_REQUIRED_LIBRARIES Ws2_32.Lib)
  endif()

  check_symbol_exists(WSAPoll
    "winsock2.h" HAVE_WSAPOLL
  )
  endif()

cmake_reset_check_state()
if(OS_WINDOWS)
  # XXX - MSVC: result currently unimplemented
  set(EC_STRTOK strtok_s) # Microsoft decided to rename strtok_r to strtok_s.
else()
  set(EC_STRTOK strtok_r)
endif()

check_symbol_exists(${EC_STRTOK}
  "string.h" HAVE_STRTOK_R
)
cmake_reset_check_state()

if(OS_WINDOWS)
  if(OS_MINGW)
    set(CMAKE_REQUIRED_LIBRARIES ws2_32)
  else()
    set(CMAKE_REQUIRED_LIBRARIES Ws2_32.Lib)
  endif()

  check_symbol_exists(select
    "winsock2.h" HAVE_SELECT
  )
else()
  check_symbol_exists(select
    "sys/select.h" HAVE_SELECT
  )
endif()

if(EC_OLDSKOOL_SELECT)
  # In case your system complies to an earlier POSIX standard,
  # you may define EC_OLDSKOOL_SELECT to check for it again with these
  # includes.
  check_symbol_exists(select
    "sys/time.h;sys/types.h;unistd.h" HAVE_SELECT
  )
  endif()
cmake_reset_check_state()

if(OS_WINDOWS)
  # Windoze making life complicated again...
  find_path(DIRENT_INCLUDE_DIR dirent.h)
  mark_as_advanced(DIRENT_INCLUDE_DIR)
  set(CMAKE_REQUIRED_INCLUDES ${DIRENT_INCLUDE_DIR})
endif()

check_symbol_exists(scandir
  "dirent.h" HAVE_SCANDIR
)
cmake_reset_check_state()

check_symbol_exists(strlcat
  "string.h" HAVE_STRLCAT_FUNCTION
)

cmake_reset_check_state()
check_symbol_exists(strlcpy
  "string.h" HAVE_STRLCPY_FUNCTION
)
cmake_reset_check_state()

check_symbol_exists(strndup
  "string.h" HAVE_STRNDUP
)
cmake_reset_check_state()

check_symbol_exists(strsep
  "string.h" HAVE_STRSEP
)
cmake_reset_check_state()

check_symbol_exists(basename
  "libgen.h" HAVE_BASENAME
)
cmake_reset_check_state()

# XXX - This used to turn out as false on linux because we never defined
# _GNU_SOURCE before running the test. See feature_test_macros(7)
# uncomment either in case the build breaks:
# add_definitions(-D_GNU_SOURCE)
# set(EC_DEFINITIONS ${EC_DEFINITIONS} -D_GNU_SOURCE)
set(CMAKE_REQUIRED_DEFINITIONS -D_GNU_SOURCE)
check_symbol_exists(memmem
  "string.h" HAVE_MEMMEM
)
cmake_reset_check_state()

check_symbol_exists(memrchr
  "string.h" HAVE_MEMRCHR
)
cmake_pop_check_state()

if(NOT HAVE_STRLCAT_FUNCTION OR NOT HAVE_STRLCPY_FUNCTION)
  check_library_exists(bsd strlcat "bsd/string.h" HAVE_STRLCAT)
  check_library_exists(bsd strlcpy "bsd/string.h" HAVE_STRLCPY)
  if(HAVE_STRLCAT OR HAVE_STRLCPY)
    set(EC_LIBS ${EC_LIBS} bsd)
  endif()
endif()


# Check if PTHREAD_MUTEX_RECURSIVE_NP exists
# ...as a macro
cmake_push_check_state(RESET)
check_symbol_exists(PTHREAD_MUTEX_RECURSIVE_NP
  "pthread.h" HAVE_MUTEX_RECURSIVE_NP
)
if(NOT HAVE_MUTEX_RECURSIVE_NP)
  # try again in case it's enum value
  unset(HAVE_MUTEX_RECURSIVE_NP CACHE)
  cmake_reset_check_state()
  check_c_source_compiles("
  #include <pthread.h>
  int main()
  {
      int blah = 0;
      switch(1) {
          case PTHREAD_MUTEX_RECURSIVE_NP:
              blah = 1;
      };
      return blah;
  }
  " HAVE_MUTEX_RECURSIVE_NP)
endif()
cmake_pop_check_state()

# Check if GeoIP is at least version least version "1.6.4"
# (this is really only needed with OS_WINDOWS)
if(ENABLE_GEOIP AND OS_WINDOWS)
  cmake_push_check_state(RESET)
  set(CMAKE_REQUIRED_INCLUDES ${GEOIP_INCLUDE_DIRS})
  # set(CMAKE_REQUIRED_QUIET 1)
  check_c_source_compiles("
  #include <GeoIP.h>
  int main()
  {
      int blah = 0;
      switch(1) {
          case GEOIP_SILENCE:
              blah = 1;
      };
      return blah;
  }
    " HAVE_GEOIP_SILENCE)
  cmake_pop_check_state()

  if(NOT HAVE_GEOIP_SILENCE)
    message(FATAL_ERROR "The GeoIP library found is too old. \
Please upgrade your GeoIP installation.")
  endif()
endif()

# Check if IP6T_SO_ORIGINAL_DST socket option is available
# (necessary for IPv6 SSL interception)
if(OS_LINUX AND ENABLE_IPV6)
  cmake_push_check_state(RESET)
  check_symbol_exists(
    IP6T_SO_ORIGINAL_DST
    "net/if.h;netinet/in.h;linux/netfilter_ipv6/ip6_tables.h"
    HAVE_IP6T_SO_ORIGINAL_DST
  )
  cmake_pop_check_state()
endif()

