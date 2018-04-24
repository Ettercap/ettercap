include(CheckSymbolExists)
include(CMakePushCheckState)

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
