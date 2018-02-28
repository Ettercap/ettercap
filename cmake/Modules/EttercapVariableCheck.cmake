# Check if PTHREAD_MUTEX_RECURSIVE_NP exists
check_variable_in_headers(PTHREAD_MUTEX_RECURSIVE_NP "pthread.h" HAVE_MUTEX_RECURSIVE_NP)

# Check if IP6T_SO_ORIGINAL_DST socket option is available - necessary for IPv6 SSL interception
if(OS_LINUX AND ENABLE_IPV6)
  include(CheckSymbolExists)
  check_symbol_exists(
    IP6T_SO_ORIGINAL_DST
    "net/if.h;netinet/in.h;linux/netfilter_ipv6/ip6_tables.h"
    HAVE_IP6T_SO_ORIGINAL_DST
  )
endif()
