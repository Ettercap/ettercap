if(HAVE_PCRE OR HAVE_PCRE2)
  if(CURL_FOUND)
    add_library(sslstrip MODULE sslstrip/sslstrip.c)
    include_directories(${CURL_INCLUDE_DIR} ${PCRE_INCLUDE_DIR})
    add_dependencies(sslstrip curl)
    target_link_libraries(sslstrip ${CURL_LIBRARY} ${PCRE_LIBRARY})
    target_link_libraries(sslstrip lib_ettercap)
    set_target_properties(sslstrip PROPERTIES PREFIX "ec_")
    install(TARGETS sslstrip
        LIBRARY DESTINATION ${INSTALL_LIBDIR}/ettercap/
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
                    GROUP_READ GROUP_EXECUTE
                    WORLD_READ WORLD_EXECUTE)

  else()
    message(STATUS "Not building sslstrip plugin. Requires libcurl.")
  endif()
else()
  message(STATUS "Not building sslstrip plugin. Requires pcre.")
endif()

set(PLUGINS arp_cop
autoadd
chk_poison
dns_spoof
mdns_spoof
dos_attack
dummy
find_conn
find_ettercap
find_ip
finger
finger_submit
fraggle_attack
gre_relay
gw_discover
isolate
link_type
nbns_spoof
pptp_chapms1
pptp_clear
pptp_pap
pptp_reneg
rand_flood
remote_browser
reply_arp
repoison_arp
scan_poisoner
search_promisc
smb_clear
smb_down
krb5_downgrade
smurf_attack
stp_mangler)

foreach(plugin ${PLUGINS})
  add_library(${plugin} MODULE ${plugin}/${plugin}.c)
  set_target_properties(${plugin} PROPERTIES PREFIX "ec_")
  target_link_libraries(${plugin} lib_ettercap)
  install(TARGETS ${plugin}
        LIBRARY DESTINATION ${INSTALL_LIBDIR}/ettercap/
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
                    GROUP_READ GROUP_EXECUTE
                    WORLD_READ WORLD_EXECUTE)
endforeach()

if(NOT HAVE_DN_EXPAND)
  target_link_libraries(dns_spoof ${HAVE_RESOLV})
  target_link_libraries(mdns_spoof ${HAVE_RESOLV})
endif()

target_link_libraries(dos_attack ${HAVE_LIBNET})
