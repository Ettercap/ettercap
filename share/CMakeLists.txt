
if(ENABLE_IPV6)
  configure_file(etter.conf.v6 etter.conf COPYONLY)
  configure_file(etter.dns.v6 etter.dns COPYONLY)
  configure_file(etter.mdns.v6 etter.mdns COPYONLY)
else()
  configure_file(etter.conf.v4 etter.conf COPYONLY)
  configure_file(etter.dns.v4 etter.dns COPYONLY)
  configure_file(etter.mdns.v4 etter.mdns COPYONLY)
endif()

set(EC_CONFFILES
    etter.nbns
)

set(EC_DATAFILES
    ettercap.png
    ettercap-small.png
    ettercap.svg
    etter.fields
    etter.filter
    etterfilter.cnt
    etter.filter.examples
    etter.filter.kill
    etter.filter.pcre
    etter.filter.ssh
    etterfilter.tbl
    etter.finger.mac
    etter.finger.os
    etterlog.dtd
    etter.mime
    etter.services
    etter.ssl.crt
    ../AUTHORS
)
if(NOT NO_INSTALL_LICENSE)
  set(EC_DATAFILES ${EC_DATAFILES} ../LICENSE)
endif()

foreach(f IN LISTS EC_DATAFILES EC_CONFFILES)
  configure_file(${f} ${f} COPYONLY)
endforeach()
install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/${EC_CONFFILES}
        ${CMAKE_CURRENT_BINARY_DIR}/etter.conf
        ${CMAKE_CURRENT_BINARY_DIR}/etter.dns
        ${CMAKE_CURRENT_BINARY_DIR}/etter.mdns
        DESTINATION ${INSTALL_SYSCONFDIR}/ettercap)
install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/${EC_DATAFILES}
        DESTINATION ${INSTALL_DATADIR}/ettercap)

# since ettercap now uses this file as the application icon
# we still need the icon even if the desktop file is not being installed
if(ENABLE_GTK)
  install(FILES ettercap.svg DESTINATION ${ICON_DIR})
endif()

