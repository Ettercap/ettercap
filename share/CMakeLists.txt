
if(ENABLE_IPV6)
  configure_file(etter.conf.v6 etter.conf COPYONLY)
else()
  configure_file(etter.conf.v4 etter.conf COPYONLY)
endif()

set(EC_CONFFILES
    etter.dns
    etter.mdns
    etter.nbns
)

set(EC_DATAFILES
    ettercap.png
    ettercap-small.png
    ettercap.svg
    etter.dns.examples
    etter.mdns.examples
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

if(HAVE_GEOIP)
  set(EC_DATAFILES ${EC_DATAFILES} GeoLite2-Country.mmdb)
endif()

foreach(f IN LISTS EC_DATAFILES EC_CONFFILES)
  configure_file(${f} ${f} COPYONLY)
endforeach()
install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/${EC_CONFFILES}
        ${CMAKE_CURRENT_BINARY_DIR}/etter.conf
        DESTINATION ${INSTALL_SYSCONFDIR}/ettercap)
install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/${EC_DATAFILES}
        DESTINATION ${INSTALL_DATADIR}/ettercap)

# since ettercap now uses this file as the application icon
# we still need the icon even if the desktop file is not being installed
if(ENABLE_GTK)
  install(FILES ettercap.svg DESTINATION ${ICON_DIR}/scalable/apps)
endif()

