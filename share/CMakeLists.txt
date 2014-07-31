
if(ENABLE_IPV6)
	configure_file(etter.conf.v6 etter.conf COPYONLY)
else(ENABLE_IPV6)
	configure_file(etter.conf.v4 etter.conf COPYONLY)
endif(ENABLE_IPV6)

set(EC_CONFFILES
            etter.dns
            etter.mdns
            etter.nbns
)

set(EC_DATAFILES
            ettercap.png
            ettercap-small.png
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
            ../LICENSE
            ../AUTHORS
)
foreach (f IN LISTS EC_DATAFILES EC_CONFFILES)
	configure_file(${f} ${f} COPYONLY)
endforeach()
install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/${EC_CONFFILES}
        ${CMAKE_CURRENT_BINARY_DIR}/etter.conf
        DESTINATION ${INSTALL_SYSCONFDIR}/ettercap)
install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/${EC_DATAFILES}
        DESTINATION ${INSTALL_DATADIR}/ettercap)
