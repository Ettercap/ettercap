
if(ENABLE_IPV6)
	configure_file(etter.conf.v6 etter.conf COPYONLY)
else(ENABLE_IPV6)
	configure_file(etter.conf.v4 etter.conf COPYONLY)
endif(ENABLE_IPV6)

install(FILES etter.dns etter.mdns etter.nbns etter.conf DESTINATION ${INSTALL_SYSCONFDIR}/ettercap)
install(FILES
            ettercap.png
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
        DESTINATION ${INSTALL_DATADIR}/ettercap)
