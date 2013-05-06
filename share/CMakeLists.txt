install(FILES etter.conf etter.dns etter.mdns etter.nbns DESTINATION ${INSTALL_SYSCONFDIR}/ettercap)

if(ENABLE_IPV6)
	install(FILES etter.conf.v6 DESTINATION ${INSTALL_SYSCONFDIR}/ettercap RENAME etter.conf)
else(ENABLE_IPV6)
	install(FILES etter.conf DESTINATION ${INSTALL_SYSCONFDIR}/ettercap)
endif(ENABLE_IPV6)

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
