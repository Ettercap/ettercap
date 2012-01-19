install(FILES etter.conf etter.nbns DESTINATION ${INSTALL_SYSCONFDIR})
install(FILES
            ettercap.png
            etter.dns
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
