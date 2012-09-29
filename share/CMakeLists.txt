install(FILES etter.conf etter.dns etter.nbns DESTINATION ${INSTALL_SYSCONFDIR}/ettercap)
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

if(ENABLE_LUA)
  add_subdirectory(lua)
endif(ENABLE_LUA)
