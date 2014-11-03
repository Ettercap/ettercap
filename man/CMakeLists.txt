# Add man page custom target
if(ENABLE_PDF_DOCS)
  find_program(GROFF_EXECUTABLE NAMES groff)
  find_program(PS2PDF_EXECUTABLE NAMES ps2pdf)
  set(PDF_FILES)
endif()

set (MAN_NAMES ettercap.8 etterfilter.8 etterlog.8 etter.conf.5)
set(MAN_FILES)

if (ENABLE_PLUGINS)
        set(MAN_NAMES ${MAN_NAMES} ettercap_plugins.8)
endif(ENABLE_PLUGINS)

if (INSTALL_DESKTOP)
        set(MAN_NAMES ${MAN_NAMES} ettercap-pkexec.8)
endif(INSTALL_DESKTOP)

if (ENABLE_CURSES)
        set(MAN_NAMES ${MAN_NAMES} ettercap_curses.8)
endif(ENABLE_CURSES)

foreach (m IN LISTS MAN_NAMES)
        set(mf ${CMAKE_BINARY_DIR}/man/${m})
        list(APPEND MAN_FILES ${mf})

        if(ENABLE_PDF_DOCS)
          set(ps ${CMAKE_BINARY_DIR}/man/${m}.ps)
          set(pdf ${CMAKE_BINARY_DIR}/man/${m}.pdf)

          add_custom_command(OUTPUT ${mf}.ps
          COMMAND ${GROFF_EXECUTABLE} -mandoc -Tps ${mf} > ${ps}
          WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
          COMMENT "Building manpage ${mf}"
          VERBATIM)

          add_custom_command(OUTPUT ${pdf}
          COMMAND ${PS2PDF_EXECUTABLE} ${ps} ${pdf}
          WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
          DEPENDS ${mf}.ps
          COMMENT "Creating PDF for ${ps}"
          VERBATIM)
          list(APPEND PDF_FILES ${pdf})
          install(FILES ${pdf} DESTINATION ${INSTALL_DATADIR}/ettercap/doc)
        endif(ENABLE_PDF_DOCS)
endforeach()

add_custom_target(man ALL DEPENDS ${MAN_FILES})
if(ENABLE_PDF_DOCS)
  add_custom_target(pdf ALL DEPENDS ${PDF_FILES})
endif(ENABLE_PDF_DOCS)

install(FILES ${CMAKE_BINARY_DIR}/man/ettercap.8 ${CMAKE_BINARY_DIR}/man/etterfilter.8 ${CMAKE_BINARY_DIR}/man/etterlog.8 DESTINATION ${MAN_INSTALLDIR}/man8/)
configure_file("ettercap.8.in" "ettercap.8")
configure_file("etterfilter.8.in" "etterfilter.8")
configure_file("etterlog.8.in" "etterlog.8")
configure_file("etter.conf.5.in" "etter.conf.5")

if (ENABLE_PLUGINS)
        install(FILES ${CMAKE_BINARY_DIR}/man/ettercap_plugins.8 DESTINATION ${MAN_INSTALLDIR}/man8/)
	configure_file("ettercap_plugins.8.in" "ettercap_plugins.8")
endif(ENABLE_PLUGINS)

if (ENABLE_CURSES)
        install(FILES ${CMAKE_BINARY_DIR}/man/ettercap_curses.8 DESTINATION ${MAN_INSTALLDIR}/man8/)
	configure_file("ettercap_curses.8.in" "ettercap_curses.8")
endif(ENABLE_CURSES)

if (INSTALL_DESKTOP)
        install(FILES ${CMAKE_BINARY_DIR}/man/ettercap-pkexec.8 DESTINATION ${MAN_INSTALLDIR}/man8/)
	configure_file("ettercap-pkexec.8.in" "ettercap-pkexec.8")
endif(INSTALL_DESKTOP)

install(FILES ${CMAKE_BINARY_DIR}/man/etter.conf.5 DESTINATION ${MAN_INSTALLDIR}/man5/)
