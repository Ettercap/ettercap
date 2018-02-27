if(ENABLE_GTK)
  configure_file(org.pkexec.ettercap.policy.in
    ${PKEXEC_INSTALL_WRAPPER}.policy @ONLY)
  install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${PKEXEC_INSTALL_WRAPPER}.policy DESTINATION ${POLKIT_DIR})
  install(FILES ettercap.desktop DESTINATION ${DESKTOP_DIR})
  install(FILES ettercap.appdata.xml DESTINATION ${APPDATA_DIR})
  install(PROGRAMS ettercap-pkexec DESTINATION ${INSTALL_BINDIR})
endif()
