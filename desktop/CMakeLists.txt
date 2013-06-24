if(INSTALL_DESKTOP)
  SET(PKEXEC_INSTALL_WRAPPER org.pkexec.ettercap.policy)
  CONFIGURE_FILE(org.pkexec.ettercap.policy.in
    ${PKEXEC_INSTALL_WRAPPER} @ONLY)
  install(FILES ${CMAKE_CURRENT_BINARY_DIR}/org.pkexec.ettercap.policy DESTINATION ${POLKIT_DIR})
  install(FILES ettercap.svg DESTINATION ${ICON_DIR})
  install(FILES ettercap.desktop DESTINATION ${DESKTOP_DIR})
  install(PROGRAMS ettercap-pkexec DESTINATION ${INSTALL_BINDIR})
endif(INSTALL_DESKTOP)
