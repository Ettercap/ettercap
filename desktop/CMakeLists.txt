# since ettercap now uses this file as the application icon
# we still need the icon even if the desktop file is not being installed
if(ENABLE_GTK)
  install(FILES ettercap.svg DESTINATION ${ICON_DIR})
endif(ENABLE_GTK)

if(INSTALL_DESKTOP AND ENABLE_GTK)
  configure_file(org.pkexec.ettercap.policy.in
    ${PKEXEC_INSTALL_WRAPPER}.policy @ONLY)
  install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${PKEXEC_INSTALL_WRAPPER}.policy DESTINATION ${POLKIT_DIR})
  install(FILES ettercap.desktop DESTINATION ${DESKTOP_DIR})
  install(FILES ettercap.appdata.xml DESTINATION ${APPDATA_DIR})
  install(PROGRAMS ettercap-pkexec DESTINATION ${INSTALL_BINDIR})
endif(INSTALL_DESKTOP AND ENABLE_GTK)
