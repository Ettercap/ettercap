FILE(GLOB files "${CMAKE_CURRENT_SOURCE_DIR}/*.lua")
install(FILES ${files} DESTINATION ${INSTALL_DATADIR}/ettercap/lib)
