## Etterfilter

set(EF_SRC
            etterfilter/ef_compiler.c
            etterfilter/ef_encode.c
            etterfilter/ef_main.c
            etterfilter/ef_output.c
            etterfilter/ef_parser.c
            etterfilter/ef_tables.c
            etterfilter/ef_test.c
)

find_package(BISON)
find_package(FLEX)
bison_target(EF_PARSER etterfilter/ef_grammar.y ${CMAKE_CURRENT_BINARY_DIR}/ef_grammar.c)
flex_target(EF_SCANNER etterfilter/ef_syntax.l ${CMAKE_CURRENT_BINARY_DIR}/ef_syntax.c)
add_flex_bison_dependency(EF_SCANNER EF_PARSER)

# For ef_grammar.h
include_directories(${CMAKE_CURRENT_BINARY_DIR})

add_executable(etterfilter ${EF_SRC} ${FLEX_EF_SCANNER_OUTPUTS} ${BISON_EF_PARSER_OUTPUTS})
target_link_libraries(etterfilter lib_ettercap)
if(NOT DISABLE_RPATH)
  set_target_properties(etterfilter PROPERTIES INSTALL_RPATH ${INSTALL_LIBDIR})
endif()

## Etterlog

set(EL_SRC
            etterlog/el_analyze.c
            etterlog/el_conn.c
            etterlog/el_decode.c
            etterlog/el_decode_http.c
            etterlog/el_display.c
            etterlog/el_log.c
            etterlog/el_main.c
            etterlog/el_parser.c
            etterlog/el_profiles.c
            etterlog/el_stream.c
            etterlog/el_target.c
)

add_executable(etterlog ${EL_SRC})
target_link_libraries(etterlog lib_ettercap)

if(NOT DISABLE_RPATH)
  set_target_properties(etterlog PROPERTIES INSTALL_RPATH ${INSTALL_LIBDIR})
endif()
install(TARGETS etterfilter etterlog DESTINATION ${INSTALL_BINDIR})
