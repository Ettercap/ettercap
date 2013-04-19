## Etterfilter

set(EF_SRC
            etterfilter/ef_compiler.c
            etterfilter/ef_ec_compat.c
            etterfilter/ef_encode.c
            etterfilter/ef_main.c
            etterfilter/ef_output.c
            etterfilter/ef_parser.c
            etterfilter/ef_tables.c
            etterfilter/ef_test.c
            ${CMAKE_SOURCE_DIR}/src/ec_error.c
            ${CMAKE_SOURCE_DIR}/src/ec_file.c
            ${CMAKE_SOURCE_DIR}/src/ec_filter.c
            ${CMAKE_SOURCE_DIR}/src/ec_strings.c
)

if(NOT HAVE_STRLCPY)
    set(EF_SRC ${EF_SRC} ${CMAKE_SOURCE_DIR}/src/missing/strlcpy.c)
endif(NOT HAVE_STRLCPY)

if(NOT HAVE_STRSEP)
    set(EF_SRC ${EF_SRC} ${CMAKE_SOURCE_DIR}/src/missing/strsep.c)
endif(NOT HAVE_STRSEP)

if(NOT HAVE_MEMMEM)
    set(EF_SRC ${EF_SRC} ${CMAKE_SOURCE_DIR}/src/missing/memmem.c)
endif(NOT HAVE_MEMMEM)

if(NOT HAVE_INET_ATON)
    set(EF_SRC ${EF_SRC} ${CMAKE_SOURCE_DIR}/src/missing/inet_aton.c)
endif(NOT HAVE_INET_ATON)

if(NOT HAVE_GETOPT_LONG)
    set(EF_SRC ${EF_SRC} ${CMAKE_SOURCE_DIR}/src/missing/getopt.c)
endif(NOT HAVE_GETOPT_LONG)

if(NOT HAVE_STRNDUP)
    set(EF_SRC ${EF_SRC} ${CMAKE_SOURCE_DIR}/src/missing/strndup.c)
endif(NOT HAVE_STRNDUP)

find_package(BISON)
find_package(FLEX)
BISON_TARGET(EF_PARSER etterfilter/ef_grammar.y ${CMAKE_CURRENT_BINARY_DIR}/ef_grammar.c)
FLEX_TARGET(EF_SCANNER etterfilter/ef_syntax.l ${CMAKE_CURRENT_BINARY_DIR}/ef_syntax.c)
ADD_FLEX_BISON_DEPENDENCY(EF_SCANNER EF_PARSER)

# For ef_grammar.h
include_directories(${CMAKE_CURRENT_BINARY_DIR})

add_executable(etterfilter ${EF_SRC} ${FLEX_EF_SCANNER_OUTPUTS} ${BISON_EF_PARSER_OUTPUTS})
target_link_libraries(etterfilter ${EF_LIBS})

## Etterlog

set(EL_SRC
            etterlog/el_analyze.c
            etterlog/el_conn.c
            etterlog/el_decode.c
            etterlog/el_decode_http.c
            etterlog/el_display.c
            etterlog/el_ec_compat.c
            etterlog/el_log.c
            etterlog/el_main.c
            etterlog/el_parser.c
            etterlog/el_profiles.c
            etterlog/el_stream.c
            etterlog/el_target.c
            ${CMAKE_SOURCE_DIR}/src/ec_error.c 
            ${CMAKE_SOURCE_DIR}/src/ec_fingerprint.c 
            ${CMAKE_SOURCE_DIR}/src/ec_manuf.c 
            ${CMAKE_SOURCE_DIR}/src/ec_services.c 
            ${CMAKE_SOURCE_DIR}/src/ec_hash.c 
            ${CMAKE_SOURCE_DIR}/src/ec_file.c 
            ${CMAKE_SOURCE_DIR}/src/ec_inet.c 
            ${CMAKE_SOURCE_DIR}/src/ec_passive.c 
            ${CMAKE_SOURCE_DIR}/src/ec_strings.c 
            ${CMAKE_SOURCE_DIR}/src/ec_format.c
)

if(NOT HAVE_BASENAME)
    set(EL_SRC ${EL_SRC} ${CMAKE_SOURCE_DIR}/src/missing/basename.c)
endif(NOT HAVE_BASENAME)

if(NOT HAVE_STRCASESTR)
    set(EL_SRC ${EL_SRC} ${CMAKE_SOURCE_DIR}/src/missing/strcasestr.c)
endif(NOT HAVE_STRCASESTR)

if(NOT HAVE_STRLCAT)
    set(EL_SRC ${EL_SRC} ${CMAKE_SOURCE_DIR}/src/missing/strlcat.c)
endif(NOT HAVE_STRLCAT)

if(NOT HAVE_STRSEP)
    set(EL_SRC ${EL_SRC} ${CMAKE_SOURCE_DIR}/src/missing/strsep.c)
endif(NOT HAVE_STRSEP)

if(NOT HAVE_MEMMEM)
    set(EL_SRC ${EL_SRC} ${CMAKE_SOURCE_DIR}/src/missing/memmem.c)
endif(NOT HAVE_MEMMEM)

if(NOT HAVE_INET_ATON)
    set(EL_SRC ${EL_SRC} ${CMAKE_SOURCE_DIR}/src/missing/inet_aton.c)
endif(NOT HAVE_INET_ATON)

if(NOT HAVE_GETOPT_LONG)
    set(EL_SRC ${EL_SRC} ${CMAKE_SOURCE_DIR}/src/missing/getopt.c)
endif(NOT HAVE_GETOPT_LONG)

if(NOT HAVE_STRNDUP)
    set(EF_SRC ${EF_SRC} ${CMAKE_SOURCE_DIR}/src/missing/strndup.c)
endif(NOT HAVE_STRNDUP)

add_executable(etterlog ${EL_SRC})
target_link_libraries(etterlog ${EL_LIBS})

install(TARGETS etterfilter etterlog DESTINATION ${INSTALL_BINDIR})
