# Copyright 2018 Ettercap Development Team.
#
# Distributed under the GPL.
#
# - Find GROFF
# Find the GNU troff text-formatting system (groff).
#
#   GROFF_FOUND - true is groff executable is found
#   GROFF_EXECUTABLE - the path to the groff executable
#   GROFF_VERSION - the version of groff

# Set ``GROFF_NEED_PDF`` to ``TRUE`` before the
# ``find_package(GROFF)`` call if PDF generation functionality is required.

find_program(GROFF_EXECUTABLE NAMES groff
  DOC "GNU troff text-formatting system (groff)"
  HINTS
    $ENV{GROFF_BIN_PATH}
)

if(GROFF_EXECUTABLE)
  # Get version string.
  execute_process(COMMAND ${GROFF_EXECUTABLE} --version
    OUTPUT_VARIABLE GROFF_OUTPUT
    ERROR_VARIABLE GROFF_ERROR
    RESULT_VARIABLE GROFF_EXIT
    OUTPUT_STRIP_TRAILING_WHITESPACE)

  if(NOT GROFF_EXIT EQUAL 0)
    if(GROFF_FIND_REQUIRED)
      message(SEND_ERROR
"Command \"${GROFF_EXECUTABLE} --version\" failed with output:
${GROFF_OUTPUT}\n${GROFF_ERROR}")
    else()
      message("Command \"${GROFF_EXECUTABLE} --version\" failed with output:
${GROFF_OUTPUT}\n${GROFF_ERROR}\nGROFF_VERSION will not be available")
    endif()
  else()
    string(REGEX MATCH "([0-9]+.)([0-9]+[.]*)([0-9]*)"
      GROFF_VERSION "${GROFF_OUTPUT}")
  endif()

  unset(GROFF_ERROR)
  unset(GROFF_EXIT)

  if(GROFF_NEED_PDF)
    # Check if groff supports PDF generation.
    execute_process(COMMAND ${GROFF_EXECUTABLE} -Tpdf -V
      RESULT_VARIABLE GROFF_EXIT
      ERROR_VARIABLE GROFF_ERROR
      OUTPUT_QUIET)

    if(NOT GROFF_EXIT EQUAL 0)
      message(SEND_ERROR
"groff (at ${GROFF_EXECUTABLE}) \
does not seem to support PDF generation (${GROFF_EXIT}).
Command \"${GROFF_EXECUTABLE} -Tpdf -V\" failed with output:\n${GROFF_ERROR}
Consider upgrading the groff installation.
Users of Debian-based distributions must also install the full groff package.")
    endif()
  endif()
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(GROFF
  REQUIRED_VARS
    GROFF_EXECUTABLE
  VERSION_VAR GROFF_VERSION
)
