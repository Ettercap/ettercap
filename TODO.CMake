==================================
  TODOs for fix-cmake
==================================

- hide most advanced variables

- GTK
    - how to tell find_path() to look in any "lib" directory for glibconfig.h?
    - disable HAVE_GTK3COMPAT related warnings only

- Curses
    - FindCurses.cmake should look for libformw when CURSES_NEED_WIDE
      is true. Report to upstream?

- Why are we enforcing an out-of-source build? This should be optional

- Deal with BUNDLED_LIBS (except libnet)

- Remove CMake Warning at cmake/Modules/EttercapOSTest.cmake:21

- Prefer using CheckSymbolExists instead of CheckFunctionExists, for the following reasons:
    1. check_function_exists() can’t detect functions that are inlined in headers or specified as a macro.
    2. check_function_exists() can’t detect anything in the 32-bit versions of the Win32 API, because of a mismatch in calling conventions.
    3. check_function_exists() only verifies linking, it does not verify that the function is declared in system headers.

- macro CHECK_VARIABLE_IN_HEADERS seems unused...

- LIBRARY_BUILD
    - add a (travis) build matrix for LIBRARY_BUILD
    - select_text_interface() is not shown in -h option of the text interface.
      Seems circular to me. Unless the text interface is selected by default of course.
      Investigating...

- INSTALL_PREFIX
    - Setting the INSTALL_PREFIX and sub directories can be done much cleaner,
      much more reliably and much elegantly.
      See the build-in module GNUInstallDirs and/or cmake-init
    - INSTALL_EXECPREFIX, and (if INSTALL_DESKTOP is set
      to OFF) DESKTOP_DIR, APPDATA_DIR, POLKIT_DIR and PKEXEC_INSTALL_WRAPPER are unused.
      I'll keep them still since they maybe useful in the future(like adding a
      desktop icon on windows, or looking for etter.conf in APPDATA_DIR as well).

- divide top-level CMakeLists.txt into sections

- create and use a check_and_add_linker_option() macro

- add a clang-tidy (make) target (instead of ASAN support)

- Add a nicer build summary at the end

- use CMakePushCheckState throughout

- reduce use of include_directories()

- link targets only with libs they really depend on (e.g. tests)

==================================
  Out of scope TODOs for fix-cmake
==================================

- Curses
    - Port curses UI to windows

- INSTALL_PREFIX
    - It should be possible to relocate ettercap and/or its
      configuration files and still use it. Ettercap should be taught to look for its
      files in different places or there should be options in etter.conf to specify these
      locations.
      See Gisle's wsock-trace for a great example.

