==================================
  TODOs for fix-cmake
==================================

- hide most advanced variables

- GTK
    - GTK3 is still not the default?
    - how to tell find_path() to look in any "lib" directory for glibconfig.h?

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

- add a (travis) build matrix for LIBRARY_BUILD

==================================
  Out of scope TODOs for fix-cmake
==================================

- Curses
    - Port curses UI to windows