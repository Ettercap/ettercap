==================================
  TODOs for fix-cmake
==================================

- hide most advanced variables

- GTK
    - GTK3 is still not the default?
    - how to tell find_path() to look
      in any "lib" directory for glibconfig.h?

- Curses
    - FindCurses.cmake should look for libformw when CURSES_NEED_WIDE
      is true. Report to upstream?

- Why are we enforcing an out-of-source build?
  This should be optional

- Deal with BUNDLED_LIBS (except libnet)

==================================
  Out of scope TODOs for fix-cmake
==================================

- Curses
    - Port curses UI to windows