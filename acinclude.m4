
dnl
dnl EC_MESSAGE(MESSAGE)
dnl

AC_DEFUN(EC_MESSAGE,[
   AC_MSG_RESULT()
   AC_MSG_RESULT(${SB}$1...${EB})
   AC_MSG_RESULT()
])

dnl
dnl EC_CHECK_OPTION(STRING, VAR)
dnl

AC_DEFUN(EC_CHECK_OPTION,[
   echo "$1 ${SB}$2${EB}"
])

dnl
dnl EC_PTHREAD_CHECK()
dnl ac_cv_ec_nopthread=1 (if fails)
dnl

AC_DEFUN(EC_PTHREAD_CHECK,[

   AC_SEARCH_LIBS(pthread_create, pthread,,
      [
         AC_MSG_CHECKING(whether $CC accepts -pthread)
         CFLAGS_store="$CFLAGS"
         CFLAGS="$CFLAGS -pthread"
         AC_TRY_COMPILE([#include <pthread.h>],[pthread_create(NULL, NULL, NULL, NULL);],
            [AC_MSG_RESULT(yes)
             LIBS="$LIBS -pthread"],
            [AC_MSG_RESULT(no)
               CFLAGS="$CFLAGS_store"
               AC_MSG_WARN(***************************);
               AC_MSG_WARN(* PTHREAD ARE REQUIRED !! *);
               AC_MSG_WARN(***************************);
               exit
            ])
         unset CFLAGS_store
      ]
   )

   if test "$OS" = "SOLARIS"; then
      AC_SEARCH_LIBS(_getfp, pthread,,)
   fi

])

dnl vim:ts=3:expandtab
