
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


dnl
dnl EC_WINDOWS_KERNEL()
dnl

AC_DEFUN(EC_WINDOWS_KERNEL,[

   AC_MSG_CHECKING(Windows kernel version)
   tech=`uname | cut -f2 -d"_" | cut -f1 -d"-"`
   major=`uname | cut -f2 -d"-" | cut -f1 -d"."`
   minor=`uname | cut -f2 -d"-" | cut -f2 -d"."`
   AC_MSG_RESULT($tech $major.$minor)
   if test "$tech" != "NT"; then
      ac_cv_ec_windows_version="-DWIN9X"
   elif test "$major$minor" -lt 50; then
      ac_cv_ec_windows_version="-DWINNT"
   else
      ac_cv_ec_windows_version="-DWIN2K_XP"
   fi

   AC_MSG_CHECKING(Cygwin dll version)
   uname=`uname -r | cut -f1 -d"("`
   major=`uname -r | cut -f1 -d"(" | cut -f1 -d"."`
   minor=`uname -r | cut -f1 -d"(" | cut -f2 -d"."`
   AC_MSG_RESULT($uname)
   if test "$major$minor" -lt 13; then
      AC_MSG_WARN(****************************);
      AC_MSG_WARN(* Cygwin 1.3.x REQUIRED !! *);
      AC_MSG_WARN(****************************);
      exit;
   fi
])


dnl
dnl EC_GCC_MACRO()
dnl
dnl check if the compiler support __VA_ARGS__ in macro declarations
dnl

AC_DEFUN(EC_GCC_MACRO,[

   AC_MSG_CHECKING(if your compiler supports __VA_ARGS__ in macro declarations)
   
   AC_TRY_RUN([
   
      #include <stdio.h>

      #define EXECUTE(x, ...) do{ if (x != NULL) x( __VA_ARGS__ ); }while(0)

      void foo() { }
      
      int main(int argc, char **argv)
      {
         EXECUTE(foo);
         return 0;
      } 
   ],
   [ AC_MSG_RESULT(yes) ],
   [ AC_MSG_RESULT(no) 
     AC_ERROR(please use gcc >= 3.2.x)
   ],
     AC_MSG_RESULT(unkown when cross-compiling)
   )

])


dnl vim:ts=3:expandtab
