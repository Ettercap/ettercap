/*
    ettercap -- signal handler

    Copyright (C) ALoR & NaGA

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

    $Header: /home/drizzt/dev/sources/ettercap.cvs/ettercap_ng/src/ec_signals.c,v 1.5 2003/04/14 21:05:26 alor Exp $
*/

#include <ec.h>
#include <ec_ui.h>

#include <signal.h>
#include <sys/resource.h>

typedef void handler_t(int);

void signal_handler(void);

static handler_t *signal_handle(int signo, handler_t *handler, int flags);
static RETSIGTYPE signal_SEGV(int sig);
static RETSIGTYPE signal_TERM(int sig);


/*************************************/

void signal_handler(void)
{
   DEBUG_MSG("signal_handler activated");

   signal_handle(SIGSEGV, signal_SEGV, 0);
   signal_handle(SIGINT, signal_TERM, 0);
   signal_handle(SIGTERM, signal_TERM, 0);
}


handler_t *signal_handle(int signo, handler_t *handler, int flags)
{
   struct sigaction act, old_act;

   act.sa_handler = handler;

   sigfillset(&act.sa_mask); /* don't permit nested signal handling */

   act.sa_flags = flags;

   if (sigaction(signo, &act, &old_act) < 0)
      ERROR_MSG("sigaction() failed");

   return (old_act.sa_handler);
}


RETSIGTYPE signal_SEGV(int sig)
{
#ifdef DEBUG

   struct rlimit corelimit = {RLIM_INFINITY, RLIM_INFINITY};

   DEBUG_MSG("Segmentation Fault...");
   
   ui_cleanup();
   
   fprintf (stderr, "\n\033[01m\033[1m Ooops !! This shouldn't happen...\n\n");
   fprintf (stderr, "Segmentation Fault...\033[0m\n\n");

   fprintf (stderr, "===========================================================================\n");
   fprintf (stderr, " To report this error follow these steps:\n\n");
   fprintf (stderr, "  1) recompile %s in debug mode : \n"
                    "  \t\"configure --enable-debug && make clean && make\"\n\n", GBL_PROGRAM);
   fprintf (stderr, "  2) reproduce the critical situation\n\n");
   fprintf (stderr, "  3) make a report : \"tar zcvf error.tar.gz %s%s_debug.log \"\n\n", GBL_PROGRAM, GBL_VERSION);
   fprintf (stderr, "  4) get the gdb backtrace :\n"
                    "  \t - \"gdb %s core\"\n"
                    "  \t - at the gdb prompt \"bt\"\n"
                    "  \t - at the gdb prompt \"quit\" and return to the shell\n"
                    "  \t - copy and paste this output.\n\n", GBL_PROGRAM);
   fprintf (stderr, "  5) mail me the output of gdb and the error.tar.gz\n");
   fprintf (stderr, "============================================================================\n");
   
   fprintf (stderr, "\n\033[01m\033[1m Overriding any 'ulimit -c 0'...\n"
                   " Setting core size to RLIM_INFINITY...\n\n"
                   " Core dumping... (use the 'core' file for gdb analysis)\033[0m\n\n");
   
   /* force the coredump */
   
   setrlimit(RLIMIT_CORE, &corelimit);
   signal(sig, SIG_DFL);
   raise(sig);

#else
   
   ui_cleanup();
   
   fprintf(stderr, "Ooops ! This shouldn't happen...");
   fprintf(stderr, "Segmentation fault !");
   fprintf(stderr, "Please recompile in debug mode and send a bugreport");
   
   exit(666);
#endif
}



RETSIGTYPE signal_TERM(int sig)
{
   ui_cleanup();
   
   #ifdef HAVE_STRSIGNAL
      DEBUG_MSG("Signal handler... (caught SIGNAL: %d) | %s", sig, strsignal(sig));
   #else
      DEBUG_MSG("Signal handler... (caught SIGNAL: %d)", sig);
   #endif

   if (sig == SIGINT) {
      fprintf(stderr, "\n\nUser requested a CTRL+C... (deprecated, next time use 'q')\n\n");
   } else {
   #ifdef HAVE_STRSIGNAL
      fprintf(stderr, "\n\n Shutting down %s (received SIGNAL: %d | %s)\n\n", GBL_PROGRAM, sig, strsignal(sig));
   #else
      fprintf(stderr, "\n\n Shutting down %s (received SIGNAL: %d)\n\n", GBL_PROGRAM, sig);
   #endif
   }
   
   signal(sig, SIG_IGN);

   clean_exit(0);

}


/* EOF */

// vim:ts=3:expandtab

