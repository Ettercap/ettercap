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

    $Id: ec_signals.c,v 1.12 2003/09/25 12:17:46 alor Exp $
*/

#include <ec.h>
#include <ec_ui.h>
#include <ec_mitm.h>

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
   signal_handle(SIGBUS, signal_SEGV, 0);
   signal_handle(SIGINT, signal_TERM, 0);
   signal_handle(SIGTERM, signal_TERM, 0);
   signal_handle(SIGCHLD, SIG_IGN, 0);

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

   if (sig == SIGBUS)
      DEBUG_MSG(" !!! BUS ERROR !!!");
   else
      DEBUG_MSG(" !!! SEGMENTATION FAULT !!!");
   
   ui_cleanup();
   
   fprintf (stderr, "\n"EC_COLOR_YELLOW"Ooops !! This shouldn't happen...\n\n"EC_COLOR_END);
   if (sig == SIGBUS)
      fprintf (stderr, EC_COLOR_RED"Bus error...\n\n"EC_COLOR_END);
   else
      fprintf (stderr, EC_COLOR_RED"Segmentation Fault...\n\n"EC_COLOR_END);

   fprintf (stderr, "===========================================================================\n");
   fprintf (stderr, " To report this error follow these steps:\n\n");
   fprintf (stderr, "  1) set ec_uid to 0 (so the core will be dumped)\n\n");
   fprintf (stderr, "  2) execute ettercap with \"-w debug_dump.pcap\"\n\n");
   fprintf (stderr, "  3) reproduce the critical situation\n\n");
   fprintf (stderr, "  4) make a report : \n\t\"tar zcvf error.tar.gz %s%s_debug.log debug_dump.pcap\"\n\n", GBL_PROGRAM, GBL_VERSION);
   fprintf (stderr, "  5) get the gdb backtrace :\n"
                    "  \t - \"gdb %s core\"\n"
                    "  \t - at the gdb prompt \"bt\"\n"
                    "  \t - at the gdb prompt \"quit\" and return to the shell\n"
                    "  \t - copy and paste this output.\n\n", GBL_PROGRAM);
   fprintf (stderr, "  6) mail us the output of gdb and the error.tar.gz\n");
   fprintf (stderr, "============================================================================\n");
   
   fprintf (stderr, EC_COLOR_CYAN"\nOverriding any 'ulimit -c 0'... (RLIMIT_CORE = RLIM_INFINITY)\n\n"EC_COLOR_END
                    EC_COLOR_BOLD" Core dumping... (use the 'core' file for gdb analysis)\n\n"EC_COLOR_END);
   
   /* force the coredump */
   
   setrlimit(RLIMIT_CORE, &corelimit);
   signal(sig, SIG_DFL);
   raise(sig);

#else
   
   ui_cleanup();
   
   fprintf(stderr, EC_COLOR_YELLOW"Ooops ! This shouldn't happen...\n"EC_COLOR_END);
   if (sig == SIGBUS)
      fprintf (stderr, EC_COLOR_RED"Bus error...\n\n"EC_COLOR_END);
   else
      fprintf (stderr, EC_COLOR_RED"Segmentation Fault...\n\n"EC_COLOR_END);
   fprintf(stderr, "Please recompile in debug mode, reproduce the bug and send a bugreport\n\n");
   
   exit(666);
#endif
}



RETSIGTYPE signal_TERM(int sig)
{
   /* terminate the UI */
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

   /* stop the mitm process (if activated) */
   mitm_stop();
   
   /* perform a clean exit */
   clean_exit(0);

}


/* EOF */

// vim:ts=3:expandtab

