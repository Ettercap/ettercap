/*
    ettercap -- everything start from this file... 

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

    $Header: /home/drizzt/dev/sources/ettercap.cvs/ettercap_ng/src/ec_main.c,v 1.1 2003/03/08 13:53:38 alor Exp $
*/

#include <ec.h>
#include <ec_version.h>
#include <ec_globals.h>
#include <ec_signals.h>
#include <ec_parser.h>
#include <ec_threads.h>
#include <ec_capture.h>
#include <ec_dispatcher.h>
#include <ec_send.h>
#include <ec_inet.h>
#include <ec_ui.h>

/* global vars */


/* protos */

void drop_privs(void);

/*******************************************/

int main(int argc, char *argv[])
{
   /*
    * Alloc the global structures
    * We can access these structs via the macro in ec_globals.h
    */
        
   globals_alloc();
  
   GBL_PROGRAM = strdup(EC_PROGRAM);
   GBL_VERSION = strdup(EC_VERSION);
   GBL_DEBUG_FILE = calloc(1, strlen(EC_PROGRAM) + strlen("_debug.log") + 1);
   ON_ERROR(GBL_DEBUG_FILE, NULL, "can't allocate debug filename");
   sprintf(GBL_DEBUG_FILE, "%s_debug.log", GBL_PROGRAM);
   
   DEBUG_INIT();
   DEBUG_MSG("main -- here we go !!");
   
   /* activate the signal handler */
   signal_handler();
   
   /* getopt related parsing...  */
   parse_options(argc, argv);
  
   /* ettercap copyright */
   fprintf(stdout, "\n\033[01m\033[1m%s %s\033[0m copyright %s %s\n\n", 
         GBL_PROGRAM, GBL_VERSION, EC_COPYRIGHT, EC_AUTHORS);

   /* initialize the user interface */
   ui_init();

   /* initialize libpcap */
   capture_init();

   /* initialize libnet */
   send_init();
 
   /* get hardware infos */
   get_hw_info();
   
   /* 
    * drop root priviledges 
    * we have alread opened the sockets with high priviledges
    * we don't need any more root privs.
    */
   drop_privs();
  
   /* load the mac-fingerprints */
//   manuf_init();

   /* load the tcp-fingerprints */
//   fingerprint_init();
   
/**** INITIALIZATION PHASE TERMINATED ****/
   
   /* initialize the sniffing method */
   EXECUTE(GBL_SNIFF->start);
  
   /* create the dispatched thread */
   ec_thread_new("top_half", "dispatching module", &top_half, NULL);
   
   /* this thread becomes the UI then displays it */
   ec_thread_register(EC_SELF, "UI", "the user interface");
   ui_start();

/******************************************** 
 * reached only when the UI is shutted down 
 ********************************************/

   /* terminate the sniffing engine */
   EXECUTE(GBL_SNIFF->cleanup);
   
   /* kill all the running threads but the current */
   ec_thread_kill_all();
  
   /* clean up the UI */
   ui_cleanup();

   return 0;
}


/* drop root privs */

void drop_privs(void)
{
   DEBUG_MSG("drop_privs: setuid(%d)", DROP_TO_UID);
   
   /* drop to a good uid ;) */
   if ( setuid(DROP_TO_UID) < 0)
      ERROR_MSG("setuid()");

   if (setuid(0) == 0)
      FATAL_MSG("Privs weren't dropped !!");
   
   DEBUG_MSG("privs: %d %d", getuid(), geteuid() );
   
}



/* EOF */


// vim:ts=3:expandtab

