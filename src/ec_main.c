/*
    ettercap -- everything start from this file... 

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

    $Header: /home/drizzt/dev/sources/ettercap.cvs/ettercap_ng/src/ec_main.c,v 1.30 2003/08/28 19:55:20 alor Exp $
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
#include <ec_plugins.h>
#include <ec_fingerprint.h>
#include <ec_manuf.h>
#include <ec_services.h>
#include <ec_scan.h>
#include <ec_ui.h>
#include <ec_conf.h>
#include <ec_conntrack.h>
#include <ec_mitm.h>

/* global vars */


/* protos */

static void drop_privs(void);
void clean_exit(int errcode);

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
   GBL_DEBUG_FILE = calloc(1, strlen(EC_PROGRAM) + strlen(EC_VERSION) + strlen("_debug.log") + 1);
   ON_ERROR(GBL_DEBUG_FILE, NULL, "can't allocate debug filename");
   sprintf(GBL_DEBUG_FILE, "%s%s_debug.log", GBL_PROGRAM, EC_VERSION);
   
   DEBUG_INIT();
   DEBUG_MSG("main -- here we go !!");
   
   /* register the main thread as "init" */
   ec_thread_register(EC_SELF, "init", "initialization phase");
   
   /* activate the signal handler */
   signal_handler();
   
   /* ettercap copyright */
   fprintf(stdout, "\n\033[01m\033[1m%s %s\033[0m copyright %s %s\n\n", 
         GBL_PROGRAM, GBL_VERSION, EC_COPYRIGHT, EC_AUTHORS);
   
   /* getopt related parsing...  */
   parse_options(argc, argv);

   /* load the configuration file */
   load_conf();
   
   /* initialize the user interface */
   ui_init();

   /* initialize libpcap */
   capture_init();

   /* initialize libnet */
   send_init();
 
   /* get hardware infos */
   get_hw_info();
  
   /* 
    * always disable the kernel ip forwarding (except when reading from file).
    * the forwarding will be done by ettercap.
    */
   if (!GBL_OPTIONS->read || GBL_OPTIONS->unoffensive)
      disable_ip_forward();
   
   /* 
    * drop root priviledges 
    * we have alread opened the sockets with high priviledges
    * we don't need any more root privs.
    */
   drop_privs();

/***** !! NO PRIVS AFTER THIS POINT !! *****/

   /* load all the plugins */
   plugin_load_all();

   /* print how many dissectors were loaded */
   conf_dissectors();
   
   /* load the mac-fingerprints */
   manuf_init();

   /* load the tcp-fingerprints */
   fingerprint_init();
   
   /* load the services names */
   services_init();
  
   /* print all the buffered messages */
   USER_MSG("\n");
   ui_msg_flush(MSG_ALL);

/**** INITIALIZATION PHASE TERMINATED ****/
   
   /* build the list of active hosts */
   if (GBL_SNIFF->type != SM_BRIDGED)
      build_hosts_list();

   /* start the mitm attack */
   mitm_start();
   
   /* initialize the sniffing method */
   EXECUTE(GBL_SNIFF->start);
  
   /* create the dispatcher thread */
   ec_thread_new("top_half", "dispatching module", &top_half, NULL);

   /* create the timeouter thread */
   ec_thread_new("timer", "conntrack timeouter", &conntrack_timeouter, NULL);
   
   /* this thread becomes the UI then displays it */
   ec_thread_register(EC_SELF, GBL_PROGRAM, "the user interface");
   ui_start();

/******************************************** 
 * reached only when the UI is shutted down 
 ********************************************/

   /* flush the exit message */
   ui_msg_flush(1);
   
   /* stop the mitm attack */
   mitm_stop();

   /* terminate the sniffing engine */
   EXECUTE(GBL_SNIFF->cleanup);
   
   /* kill all the running threads but the current */
   ec_thread_kill_all();
  
   /* clean up the UI */
   ui_cleanup();

   return 0;
}


/* drop root privs */

static void drop_privs(void)
{
   u_int uid;
   char *var;

   /* are we root ? */
   if (getuid() != 0)
      return;

   /* get the env variable for the UID to drop privs to */
   var = getenv("EC_UID");
   
   /* if the EC_UID variable is not set, default to DROP_TO_UID (nobody) */
   if (var != NULL)
      uid = atoi(var);
   else
      uid = GBL_CONF->ec_uid;
   
   DEBUG_MSG("drop_privs: setuid(%d)", uid);
   
   /* drop to a good uid ;) */
   if ( setuid(uid) < 0)
      ERROR_MSG("setuid()");

   DEBUG_MSG("privs: %d %d", getuid(), geteuid() );
   USER_MSG("Priviledges dropped to UID %d...\n\n", getuid() ); 
}


/*
 * cleanly exit from the program
 */

void clean_exit(int errcode)
{
   DEBUG_MSG("clean_exit: %d", errcode);
  
   GBL_LOCK = 1;
   
   USER_MSG("\n\nTerminating %s...\n\n", GBL_PROGRAM);

   /* close the UI */
   ui_cleanup();

   exit(errcode);
}


/* EOF */


// vim:ts=3:expandtab

