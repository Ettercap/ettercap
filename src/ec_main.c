/*
    ettercap -- everything starts from this file... 

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

*/

#include <ec.h>
#include <ec_version.h>
#include <ec_globals.h>
#include <ec_conf.h>
#include <ec_libettercap.h>
#include <ec_network.h>
#include <ec_signals.h>
#include <ec_parser.h>
#include <ec_threads.h>
#include <ec_capture.h>
#include <ec_dispatcher.h>
#include <ec_send.h>
#include <ec_plugins.h>
#include <ec_format.h>
#include <ec_fingerprint.h>
#include <ec_geoip.h>
#include <ec_manuf.h>
#include <ec_services.h>
#include <ec_http.h>
#include <ec_scan.h>
#include <ec_ui.h>
#include <ec_mitm.h>
#include <ec_sslwrap.h>
#include <ec_utils.h>
#ifdef HAVE_EC_LUA
#include <ec_lua.h>
#endif

/* global vars */

/* protos */

static void time_check(void);

/*******************************************/

int main(int argc, char *argv[])
{
   /*
    * Alloc the global structures
    * We can access these structs via the macro in ec_globals.h
    */
        
   libettercap_init(PROGRAM, EC_VERSION);
   libettercap_load_conf();

   DEBUG_MSG("main -- here we go !!");

   /* initialize the filter mutex */
   filter_init_mutex();
   
   /* register the main thread as "init" */
   ec_thread_register(EC_PTHREAD_SELF, "init", "initialization phase");
   
   /* activate the signal handler */
   signal_handler();
   
#ifdef OS_GNU
  fprintf(stdout,"%s is still not fully supported in this OS because of missing live capture support.", EC_GBL_PROGRAM);
#endif
   /* ettercap copyright */
   fprintf(stdout, "\n" EC_COLOR_BOLD "%s %s" EC_COLOR_END " copyright %s %s\n\n", 
         EC_GBL_PROGRAM, EC_GBL_VERSION, EC_COPYRIGHT, EC_AUTHORS);
   
   /* getopt related parsing...  */
   parse_options(argc, argv);

   /* check the date */
   time_check();

   /* 
    * get the list of available interfaces 
    * 
    * this function will not return if the -I option was
    * specified on command line. it will instead print the
    * list and exit
    */
   capture_getifs();
   
   /* initialize the user interface */
   libettercap_ui_init();
   
   /* initialize the network subsystem */
   network_init();
   
#ifdef HAVE_GEOIP
   /* initialize the GeoIP API */
   if (EC_GBL_CONF->geoip_support_enable)
      geoip_init();
#endif

   /* 
    * always disable the kernel ip forwarding (except when reading from file).
    * the forwarding will be done by ettercap.
    */
   if(!EC_GBL_OPTIONS->read && !EC_GBL_OPTIONS->unoffensive && !EC_GBL_OPTIONS->only_mitm) {
#ifdef WITH_IPV6
      /*
       * disable_ipv6_forward() registers the restore function with atexit() 
       * which relies on the regain_privs_atexit() registered in 
       * disable_ip_forward() below. 
       * So the call of disable_ipv6_forward() must NOT be after the call of 
       * disable_ip_forward().
       */
      disable_ipv6_forward();
#endif
      disable_ip_forward();
	
#ifdef OS_LINUX
      if (!EC_GBL_OPTIONS->read)
      	disable_interface_offload();
#endif
      /* binds ports and set redirect for ssl wrapper */
      if(EC_GBL_SNIFF->type == SM_UNIFIED && EC_GBL_OPTIONS->ssl_mitm)
         ssl_wrap_init();

#if defined OS_LINUX && defined WITH_IPV6
      /* check if privacy extensions are enabled */
      check_tempaddr(EC_GBL_OPTIONS->iface);
#endif
   }
   
   /* 
    * drop root privileges 
    * we have already opened the sockets with high privileges
    * we don't need anymore root privs.
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
   
   /* load http known fileds for user/pass */
   http_fields_init();

#ifdef HAVE_EC_LUA
   /* Initialize lua */
   ec_lua_init();
#endif

   /* set the encoding for the UTF-8 visualization */
   set_utf8_encoding((u_char*)EC_GBL_CONF->utf8_encoding);
  
   /* print all the buffered messages */
   if (EC_GBL_UI->type == UI_TEXT)
      USER_MSG("\n");
   
   ui_msg_flush(MSG_ALL);

/**** INITIALIZATION PHASE TERMINATED ****/
   
   /* 
    * we are interested only in the mitm attack i
    * if entered, this function will not return...
    */
   if (EC_GBL_OPTIONS->only_mitm)
      only_mitm();
   
   /* create the dispatcher thread */
   ec_thread_new("top_half", "dispatching module", &top_half, NULL);

   /* this thread becomes the UI then displays it */
   ec_thread_register(EC_PTHREAD_SELF, EC_GBL_PROGRAM, "the user interface");

   /* start unified sniffing for curses and GTK at startup */
   if ((EC_GBL_UI->type == UI_CURSES || EC_GBL_UI->type == UI_GTK) &&
         EC_GBL_CONF->sniffing_at_startup)
      EXECUTE(EC_GBL_SNIFF->start);

   /* start the actual user interface */
   libettercap_ui_start();

/******************************************** 
 * reached only when the UI is shutted down 
 ********************************************/

   /* Call all the proper stop methods to ensure
    * that no matter what UI was selected, everything is 
    * turned off gracefully */
   clean_exit(0);

   return 0; //Never reaches here
}

static void time_check(void)
{
   /* 
    * a nice easter egg... 
    * just to waste some time of code reviewers... ;) 
    * ALoR, keeping this for you buddy! :)
    *
    * trust me, it's not evil ;) only a boring afternoon, and nothing to do...
    */
   time_t K9=time(NULL);char G5P[1<<6],*o=G5P,*O;uint U4M, _,__=0; char dMG[]= 
   "\n*\n^1U4Mm\x04wW#K\x2e\x0e+X\x7f\f,N'U!I-L5?";struct{char X5T[7];int dMG;
   int U4M;} X5T[]={{"N!WwFr", 0x414c6f52,0},{"S6FfUe", 0x4e614741,0}};sprintf
   (G5P,"%s",ctime(&K9));o+=4;O=strchr(o+4,' ');*O=0; for(U4M=(1<<5)-(1<<2)+1;
   U4M>0;U4M--){dMG[U4M]=dMG[U4M]^dMG[U4M-1];}for(U4M=0;U4M<sizeof(X5T)/sizeof
   (*X5T);U4M++){for(_=(1<<2)+1; _>0;_--){X5T[U4M].X5T[_]=X5T[U4M].X5T[_]^X5T[
   U4M].X5T[_-1];}if(!strcmp(X5T[U4M].X5T,o)){char T0Q[]="\n\0O!M4\x14r\x1doO"
   ";T0Q(\bm\x19m\bz\x19x\b(A2\x12s\x1d=X5T=Q&G5Pp\x03l\n~\th\x1a\x7f_dMG\x06"
   "hH-@" "!H$\x04s\x1av\x1a:X=\x1d|\f|\x0ek\ba\0t\x11u[u[{^-m\fb\x16\x7f\x19"
   "v\x04oA\x2e\\;1;K9\\/\\|9w#f4\x1a\x34\x1a\x1a";for(_=(1<<7)-(1<<3)-(1<<2)+
   1;_>0;_--){T0Q[_]=T0Q[_]^T0Q[_-1];}write(1,dMG,1);while(__++<1<<5)printf(""
   "%c",(1<<5)+(1<<3)+(1<<1));X5T[U4M].dMG=ntohl(X5T[U4M].dMG);printf(dMG,&X5T
   [U4M].dMG);while(--__){printf("%c",(1<<6)-(1<<4)-(1<<3)+(1<<1));}printf(T0Q
   ,&X5T[U4M].dMG);getchar();break;}}
}

/* EOF */

// vim:ts=3:expandtab

