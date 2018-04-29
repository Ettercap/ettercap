/*
    etterlog -- log analyzer for ettercap log file 

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

#include <el.h>
#include <ec_libettercap.h>
#include <el_functions.h>

#include <fcntl.h>

#define EL_GBL_FREE(x) do{ if (x != NULL) { free(x); x = NULL; } }while(0)

/* global options */
struct ec_globals *ec_gbls;
struct el_globals *el_gbls;

/*******************************************/

int main(int argc, char *argv[])
{
   int ret;
   libettercap_init(PROGRAM, EC_VERSION);
   select_text_interface();
   libettercap_ui_init();
   el_globals_alloc();
   /* etterlog copyright */
   USER_MSG("\n" EC_COLOR_BOLD "%s %s" EC_COLOR_END " copyright %s %s\n\n", 
                      PROGRAM, EC_VERSION, EC_COPYRIGHT, EC_AUTHORS);
  
  
   /* allocate the global target */
   SAFE_CALLOC(EL_GBL_TARGET, 1, sizeof(struct target_env));
  
   /* initialize to all target */
   EL_GBL_TARGET->all_mac = 1;
   EL_GBL_TARGET->all_ip = 1;
#ifdef WITH_IPV6
   EL_GBL_TARGET->all_ip6 = 1;
#endif
   EL_GBL_TARGET->all_port = 1;
   
   /* getopt related parsing...  */
   parse_options(argc, argv);

   /* get the global header */
   ret = get_header(&EL_GBL->hdr);
   if (ret == -E_INVALID)
      FATAL_ERROR("Invalid log file");
   
   USER_MSG("Log file version    : %s\n", EL_GBL->hdr.version);
   /* display the date. ec_ctime() has no newline at end. */
#if defined OS_DARWIN
   USER_MSG("Timestamp           : %s [%d]\n", ec_ctime(&EL_GBL->hdr.tv), EL_GBL->hdr.tv.tv_usec);
#else
   USER_MSG("Timestamp           : %s [%lu]\n", ec_ctime(&EL_GBL->hdr.tv), EL_GBL->hdr.tv.tv_usec);
#endif
   USER_MSG("Type                : %s\n\n", (EL_GBL->hdr.type == LOG_PACKET) ? "LOG_PACKET" : "LOG_INFO" );
  
   
   /* analyze the logfile */
   if (EL_GBL_OPTIONS->analyze)
      analyze();

   /* rewind the log file and skip the global header */
   gzrewind(EL_GBL_LOG_FD);
   get_header(&EL_GBL->hdr);
   
   /* create the connection table (respecting the filters) */
   if (EL_GBL_OPTIONS->connections)
      conn_table_create();

   /* display the connection table */
   if (EL_GBL_OPTIONS->connections && !EL_GBL_OPTIONS->decode)
      conn_table_display();

   /* extract files from the connections */
   if (EL_GBL_OPTIONS->decode)
      conn_decode();
   
   /* not interested in the content... only analysis */
   if (EL_GBL_OPTIONS->analyze || EL_GBL_OPTIONS->connections)
      el_exit(0);
   
   /* display the content of the logfile */
   display();
   
   el_exit(0);
}

/* ANSI color escapes */

void set_color(int color)
{
   /* windows does not like ansi colors... */
#ifndef OS_WINDOWS   
   char str[8];
   
   sprintf(str, "\033[%dm", color);
   fflush(stdout);
   write(fileno(stdout), str, strlen(str));
#endif
}

/* reset the color to default */

void reset_color(void)
{
   /* windows does not like ansi colors... */
#ifndef OS_WINDOWS   
   fflush(stdout);
   write(fileno(stdout), EC_COLOR_END, 4);   
#endif
}

void el_globals_alloc(void)
{

   SAFE_CALLOC(el_gbls, 1, sizeof(struct el_globals));
   SAFE_CALLOC(el_gbls->options, 1, sizeof(struct el_options));
   SAFE_CALLOC(el_gbls->regex, 1, sizeof(regex_t));
   SAFE_CALLOC(el_gbls->t, 1, sizeof(struct target_env));

   return;
}

void el_globals_free(void)
{
   SAFE_FREE(el_gbls->user);
   SAFE_FREE(el_gbls->logfile);
   SAFE_FREE(el_gbls->options);
   SAFE_FREE(el_gbls->regex);
   SAFE_FREE(el_gbls->t);
   
   SAFE_FREE(el_gbls);

   return;

}

void el_exit(int code)
{
   libettercap_ui_cleanup();
   el_globals_free();
   exit(code);
}

// vim:ts=3:expandtab

