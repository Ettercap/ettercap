/*
    ettercap -- global variables handling module

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

#include <ec_libettercap.h>
#include <ec_globals.h>
#include <ec_conf.h>
#include <ec_ui.h>
#include <ec_file.h>
/* global vars */

/* proto */

/*******************************************/

void libettercap_init(char* program, char* version)
{
   ec_globals_alloc();
   EC_GBL_PROGRAM = strdup(program);
   EC_GBL_VERSION = strdup(version);
   SAFE_CALLOC(EC_GBL_DEBUG_FILE, strlen(EC_GBL_PROGRAM) + strlen("-") + 
         strlen(EC_GBL_VERSION) + strlen("_debug.log") + 1, sizeof(char));
   sprintf(EC_GBL_DEBUG_FILE, "%s-%s_debug.log", EC_GBL_PROGRAM, EC_GBL_VERSION);

   DEBUG_INIT();
}

void libettercap_load_conf(void)
{
   /* load the configuration file */
   load_conf();
}

void libettercap_ui_init()
{
   /* initialize the user interface */
   ui_init();
}

void libettercap_ui_start()
{
   /* start the actual user interface */
   ui_start();
}

void libettercap_ui_cleanup()
{
   /* shutdown the user interface */
   ui_cleanup();
}
/* EOF */

// vim:ts=3:expandtab
