/*
    dummy -- ettercap plugin -- it does nothig !
                                only demostrates how to write a plugin !

    Copyright (C) 2001  ALoR <alor@users.sourceforge.net>, NaGA <crwm@freemail.it>
    
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

    $Id: dummy.c,v 1.1 2003/03/08 13:53:38 alor Exp $
*/


#include <ec.h>                        /* required for global variables */
#include <ec_version.h>
#include <ec_plugins.h>                /* required for input/output and plugin ops*/

#include <stdlib.h>
#include <string.h>

// protos...

int Plugin_Init(void *);               /* prototypes is required for -Wmissing-prototypes */
int Plugin_Fini(void *);
int dummy_function(void *dummy);

// global variables

char *dummy_message;

// plugin operation

struct plugin_ops dummy_ops = {
   ettercap_version: VERSION,                            /* ettercap version MUST be the global VERSION */
   plug_info:        "Dummy plugin. It does nothing !",  /* a short description of the plugin (max 50 chars) */
   plug_version:     20,                                 /* the plugin version. note: 15 will be displayed as 1.5 */
   plug_type:        PT_EXT,                             /* the pluging type: external (PT_EXT) or hooking (PT_HOOK) */
   hook_point:       HOOK_NONE,                          /* the hook point */
   hook_function:    &dummy_function,                    /* function to be executed */
};

//==================================

int Plugin_Init(void *params)                            /* this function is called on plugin load */
{
   /*
    *  here we can inizialize our structures or global variables
    */

   dummy_message = strdup("\nThis plugin does nothing !\n\nIt is only a template...\n\n");

   /*
    *  in this fuction we MUST call the registration procedure that will set
    *  up the plugin according to the plugin_ops structure.
    *  the returned value MUST be the same as Plugin_Register()
    *  the opaque pointer params MUST be passed to Plugin_Register()
    */
   return Plugin_Register(params, &dummy_ops);
}

int Plugin_Fini(void *params)                            /* this function is called on plugin unload */
{
   /*
    *  no Input Output is admitted in this function !!
    *  here we can free our resource...
    */
   free(dummy_message);

   return 0;
}

// =================================

int dummy_function(void *dummy)                          /* required: hooking function */
{

   Plugin_Output("\n%s\n\n", dummy_message);

   return 0;
}

/* EOF */
