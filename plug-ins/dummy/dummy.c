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

    $Id: dummy.c,v 1.4 2003/03/22 15:41:21 alor Exp $
*/


#include <ec.h>                        /* required for global variables */
#include <ec_plugins.h>                /* required for plugin ops */

#include <stdlib.h>
#include <string.h>

/* prototypes is required for -Wmissing-prototypes */

/* 
 * this function must be present.
 * it is the entry point of the plugin 
 */
int plugin_load(void *);

/* additional functions */
int dummy_init(void *);
int dummy_fini(void *);


/* plugin operations */

struct plugin_ops dummy_ops = { 
   /* ettercap version MUST be the global EC_VERSION */
   ettercap_version: EC_VERSION,                        
   /* the name of the plugin */
   name:             "dummy",  
    /* a short description of the plugin (max 50 chars) */                    
   info:             "Only a standalone plugin template",  
   /* the plugin version. note: 15 will be displayed as 1.5 */                    
   version:          "3.0",   
   /* the pluging type: PL_STANDALONE or PL_HOOK */                    
   type:             PL_STANDALONE,
   /* activation function */
   init:             &dummy_init,
   /* deactivation function */                     
   fini:             &dummy_fini,
};

/**********************************************************/

/* this function is called on plugin load */
int plugin_load(void *handle) 
{
   DEBUG_MSG("dummy plugin load function");
   /*
    *  in this fuction we MUST call the registration procedure that will set
    *  up the plugin according to the plugin_ops structure.
    *  the returned value MUST be the same as plugin_register()
    *  the opaque pointer params MUST be passed to plugin_register()
    */
   return plugin_register(handle, &dummy_ops);
}

/*********************************************************/

int dummy_init(void *dummy) 
{
   /* the control is given to this function
    * and ettercap is suspended until its return.
    * 
    * you can create a thread and return immediately
    * and then kill it in the fini function.
    *
    * you can also set an hook point with
    * hook_add(), in this case you have to set the
    * plugin type to PL_HOOK.
    */
   
   USER_MSG("DUMMY: plugin initialized\n");
   return 0;
}


int dummy_fini(void *dummy) 
{
   /* called to terminate a plugin.
    * usually to kill threads created in the 
    * init function or to remove hook added 
    * previously.
    */
   USER_MSG("DUMMY: plugin terminated\n");
   return 0;
}


/* EOF */

