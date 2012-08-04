/*
    dynamic_ruby -- ettercap plugin -- it does nothig !
                                only demostrates how to write a plugin !

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

    $Id: dynamic_ruby.c,v 1.10 2004/03/19 13:55:02 alor Exp $
*/


#include <ec.h>                        /* required for global variables */
#include <ec_plugins.h>                /* required for plugin ops */
#include <ec_hook.h>

#include "ruby_swig.h"
#include "ruby.h"

#include <stdlib.h>
#include <string.h>

/* prototypes is required for -Wmissing-prototypes */

/* 
 * this function must be present.
 * it is the entry point of the plugin 
 */
int plugin_load(void *);

/* additional functions */
static int dynamic_ruby_init(void *);
static int dynamic_ruby_fini(void *);
static void dynamic_ruby_handle_dns(struct packet_object *);
static void dynamic_ruby_handle_http(struct packet_object *);
static void dynamic_ruby_handle_eth(struct packet_object *);

void Init_ettercap(void);

// swig_type_info* _p_swigt__p_packet_object;

/* plugin operations */

struct plugin_ops dynamic_ruby_ops = { 
   /* ettercap version MUST be the global EC_VERSION */
   .ettercap_version =  EC_VERSION,                        
   /* the name of the plugin */
   .name =              "dynamic_ruby",  
    /* a short description of the plugin (max 50 chars) */                    
   .info =              "A plugin template (for developers)",  
   /* the plugin version. */ 
   .version =           "3.0",   
   /* activation function */
   .init =              &dynamic_ruby_init,
   /* deactivation function */                     
   .fini =              &dynamic_ruby_fini,
};

/**********************************************************/

/* this function is called on plugin load */
int plugin_load(void *handle) 
{
   DEBUG_MSG("dynamic_ruby plugin load function");
   /*
    *  in this fuction we MUST call the registration procedure that will set
    *  up the plugin according to the plugin_ops structure.
    *  the returned value MUST be the same as plugin_register()
    *  the opaque pointer params MUST be passed to plugin_register()
    */
   return plugin_register(handle, &dynamic_ruby_ops);
}

/*********************************************************/

static int dynamic_ruby_init(void *dynamic_ruby) 
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

    USER_MSG("DYNAMIC_RUBY: plugin running...\n");
    ruby_init();
    ruby_init_loadpath();
    Init_ettercap();
    rb_load_file("hello.rb");
    ruby_exec();

    hook_add(HOOK_PROTO_DNS, &dynamic_ruby_handle_dns);
    hook_add(HOOK_PROTO_HTTP, &dynamic_ruby_handle_http);
    hook_add(HOOK_PACKET_ETH, &dynamic_ruby_handle_eth);
   /* return PLUGIN_FINISHED if the plugin has terminated
    * its execution.
    * return PLUGIN_RUNNING if it has spawned a thread or it
    * is hooked to an ettercap hookpoint and
    * it needs to be deactivated with the fini method.
    */
    return PLUGIN_RUNNING;
}


static int dynamic_ruby_fini(void *dynamic_ruby) 
{
   /* 
    * called to terminate a plugin.
    * usually to kill threads created in the 
    * init function or to remove hook added 
    * previously.
    */
    USER_MSG("DYNAMIC_RUBY: plugin finalization\n");
    ruby_finalize();
    hook_del(HOOK_PROTO_DNS, &dynamic_ruby_handle_dns);
    hook_del(HOOK_PROTO_HTTP, &dynamic_ruby_handle_http);
    hook_del(HOOK_PACKET_ETH, &dynamic_ruby_handle_eth);
    return PLUGIN_FINISHED;
}

static void dynamic_ruby_handle_dns(struct packet_object *po)
{
}

static void dynamic_ruby_handle_http(struct packet_object *po)
{
}

static void dynamic_ruby_handle_eth(struct packet_object *po)
{
}

/* EOF */

// vim:ts=3:expandtab



