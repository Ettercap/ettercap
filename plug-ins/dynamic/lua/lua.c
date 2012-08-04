/*
    dynamic_lua -- ettercap plugin -- it does nothig !
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

    $Id: dynamic_lua.c,v 1.10 2004/03/19 13:55:02 alor Exp $
*/


#include <ec.h>                        /* required for global variables */
#include <ec_plugins.h>                /* required for plugin ops */
#include <ec_hook.h>

#include "lua_swig.h"

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

#include <stdlib.h>
#include <string.h>

/* prototypes is required for -Wmissing-prototypes */

/* 
 * this function must be present.
 * it is the entry point of the plugin 
 */
int plugin_load(void *);

// This is our lua SWIG interface into ettercap!
extern int luaopen_ettercap(lua_State* L);

/* additional functions */
static int dynamic_lua_init(void *);
static int dynamic_lua_fini(void *);
static void dynamic_lua_handle_dns(struct packet_object *);
static void dynamic_lua_handle_http(struct packet_object *);
static void dynamic_lua_handle_eth(struct packet_object *);

lua_State* _lua_state;
swig_type_info* _p_swigt__p_packet_object;

/* plugin operations */

struct plugin_ops dynamic_lua_ops = { 
   /* ettercap version MUST be the global EC_VERSION */
   .ettercap_version =  EC_VERSION,                        
   /* the name of the plugin */
   .name =              "dynamic_lua",  
    /* a short description of the plugin (max 50 chars) */                    
   .info =              "A plugin template (for developers)",  
   /* the plugin version. */ 
   .version =           "3.0",   
   /* activation function */
   .init =              &dynamic_lua_init,
   /* deactivation function */                     
   .fini =              &dynamic_lua_fini,
};

/**********************************************************/

/* this function is called on plugin load */
int plugin_load(void *handle) 
{
   DEBUG_MSG("dynamic_lua plugin load function");
   /*
    *  in this fuction we MUST call the registration procedure that will set
    *  up the plugin according to the plugin_ops structure.
    *  the returned value MUST be the same as plugin_register()
    *  the opaque pointer params MUST be passed to plugin_register()
    */
   return plugin_register(handle, &dynamic_lua_ops);
}

/*********************************************************/

static int dynamic_lua_init(void *dynamic_lua) 
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

    USER_MSG("DYNAMIC_LUA: plugin running...\n");
    // Initialize lua
    _lua_state = luaL_newstate();
    /* load lua libraries */
    luaL_openlibs(_lua_state);
    luaopen_ettercap(_lua_state);

    /* get pointers to all the different types that we'll be casting from/to */
    _p_swigt__p_packet_object = SWIG_MangledTypeQuery(_lua_state, "_p_packet_object");
    // Create a lua-style version of the object.
    if(_p_swigt__p_packet_object) {
      USER_MSG("WOOO, Got the proper type.\n");
    } else {
      USER_MSG("No dice.\n");
    }
  
    /* Now load the lua files */
    int dofile = luaL_dofile(_lua_state, "hello.lua");

    if (dofile == 0) {
      USER_MSG("DYNAMIC_LUA: Ran hello.lua \n");
    } else {
      USER_MSG("DYNAMIC_LUA: Failed to run hello.lua \n");
      lua_close(_lua_state);
      _lua_state = NULL;
      return PLUGIN_FINISHED;
    }

    hook_add(HOOK_PROTO_DNS, &dynamic_lua_handle_dns);
    hook_add(HOOK_PROTO_HTTP, &dynamic_lua_handle_http);
    hook_add(HOOK_PACKET_ETH, &dynamic_lua_handle_eth);
   /* return PLUGIN_FINISHED if the plugin has terminated
    * its execution.
    * return PLUGIN_RUNNING if it has spawned a thread or it
    * is hooked to an ettercap hookpoint and
    * it needs to be deactivated with the fini method.
    */
    return PLUGIN_RUNNING;
}


static int dynamic_lua_fini(void *dynamic_lua) 
{
   /* 
    * called to terminate a plugin.
    * usually to kill threads created in the 
    * init function or to remove hook added 
    * previously.
    */
    USER_MSG("DYNAMIC_LUA: plugin finalization\n");
    hook_del(HOOK_PROTO_DNS, &dynamic_lua_handle_dns);
    hook_del(HOOK_PROTO_HTTP, &dynamic_lua_handle_http);
    hook_del(HOOK_PACKET_ETH, &dynamic_lua_handle_eth);
    /* cleanup Lua */
    if (_lua_state) {
      lua_close(_lua_state);
    }
    _lua_state = NULL;
    _p_swigt__p_packet_object = NULL;
    return PLUGIN_FINISHED;
}

static void dynamic_lua_handle_dns(struct packet_object *po)
{
    if (_lua_state) {
      lua_getglobal(_lua_state,"handle_dns_packet");

      SWIG_NewPointerObj(_lua_state, (void *) po, _p_swigt__p_packet_object, 0);
      lua_call(_lua_state,1,0);
    }
}

static void dynamic_lua_handle_http(struct packet_object *po)
{
    if (_lua_state) {
      lua_getglobal(_lua_state,"handle_http_packet");

      SWIG_NewPointerObj(_lua_state, (void *) po, _p_swigt__p_packet_object, 0);
      lua_call(_lua_state,1,0);
    }
}

static void dynamic_lua_handle_eth(struct packet_object *po)
{
    if (_lua_state) {
      lua_getglobal(_lua_state,"handle_eth_packet");

      SWIG_NewPointerObj(_lua_state, (void *) po, _p_swigt__p_packet_object, 0);
      lua_call(_lua_state,1,0);
    }
}

/* EOF */

// vim:ts=3:expandtab


