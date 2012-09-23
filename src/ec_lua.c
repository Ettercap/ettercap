/*
    ec_lua -- LUA integration

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

    $Id: ec_lua.c,v 1.10 2004/03/19 13:55:02 alor Exp $
*/


#include <ec.h>                        /* required for global variables */
#include <ec_hook.h>
#include <ec_lua.h>
#include <ec_error.h>
#include <ec_packet.h>
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

#include <stdlib.h>
#include <string.h>


/* additional functions */
lua_State* _lua_state;
int _lua_script_count = 0;
char **_lua_scripts = NULL;
int _lua_arg_count = 0;
char **_lua_args = NULL;

/*********************************************************/

EC_API_EXTERN int ec_lua_init() 
{
    int i = 0;
    DEBUG_MSG("EC_LUA: ec_lua_init started...");

    if (_lua_script_count == 0) {
      // We've got no scripts to load, so there's no reason to start up.
      USER_MSG("Lua: no scripts were specified, not starting up!");
      return 0;
    }

    // Initialize lua
    if ((_lua_state = luaL_newstate()) == NULL) 
    {
      // Lua failed to initialize! 
      LUA_FATAL_ERROR("EC_LUA: Failed to initialize LUA instance!");
    }

    // Set up the 'panic' handler, which let's us control 
    lua_atpanic(_lua_state, ec_lua_panic);

    /* load lua libraries */
    luaL_openlibs(_lua_state);
    luaopen_ettercap_c(_lua_state);

    /* Now load the lua files */
    int dofile_err_code = luaL_dofile(_lua_state, INSTALL_LUA_INIT);

    if (dofile_err_code == 0) {
      DEBUG_MSG("EC_LUA: initialized %s", INSTALL_LUA_INIT);
    } else {
      // We just error out of the whole process..
      LUA_FATAL_ERROR("EC_LUA Failed to initialize %s. Error %d: %s\n", 
          INSTALL_LUA_INIT, dofile_err_code, lua_tostring(_lua_state, -1));
    }
    
    // Push an array of the list of scripts specified on the command line
    // we don't have args yet, but that should be next
    lua_getglobal(_lua_state,ETTERCAP_LUA_MODULE);
    lua_getfield(_lua_state, -1, "main");

    lua_newtable(_lua_state); // lua_scripts
    for(i = 0; i < _lua_script_count; i++)
    {
      lua_pushstring(_lua_state,_lua_scripts[i]);
      lua_rawseti(_lua_state,-2, i+1);
    }

    lua_newtable(_lua_state);  // lua_args
    for(i = 0; i < _lua_arg_count; i++)
    {
      lua_pushstring(_lua_state, _lua_args[i]);
      lua_rawseti(_lua_state,-2, i+1);
    }
    int err_code = lua_pcall(_lua_state,2,0,0);

    if (err_code != 0)
    {
      // Flush all messages so we can see where we are.
      ui_msg_flush(MSG_ALL);
      LUA_FATAL_ERROR("EC_LUA script load failed with error %d: \n\t%s\n", err_code,
                lua_tostring(_lua_state, -1));
    }

    USER_MSG("Lua initialized!");
    return 0;
}

EC_API_EXTERN int ec_lua_cli_add_script(char * script) 
{
    if (_lua_script_count == 0) 
        SAFE_CALLOC(_lua_scripts,1,sizeof(char *));
    else
        SAFE_REALLOC(_lua_scripts, (_lua_script_count + 1) * sizeof(char *));
    
    _lua_scripts[_lua_script_count] = script;
    _lua_script_count = _lua_script_count + 1;
    return 0;
}

EC_API_EXTERN int ec_lua_cli_add_args(char * args) 
{
    if (_lua_arg_count == 0) 
        SAFE_CALLOC(_lua_args, 1, sizeof(char *));
    else
        SAFE_REALLOC(_lua_args, (_lua_arg_count + 1) * sizeof(char *));

    _lua_args[_lua_arg_count] = args;
    _lua_arg_count = _lua_arg_count + 1;
    return 0;
}

EC_API_EXTERN int ec_lua_load_script(const char * name) 
{
    lua_getglobal(_lua_state,ETTERCAP_LUA_MODULE);
    lua_getfield(_lua_state, -1, "load_script");
    lua_pushstring(_lua_state, name);
    lua_call(_lua_state,1,0);

    return 0;
}

EC_API_EXTERN int ec_lua_fini() 
{
   /* 
    * called to terminate a plugin.
    * usually to kill threads created in the 
    * init function or to remove hook added 
    * previously.
    */
    DEBUG_MSG("EC_LUA: cleanup started...");
    /* cleanup Lua */
    if (_lua_state != NULL) {
      lua_getglobal(_lua_state,ETTERCAP_LUA_MODULE);
      lua_getfield(_lua_state, -1, "cleanup");
      int err_code = lua_pcall(_lua_state,0,0,0);
      if (err_code == 0) 
      {
        // Close things down all nice-nice.
        lua_close(_lua_state);
      }
      else
      {
        // Let's make sure all the messages are flushed so we can see where 
        // we are at.
        ui_msg_flush(MSG_ALL);
        
        // Dump our error and exit. We can't continue on becuase it is very
        // possible that we still have hooks dangling around out there, and
        // if we're only partially handling things then we could very well
        // get segfaults and such.
        FATAL_ERROR("EC_LUA: cleanup failed with error %d: %s\n", err_code, 
                  lua_tostring(_lua_state, -1));
      }
    }
    else 
    {
      DEBUG_MSG("EC_LUA: cleanup No cleanup needed! Lua wasn't even loaded.");
    }

    _lua_state = NULL;
    USER_MSG("Lua cleanup complete!");
    return 0;
}

// Handles 'panic' errors in the event that lua freaks out at some point.
// This just let's us handle things the "ettercap" way, if need be.
int ec_lua_panic(lua_State * state)
{
  const char *err_msg = lua_tostring(state, 1);
  LUA_FATAL_ERROR("EC_LUA: Unprotected error from LUA runtime: %s\n", err_msg);
  return 0;
}


// Passes the hooked packet into Lua, along with its hook point.
int ec_lua_dispatch_hooked_packet(int point, struct packet_object * po)
{
  // Don't have to do anything if we don't have a state.
  if (_lua_state == NULL)
    return 0;

  // For now, we dispatch all packets into Lua. Once we implement l_hook_add,
  // we can start filtering things down to only those packets that need 
  // dispatching.
  lua_getglobal(_lua_state,ETTERCAP_LUA_MODULE);
  lua_getfield(_lua_state, -1, "dispatch_hook");
  lua_pushinteger(_lua_state, point);
  lua_pushlightuserdata(_lua_state, (void *) po);
  int err_code = lua_pcall(_lua_state,2,0,0);
  if (err_code != 0) {
    // We just error out of the whole process..
    LUA_FATAL_ERROR("EC_LUA ec_lua_dispatch_hooked_packet Failed. Error %d: %s\n", 
        err_code, lua_tostring(_lua_state, -1));
  }
  return 0;
}


/// Lua APIs

// This is called when a hook is added in lua-land. We'll use this in the 
// near future to make our dispatching to lua much more efficient. 
static int l_hook_add(lua_State* state)
{
  USER_MSG("hook_add called from lua!\n");
  return 0;
}

static const struct luaL_reg ec_lua_lib[] = {
  {"hook_add", l_hook_add},
  {NULL, NULL}
};

LUALIB_API int luaopen_ettercap_c(lua_State *L) 
{
  luaL_register(L, ETTERCAP_C_API_LUA_MODULE, ec_lua_lib);
  return 1;
}


/* EOF */

// vim:ts=3:expandtab


