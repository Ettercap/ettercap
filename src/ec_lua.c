/*
    ec_lua -- ettercap plugin -- it does nothig !
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

    $Id: ec_lua.c,v 1.10 2004/03/19 13:55:02 alor Exp $
*/


#include <ec.h>                        /* required for global variables */
#include <ec_plugins.h>                /* required for plugin ops */
#include <ec_hook.h>
#include <ec_lua.h>
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

#include <stdlib.h>
#include <string.h>


/* additional functions */
lua_State* _lua_state;

/*********************************************************/

EC_API_EXTERN int ec_lua_init() 
{
  char filename[2048];
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

    USER_MSG("EC_LUA: plugin running...\n");
    // Initialize lua
    _lua_state = luaL_newstate();
    /* load lua libraries */
    luaL_openlibs(_lua_state);

    /* Temp hack, create the path to the the ec_helpers file */
    sprintf(filename,"%s/%s/lib/%s",INSTALL_DATADIR, EC_PROGRAM,"ec_helpers.lua");

    /* Now load the lua files */
    int dofile = luaL_dofile(_lua_state, filename);

    if (dofile == 0) {
      USER_MSG("EC_LUA: loaded ec_helpers.lua \n");
    } else {
      USER_MSG("EC_LUA: Failed to load ec_helpers.lua \n");
      lua_close(_lua_state);
      _lua_state = NULL;
      return PLUGIN_FINISHED;
    }
   /* return PLUGIN_FINISHED if the plugin has terminated
    * its execution.
    * return PLUGIN_RUNNING if it has spawned a thread or it
    * is hooked to an ettercap hookpoint and
    * it needs to be deactivated with the fini method.
    */
    return PLUGIN_RUNNING;
}


EC_API_EXTERN int ec_lua_fini() 
{
   /* 
    * called to terminate a plugin.
    * usually to kill threads created in the 
    * init function or to remove hook added 
    * previously.
    */
    USER_MSG("EC_LUA: plugin finalization\n");
    /* cleanup Lua */
    if (_lua_state) {
      lua_getglobal(_lua_state,"Ettercap");
      lua_getfield(_lua_state, -1, "cleanup");
      lua_call(_lua_state,0,0);
      lua_close(_lua_state);
    }
    _lua_state = NULL;
    return PLUGIN_FINISHED;
}


/* EOF */

// vim:ts=3:expandtab


