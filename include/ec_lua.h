#ifndef EC_LUA_H
#define EC_LUA_H
#include "lua.h"
EC_API_EXTERN int ec_lua_init();
EC_API_EXTERN int ec_lua_fini();
EC_API_EXTERN int ec_lua_load_script(const char * name);
int ec_lua_panic(lua_State * state);
char **lua_scripts;
char *lua_args;

#endif
