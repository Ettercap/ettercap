#ifndef EC_LUA_H
#define EC_LUA_H
#include <ec_packet.h>
#include "lua.h"
EC_API_EXTERN int ec_lua_init();
EC_API_EXTERN int ec_lua_fini();
EC_API_EXTERN int ec_lua_load_script(const char * name);
LUALIB_API int luaopen_ec_lua(lua_State *L);
int ec_lua_dispatch_hooked_packet(int point, struct packet_object * po);
int ec_lua_panic(lua_State * state);
char **lua_scripts;
char *lua_args;

#endif
