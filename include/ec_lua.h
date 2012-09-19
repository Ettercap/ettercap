#ifndef EC_LUA_H
#define EC_LUA_H
#include <ec_packet.h>
#include "lua.h"
EC_API_EXTERN int ec_lua_init();
EC_API_EXTERN int ec_lua_fini();
EC_API_EXTERN int ec_lua_cli_add_script(char * script);
EC_API_EXTERN int ec_lua_cli_add_args(char * args);
LUALIB_API int luaopen_ettercap(lua_State *L);
int ec_lua_dispatch_hooked_packet(int point, struct packet_object * po);
int ec_lua_panic(lua_State * state);

#define LUA_FATAL_ERROR(x, ...) do { fprintf(stderr, x, ## __VA_ARGS__ ); exit(-1);} while(0)

#endif
