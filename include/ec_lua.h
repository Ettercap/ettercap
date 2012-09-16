#ifndef EC_LUA_H
#define EC_LUA_H
EC_API_EXTERN int ec_lua_init();
EC_API_EXTERN int ec_lua_fini();
EC_API_EXTERN int ec_lua_load_script(const char * name);

#endif
