#ifndef ETTERCAP_LUA_H
#define ETTERCAP_LUA_H
#include <ec_packet.h>
#define ETTERCAP_LUA_MODULE "ettercap"
#define ETTERCAP_C_API_LUA_MODULE "ettercap_c"

EC_API_EXTERN int ec_lua_init();
EC_API_EXTERN int ec_lua_fini();
EC_API_EXTERN int ec_lua_cli_add_script(char * script);
EC_API_EXTERN int ec_lua_cli_add_args(char * args);
EC_API_EXTERN void ec_lua_print_info(FILE* debug_file);
EC_API_EXTERN void ec_lua_print_version(FILE* debug_file);
int ec_lua_dispatch_hooked_packet(int point, struct packet_object * po);
void ec_lua_print_stack(FILE * io);

#define LUA_FATAL_ERROR(x, ...) do { fprintf(stderr, x, ## __VA_ARGS__ ); exit(-1);} while(0)

#endif
