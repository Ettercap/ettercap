#ifndef ETTERCAP_LIBETTERCAP_H
#define ETTERCAP_LIBETTERCAP_H

#include <ec.h>
#include <ec_stdint.h>
#include <ec_version.h>


EC_API_EXTERN void libettercap_init(char* program, char* version);
EC_API_EXTERN void libettercap_load_conf(void);
EC_API_EXTERN void libettercap_ui_init(void);
EC_API_EXTERN void libettercap_ui_start(void);
EC_API_EXTERN void libettercap_ui_cleanup(void);

#endif

/* EOF */

