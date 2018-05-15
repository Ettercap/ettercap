/*
    ettercap -- Set functions, for library and UI support

    Copyright (C) Ettercap Development Team

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

*/


#include <ec.h>
#include <ec_sniff.h>
#include <ec_send.h>
#include <ec_log.h>
#include <ec_format.h>
#include <ec_mitm.h>
#include <ec_filter.h>
#include <ec_plugins.h>
#include <ec_conf.h>
#include <ec_strings.h>
#include <ec_encryption.h>
#ifdef HAVE_EC_LUA
#include <ec_lua.h>
#endif

#include <ctype.h>


/* set functions */
void set_mitm(char *mitm) 
{
	EC_GBL_OPTIONS->mitm = 1;
	if(mitm_set(mitm) != E_SUCCESS)
		FATAL_ERROR("MiTM method '%s' not supported...\n", mitm);
}

void set_onlymitm(void)
{
	EC_GBL_OPTIONS->only_mitm = 1;
}

void set_broadcast(void)
{
	EC_GBL_OPTIONS->broadcast = 1;
}

void set_iface_bridge(char *iface)
{
	EC_GBL_OPTIONS->iface_bridge = strdup(iface);
	set_bridge_sniff();
}

void set_promisc(void)
{
	EC_GBL_PCAP->promisc = 0;
}

void set_reversed(void)
{
	EC_GBL_OPTIONS->reversed = 1;
}

void set_plugin(char *name)
{
    struct plugin_list *plugin;

    if(!strcasecmp(name, "list")) {
        plugin_list();
        clean_exit(0);
    }

    SAFE_CALLOC(plugin, 1, sizeof(struct plugin_list));
    plugin->name = strdup(name);
    plugin->exists = true;
    LIST_INSERT_HEAD(&EC_GBL_OPTIONS->plugins, plugin, next);

}

void set_proto(char *proto)
{
	EC_GBL_OPTIONS->proto = strdup(proto);
}

void set_iface(char *iface)
{
	EC_GBL_OPTIONS->iface = strdup(iface);
}

void set_lifaces(void)
{
#ifndef JUST_LIBRARY
	EC_GBL_OPTIONS->lifaces = 1;
#endif
}

void set_secondary(char *iface)
{
	EC_GBL_OPTIONS->secondary = parse_iflist(iface);
}

void set_netmask(char *netmask)
{
	EC_GBL_OPTIONS->netmask = strdup(netmask);
}

void set_address(char *address)
{
	EC_GBL_OPTIONS->address = strdup(address);
}

void set_read_pcap(char *pcap_file)
{
	/* we don't want to scan th eLAN while reading from file */
	EC_GBL_OPTIONS->silent = 1;
	EC_GBL_OPTIONS->read = 1;
	EC_GBL_OPTIONS->pcapfile_in = strdup(pcap_file);
}

void set_write_pcap(char *pcap_file)
{
	EC_GBL_OPTIONS->write = 1;
	EC_GBL_OPTIONS->pcapfile_out = strdup(pcap_file);
}

void set_pcap_filter(char *filter)
{
	EC_GBL_PCAP->filter = strdup(filter);
}

void set_filter(char *end, const char *filter)
{
	uint8_t f_enabled = 1;
	if ( (end-filter >=2) && *(end-2) == ':') {
		*(end-2) = '\0';
		f_enabled = !( *(end-1) == '0' );
	}	
	
	if (filter_load_file(filter, EC_GBL_FILTERS, f_enabled) != E_SUCCESS)
		FATAL_ERROR("Cannot load filter file \"%s\"", filter);
}


void set_loglevel_packet(char *arg)
{
	if (set_loglevel(LOG_PACKET, arg) == -E_FATAL)
		clean_exit(-E_FATAL);
}

void set_loglevel_info(char *arg)
{
	if (set_loglevel(LOG_INFO, arg) == -E_FATAL)
		clean_exit(-E_FATAL);
}

void set_loglevel_true(char *arg)
{
	if (set_msg_loglevel(LOG_TRUE, arg) == -E_FATAL)
		clean_exit(-E_FATAL);
}

void set_compress(void)
{
	EC_GBL_OPTIONS->compress = 1;
}

void opt_set_regex(char *regex)
{
	if (set_regex(regex) == -E_FATAL)
		clean_exit(-E_FATAL);
}

void set_superquiet()
{
	EC_GBL_OPTIONS->superquiet = 1;
}

void set_quiet(void)
{
	EC_GBL_OPTIONS->quiet = 1;
}

void set_script(char *script)
{
	EC_GBL_OPTIONS->script = strdup(script);
}

void set_silent(void)
{
	EC_GBL_OPTIONS->silent = 1;
}

#ifdef WITH_IPV6
void set_ip6scan(void)
{
	EC_GBL_OPTIONS->ip6scan = 1;
}
#endif

void set_unoffensive(void)
{
	EC_GBL_OPTIONS->unoffensive = 1;
}

void disable_sslmitm(void)
{
	EC_GBL_OPTIONS->ssl_mitm = 0;
}

void set_resolve(void)
{
	EC_GBL_OPTIONS->resolve = 1;
   resolv_thread_init();
   atexit(resolv_thread_fini);
}

void set_load_hosts(char *file)
{
	EC_GBL_OPTIONS->silent = 1;
	EC_GBL_OPTIONS->load_hosts = 1;
	EC_GBL_OPTIONS->hostsfile = strdup(file);
}

void set_save_hosts(char *file)
{
	EC_GBL_OPTIONS->save_hosts = 1;
	EC_GBL_OPTIONS->hostsfile = strdup(file);
}

void opt_set_format(char *format)
{
	if (set_format(format) != E_SUCCESS)
		clean_exit(-E_FATAL);	
}

void set_ext_headers(void)
{
	EC_GBL_OPTIONS->ext_headers = 1;
}

void set_wifi_key(char *key)
{
	wifi_key_prepare(key);
}

void set_conf_file(char *file)
{
	EC_GBL_CONF->file = strdup(file);
}

void set_ssl_cert(char *cert)
{
	EC_GBL_OPTIONS->ssl_cert = strdup(cert);
}

void set_ssl_key(char *key)
{
	EC_GBL_OPTIONS->ssl_pkey = strdup(key);
}

#ifdef HAVE_EC_LUA
void set_lua_args(char *args)
{
	ec_lua_cli_add_args(strdup(args));
}

void set_lua_script(char *script)
{
	ec_lua_cli_add_script(strdup(script));
}
#endif

void set_target_target1(char *target1)
{
	EC_GBL_OPTIONS->target1 = strdup(target1);
}

void set_target_target2(char *target2)
{
	EC_GBL_OPTIONS->target2 = strdup(target2);
}

/* EOF */


// vim:ts=3:expandtab

