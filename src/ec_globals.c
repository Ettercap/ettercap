/*
    ettercap -- global variables handling module

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

*/

#include <ec.h>
#include <ec_sniff.h>
#include <ec_filter.h>
#include <ec_plugins.h>

#define EC_GBL_FREE(x) do{ if (x != NULL) { free(x); x = NULL; } }while(0)


/* global vars */

struct ec_globals *ec_gbls;

/* proto */

/*******************************************/

void ec_globals_alloc(void)
{
   
   SAFE_CALLOC(ec_gbls, 1, sizeof(struct ec_globals));
   SAFE_CALLOC(ec_gbls->conf, 1, sizeof(struct ec_conf)); 
   SAFE_CALLOC(ec_gbls->options, 1, sizeof(struct ec_options));         
   SAFE_CALLOC(ec_gbls->stats, 1, sizeof(struct gbl_stats));
   SAFE_CALLOC(ec_gbls->ui, 1, sizeof(struct ui_ops));
   SAFE_CALLOC(ec_gbls->env, 1, sizeof(struct program_env)); 
   SAFE_CALLOC(ec_gbls->pcap, 1, sizeof(struct pcap_env));
   SAFE_CALLOC(ec_gbls->lnet, 1, sizeof(struct lnet_env)); 
   SAFE_CALLOC(ec_gbls->iface, 1, sizeof(struct iface_env));
   SAFE_CALLOC(ec_gbls->bridge, 1, sizeof(struct iface_env));
   SAFE_CALLOC(ec_gbls->sm, 1, sizeof(struct sniffing_method));
   SAFE_CALLOC(ec_gbls->t1, 1, sizeof(struct target_env));
   SAFE_CALLOC(ec_gbls->t2, 1, sizeof(struct target_env));
   SAFE_CALLOC(ec_gbls->wifi, 1, sizeof(struct wifi_env));
   /* filter list entries are allocated as needed */
   ec_gbls->filters = NULL;

   /* init the structures */
   TAILQ_INIT(&EC_GBL_PROFILES);
   LIST_INIT(&EC_GBL_HOSTLIST);
   
   return;
}


void ec_globals_free(void)
{
 
   EC_GBL_FREE(ec_gbls->pcap);
   EC_GBL_FREE(ec_gbls->lnet);
   EC_GBL_FREE(ec_gbls->iface);
   EC_GBL_FREE(ec_gbls->bridge);
   EC_GBL_FREE(ec_gbls->sm);
   EC_GBL_FREE(ec_gbls->filters);

   free_ip_list(ec_gbls->t1);
   EC_GBL_FREE(ec_gbls->t1);
   free_ip_list(ec_gbls->t2);
   EC_GBL_FREE(ec_gbls->t2);
   
   EC_GBL_FREE(ec_gbls->env->name);
   EC_GBL_FREE(ec_gbls->env->version);
   EC_GBL_FREE(ec_gbls->env->debug_file);
   EC_GBL_FREE(ec_gbls->env);
   
   free_plugin_list(ec_gbls->options->plugins);
   EC_GBL_FREE(ec_gbls->options->proto);
   EC_GBL_FREE(ec_gbls->options->pcapfile_in);
   EC_GBL_FREE(ec_gbls->options->pcapfile_out);
   EC_GBL_FREE(ec_gbls->options->iface);
   EC_GBL_FREE(ec_gbls->options->iface_bridge);
   EC_GBL_FREE(ec_gbls->options->target1);
   EC_GBL_FREE(ec_gbls->options->target2);
   EC_GBL_FREE(ec_gbls->stats);
   EC_GBL_FREE(ec_gbls->options);
   EC_GBL_FREE(ec_gbls->conf);
   /* destroy the list structure */
   filter_clear();
   
   EC_GBL_FREE(ec_gbls);
   
   return;
}


/* EOF */

// vim:ts=3:expandtab

