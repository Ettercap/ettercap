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

    $Header: /home/drizzt/dev/sources/ettercap.cvs/ettercap_ng/src/ec_globals.c,v 1.6 2003/06/02 19:41:13 alor Exp $
*/

#include <ec.h>
#include <ec_sniff.h>

#define GBL_FREE(x) do{ if (x != NULL) { free(x); x = NULL; } }while(0)


/* global vars */

struct globals *gbls;

/* proto */

void globals_alloc(void);
void globals_free(void);

/*******************************************/

void globals_alloc(void)
{
   
   gbls = calloc(1, sizeof(struct globals));
   ON_ERROR(gbls, NULL, "can't allocate globals");
           
   gbls->stats = calloc(1, sizeof(struct gbl_stats));
   ON_ERROR(gbls->stats, NULL, "can't allocate gbl_stats");
   
   gbls->options = calloc(1, sizeof(struct ec_options));
   ON_ERROR(gbls->options, NULL, "can't allocate ec_options");

   gbls->ui = calloc(1, sizeof(struct ui_ops));
   ON_ERROR(gbls->ui, NULL, "can't allocate ui_ops");
   
   gbls->env = calloc(1, sizeof(struct program_env));
   ON_ERROR(gbls->env, NULL, "can't allocate program_env");
  
   gbls->pcap = calloc(1, sizeof(struct pcap_env));
   ON_ERROR(gbls->pcap, NULL, "can't allocate pcap_env");
   
   gbls->lnet = calloc(1, sizeof(struct lnet_env));
   ON_ERROR(gbls->lnet, NULL, "can't allocate lnet_env");
   
   gbls->iface = calloc(1, sizeof(struct iface_env));
   ON_ERROR(gbls->iface, NULL, "can't allocate iface_env");
   
   gbls->bridge = calloc(1, sizeof(struct iface_env));
   ON_ERROR(gbls->bridge, NULL, "can't allocate bridge_env");
   
   gbls->sm = calloc(1, sizeof(struct sniffing_method));
   ON_ERROR(gbls->sm, NULL, "can't allocate sniff_method");
   
   gbls->t1 = calloc(1, sizeof(struct target_env));
   ON_ERROR(gbls->t1, NULL, "can't allocate target t1");
   
   gbls->t2 = calloc(1, sizeof(struct target_env));
   ON_ERROR(gbls->t2, NULL, "can't allocate target t2");
   
   return;
}


void globals_free(void)
{
 
   GBL_FREE(gbls->pcap);
   GBL_FREE(gbls->lnet);
   GBL_FREE(gbls->iface);
   GBL_FREE(gbls->bridge);
   GBL_FREE(gbls->sm);

   free_ip_list(gbls->t1);
   GBL_FREE(gbls->t1);
   free_ip_list(gbls->t2);
   GBL_FREE(gbls->t2);
   
   GBL_FREE(gbls->env->name);
   GBL_FREE(gbls->env->version);
   GBL_FREE(gbls->env->debug_file);
   GBL_FREE(gbls->env);
   
   GBL_FREE(gbls->options->plugin);
   GBL_FREE(gbls->options->proto);
   GBL_FREE(gbls->options->dumpfile);
   GBL_FREE(gbls->options->iface);
   GBL_FREE(gbls->options->iface_bridge);
   GBL_FREE(gbls->options->target1);
   GBL_FREE(gbls->options->target2);
   GBL_FREE(gbls->options);
   GBL_FREE(gbls->stats);
   
   GBL_FREE(gbls);
   
   return;
}


/* EOF */

// vim:ts=3:expandtab

