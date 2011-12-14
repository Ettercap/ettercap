/*
    ettercap -- iface and capture functions

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

    $Id: ec_capture.c,v 1.57 2005/06/30 08:24:16 lordnaga Exp $
*/

#include <ec.h>
#include <ec_decode.h>
#include <ec_threads.h>
#include <ec_capture.h>
#include <ec_ui.h>
#include <ec_inet.h>

#include <pcap.h>
#include <libnet.h>
#include <ifaddrs.h>


/* globals */

static SLIST_HEAD (, align_entry) aligners_table;

struct align_entry {
   int dlt;
   FUNC_ALIGNER_PTR(aligner);
   SLIST_ENTRY (align_entry) next;
};

/* protos */

EC_THREAD_FUNC(capture);
EC_THREAD_FUNC(capture_bridge);

void capture_getifs(void);
int is_pcap_file(char *file, char *errbuf);

u_int8 get_alignment(int dlt);
void add_aligner(int dlt, int (*aligner)(void));

/*******************************************/

/* 
 * return the name of the interface.
 * used to deal with unicode under Windows
 */
static char *iface_name(const char *s)
{
   char *buf;
   
#if defined(OS_WINDOWS) || defined(OS_CYGWIN)
   size_t len = wcslen ((const wchar_t*)s);
   
   if (!s[1]) {   /* should probably use IsTextUnicode() ... */
      SAFE_CALLOC(buf, len + 1, sizeof(char));
      
      snprintf (buf, len+1, "%S", s);
      DEBUG_MSG("iface_name: '%S', is_unicode '%s'", s, buf);
      return buf;
   }
#endif

   SAFE_STRDUP(buf, s);
   return buf;
}

/*
 * start capturing packets
 */

EC_THREAD_FUNC(capture)
{
   int ret;
   
   /* init the thread and wait for start up */
   ec_thread_init();
   
   DEBUG_MSG("neverending loop (capture)");

   /* wipe the stats */
   stats_wipe();
   
   /* 
    * infinite loop 
    * dispatch packets to ec_decode
    */
   ret = pcap_loop(GBL_IFACE->pcap, -1, ec_decode, EC_THREAD_PARAM);
   ON_ERROR(ret, -1, "Error while capturing: %s", pcap_geterr(GBL_IFACE->pcap));
   
   return NULL;
}


EC_THREAD_FUNC(capture_bridge)
{
   int ret;

   /* init the thread and wait for start up */
   ec_thread_init();
   
   DEBUG_MSG("neverending loop (capture_bridge)");
   
   /* wipe the stats */
   stats_wipe();
   
   /* 
    * infinite loop 
    * dispatch packets to ec_decode
    */
   ret = pcap_loop(GBL_BRIDGE->pcap, -1, ec_decode, EC_THREAD_PARAM);
   ON_ERROR(ret, -1, "Error while capturing: %s", pcap_geterr(GBL_BRIDGE->pcap));

   return NULL;
}

/*
 * get the list of all network interfaces
 */
void capture_getifs(void)
{
   pcap_if_t *dev, *pdev, *ndev;
   char pcap_errbuf[PCAP_ERRBUF_SIZE];
   
   DEBUG_MSG("capture_getifs");
  
   /* retrieve the list */
   if (pcap_findalldevs((pcap_if_t **)&GBL_PCAP->ifs, pcap_errbuf) == -1)
      ERROR_MSG("%s", pcap_errbuf);

   /* analize the list and remove unwanted entries */
   for (pdev = dev = (pcap_if_t *)GBL_PCAP->ifs; dev != NULL; dev = ndev) {
      
      /* the next entry in the list */
      ndev = dev->next;
      
      /* set the description for the local loopback */
      if (dev->flags & PCAP_IF_LOOPBACK) {
         SAFE_FREE(dev->description);
         dev->description = strdup("Local Loopback");
      }
     
      /* fill the empty descriptions */
      if (dev->description == NULL)
         dev->description = dev->name;

      /* remove the pseudo device 'any' */
      if (!strcmp(dev->name, "any")) {
         /* check if it is the first in the list */
         if (dev == GBL_PCAP->ifs)
            GBL_PCAP->ifs = ndev;
         else
            pdev->next = ndev;

         SAFE_FREE(dev->name);
         SAFE_FREE(dev->description);
         SAFE_FREE(dev);

         continue;
      }
     
      /* remember the previous device for the next loop */
      pdev = dev;
      
      DEBUG_MSG("capture_getifs: [%s] %s", dev->name, dev->description);
   }

   /* do we have to print the list ? */
   if (GBL_OPTIONS->lifaces) {
     
      /* we are before ui_init(), can use printf */
      fprintf(stdout, "List of available Network Interfaces:\n\n");
      
      for (dev = (pcap_if_t *)GBL_PCAP->ifs; dev != NULL; dev = dev->next)
         fprintf(stdout, " %s  \t%s\n", dev->name, dev->description);

      fprintf(stdout, "\n\n");

      clean_exit(0);
   }
                   
}

/*
 * check if the given file is a pcap file
 */
int is_pcap_file(char *file, char *errbuf)
{
   pcap_t *pd;
   
   pd = pcap_open_offline(file, errbuf);
   if (pd == NULL)
      return -EINVALID;

   pcap_close(pd);
   
   return ESUCCESS;
}

/*
 * set the alignment for the buffer 
 */
u_int8 get_alignment(int dlt)
{
   struct align_entry *e;

   SLIST_FOREACH (e, &aligners_table, next)
      if (e->dlt == dlt) 
         return e->aligner();

   /* not found */
   BUG("Don't know how to align this media header");
}

/*
 * add a alignment function to the table 
 */
void add_aligner(int dlt, FUNC_ALIGNER_PTR(aligner))
{
   struct align_entry *e;

   SAFE_CALLOC(e, 1, sizeof(struct align_entry));
   
   e->dlt = dlt;
   e->aligner = aligner;

   SLIST_INSERT_HEAD(&aligners_table, e, next); 
}

/* EOF */

// vim:ts=3:expandtab

