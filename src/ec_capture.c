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

*/

#include <ec.h>
#include <ec_decode.h>
#include <ec_threads.h>
#include <ec_capture.h>
#include <ec_ui.h>
#include <ec_inet.h>

#include <pcap.h>
#include <libnet.h>
#if !defined(OS_WINDOWS)
#include <ifaddrs.h>
#endif


/* globals */

static SLIST_HEAD (, align_entry) aligners_table;

struct align_entry {
   int dlt;
   FUNC_ALIGNER_PTR(aligner);
   SLIST_ENTRY (align_entry) next;
};

/*******************************************/

void capture_start(struct iface_env *iface)
{
   char thread_name[64];

   snprintf(thread_name, sizeof(thread_name), "capture[%s]", iface->name);
   ec_thread_new(thread_name, "pcap handler and packet decoder", &capture, iface);
}

void capture_stop(struct iface_env *iface)
{
   pthread_t pid;
   char thread_name[64];

   snprintf(thread_name, sizeof(thread_name), "capture[%s]", iface->name);
   pid = ec_thread_getpid(thread_name);
   if(!pthread_equal(pid, ec_thread_getpid(NULL)))
      ec_thread_destroy(pid);
}

/*
 * start capturing packets
 */

EC_THREAD_FUNC(capture)
{
   int ret;
   struct iface_env *iface;

   /* init the thread and wait for start up */
   ec_thread_init();

   iface = EC_THREAD_PARAM;
   
   DEBUG_MSG("neverending loop (capture)");

   /* wipe the stats */
   stats_wipe();
   
   /* 
    * infinite loop 
    * dispatch packets to ec_decode
    */
   ret = pcap_loop(iface->pcap, -1, ec_decode, EC_THREAD_PARAM);
   ON_ERROR(ret, -1, "Error while capturing: %s", pcap_geterr(iface->pcap));

   if (EC_GBL_OPTIONS->read) {
   	if (ret==0) {
		USER_MSG("\n\nCapture file read completely, please exit at your convenience.\n\n");
   	}
   }
   
   return NULL;
}

/*
 * get the list of all network interfaces
 */
void capture_getifs(void)
{
   pcap_if_t *dev, *pdev, *ndev, *cdev;
   char pcap_errbuf[PCAP_ERRBUF_SIZE];
   
   DEBUG_MSG("capture_getifs");

   /* pointer for the filtered list */
   pdev = cdev = NULL;
  
   /* retrieve the list of all interfaces */
   if (pcap_findalldevs((pcap_if_t **)&EC_GBL_PCAP->allifs, pcap_errbuf) == -1)
      ERROR_MSG("%s", pcap_errbuf);

   /* analyze the list and take over only wanted entries to the filtered list */
   for (dev = (pcap_if_t *)EC_GBL_PCAP->allifs; dev != NULL; dev = ndev) {
      
      /* the next entry in the list */
      ndev = dev->next;
      
      /* skip the pseudo device 'any' 'nflog' and 'nfqueue' */
      /* skip the pseudo device 'dbus-system' and 'dbus-session' shown on mac when ran without sudo*/
      if (
            !strcmp(dev->name, "any") ||
            !strcmp(dev->name, "nflog") ||
            !strcmp(dev->name, "nfqueue")  ||
            !strcmp(dev->name, "dbus-system") ||
            !strcmp(dev->name, "dbus-session")
         )
         continue;

      /* take over entry in filtered list */
      SAFE_CALLOC(cdev, 1, sizeof(pcap_if_t));
      memcpy(cdev, dev, sizeof(pcap_if_t));

      /* fill the empty descriptions */
      if (cdev->description == NULL)
         cdev->description = strdup(cdev->name);
      else /* use separate pointer to avoid double-free through pcap_freealldevs() */
         cdev->description = strdup(cdev->description);

      /* Normalize the description for the local loopback */
      if (cdev->flags & PCAP_IF_LOOPBACK) {
         SAFE_FREE(cdev->description);
         cdev->description = strdup("Local Loopback");
      }
     
      DEBUG_MSG("capture_getifs: [%s] %s", cdev->name, cdev->description);

      /* reset link to next list element */
      cdev->next = NULL;

      /* Safe the head of list of not done already */
      if (EC_GBL_PCAP->ifs == NULL)
         EC_GBL_PCAP->ifs = cdev;
      else /* redefine list link */
         pdev->next = cdev;

      /* preserve pointer for next run */
      pdev = cdev;
     
   }

   /* do we have to print the list ? */
   if (EC_GBL_OPTIONS->lifaces) {
     
      /* we are before ui_init(), can use printf */
      fprintf(stdout, "List of available Network Interfaces:\n\n");
      
      for (dev = (pcap_if_t *)EC_GBL_PCAP->ifs; dev != NULL; dev = dev->next)
         fprintf(stdout, " %s  \t%s\n", dev->name, dev->description);

      fprintf(stdout, "\n\n");

      clean_exit(0);
   }
                   
}

/*
 * properly free interfaces list from libpcap
 */
void capture_freeifs(void)
{
   pcap_if_t *dev, *ndev;

   /* first free filtered list entries */
   for (dev = EC_GBL_PCAP->ifs; dev != NULL; dev = ndev) {
      /* save the next entry in the list and free memory for the entry */
      ndev = dev->next;
      SAFE_FREE(dev->description);
      SAFE_FREE(dev);
   }

   /* Finally free the complete data structure using libpcap */
   if (EC_GBL_PCAP && EC_GBL_PCAP->allifs)
      pcap_freealldevs(EC_GBL_PCAP->allifs);
}

/*
 * return default interface
 */
char* capture_default_if(void)
{
   /*
    * as per deprecation message of pcap_lookupdev() the new way to determine
    * the default interface, is to use the first interface detected by the call
    * of pcap_findalldevs(). This is already determined in capture_getifs() and
    * stored in EC_GBL_PCAP->ifs
    */

   if (EC_GBL_PCAP && EC_GBL_PCAP->ifs)
      return EC_GBL_PCAP->ifs->name;

   return NULL;
}

/*
 * check if the given file is a pcap file
 */
int is_pcap_file(char *file, char *pcap_errbuf)
{
   pcap_t *pcap;
   
   pcap = pcap_open_offline(file, pcap_errbuf);
   if (pcap == NULL)
      return -E_INVALID;

   pcap_close(pcap);
   
   return E_SUCCESS;
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
   return 1;
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

