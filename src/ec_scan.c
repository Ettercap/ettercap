/*
    ettercap -- initial scan to build the hosts list

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
#include <ec_packet.h>
#include <ec_threads.h>
#include <ec_send.h>
#include <ec_decode.h>
#include <ec_resolv.h>
#include <ec_file.h>
#include <ec_sleep.h>
#include <ec_capture.h>

#include <pthread.h>
#include <pcap.h>
#include <libnet.h>

/* globals */
static pthread_mutex_t scan_mutex = PTHREAD_MUTEX_INITIALIZER;
/*
 * SCAN_{LOCK,UNLOCK} and SCANUI_{LOCK,UNLOCK} are two macros
 * that handles the SAME mutex "scan_mutex".
 * They are intended to cancel threads that are not getting
 * the lock (Pressing Crtl+S multiple times while scanning).
 * They are split because the lock is used in different functions
 * of different types (void/void*).
 */
#define SCAN_LOCK do{ if (pthread_mutex_trylock(&scan_mutex)) { \
 ec_thread_exit(); return NULL;} \
 } while(0)
#define SCAN_UNLOCK do{ pthread_mutex_unlock(&scan_mutex); } while(0)

#define SCANUI_LOCK do{ if (pthread_mutex_trylock(&scan_mutex)) { \
 return; } \
 } while (0)

#define SCANUI_UNLOCK SCAN_UNLOCK

#define EC_CHECK_LIBNET_VERSION(major,minor)   \
   (LIBNET_VERSION_MAJOR > (major) ||          \
    (LIBNET_VERSION_MAJOR == (major) && LIBNET_VERSION_MINOR >= (minor)))


/* used to create the random list */
static LIST_HEAD (, ip_list) ip_list_head;
static struct ip_list **rand_array;

/* protos */

void build_hosts_list(void);
void del_hosts_list(void);

static void scan_netmask();
#ifdef WITH_IPV6
static void scan_ip6_onlink();
#endif
static void scan_targets();

int scan_load_hosts(char *filename);
int scan_save_hosts(char *filename);

void add_host(struct ip_addr *ip, u_int8 mac[MEDIA_ADDR_LEN], char *name);

static void random_list(struct ip_list *e, int max);

static void get_response(struct packet_object *po);
static EC_THREAD_FUNC(scan_thread);

void __init hook_init(void);
static void hosts_list_hook(struct packet_object *po);

/*******************************************/

/*
 * build the initial host list with ARP requests
 */

void build_hosts_list(void)
{
   struct hosts_list *hl;
   int nhosts = 0;

   DEBUG_MSG("build_hosts_list");

   /* don't create the list in bridged mode */
   if (EC_GBL_SNIFF->type == SM_BRIDGED)
      return;

   /*
    * load the list from the file
    * this option automatically enable EC_GBL_OPTIONS->silent
    */
   if (EC_GBL_OPTIONS->load_hosts) {
      scan_load_hosts(EC_GBL_OPTIONS->hostsfile);

      LIST_FOREACH(hl, &EC_GBL_HOSTLIST, next)
         nhosts++;

      INSTANT_USER_MSG("%d hosts added to the hosts list...\n", nhosts);

      return;
   }

   /* in silent mode, the list should not be created */
   if (EC_GBL_OPTIONS->silent)
      return;

   /* it not initialized don't make the list */
   if (EC_GBL_IFACE->lnet == NULL)
      return;

   /* no target defined... */
   if (EC_GBL_TARGET1->all_ip && EC_GBL_TARGET2->all_ip &&
       EC_GBL_TARGET1->all_ip6 && EC_GBL_TARGET2->all_ip6 &&
       !EC_GBL_TARGET1->scan_all && !EC_GBL_TARGET2->scan_all)
      return;

   /* delete the previous list */
   del_hosts_list();

   /* check the type of UI we are running under... */
   if (EC_GBL_UI->type == UI_TEXT || EC_GBL_UI->type == UI_DAEMONIZE)
      /* in text mode and daemonized call the function directly */
      scan_thread(NULL);
   else 
      /* do the scan in a separate thread */
      ec_thread_new("scan", "scanning thread", &scan_thread, NULL);
}

/*
 * the thread responsible of the hosts scan
 */
static EC_THREAD_FUNC(scan_thread)
{
   struct hosts_list *hl;
   int i = 1, ret;
   int nhosts = 0;
   int threadize = 1;

   /* variable not used */
   (void) EC_THREAD_PARAM;

   DEBUG_MSG("scan_thread");

   /* in text mode and demonized this function should NOT be a thread */
   if (EC_GBL_UI->type == UI_TEXT || EC_GBL_UI->type == UI_DAEMONIZE)
      threadize = 0;

#ifdef OS_MINGW
   /* FIXME: for some reason under windows it does not work in thread mode
    * to be investigated...
    */
   threadize = 0;
#endif

   /* if necessary, don't create the thread */
   if (threadize)
      ec_thread_init();

   /* Only one thread is allowed to scan at a time */
   SCAN_LOCK;

   /* if sniffing is not yet started we need a decoder for the ARP/ND replies */
   if (!EC_GBL_SNIFF->active)
      capture_start(EC_GBL_IFACE);

   /*
    * create a simple decode thread, it will call
    * the right HOOK POINT. so we only have to hook to
    * ARP packets.
    */
   hook_add(HOOK_PACKET_ARP_RP, &get_response);
#ifdef WITH_IPV6
   hook_add(HOOK_PACKET_ICMP6_NADV, &get_response);
   hook_add(HOOK_PACKET_ICMP6_RPLY, &get_response);
   hook_add(HOOK_PACKET_ICMP6_PARM, &get_response);
#endif

   /*
    * if at least one ip target is ANY, scan the whole netmask
    *
    * the pid parameter is used to kill the thread if
    * the user request to stop the scan.
    *
    * FIXME: ipv4 host gets scanned twice if in target list
    */
   if(EC_GBL_TARGET1->all_ip || EC_GBL_TARGET2->all_ip) {
      scan_netmask();
#ifdef WITH_IPV6
      if (EC_GBL_OPTIONS->ip6scan) 
          scan_ip6_onlink();
#endif
   }
   scan_targets();

   /*
    * free the temporary array for random computations
    * allocated in random_list()
    */
   SAFE_FREE(rand_array);

   /*
    * wait a second for some delayed packets...
    * the other thread is listening for ARP pachets
    */
   ec_usleep(SEC2MICRO(1));

   /* remove the hooks for parsing the ARP/ND packets during scan */
   hook_del(HOOK_PACKET_ARP, &get_response);
#ifdef WITH_IPV6
   hook_del(HOOK_PACKET_ICMP6_NADV, &get_response);
   hook_del(HOOK_PACKET_ICMP6_RPLY, &get_response);
   hook_del(HOOK_PACKET_ICMP6_PARM, &get_response);
#endif

   /* if sniffing is not started we have to stop the decoder after scan */
   if (!EC_GBL_SNIFF->active)
      capture_stop(EC_GBL_IFACE);

   /* Unlock Mutex */
   SCAN_UNLOCK;

   /* count the hosts and print the message */
   LIST_FOREACH(hl, &EC_GBL_HOSTLIST, next) {
      char tmp[MAX_ASCII_ADDR_LEN];
      (void)tmp;
      DEBUG_MSG("Host: %s", ip_addr_ntoa(&hl->ip, tmp));
      nhosts++;
   }

   INSTANT_USER_MSG("%d hosts added to the hosts list...\n", nhosts);

   /* update host list*/
   ui_update(UI_UPDATE_HOSTLIST);

   /*
    * resolve the hostnames only if we are scanning
    * the lan. when loading from file, hostnames are
    * already in the file.
    */

   if (!EC_GBL_OPTIONS->load_hosts && EC_GBL_OPTIONS->resolve) {
      char title[50];

      snprintf(title, sizeof(title)-1, "Resolving %d hostnames...", nhosts);

      INSTANT_USER_MSG("%s\n", title);

      LIST_FOREACH(hl, &EC_GBL_HOSTLIST, next) {
         char tmp[MAX_HOSTNAME_LEN];

         host_iptoa(&hl->ip, tmp);
         hl->hostname = strdup(tmp);

         ret = ui_progress(title, i++, nhosts);

         /* user has requested to stop the task */
         if (ret == UI_PROGRESS_INTERRUPTED) {
            INSTANT_USER_MSG("Interrupted by user. Partial results may have been recorded...\n");
            ec_thread_exit();
         }
      }
   }

   /* save the list to the file */
   if (EC_GBL_OPTIONS->save_hosts)
      scan_save_hosts(EC_GBL_OPTIONS->hostsfile);

   /* if necessary, don't create the thread */
   if (threadize)
      ec_thread_exit();

   /* NOT REACHED */
   return NULL;
}


/*
 * delete the hosts list
 */
void del_hosts_list(void)
{
   struct hosts_list *hl, *tmp = NULL;

   SCANUI_LOCK;

   LIST_FOREACH_SAFE(hl, &EC_GBL_HOSTLIST, next, tmp) {
      SAFE_FREE(hl->hostname);
      LIST_REMOVE(hl, next);
      SAFE_FREE(hl);
   }

   SCANUI_UNLOCK;
}

/*
 * receives the ARP and ICMPv6 ND packets 
 */
static void get_response(struct packet_object *po)
{
   struct ip_list *t;
   char tmp[MAX_ASCII_ADDR_LEN];

   DEBUG_MSG("get_response from %s", ip_addr_ntoa(&po->L3.src, tmp));

   /* if at least one target is the whole netmask, add the entry */
   if (EC_GBL_TARGET1->scan_all || EC_GBL_TARGET2->scan_all) {
      add_host(&po->L3.src, po->L2.src, NULL);
      return;
   }

   /* else only add arp and icmp6 replies within the targets */

   /* search in target 1 */
   LIST_FOREACH(t, &EC_GBL_TARGET1->ips, next)
      if (!ip_addr_cmp(&t->ip, &po->L3.src)) {
         add_host(&po->L3.src, po->L2.src, NULL);
         return;
      }

   /* search in target 2 */
   LIST_FOREACH(t, &EC_GBL_TARGET2->ips, next)
      if (!ip_addr_cmp(&t->ip, &po->L3.src)) {
         add_host(&po->L3.src, po->L2.src, NULL);
         return;
      }

#ifdef WITH_IPV6
   /* same for IPv6 */
   /* search in target 1 */
   LIST_FOREACH(t, &EC_GBL_TARGET1->ip6, next)
      if (!ip_addr_cmp(&t->ip, &po->L3.src)) {
         return;
      }

   /* search in target 2 */
   LIST_FOREACH(t, &EC_GBL_TARGET2->ip6, next)
      if (!ip_addr_cmp(&t->ip, &po->L3.src)) {
         add_host(&po->L3.src, po->L2.src, NULL);
         return;
      }
#endif

}


/*
 * scan the netmask to find all hosts
 */
static void scan_netmask(void)
{
   u_int32 netmask, current, myip;
   int nhosts, i, ret;
   struct ip_addr scanip;
   struct ip_list *e, *tmp;
   char title[100];

   netmask = *EC_GBL_IFACE->netmask.addr32;
   myip = *EC_GBL_IFACE->ip.addr32;

   /* the number of hosts in this netmask */
   nhosts = ntohl(~netmask);

   DEBUG_MSG("scan_netmask: %d hosts", nhosts);

   INSTANT_USER_MSG("Randomizing %d hosts for scanning...\n", nhosts);

   /* scan the netmask */
   for (i = 1; i <= nhosts; i++) {
      /* calculate the ip */
      current = (myip & netmask) | htonl(i);
      ip_addr_init(&scanip, AF_INET, (u_char *)&current);

      SAFE_CALLOC(e, 1, sizeof(struct ip_list));

      memcpy(&e->ip, &scanip, sizeof(struct ip_addr));

      /* add to the list randomly */
      random_list(e, i);

   }

   snprintf(title, sizeof(title)-1, "Scanning the whole netmask for %d hosts...", nhosts);
   INSTANT_USER_MSG("%s\n", title);

   i = 1;

   /* send the actual ARP request */
   LIST_FOREACH(e, &ip_list_head, next) {
      /* send the arp request */
      send_arp(ARPOP_REQUEST, &EC_GBL_IFACE->ip, EC_GBL_IFACE->mac, &e->ip, MEDIA_BROADCAST);

      /* update the progress bar */
      ret = ui_progress(title, i++, nhosts);

      /* user has requested to stop the task */
      if (ret == UI_PROGRESS_INTERRUPTED) {
         INSTANT_USER_MSG("Scan interrupted by user. Partial results may have been recorded...\n");
         /* stop the capture thread if sniffing is not active */
         if (!EC_GBL_SNIFF->active)
            capture_stop(EC_GBL_IFACE);

         hook_del(HOOK_PACKET_ARP, &get_response);
         /* delete the temporary list */
         LIST_FOREACH_SAFE(e, &ip_list_head, next, tmp) {
            LIST_REMOVE(e, next);
            SAFE_FREE(e);
         }
         SCAN_UNLOCK;
         /* cancel the scan thread */
         ec_thread_exit();
      }

      /* wait for a delay */
      ec_usleep(MILLI2MICRO(EC_GBL_CONF->arp_storm_delay));

   }

   /* delete the temporary list */
   LIST_FOREACH_SAFE(e, &ip_list_head, next, tmp) {
      LIST_REMOVE(e, next);
      SAFE_FREE(e);
   }

   DEBUG_MSG("scan_netmask: Complete");
}


#ifdef WITH_IPV6
/*
 * probe active IPv6 hosts
 */
static void scan_ip6_onlink(void)
{
   int ret, i = 0;
   struct net_list *e;
   struct ip_addr an;
   char title[100];

   ip_addr_init(&an, AF_INET6, (u_char *)IP6_ALL_NODES);

   snprintf(title, sizeof(title)-1, "Probing %d seconds for active IPv6 nodes ...", EC_GBL_CONF->icmp6_probe_delay);
   INSTANT_USER_MSG("%s\n", title);

   DEBUG_MSG("scan_ip6_onlink: ");

   /* go through the list of IPv6 addresses on the selected interface */
   LIST_FOREACH(e, &EC_GBL_IFACE->ip6_list, next) {
      /*
       * ping to all-nodes from all ip addresses to get responses from all 
       * IPv6 networks (global, link-local, ...)
       */
      send_L2_icmp6_echo(&e->ip, &an, LLA_IP6_ALLNODES_MULTICAST);

#if EC_CHECK_LIBNET_VERSION(1,2)
      /*
       * sending this special icmp probe motivates hosts to respond with a icmp 
       * error message even if they are configured not to respond to icmp requests.
       * since libnet < 1.2 has a bug when sending IPv6 option headers
       * we can only use this type of probe if we have at least libnet 1.2 or above
       */
      send_L2_icmp6_echo_opt(&e->ip, &an,
            IP6_DSTOPT_UNKN, sizeof(IP6_DSTOPT_UNKN), LLA_IP6_ALLNODES_MULTICAST);
#endif
   }

   for (i=0; i<=EC_GBL_CONF->icmp6_probe_delay * 1000; i++) {
      /* update the progress bar */
      ret = ui_progress(title, i, EC_GBL_CONF->icmp6_probe_delay * 1000);

      /* user has requested to stop the task */
      if (ret == UI_PROGRESS_INTERRUPTED) {
         INSTANT_USER_MSG("Scan interrupted by user. Partial results may have been recorded...\n");
         /* stop the capture thread if sniffing is not active */
         if (!EC_GBL_SNIFF->active)
            capture_stop(EC_GBL_IFACE);

         hook_del(HOOK_PACKET_ICMP6_NADV, &get_response);
         hook_del(HOOK_PACKET_ICMP6_RPLY, &get_response);
         hook_del(HOOK_PACKET_ICMP6_PARM, &get_response);
         SCAN_UNLOCK;
         /* cancel the scan thread */
         ec_thread_exit();
      }
      /* wait for a delay */
      ec_usleep(MILLI2MICRO(1)); // 1ms
   }
   
}
#endif


/*
 * scan only the target hosts
 */
static void scan_targets(void)
{
   int nhosts = 0, found, n = 1, ret;
   struct ip_list *e, *i, *m, *tmp;
   char title[100];

#ifdef WITH_IPV6
   struct ip_addr ip;
   struct ip_addr sn;
   u_int8 tmac[MEDIA_ADDR_LEN];
#endif

   DEBUG_MSG("scan_targets: merging targets...");

   /*
    * make an unique list merging the two target
    * and count the number of hosts to be scanned
    */

   /* first get all the target1 ips */
   LIST_FOREACH(i, &EC_GBL_TARGET1->ips, next) {

      SAFE_CALLOC(e, 1, sizeof(struct ip_list));

      memcpy(&e->ip, &i->ip, sizeof(struct ip_addr));

      nhosts++;

      /* add to the list randomly */
      random_list(e, nhosts);
   }
#ifdef WITH_IPV6
   LIST_FOREACH(i, &EC_GBL_TARGET1->ip6, next) {

      SAFE_CALLOC(e, 1, sizeof(struct ip_list));
      memcpy(&e->ip, &i->ip, sizeof(struct ip_addr));
      nhosts++;

      random_list(e, nhosts);
   }
#endif

   /* then merge the target2 ips */
   LIST_FOREACH(i, &EC_GBL_TARGET2->ips, next) {

      found = 0;

      /* search if it is already in the list */
      LIST_FOREACH(m, &ip_list_head, next)
         if (!ip_addr_cmp(&m->ip, &i->ip)) {
            found = 1;
            break;
         }

      /* add it */
      if (!found) {
         SAFE_CALLOC(e, 1, sizeof(struct ip_list));
         memcpy(&e->ip, &i->ip, sizeof(struct ip_addr));

         nhosts++;
         /* add to the list randomly */
         random_list(e, nhosts);
      }
   }

#ifdef WITH_IPV6
   LIST_FOREACH(i, &EC_GBL_TARGET2->ip6, next) {
      found = 0;

      LIST_FOREACH(m, &ip_list_head, next)
         if (!ip_addr_cmp(&m->ip, &i->ip)) {
            found = 1;
            break;
         }

      if (!found) {
         SAFE_CALLOC(e, 1, sizeof(struct ip_list));
         memcpy(&e->ip, &i->ip, sizeof(struct ip_addr));

         nhosts++;
         /* add to the list randomly */
         random_list(e, nhosts);
      }
   }
#endif


   DEBUG_MSG("scan_targets: %d hosts to be scanned", nhosts);

   /* don't scan if there are no hosts */
   if (nhosts == 0)
      return;

   snprintf(title, sizeof(title)-1, "Scanning for merged targets (%d hosts)...", nhosts);
   INSTANT_USER_MSG("%s\n\n", title);

   /* and now scan the LAN */
   LIST_FOREACH(e, &ip_list_head, next) {
      /* send the arp request */
      switch(ntohs(e->ip.addr_type)) {
         case AF_INET:
            send_arp(ARPOP_REQUEST, &EC_GBL_IFACE->ip, EC_GBL_IFACE->mac, &e->ip, MEDIA_BROADCAST);
            break;
#ifdef WITH_IPV6
         case AF_INET6:
            if (ip_addr_is_local(&e->ip, &ip) == E_SUCCESS) {
               ip_addr_init_sol(&sn, &e->ip, tmac);
               send_L2_icmp6_nsol(&ip, &sn, &e->ip, EC_GBL_IFACE->mac, tmac);
            }
            break;
#endif
      }

      /* update the progress bar */
      ret = ui_progress(title, n++, nhosts);

      /* user has requested to stop the task */
      if (ret == UI_PROGRESS_INTERRUPTED) {
         INSTANT_USER_MSG("Scan interrupted by user. Partial results may have been recorded...\n");
         /* stop the capture thread if sniffing is not active */
         if (!EC_GBL_SNIFF->active)
            capture_stop(EC_GBL_IFACE);

         hook_del(HOOK_PACKET_ARP, &get_response);
#ifdef WITH_IPV6
         hook_del(HOOK_PACKET_ICMP6_NADV, &get_response);
         hook_del(HOOK_PACKET_ICMP6_RPLY, &get_response);
         hook_del(HOOK_PACKET_ICMP6_PARM, &get_response);
#endif
         /* delete the temporary list */
         LIST_FOREACH_SAFE(e, &ip_list_head, next, tmp) {
            LIST_REMOVE(e, next);
            SAFE_FREE(e);
         }
         SCAN_UNLOCK;
         /* cancel the scan thread */
         ec_thread_exit();
      }

      /* wait for a delay */
      ec_usleep(MILLI2MICRO(EC_GBL_CONF->arp_storm_delay));

   }

   /* delete the temporary list */
   LIST_FOREACH_SAFE(e, &ip_list_head, next, tmp) {
      LIST_REMOVE(e, next);
      SAFE_FREE(e);
   }

}

/*
 * load the hosts list from this file
 */
int scan_load_hosts(char *filename)
{
   FILE *hf;
   int nhosts;
   char ip[MAX_ASCII_ADDR_LEN];
   char mac[ETH_ASCII_ADDR_LEN];
   char name[MAX_HOSTNAME_LEN];
   struct ip_addr hip;
   u_int8 hmac[MEDIA_ADDR_LEN];

   DEBUG_MSG("scan_load_hosts: %s", filename);

   /* open the file */
   hf = fopen(filename, FOPEN_READ_TEXT);
   if (hf == NULL)
      SEMIFATAL_ERROR("Cannot open %s", filename);

   INSTANT_USER_MSG("Loading hosts list from file %s\n", filename);

   /* read the file */
   for (nhosts = 0; !feof(hf); nhosts++) {

      if (fscanf(hf, "%"EC_TOSTRING(MAX_ASCII_ADDR_LEN)"s %"EC_TOSTRING(ETH_ASCII_ADDR_LEN)"s %"EC_TOSTRING(MAX_HOSTNAME_LEN)"s\n", ip, mac, name) != 3 ||
         *ip == '#' || *mac == '#' || *name == '#')
         continue;

      /* convert to network */
      if (!mac_addr_aton(mac, hmac)) {
         USER_MSG("Bad MAC address while parsing line %d", nhosts + 1);
         continue;
      }

      if (ip_addr_pton(ip, &hip) != E_SUCCESS) {
         /* neither IPv4 nor IPv6 - inform user and skip line*/
         USER_MSG("Bad IP address while parsing line %d", nhosts + 1);
         continue;
         //del_hosts_list();
         //SEMIFATAL_ERROR("Bad parsing on line %d", nhosts + 1);
      }

      /* wipe the null hostname */
      if (!strcmp(name, "-"))
         name[0] = '\0';

      /* add to the list */
      add_host(&hip, hmac, name);
   }

   fclose(hf);

   DEBUG_MSG("scan_load_hosts: loaded %d hosts lines", nhosts);

   return E_SUCCESS;
}


/*
 * save the host list to this file
 */
int scan_save_hosts(char *filename)
{
   FILE *hf;
   int nhosts = 0;
   struct hosts_list *hl;
   char tmp[MAX_ASCII_ADDR_LEN];

   DEBUG_MSG("scan_save_hosts: %s", filename);

   /* open the file */
   hf = fopen(filename, FOPEN_WRITE_TEXT);
   if (hf == NULL)
      SEMIFATAL_ERROR("Cannot open %s for writing", filename);

   /* save the list */
   LIST_FOREACH(hl, &EC_GBL_HOSTLIST, next) {
      fprintf(hf, "%s ", ip_addr_ntoa(&hl->ip, tmp));
      fprintf(hf, "%s ", mac_addr_ntoa(hl->mac, tmp));
      if (hl->hostname && *hl->hostname != '\0')
         fprintf(hf, "%s\n", hl->hostname);
      else
         fprintf(hf, "-\n");
      nhosts++;
   }

   /* close the file */
   fclose(hf);

   INSTANT_USER_MSG("%d hosts saved to file %s\n", nhosts, filename);

   return E_SUCCESS;
}


/*
 * add an host to the list
 * order the list while inserting the elements
 */
void add_host(struct ip_addr *ip, u_int8 mac[MEDIA_ADDR_LEN], char *name)
{
   struct hosts_list *hl, *h;

   /* don't add to hostlist if the found IP is ours */
   if (ip_addr_is_ours(ip) == E_FOUND) 
      return;

   /* don't add undefined address */
   if (ip_addr_is_zero(ip))
      return;

   SAFE_CALLOC(h, 1, sizeof(struct hosts_list));

   /* fill the struct */
   memcpy(&h->ip, ip, sizeof(struct ip_addr));
   memcpy(&h->mac, mac, MEDIA_ADDR_LEN);

   if (name)
      h->hostname = strdup(name);

   /* insert in order (ascending) */
   LIST_FOREACH(hl, &EC_GBL_HOSTLIST, next) {

      if (ip_addr_cmp(&h->ip, &hl->ip) == 0) {
         /* the ip was already collected skip it */
         SAFE_FREE(h->hostname);
         SAFE_FREE(h);
         return;
      } else if (ip_addr_cmp(&hl->ip, &h->ip) < 0 && LIST_NEXT(hl, next) != LIST_END(&EC_GBL_HOSTLIST) )
         continue;
      else if (ip_addr_cmp(&h->ip, &hl->ip) > 0) {
         LIST_INSERT_AFTER(hl, h, next);
         break;
      } else {
         LIST_INSERT_BEFORE(hl, h, next);
         break;
      }

   }

   /* the first element */
   if (LIST_FIRST(&EC_GBL_HOSTLIST) == LIST_END(&EC_GBL_HOSTLIST))
      LIST_INSERT_HEAD(&EC_GBL_HOSTLIST, h, next);

}


/*
 * insert the element in the list randomly.
 * 'max' is the number of elements in the list
 */
static void random_list(struct ip_list *e, int max)
{
   int rnd;

   srand(time(NULL));

   /* calculate the position in the list. */
   rnd = rand() % ((max == 1) ? max : max - 1);

   //rnd = 1+(int) ((float)max*rand()/(RAND_MAX+1.0));

   /* allocate the array used to keep track of the pointer
    * to the elements in the list. this array speed up the
    * access method to the list
    */
   SAFE_REALLOC(rand_array, (max + 1) * sizeof(struct ip_addr *));

   /* the first element */
   if (LIST_FIRST(&ip_list_head) == LIST_END(&ip_list_head)) {
      LIST_INSERT_HEAD(&ip_list_head, e, next);
      rand_array[0] = e;
      return;
   }

   /* bound checking */
   rnd = (rnd > 1) ? rnd : 1;

   /* insert the element in the list */
   LIST_INSERT_AFTER(rand_array[rnd - 1], e, next);
   /* and add the pointer in the array */
   rand_array[max - 1] = e;

}

void __init hook_init(void)
{
   hook_add(HOOK_PACKET_IP, &hosts_list_hook);
   hook_add(HOOK_PACKET_IP6, &hosts_list_hook);
}

/*
 * This function adds local nodes to the global hosts list.
 * Its quite slow and I don't have any better ideas at the moment.
 */
static void hosts_list_hook(struct packet_object *po)
{
   switch(ip_addr_is_ours(&po->L3.src)) {
      case E_FOUND:
      case E_BRIDGE:
         return;
   }

   if(ip_addr_is_local(&po->L3.src, NULL) == E_SUCCESS) {
      add_host(&po->L3.src, po->L2.src, NULL);
   }

   return;
}

/* EOF */

// vim:ts=3:expandtab

