/*
    ettercap -- sniffing method module

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

    $Header: /home/drizzt/dev/sources/ettercap.cvs/ettercap_ng/src/ec_sniff.c,v 1.15 2003/04/14 21:05:26 alor Exp $
*/

#include <ec.h>
#include <ec_parser.h>
#include <ec_sniff.h>
#include <ec_sniff_unified.h>
#include <ec_sniff_bridge.h>
#include <ec_sniff_arp.h>
#include <ec_packet.h>
#include <ec_inet.h>

#include <pthread.h>
#include <sys/socket.h>

/* proto */

void set_sniffing_method(struct sniffing_method *sm);
void set_unified_sniff(void);
void set_bridge_sniff(void);
void set_arp_sniff(void);

void display_packet_for_us(struct packet_object *po);
int compile_display_filter(void);
void reset_display_filter(struct target_env *t);

static void set_forwardable_flag(struct packet_object *po);

static void add_port(void *ports, int n);
static void add_ip(void *digit, int n);
static int expand_range_ip(char *str, void *target);

void del_ip_list(struct ip_addr *ip, struct target_env *t);
int cmp_ip_list(struct ip_addr *ip, struct target_env *t);
void add_ip_list(struct ip_addr *ip, struct target_env *t);
void free_ip_list(struct target_env *t);

static pthread_mutex_t ip_list_mutex = PTHREAD_MUTEX_INITIALIZER;
#define IP_LIST_LOCK     do{ pthread_mutex_lock(&ip_list_mutex); } while(0)
#define IP_LIST_UNLOCK   do{ pthread_mutex_unlock(&ip_list_mutex); } while(0)

/*******************************************/

/* 
 * if the dest mac address of the packet is
 * the same of GBL_IFACE->mac but the dest ip is
 * not the same as GBL_IFACE->ip, the packet is not
 * for us and we can do mitm on it before forwarding.
 */
void set_forwardable_flag(struct packet_object *po)
{
   /* in bridged sniffing all the packet have to be forwarded */
   if (GBL_SNIFF->type == SM_BRIDGED)
      po->flags |= PO_FORWARDABLE;
   
   /* 
    * if the mac is our, but the ip is not...
    * it has to be forwarded
    */
   
   if (!memcmp(GBL_IFACE->mac, po->L2.dst, ETH_ADDR_LEN) &&
       ip_addr_cmp(&GBL_IFACE->ip, &po->L3.dst) )
      po->flags |= PO_FORWARDABLE;
   
}


void set_sniffing_method(struct sniffing_method *sm)
{
   /* set the method and all its pointer */
   memcpy(GBL_SNIFF, sm, sizeof(struct sniffing_method));
}

/*
 * classic sniffing method.
 * based on IP and MAC filtering
 */

void set_unified_sniff(void)
{
   struct sniffing_method sm;

   DEBUG_MSG("set_unified_sniff");
   
   sm.type = SM_UNIFIED;
   sm.start = &start_unified_sniff;
   sm.cleanup = NULL;
   /* unified forwarding is done at layer 3 */
   sm.forward = &forward_unified_sniff;
   sm.display = &display_packet_for_us;

   set_sniffing_method(&sm);
}

/*
 * bridged sniffing method.
 * it uses two network interfaces and
 * it is totally stealthy
 */

void set_bridge_sniff(void)
{
   struct sniffing_method sm;

   DEBUG_MSG("set_bridge_sniff");
   
   sm.type = SM_BRIDGED;
   sm.start = &start_bridge_sniff;
   sm.cleanup = NULL;
   sm.forward = &forward_bridge_sniff;
   sm.display = &display_packet_for_us;

   set_sniffing_method(&sm);
}

/*
 * arp poisoning sniffing method.
 * it uses the arp poisoning attack to achieve 
 * man in the middle attack.
 */

void set_arp_sniff(void)
{
   struct sniffing_method sm;

   DEBUG_MSG("set_arp_sniff");
   
   sm.type = SM_ARPSNIFF;
   sm.start = &start_arp_sniff;
   sm.cleanup = &stop_arp_sniff;
   sm.forward = &forward_unified_sniff;
   sm.display = &display_packet_for_us;

   set_sniffing_method(&sm);
}

/* 
 * set the PO_IGNORE based on the 
 * ip specified on command line
 *
 * also set PO_OUTGOING if in bridged or arp sniffing
 */

void display_packet_for_us(struct packet_object *po)
{
   char value = 0;
   char good = 0;
   char proto = 0;

   /* check if the packet is OUTGOING */
   set_forwardable_flag(po);
  
   /* 
    * first check the protocol.
    * if it is not the one specified it is 
    * useless to parse the mac, ip and port
    */

    if (!GBL_OPTIONS->proto || !strcasecmp(GBL_OPTIONS->proto, "all"))  
       proto = 1;

    if (GBL_OPTIONS->proto && !strcasecmp(GBL_OPTIONS->proto, "tcp") 
          && po->L4.proto == NL_TYPE_TCP)
       proto = 1;
   
    if (GBL_OPTIONS->proto && !strcasecmp(GBL_OPTIONS->proto, "udp") 
          && po->L4.proto == NL_TYPE_UDP)
       proto = 1;
    
    /* the protocol does not match */
    if (!GBL_OPTIONS->reversed && proto == 0)
       return;
    
   /*
    * we have to check if the packet is complying with the filter
    * specified by the users.
    */
 
   /* FROM TARGET1 TO TARGET2 */
   
   /* T1.mac == src & T1.ip = src & T1.port = src */
   if ( (GBL_TARGET1->all_mac  || !memcmp(GBL_TARGET1->mac, po->L2.src, ETH_ADDR_LEN)) &&
        (GBL_TARGET1->all_ip   || cmp_ip_list(&po->L3.src, GBL_TARGET1) ) &&
        (GBL_TARGET1->all_port || BIT_TEST(GBL_TARGET1->ports, ntohs(po->L4.src))) )
      value = 1;

   /* T2.mac == dst & T2.ip = dst & T2.port = dst */
   if ( value && (
        (GBL_TARGET2->all_mac || !memcmp(GBL_TARGET2->mac, po->L2.dst, ETH_ADDR_LEN)) &&
        (GBL_TARGET2->all_ip || cmp_ip_list(&po->L3.dst, GBL_TARGET2)) &&
        (GBL_TARGET2->all_port || BIT_TEST(GBL_TARGET2->ports, ntohs(po->L4.dst))) ) )
      good = 1;   
  

   if (GBL_OPTIONS->reversed ^ (good && proto) ) {
      po->flags &= ~PO_IGNORE;
      return;
   }
   
   value = 0;
   
   /* FROM TARGET12 TO TARGET1 */
   
   /* T1.mac == dst & T1.ip = dst & T1.port = dst */
   if ( (GBL_TARGET1->all_mac  || !memcmp(GBL_TARGET1->mac, po->L2.dst, ETH_ADDR_LEN)) &&
        (GBL_TARGET1->all_ip   || cmp_ip_list(&po->L3.dst, GBL_TARGET1) ) &&
        (GBL_TARGET1->all_port || BIT_TEST(GBL_TARGET1->ports, ntohs(po->L4.dst))) )
      value = 1;

   /* T2.mac == src & T2.ip = src & T2.port = src */
   if ( value && (
        (GBL_TARGET2->all_mac || !memcmp(GBL_TARGET2->mac, po->L2.src, ETH_ADDR_LEN)) &&
        (GBL_TARGET2->all_ip || cmp_ip_list(&po->L3.src, GBL_TARGET2)) &&
        (GBL_TARGET2->all_port || BIT_TEST(GBL_TARGET2->ports, ntohs(po->L4.src))) ) )
      good = 1;   
   
   
   if (GBL_OPTIONS->reversed ^ (good && proto) )
      po->flags &= ~PO_IGNORE;
 
   return; 
}

/*
 * set the filter to ANY/ANY/ANY
 */

void reset_display_filter(struct target_env *t)
{

   DEBUG_MSG("reset_display_filter %p", t);
   
   free_ip_list(t);
   memset(t->ports, 0, sizeof(t->ports));
   memset(t->mac, 0, sizeof(t->mac));
   t->all_mac = 1;
   t->all_ip = 1;
   t->all_port = 1;
   
}


/*
 * compile the list of MAC, IPs and PORTs to be displayed
 */

int compile_display_filter(void)
{
#define MAX_TOK 3
   char valid[] = "1234567890/.,-;:ABCDEFabcdef";
   char *tok[MAX_TOK];
   char *p;
   int i = 0;
   
   DEBUG_MSG("compile_display_filter TARGET1: %s", GBL_OPTIONS->target1);

   if (strlen(GBL_OPTIONS->target1) != strspn(GBL_OPTIONS->target1, valid))
      FATAL_ERROR("TARGET1 contains invalid chars !");
   
   if (strlen(GBL_OPTIONS->target2) != strspn(GBL_OPTIONS->target2, valid))
      FATAL_ERROR("TARGET2 contains invalid chars !");
   
   /* TARGET 1 parsing */
   for(p=strsep(&GBL_OPTIONS->target1, "/"); p != NULL; p=strsep(&GBL_OPTIONS->target1, "/")) {
      tok[i++] = strdup(p);
      /* bad parsing */
      if (i > MAX_TOK) break;
   }
  
   if (i != MAX_TOK)
      FATAL_ERROR("Incorrect number of token (//) in TARGET1 !!");
   
   DEBUG_MSG("MAC  : [%s]", tok[0]);
   DEBUG_MSG("IP   : [%s]", tok[1]);
   DEBUG_MSG("PORT : [%s]", tok[2]);
  
   /* set the mac address */
   if (!strcmp(tok[0], ""))
      GBL_TARGET1->all_mac = 1;
   else if (mac_addr_aton(tok[0], GBL_TARGET1->mac) == 0)
      FATAL_ERROR("Incorrect TARGET1 MAC parsing... (%s)", tok[0]);

  
   /* parse the IP range */
   if (!strcmp(tok[1], ""))
      GBL_TARGET1->all_ip = 1;
   else
     for(p=strsep(&tok[1], ";"); p != NULL; p=strsep(&tok[1], ";"))
        expand_range_ip(p, GBL_TARGET1);
   
   /* 
    * expand the range into the port bitmap array
    * 1<<16 is MAX_PORTS 
    */
   if (!strcmp(tok[2], ""))
      GBL_TARGET1->all_port = 1;
   else {
      if (expand_token(tok[2], 1<<16, &add_port, GBL_TARGET1->ports) == -EFATAL)
         clean_exit(-EFATAL);
   }
   
   for(i=0; i < MAX_TOK; i++)
      SAFE_FREE(tok[i]);

   DEBUG_MSG("compile_display_filter TARGET2: %s", GBL_OPTIONS->target2);
   
   /* TARGET 2 parsing */
   i = 0;
   
   for(p=strsep(&GBL_OPTIONS->target2, "/"); p != NULL; p=strsep(&GBL_OPTIONS->target2, "/")) {
      tok[i++] = strdup(p);
      /* bad parsing */
      if (i > MAX_TOK) break;
   }
  
   if (i != MAX_TOK)
      FATAL_ERROR("Incorrect number of token (//) in TARGET2 !!");
   
   DEBUG_MSG("MAC  : [%s]", tok[0]);
   DEBUG_MSG("IP   : [%s]", tok[1]);
   DEBUG_MSG("PORT : [%s]", tok[2]);
  
   /* set the mac address */
   if (!strcmp(tok[0], ""))
      GBL_TARGET2->all_mac = 1;
   else if (mac_addr_aton(tok[0], GBL_TARGET2->mac) == 0)
      FATAL_ERROR("Incorrect TARGET2 MAC parsing... (%s)", tok[0]);

   /* parse the IP range */
   if (!strcmp(tok[1], ""))
      GBL_TARGET2->all_ip = 1;
   else
     for(p=strsep(&tok[1], ";"); p != NULL; p=strsep(&tok[1], ";"))
        expand_range_ip(p, GBL_TARGET2);
   
   /* set the port range */
   if (!strcmp(tok[2], ""))
      GBL_TARGET2->all_port = 1;
   else {
      if (expand_token(tok[2], 1<<16, &add_port, GBL_TARGET2->ports) == -EFATAL)
         clean_exit(-EFATAL);
   }
   
   for(i=0; i < MAX_TOK; i++)
      SAFE_FREE(tok[i]);

   return ESUCCESS;
}

static void add_port(void *ports, int n)
{
   u_int8 *bitmap = ports;
  
   BIT_SET(bitmap, n);
}

/*
 * this structure is used to contain all the possible
 * value of a token.
 * it is used as a digital clock.
 * an impulse is made to the last digit and it increment
 * its value, when it reach the maximum, it reset itself 
 * and gives an impulse to the second to last digit.
 * the impulse is propagated till the first digit so all
 * the values are displayed as in a daytime from 00:00 to 23:59
 */

struct digit {
   int n;
   int cur;
   u_char values[0xff];
};


/* 
 * prepare the set of 4 digit to create an IP address
 */

static int expand_range_ip(char *str, void *target)
{
   struct digit ADDR[4];
   struct ip_addr tmp;
   struct in_addr ipaddr;
   char *addr[4];
   char parsed_ip[16];
   char *p, *q;
   int i = 0, j;
   int permut = 1;
                     
   memset(&ADDR, 0, sizeof(ADDR));

   p = str;

   /* tokenize the ip into 4 slices */
   while ( (q = strtok(p, ".")) ) {
      addr[i++] = strdup(q);
      /* reset p for the next strtok */
      if (p != NULL) p = NULL;
      if (i > 4) break;
   }

   if (i != 4)
      FATAL_ERROR("Invalid IP format !!");

   DEBUG_MSG("expand_range_ip -- [%s] [%s] [%s] [%s]", addr[0], addr[1], addr[2], addr[3]);

   for (i = 0; i < 4; i++) {
      p = addr[i];
      if (expand_token(addr[i], 255, &add_ip, &ADDR[i]) == -EFATAL)
         clean_exit(-EFATAL);
   }

   /* count the free permutations */
   for (i = 0; i < 4; i++) 
      permut *= ADDR[i].n;

   /* give the impulses to the last digit */
   for (i = 0; i < permut; i++) {

      sprintf(parsed_ip, "%d.%d.%d.%d",  ADDR[0].values[ADDR[0].cur],
                                         ADDR[1].values[ADDR[1].cur],
                                         ADDR[2].values[ADDR[2].cur],
                                         ADDR[3].values[ADDR[3].cur]);

      if (inet_aton(parsed_ip, &ipaddr) == 0)
         FATAL_ERROR("Invalid IP address (%s)", parsed_ip);

      ip_addr_init(&tmp, AF_INET,(char *)&ipaddr );
      add_ip_list(&tmp, target);
      
      /* give the impulse to the last octet */ 
      ADDR[3].cur++;

      /* adjust the other digits as in a digital clock */
      for (j = 2; j >= 0; j--) {    
         if ( ADDR[j+1].cur >= ADDR[j+1].n  ) {
            ADDR[j].cur++;
            ADDR[j+1].cur = 0;
         }
      }
   } 
  
   for (i = 0; i < 4; i++)
      SAFE_FREE(addr[i]);
     
   return ESUCCESS;
}

/* fill the digit structure with data */
static void add_ip(void *digit, int n)
{
   struct digit *buf = digit;
   
   buf->n++;
   buf->values[buf->n - 1] = (u_char) n;
}


/*
 * add an IP to the list 
 */

void add_ip_list(struct ip_addr *ip, struct target_env *t)
{
   struct ip_list *e;
   struct ip_list *last;

   e = calloc(1, sizeof(struct ip_list));
   ON_ERROR(e, NULL, "can't allocate memory");

   memcpy(&e->ip, ip, sizeof(struct ip_addr));

   IP_LIST_LOCK;
   
   /* insert it at the beginning of the list */
   //SLIST_INSERT_HEAD (&t->ips, e, next); 

   /* 
    * insert it at the end of the list.
    * search the last element then insert the new one
    */
   SLIST_FOREACH (last, &t->ips, next) {
      if (SLIST_NEXT(last, next) == SLIST_END(&t->ips))
         break;
   }

   if (last)
      SLIST_INSERT_AFTER(last, e, next);
   else 
      SLIST_INSERT_HEAD(&t->ips, e, next);
   
   IP_LIST_UNLOCK;
   
   return;
}

/*
 * return true if the ip is in the list
 */

int cmp_ip_list(struct ip_addr *ip, struct target_env *t)
{
   struct ip_list *e;

   IP_LIST_LOCK;
   
   SLIST_FOREACH (e, &t->ips, next)
      if (!ip_addr_cmp(&(e->ip), ip)) {
         IP_LIST_UNLOCK;
         return 1;
      }

   IP_LIST_UNLOCK;
   
   return 0;
}

/*
 * remove an IP from the list
 */

void del_ip_list(struct ip_addr *ip, struct target_env *t)
{
   struct ip_list *e;

   IP_LIST_LOCK;
   
   SLIST_FOREACH (e, &t->ips, next) {
      if (!ip_addr_cmp(&(e->ip), ip)) {
         SLIST_REMOVE(&t->ips, e, ip_list, next);
         SAFE_FREE(e);
         IP_LIST_UNLOCK;
         return;
      }
   }
   
   IP_LIST_UNLOCK;
   
   return;
}

/*
 * free the IP list
 */

void free_ip_list(struct target_env *t)
{
   struct ip_list *e;
  
   IP_LIST_LOCK;
   
   while (SLIST_FIRST(&t->ips) != NULL) {
      e = SLIST_FIRST(&t->ips);
      SLIST_REMOVE_HEAD(&t->ips, next);
      SAFE_FREE(e);
   }

   IP_LIST_UNLOCK;
}


/* EOF */

// vim:ts=3:expandtab

