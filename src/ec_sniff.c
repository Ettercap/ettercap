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

    $Id: ec_sniff.c,v 1.46 2004/01/21 21:05:52 alor Exp $
*/

#include <ec.h>
#include <ec_parser.h>
#include <ec_sniff.h>
#include <ec_sniff_unified.h>
#include <ec_sniff_bridge.h>
#include <ec_packet.h>
#include <ec_inet.h>
#include <ec_strings.h>

#include <pthread.h>
#include <sys/socket.h>

/* proto */

void set_sniffing_method(struct sniffing_method *sm);
void set_unified_sniff(void);
void set_bridge_sniff(void);

static void set_interesting_flag(struct packet_object *po);
int compile_display_filter(void);
int compile_target(char *string, struct target_env *target);
void reset_display_filter(struct target_env *t);

void set_forwardable_flag(struct packet_object *po);
int check_forwarded(struct packet_object *po);

static void add_port(void *ports, u_int n);
static void add_ip(void *digit, u_int n);
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

   if (!memcmp(GBL_IFACE->mac, po->L2.dst, MEDIA_ADDR_LEN) &&
       memcmp(GBL_IFACE->mac, po->L2.src, MEDIA_ADDR_LEN) &&
       ip_addr_cmp(&GBL_IFACE->ip, &po->L3.dst) )
      po->flags |= PO_FORWARDABLE;
   
}

/*
 * check if the packet has been forwarded by us
 */
int check_forwarded(struct packet_object *po) 
{
   /* the interface was not configured, the packets are not forwardable */
   if (!GBL_IFACE->configured)
      return 0;
   
   /* 
    * dont sniff forwarded packets (equal mac, different ip) 
    * but only if we are on live connections
    */
   if ( GBL_CONF->skip_forwarded && !GBL_OPTIONS->read &&
        !memcmp(GBL_IFACE->mac, po->L2.src, MEDIA_ADDR_LEN) &&
        ip_addr_cmp(&GBL_IFACE->ip, &po->L3.src) ) {
      return 1;
   }
   return 0;   
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
   sm.cleanup = &stop_unified_sniff;
   /* unified forwarding is done at layer 3 */
   sm.forward = &forward_unified_sniff;
   sm.interesting = &set_interesting_flag;

   set_sniffing_method(&sm);
}

/*
 * bridged sniffing method.
 * it uses two network interfaces and
 * it is totally stealthy
 */

void set_bridge_sniff(void)
{
#ifdef ENABLE_BRIDGED_SNIFF
   struct sniffing_method sm;

   DEBUG_MSG("set_bridge_sniff");

   NOT_IMPLEMENTED();
   
   sm.type = SM_BRIDGED;
   sm.start = &start_bridge_sniff;
   sm.cleanup = &stop_bridge_sniff;
   sm.forward = &forward_bridge_sniff;
   sm.interesting = &set_interesting_flag;

   set_sniffing_method(&sm);
#else
   FATAL_ERROR("Bridged sniffing not supported.");
#endif
}


/* 
 * set the PO_IGNORE based on the 
 * TARGETS specified on command line
 */
static void set_interesting_flag(struct packet_object *po)
{
   char value = 0;
   char good = 0;
   char proto = 0;

   /* 
    * first check the protocol.
    * if it is not the one specified it is 
    * useless to parse the mac, ip and port
    */

    if (!GBL_OPTIONS->proto || !strcasecmp(GBL_OPTIONS->proto, "all"))  
       proto = 1;
    else {

       if (GBL_OPTIONS->proto && !strcasecmp(GBL_OPTIONS->proto, "tcp") 
             && po->L4.proto == NL_TYPE_TCP)
          proto = 1;
      
       if (GBL_OPTIONS->proto && !strcasecmp(GBL_OPTIONS->proto, "udp") 
             && po->L4.proto == NL_TYPE_UDP)
          proto = 1;
    }

    /* the protocol does not match */
    if (!GBL_OPTIONS->reversed && proto == 0)
       return;
    
   /*
    * we have to check if the packet is complying with the TARGETS
    * specified by the users.
    *
    * 1) also accept the packet if the destination mac address is equal
    * to the attacker mac address. this is because we need to sniff
    * during mitm attacks and in the target specification you select
    * the real mac address...
    *
    * 2) to sniff thru a gateway, accept also the packet if it has non local
    * ip address.
    *
    */
    
   /* FROM TARGET1 TO TARGET2 */
   
   /* T1.mac == src & T1.ip = src & T1.port = src */
   if ( (GBL_TARGET1->all_mac  || !memcmp(GBL_TARGET1->mac, po->L2.src, MEDIA_ADDR_LEN)) &&
        (GBL_TARGET1->all_ip   || cmp_ip_list(&po->L3.src, GBL_TARGET1) || 
            (GBL_OPTIONS->remote && ip_addr_is_local(&po->L3.src) != ESUCCESS) ) &&
        (GBL_TARGET1->all_port || BIT_TEST(GBL_TARGET1->ports, ntohs(po->L4.src))) )
      value = 1;

   /* T2.mac == dst & T2.ip = dst & T2.port = dst */
   if ( value && (
        (GBL_TARGET2->all_mac || !memcmp(GBL_TARGET2->mac, po->L2.dst, MEDIA_ADDR_LEN) || !memcmp(GBL_IFACE->mac, po->L2.dst, MEDIA_ADDR_LEN)) &&
        (GBL_TARGET2->all_ip || cmp_ip_list(&po->L3.dst, GBL_TARGET2) || 
            (GBL_OPTIONS->remote && ip_addr_is_local(&po->L3.dst) != ESUCCESS) ) &&
        (GBL_TARGET2->all_port || BIT_TEST(GBL_TARGET2->ports, ntohs(po->L4.dst))) ) )
      good = 1;   
  
   /* 
    * reverse the matching but only if it has matched !
    * if good && proto is valse, we have to go on with
    * tests and evaluate it later
    */
   if ((good && proto) && GBL_OPTIONS->reversed ^ (good && proto) ) {
      po->flags &= ~PO_IGNORE;
      return;
   }
   
   value = 0;
   
   /* FROM TARGET12 TO TARGET1 */
   
   /* T1.mac == dst & T1.ip = dst & T1.port = dst */
   if ( (GBL_TARGET1->all_mac  || !memcmp(GBL_TARGET1->mac, po->L2.dst, MEDIA_ADDR_LEN) || !memcmp(GBL_IFACE->mac, po->L2.dst, MEDIA_ADDR_LEN)) &&
        (GBL_TARGET1->all_ip   || cmp_ip_list(&po->L3.dst, GBL_TARGET1) || 
            (GBL_OPTIONS->remote && ip_addr_is_local(&po->L3.dst) != ESUCCESS) ) &&
        (GBL_TARGET1->all_port || BIT_TEST(GBL_TARGET1->ports, ntohs(po->L4.dst))) )
      value = 1;

   /* T2.mac == src & T2.ip = src & T2.port = src */
   if ( value && (
        (GBL_TARGET2->all_mac || !memcmp(GBL_TARGET2->mac, po->L2.src, MEDIA_ADDR_LEN)) &&
        (GBL_TARGET2->all_ip || cmp_ip_list(&po->L3.src, GBL_TARGET2) || 
            (GBL_OPTIONS->remote && ip_addr_is_local(&po->L3.src) != ESUCCESS) ) &&
        (GBL_TARGET2->all_port || BIT_TEST(GBL_TARGET2->ports, ntohs(po->L4.src))) ) )
      good = 1;   
   
   /* reverse the matching */ 
   if (GBL_OPTIONS->reversed ^ (good && proto) ) {
      po->flags &= ~PO_IGNORE;
   }
 
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
   t->scan_all = 0;
}


/*
 * compile the list of MAC, IPs and PORTs to be displayed
 */
int compile_display_filter(void)
{
   /* if not specified default to // */
   if (!GBL_OPTIONS->target1)
      GBL_OPTIONS->target1 = strdup("//");
   /* if // was specified, select all */
   else if (!strncmp(GBL_OPTIONS->target1, "//", 2))
      GBL_TARGET1->scan_all = 1;
   
   if (!GBL_OPTIONS->target2)
      GBL_OPTIONS->target2 = strdup("//");
   else if (!strncmp(GBL_OPTIONS->target2, "//", 2))
      GBL_TARGET2->scan_all = 1;

   /* compile TARGET1 */
   if (compile_target(GBL_OPTIONS->target1, GBL_TARGET1) != ESUCCESS)
      clean_exit(-EFATAL);
   
   /* compile TARGET2 */
   if (compile_target(GBL_OPTIONS->target2, GBL_TARGET2) != ESUCCESS)
      clean_exit(-EFATAL);

   /* the strings were modified, we can't use them anymore */
   SAFE_FREE(GBL_OPTIONS->target1);
   SAFE_FREE(GBL_OPTIONS->target2);
   
   return ESUCCESS;
}


/*
 * convert a string into a target env
 */
int compile_target(char *string, struct target_env *target)
{
#define MAX_TOK 3
   char valid[] = "1234567890/.,-;:ABCDEFabcdef";
   char *tok[MAX_TOK];
   char *p;
   int i = 0;
   
   DEBUG_MSG("compile_target TARGET: %s", string);

   /* reset the special marker */
   target->all_mac = 0;
   target->all_ip = 0;
   target->all_port = 0;
   
   /* check for invalid char */
   if (strlen(string) != strspn(string, valid))
      FATAL_MSG("TARGET (%s) contains invalid chars !", string);
   
   /* TARGET parsing */
   for (p = strsep(&string, "/"); p != NULL; p = strsep(&string, "/")) {
      tok[i++] = strdup(p);
      /* bad parsing */
      if (i > MAX_TOK) break;
   }
  
   if (i != MAX_TOK)
      FATAL_MSG("Incorrect number of token (//) in TARGET !!");
   
   DEBUG_MSG("MAC  : [%s]", tok[0]);
   DEBUG_MSG("IP   : [%s]", tok[1]);
   DEBUG_MSG("PORT : [%s]", tok[2]);
  
   /* set the mac address */
   if (!strcmp(tok[0], ""))
      target->all_mac = 1;
   else if (mac_addr_aton(tok[0], target->mac) == 0)
      FATAL_ERROR("Incorrect TARGET MAC parsing... (%s)", tok[0]);

   /* parse the IP range */
   if (!strcmp(tok[1], ""))
      target->all_ip = 1;
   else
     for(p = strsep(&tok[1], ";"); p != NULL; p = strsep(&tok[1], ";"))
        expand_range_ip(p, target);
   
   /* 
    * expand the range into the port bitmap array
    * 1<<16 is MAX_PORTS 
    */
   if (!strcmp(tok[2], ""))
      target->all_port = 1;
   else {
      if (expand_token(tok[2], 1<<16, &add_port, target->ports) == -EFATAL)
         clean_exit(-EFATAL);
   }
   
   for(i = 0; i < MAX_TOK; i++)
      SAFE_FREE(tok[i]);

   return ESUCCESS;
}


/*
 * set the bit of the relative port 
 */
static void add_port(void *ports, u_int n)
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
static void add_ip(void *digit, u_int n)
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

   SAFE_CALLOC(e, 1, sizeof(struct ip_list));
   
   memcpy(&e->ip, ip, sizeof(struct ip_addr));

   IP_LIST_LOCK;
   
   /* insert it at the beginning of the list */
   //SLIST_INSERT_HEAD (&t->ips, e, next); 

   /* 
    * insert it at the end of the list.
    * search the last element then insert the new one
    */
   LIST_FOREACH (last, &t->ips, next) {
      /* if already in the list, skip it */
      if (!ip_addr_cmp(&last->ip, ip)) {
         IP_LIST_UNLOCK;
         return;
      }
      
      if (LIST_NEXT(last, next) == LIST_END(&t->ips))
         break;
   }

   if (last)
      LIST_INSERT_AFTER(last, e, next);
   else 
      LIST_INSERT_HEAD(&t->ips, e, next);
   
   /* the target has at least one ip, so remove the "all" flag */
   t->all_ip = 0;
   
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
   
   LIST_FOREACH (e, &t->ips, next)
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
   
   LIST_FOREACH (e, &t->ips, next) {
      if (!ip_addr_cmp(&(e->ip), ip)) {
         LIST_REMOVE(e, next);
         SAFE_FREE(e);
         /* check if the list is empty */
         if (LIST_FIRST(&t->ips) == LIST_END(&t->ips)) {
            /* the list is empty, set the "all" flag */
            t->all_ip = 1;
         }
         
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
   struct ip_list *e, *tmp;
  
   IP_LIST_LOCK;
  
   /* delete the list */
   LIST_FOREACH_SAFE(e, &t->ips, next, tmp) {
      LIST_REMOVE(e, next);
      SAFE_FREE(e);
   }  
   
   IP_LIST_UNLOCK;
}


/* EOF */

// vim:ts=3:expandtab

