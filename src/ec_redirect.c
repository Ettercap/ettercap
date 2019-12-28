/*
    ettercap -- manage traffic redirect

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
#include <ec_redirect.h>

#ifndef OS_WINDOWS
   #include <sys/wait.h>
#endif

#if defined(OS_DARWIN) || defined(OS_BSD)
   #define IPFW_SET "20"
   #define IPV4_ANY "any"
   #define IPV6_ANY "any"
#else
   #define IPV4_ANY "0.0.0.0/0"
   #define IPV6_ANY "::/0"
#endif


/* proto */
static int set_redir_command(ec_redir_proto_t proto, char *commands[]);
static void register_redir_service(char *name,
      u_int16 from_port, u_int16 to_port);

/* globals */
static LIST_HEAD (, redir_entry) redirect_entries;
static SLIST_HEAD (, serv_entry) redirect_services;

enum {
   EC_REDIR_COMMAND_INSERT,
   EC_REDIR_COMMAND_REMOVE
};

/*
 * execute the script to add or remove the redirection
 */
int ec_redirect(ec_redir_act_t action, char *name, ec_redir_proto_t proto,
      const char *destination, u_int16 sport, u_int16 dport)
{
   char asc_sport[16];
   char asc_dport[16];
   char asc_destination[MAX_ASCII_ADDR_LEN];
   int  ret_val = 0;
   char *param[4];
   char *commands[2] = {NULL, NULL};
   char *command = NULL;
   struct redir_entry *re, *tmp;
   char *str_dstnet = NULL;
   char *str_dstmask = NULL;
   char *str_tmp = NULL;
   u_char *binmask = NULL;

   /* undefined defaults to any */
   switch (proto) {
      case EC_REDIR_PROTO_IPV4:
         if (destination == NULL)
            destination = "0.0.0.0/0";
         break;
      case EC_REDIR_PROTO_IPV6:
         if (destination == NULL)
            destination = "::/0";
         break;
      default:
         DEBUG_MSG("ec_redirect(): invalid address family given");
         return -E_INVALID;
   }


   DEBUG_MSG("ec_redirect(\"%s\", \"%s\", %s, %s, %d, %d)",
         (action == EC_REDIR_ACTION_INSERT ? "insert" : "remove"),
         name,
         (proto == EC_REDIR_PROTO_IPV4 ? "IPv4" : "IPv6"),
         destination,
         sport,
         dport);
   /* check and set redirects commands from etter.conf */
   set_redir_command(proto, commands);


   /* insert or remove commands */
   switch (action) {
      case EC_REDIR_ACTION_INSERT:
         /* check if entry is already present */
         LIST_FOREACH_SAFE(re, &redirect_entries, next, tmp) {
            if (proto == re->proto &&
                !strcmp(destination, re->destination) &&
                sport == re->from_port && dport == re->to_port) {
               DEBUG_MSG("ec_redirect(): redirect entry already present");
               return -E_INVALID;
            }
         }
         /* get command and check if it's defined */
         command = commands[EC_REDIR_COMMAND_INSERT];
         if (command == NULL) {
            DEBUG_MSG("ec_redirect(): redirect insert command for %s desired "
                  "but not set in etter.conf - skipping...",
                  proto == EC_REDIR_PROTO_IPV4 ? "IPv4" : "IPv6");
            return -E_NOTHANDLED;
         }

         /* allocate memory for redirect entry and parse input and set values */
         SAFE_CALLOC(re, 1, sizeof(struct redir_entry));

         re->name = strdup(name);
         re->proto = proto;
         re->destination = strdup(destination);
         re->from_port = sport;
         re->to_port = dport;
         re->orig_nport = htons(sport);

         /* parse destination specification */
         str_tmp = strdup(destination);
         str_dstnet = ec_strtok(str_tmp, "/", &str_dstmask);
         if (str_dstnet != NULL) {
            /* convert network */
            if (ip_addr_pton(str_dstnet, &re->dst_network) != E_SUCCESS)
               goto clean_abort;

            /* convert prefix length to netmask */
            if (str_dstmask != NULL && strlen(str_dstmask)) {
               /* prefix length specified */
               u_int32 dstmask;
               if ((dstmask = strtoul(str_dstmask, NULL, 10)) <= 128) {
                  binmask = ec_plen_to_binary(ntohs(re->dst_network.addr_len), dstmask);
                  ip_addr_init(&re->dst_netmask, ntohs(re->dst_network.addr_type), binmask);
                  SAFE_FREE(binmask);
                  SAFE_FREE(str_tmp);
               }
               else
                  goto clean_abort;
            }
            else {
               /* no prefix length specified */
               u_int32 dstmask;

               /* assume full (host) prefix length */
               dstmask = ntohs(re->dst_network.addr_len) * 8;
               binmask = ec_plen_to_binary(ntohs(re->dst_network.addr_len), dstmask);
               ip_addr_init(&re->dst_netmask, ntohs(re->dst_network.addr_type), binmask);
               SAFE_FREE(binmask);
               SAFE_FREE(str_tmp);
            }
         }
         else /* destination specification invalid */
            goto clean_abort;

         /* sanity check */
         switch (proto) {
            case EC_REDIR_PROTO_IPV4:
               if (ntohs(re->dst_network.addr_type) != AF_INET) {
                  DEBUG_MSG("ec_redirect(): address family mixup! - aborting");
                  goto clean_abort;
               }
               break;
            case EC_REDIR_PROTO_IPV6:
               if (ntohs(re->dst_network.addr_type) != AF_INET6) {
                  DEBUG_MSG("ec_redirect(): address family mixup! - aborting");
                  goto clean_abort;
               }
               break;
            default:
clean_abort:
               SAFE_FREE(re->name);
               SAFE_FREE(re->destination);
               SAFE_FREE(re);
               SAFE_FREE(str_tmp);
               return -E_INVALID;
               break;
         }
         break;
      case EC_REDIR_ACTION_REMOVE:
         /* check if entry is still present */
         LIST_FOREACH_SAFE(re, &redirect_entries, next, tmp) {
            if (proto == re->proto &&
                !strcmp(destination, re->destination) &&
                sport == re->from_port && dport == re->to_port) {
               /* entry present - ready to be removed */
               command = commands[EC_REDIR_COMMAND_REMOVE];
               if (command == NULL) {
                  DEBUG_MSG("ec_redirect(): redirect insert command for %s "
                        "desired but not set in etter.conf - skipping...",
                        proto == EC_REDIR_PROTO_IPV4 ? "IPv4" : "IPv6");
                  return -E_NOTHANDLED;
               }
               break;
            }
         }
         if (command == NULL) {
            DEBUG_MSG("ec_redirect(): redirect entry not present anymore");
            return -E_INVALID;
         }
         break;
      default:
         DEBUG_MSG("ec_redirect(): no valid action defined - aborting!");
         return -E_FATAL;
   }

   /* ready to complete redirect commands */
   if (!strcmp(destination, "0.0.0.0/0")) {
      snprintf(asc_destination, MAX_ASCII_ADDR_LEN, "%s", IPV4_ANY);
   }
   else if (!strcmp(destination, "::/0")) {
      snprintf(asc_destination, MAX_ASCII_ADDR_LEN, "%s", IPV6_ANY);
   }
   else {
      snprintf(asc_destination, MAX_ASCII_ADDR_LEN, "%s", destination);
   }

   snprintf(asc_sport, 16, "%u", sport);
   snprintf(asc_dport, 16, "%u", dport);


   /* make the substitutions in the script */
   str_replace(&command, "%iface", EC_GBL_OPTIONS->iface);
   str_replace(&command, "%destination", asc_destination);
   str_replace(&command, "%port", asc_sport);
   str_replace(&command, "%rport", asc_dport);

#if defined(OS_DARWIN) || defined(OS_BSD)
   str_replace(&command, "%set", IPFW_SET);
#endif

   DEBUG_MSG("ec_redirect(): execute [%s]", command);

   /* construct the params array for execvp */
   param[0] = "sh";
   param[1] = "-c";
   param[2] = command;
   param[3] = NULL;

   /* execute the script */
   switch (fork()) {
      case 0:
         regain_privs();
         execvp(param[0], param);
         drop_privs();
         WARN_MSG("Cannot setup redirect (command: %s), please edit your "
               "etter.conf file and put a valid value in redir_command_on"
               "|redir_command_off field\n", param[0]);
         SAFE_FREE(command);
         SAFE_FREE(re->name);
         SAFE_FREE(re->destination);
         SAFE_FREE(re);
         _exit(-E_INVALID);
      case -1:
         SAFE_FREE(command);
         return -E_INVALID;
      default:
         wait(&ret_val);
         if (WIFEXITED(ret_val) && WEXITSTATUS(ret_val)) {
            DEBUG_MSG("ec_redirect(): child exited with non-zero return "
                  "code: %d", WEXITSTATUS(ret_val));
            USER_MSG("ec_redirect(): redir_command_on had non-zero exit "
                  "status (%d): [%s]\n", WEXITSTATUS(ret_val), command);
            SAFE_FREE(command);
            SAFE_FREE(re->name);
            SAFE_FREE(re->destination);
            SAFE_FREE(re);
            return -E_INVALID;
         }
         else { /* redirect command exited normally */
            switch (action) {
               case EC_REDIR_ACTION_INSERT:
                  /* register entry */
                  LIST_INSERT_HEAD(&redirect_entries, re, next);
                  register_redir_service(name, sport, dport);
                  break;
               case EC_REDIR_ACTION_REMOVE:
                  /* remove entry from list */
                  LIST_FOREACH_SAFE(re, &redirect_entries, next, tmp) {
                     if (re->proto == proto && 
                         !strcmp(re->destination, destination) &&
                         sport == re->from_port &&
                         dport == re->to_port) {
                        LIST_REMOVE(re, next);
                        SAFE_FREE(re->name);
                        SAFE_FREE(re->destination);
                        SAFE_FREE(re);
                     }
                  }

                  break;
               default:
                  break;
            }
         }
   }

   SAFE_FREE(command);
   return E_SUCCESS;
}

/* check and set redirect commands from etter.conf */
static int set_redir_command(ec_redir_proto_t proto, char *commands[])
{

   switch (proto) {
      case EC_REDIR_PROTO_IPV4:
         /* the script is not defined */
         if (EC_GBL_CONF->redir_command_on == NULL)
         {
            USER_MSG("set_redir_commands(): cannot setup the redirect, did "
                  "you uncomment the redir_command_on command on your "
                  "etter.conf file?\n");
            return -E_FATAL;
         }

         commands[EC_REDIR_COMMAND_INSERT] =
            strdup(EC_GBL_CONF->redir_command_on);

         /* the script is not defined */
         if (EC_GBL_CONF->redir_command_off == NULL)
         {
            USER_MSG("set_redir_commands(): cannot remove the redirect, did "
                  "you uncomment the redir_command_off command on your "
                  "etter.conf file?\n");
            return -E_FATAL;
         }

         commands[EC_REDIR_COMMAND_REMOVE] =
            strdup(EC_GBL_CONF->redir_command_off);
         break;

#ifdef WITH_IPV6
      case EC_REDIR_PROTO_IPV6:

         /* IPv6 redirect script is optional */
         if (EC_GBL_CONF->redir6_command_on == NULL)
         {
            USER_MSG("set_redir_commands(): cannot setup the redirect for "
                  "IPv6, did you uncomment the redir6_command_on command on "
                  "your etter.conf file?\n");
            return -E_FATAL;
         }

         commands[EC_REDIR_COMMAND_INSERT] =
            strdup(EC_GBL_CONF->redir6_command_on);

         if (EC_GBL_CONF->redir6_command_off == NULL)
         {
            USER_MSG("set_redir_commands(): cannot remove the redirect for "
                  "IPv6, did you uncommend the redir6_command_off command in "
                  "your etter.conf file?\n");
            return -E_FATAL;
         }

         commands[EC_REDIR_COMMAND_REMOVE] =
            strdup(EC_GBL_CONF->redir6_command_off);
         break;
#endif

      default:
         return -E_INVALID;
   }

   return E_SUCCESS;

}

/*
 * compile the list of registered redirects
 */
int ec_walk_redirects(void (*func)(struct redir_entry*))
{
   struct redir_entry *re, *tmp;
   int i = 0;

   DEBUG_MSG("ec_walk_redirects()");

   LIST_FOREACH_SAFE(re, &redirect_entries, next, tmp) {
      func(re);
      i++;
   }

   return i ? i : -E_NOTFOUND;
}

/*
 * check if a packet matches a installed redirect
 */
int ec_redirect_lookup(struct packet_object *po)
{
   struct redir_entry *re, *tmp;
   struct ip_addr srv_network;

   LIST_FOREACH_SAFE(re, &redirect_entries, next, tmp) {
      if (po->L4.dst == re->orig_nport) {
         /* port matched - now check on the IPs */
         ip_addr_get_network(&po->L3.dst, &re->dst_netmask, &srv_network);
         if (!ip_addr_cmp(&re->dst_network, &srv_network))
            return E_SUCCESS;
      }
      else if (po->L4.src == re->orig_nport) {
         /* port matched - now check on the IPs */
         ip_addr_get_network(&po->L3.src, &re->dst_netmask, &srv_network);
         if (!ip_addr_cmp(&re->dst_network, &srv_network))
            return E_SUCCESS;
      }
   }
   return -E_NOMATCH;
}

/*
 * remove all registered redirects
 */
void ec_redirect_cleanup(void)
{
   struct redir_entry *re, *tmp;
   struct serv_entry *se, *stmp;

   DEBUG_MSG("ec_redirect_cleanup()");

   LIST_FOREACH_SAFE(re, &redirect_entries, next, tmp)
      ec_redirect(EC_REDIR_ACTION_REMOVE, re->name, re->proto,
            re->destination, re->from_port, re->to_port);

   SLIST_FOREACH_SAFE(se, &redirect_services, next, stmp) {
      SAFE_FREE(se->name);
      SAFE_FREE(se);
   }
}

/*
 * store redirect services in a unique list
 */
static void register_redir_service(char *name,
      u_int16 from_port, u_int16 to_port)
{
   struct serv_entry *se;

   DEBUG_MSG("register_redir_service(%s)", name);

   /* avoid duplicates */
   SLIST_FOREACH(se, &redirect_services, next)
      if (se->from_port == from_port && se->to_port == to_port)
         return;

   SAFE_CALLOC(se, 1, sizeof(struct serv_entry));
   se->name = strdup(name);
   se->from_port = from_port;
   se->to_port = to_port;

   SLIST_INSERT_HEAD(&redirect_services, se, next);

}

/*
 * compile the list of redirectable services
 */
int ec_walk_redirect_services(void (*func)(struct serv_entry*))
{
   struct serv_entry *se, *tmp;
   int i = 0;

   DEBUG_MSG("ec_walk_redirect_services()");

   SLIST_FOREACH_SAFE(se, &redirect_services, next, tmp) {
      func(se);
      i++;
   }

   return i ? i : -E_NOTFOUND;
}

/* EOF */

// vim:ts=3:expandtab

