/*
    ettercap -- text GUI for SSL redirect management

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
#include <ec_ui.h>
#include <ec_redirect.h>

/* proto */
static void text_redirect_print_rule(struct redir_entry *re);
static void text_redirect_print_serv(struct serv_entry *se);


/* globals */
struct redir_entry **redirect_list = NULL;
struct serv_entry **service_list = NULL;
int n_redir = 0;
int n_serv = 0;

/********************************/

void text_redirect_print(void)
{
   /* free list of redirects if allocated before */
   SAFE_FREE(redirect_list);
   SAFE_FREE(service_list);
   n_redir = 0;

   /* print header */
   fprintf(stdout, "SSL Intercepts\n");
   fprintf(stdout, " # proto %30s %30s service\n",
         "source", "destination");

   /* print rules */
   ec_walk_redirects(text_redirect_print_rule);

}

/* 
 * delete redirect 
 */
void text_redirect_del(int num)
{
   int ret;
   struct redir_entry *re;

   if (num < 1 || num > n_redir) {
      INSTANT_USER_MSG("Entered number '%d' is not in the range of "
            "registered redirects.\n", num);
      return;
   }

   re = redirect_list[num - 1];

   ret = ec_redirect(EC_REDIR_ACTION_REMOVE, re->name, re->proto, 
         re->source, re->destination, re->from_port, re->to_port);

   if (ret == E_SUCCESS)
      INSTANT_USER_MSG("Redirect removed successfully\n",
            (re->proto == EC_REDIR_PROTO_IPV4 ? "ipv4" : "ipv6"),
            re->source, re->destination, re->name);
   else
      INSTANT_USER_MSG("Removing redirect [%s] %s -> %s:%s failed!\n",
            (re->proto == EC_REDIR_PROTO_IPV4 ? "ipv4" : "ipv6"),
            re->source, re->destination, re->name);

}

/*
 * add a redirect rule
 */
void text_redirect_add(void)
{
   char ipver[20], service[20];
   char sourcebuf[MAX_ASCII_ADDR_LEN], destinationbuf[MAX_ASCII_ADDR_LEN];
   char *p, *source, *destination;
   int i, ret, found = 0, invalid = 0;
   ec_redir_proto_t proto;

   fprintf(stdout, "Interceptable services: \n");
   /* print available services */
   SAFE_FREE(service_list);
   n_serv = 0;
   ec_walk_redirect_services(text_redirect_print_serv);
   fprintf(stdout, "\n\n");

   fprintf(stdout, "IP version  [ipv4]: ");
   fgets(ipver, 20, stdin);
   /* remove trailing line feed */
   if ((p = strrchr(ipver, '\n')) != NULL)
      *p = 0;
   
   fprintf(stdout, "Source [any]: ");
   fgets(sourcebuf, MAX_ASCII_ADDR_LEN, stdin);
   /* remove trailing line feed */
   if ((p = strrchr(sourcebuf, '\n')) != NULL)
      *p = 0;
   
   fprintf(stdout, "Destination [any]: ");
   fgets(destinationbuf, MAX_ASCII_ADDR_LEN, stdin);
   /* remove trailing line feed */
   if ((p = strrchr(destinationbuf, '\n')) != NULL)
      *p = 0;
   
   fprintf(stdout, "Service [ftps]: ");
   fgets(service, 20, stdin);
   /* remove trailing line feed */
   if ((p = strrchr(service, '\n')) != NULL)
      *p = 0;

   /* check user input for IP version */
   if (!strcmp(ipver, "") || !strcasecmp(ipver, "ipv4"))
      proto = EC_REDIR_PROTO_IPV4;

   else if (!strcasecmp(ipver, "ipv6"))
      proto = EC_REDIR_PROTO_IPV6;

   else {
      INSTANT_USER_MSG("Invalid IP version entered. "
            "Either \"ipv4\" or \"ipv6\"\n");
      invalid = 1;
   }

   /* check user input for source and destination */
   if (!strcmp(sourcebuf, "") || !strcasecmp(sourcebuf, "any"))
      source = NULL;
   else
      source = sourcebuf;

   if (!strcmp(destinationbuf, "") || !strcasecmp(destinationbuf, "any"))
      destination = NULL;
   else
      destination = destinationbuf;

   /* check user input for service */
   if (!strcmp(service, ""))
      strcpy(service, "ftps");

   for (i = 0; i < n_serv; i++) {
      if (!strcasecmp(service, service_list[i]->name)) {
         found = 1;
         break;
      }
   }
   if (found == 0) {
      INSTANT_USER_MSG("Invalid interceptable service entered.\n");
      invalid = 1;
   }

   if (invalid == 1) {
      INSTANT_USER_MSG("Redirect could not be inserted due to invalid "
            "input.\n");
      return;
   }

   ret = ec_redirect(EC_REDIR_ACTION_INSERT, service_list[i]->name,
         proto, source, destination, service_list[i]->from_port,
         service_list[i]->to_port);

   if (ret == E_SUCCESS)
      INSTANT_USER_MSG("New redirect inserted successfully.\n");
   else
      INSTANT_USER_MSG("Insertion of new redirect failed.\n");

}


/*
 * print a redirect rule
 */
static void text_redirect_print_rule(struct redir_entry *re)
{
   /* allocate a new entry in the list and safe redir pointer */
   SAFE_REALLOC(redirect_list, (n_redir+1) * sizeof(struct redir_entry *));
   redirect_list[n_redir] = re;

   n_redir++;

   /* print the rule */
   fprintf(stdout, "%2d %5s %30s %30s %s\n", n_redir, 
         (re->proto == EC_REDIR_PROTO_IPV4 ? "ipv4" : "ipv6"),
         re->source, re->destination, re->name);

}

/* 
 * print a registered redirect service name 
 */
static void text_redirect_print_serv(struct serv_entry *se)
{
   /* allocate new entry in the list and rember service */
   SAFE_REALLOC(service_list, (n_serv+1) * sizeof(struct serv_entry *));
   service_list[n_serv] = se;

   n_serv++;

   fprintf(stdout, "\t%d. %s\n", n_serv, se->name);

}
