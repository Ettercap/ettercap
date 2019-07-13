/*
    ettercap -- curses GUI

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
#include <wdg.h>
#include <ec_curses.h>
#include <ec_mitm.h>
#include <ec_redirect.h>

/* proto */

static void curses_arp_poisoning(void);
static void curses_icmp_redir(void);
static void curses_port_stealing(void);
static void curses_dhcp_spoofing(void);
#ifdef WITH_IPV6
static void curses_ndp_poisoning(void);
#endif
static void curses_start_mitm(void);
static void curses_mitm_stop(void);

static void curses_sslredir_show(void);
static void curses_sslredir_create_lists(void);
static void curses_sslredir_destroy(void);
static void curses_sslredir_update(void);
static void curses_sslredir_add_list(struct redir_entry *re);
static void curses_sslredir_add_service(struct serv_entry *se);
static void curses_sslredir_add(void *dummy);
static void curses_sslredir_add_rule(void);
static void curses_sslredir_del(void *dummy);
static void curses_sslredir_help(void *dummy);

/* globals */

#define PARAMS_LEN   64
#define MAX_DESC_LEN 75

static char params[PARAMS_LEN];

struct wdg_menu menu_mitm[] = { {"Mitm",                'M', "", NULL},
                                {"ARP poisoning...",    0,   "", curses_arp_poisoning},
                                {"ICMP redirect...",    0,   "", curses_icmp_redir},
                                {"PORT stealing...",    0,   "", curses_port_stealing},
                                {"DHCP spoofing...",    0,   "", curses_dhcp_spoofing},
#ifdef WITH_IPV6
                                {"NDP poisoning...",    0,   "", curses_ndp_poisoning},
#endif
                                {"-",                   0,   "", NULL},
                                {"Stop mitm attack(s)", 0,   "", curses_mitm_stop},
                                {"-",                   0,   "", NULL},
                                {"SSL Intercept",       0,   "", curses_sslredir_show},
                                {NULL, 0, NULL, NULL},
                              };

static wdg_t *wdg_redirect = NULL;
static struct wdg_list *wdg_redirect_elements = NULL;
static struct wdg_list *wdg_redirect_services = NULL;
static size_t n_redir = 0;
static size_t n_serv  = 0;
static char redir_proto[5] = "ipv4";
static char redir_name[50] = "ftps";
static char redir_source[MAX_ASCII_ADDR_LEN] = "0.0.0.0/0";
static char redir_destination[MAX_ASCII_ADDR_LEN] = "0.0.0.0/0";


/*******************************************/

static void curses_arp_poisoning(void)
{
   char *method = "arp:";
   char *default_param = "remote";
   size_t len = strlen(method);
   
   DEBUG_MSG("curses_arp_poisoning");

   snprintf(params, PARAMS_LEN, "%s%s", method, default_param);

   curses_input("Parameters :", params + len, PARAMS_LEN - len - 1, curses_start_mitm);
}

static void curses_icmp_redir(void)
{
   char *method = "icmp:";
   size_t len = strlen(method);

   DEBUG_MSG("curses_icmp_redir");

   strncpy(params, method, len);
   
   curses_input("Parameters :", params + len, PARAMS_LEN - len - 1, curses_start_mitm);
}

static void curses_port_stealing(void)
{
   char *method = "port:";
   size_t len = strlen(method);

   DEBUG_MSG("curses_port_stealing");

   strncpy(params, method, len);
   
   curses_input("Parameters :", params + len, PARAMS_LEN - len - 1, curses_start_mitm);
}

static void curses_dhcp_spoofing(void)
{
   char *method = "dhcp:";
   size_t len = strlen(method);

   DEBUG_MSG("curses_dhcp_spoofing");

   strncpy(params, method, len);
   
   curses_input("Parameters :", params + len, PARAMS_LEN - len - 1, curses_start_mitm);
}

#ifdef WITH_IPV6
static void curses_ndp_poisoning(void)
{
   char *method = "ndp:";
   char *default_param = "remote";
   size_t len = strlen(method);

   DEBUG_MSG("curses_ndp_poisoning");

   snprintf(params, PARAMS_LEN, "%s%s", method, default_param);

   curses_input("Parameters :", params + len, PARAMS_LEN - len - 1, curses_start_mitm);
}
#endif

/* 
 * start the mitm attack by passing the name and parameters 
 */
static void curses_start_mitm(void)
{
   DEBUG_MSG("curses_start_mitm");
   
   mitm_set(params);
   mitm_start();
}


/*
 * stop all the mitm attack(s)
 */
static void curses_mitm_stop(void)
{
   wdg_t *dlg;
   
   DEBUG_MSG("curses_mitm_stop");

   /* create the dialog */
   wdg_create_object(&dlg, WDG_DIALOG, WDG_OBJ_WANT_FOCUS);
   
   wdg_set_color(dlg, WDG_COLOR_SCREEN, EC_COLOR);
   wdg_set_color(dlg, WDG_COLOR_WINDOW, EC_COLOR);
   wdg_set_color(dlg, WDG_COLOR_FOCUS, EC_COLOR_FOCUS);
   wdg_set_color(dlg, WDG_COLOR_TITLE, EC_COLOR_TITLE);
   wdg_dialog_text(dlg, WDG_NO_BUTTONS, "Stopping the mitm attack...");
   wdg_draw_object(dlg);
   
   wdg_set_focus(dlg);
  
   wdg_update_screen();
   
   /* stop the mitm process */
   mitm_stop();

   wdg_destroy_object(&dlg);
   
   curses_message("MITM attack(s) stopped");
}

/*
 * build SSL Redir window
 */
static void curses_sslredir_show(void)
{
   DEBUG_MSG("curses_sslredir_show()");

   /* create the array for the list widget */
   curses_sslredir_create_lists();

   /* if the object already exists, set the focus to it */
   if (wdg_redirect) {
      /* set the new array */
      wdg_list_set_elements(wdg_redirect, wdg_redirect_elements);
      return;
   }

   wdg_create_object(&wdg_redirect, WDG_LIST, WDG_OBJ_WANT_FOCUS);

   wdg_set_size(wdg_redirect, 1, 2, -1, SYSMSG_WIN_SIZE - 1);
   wdg_set_title(wdg_redirect, "Delete or Insert SSL Intercept rules", 
         WDG_ALIGN_LEFT);
   wdg_set_color(wdg_redirect, WDG_COLOR_SCREEN, EC_COLOR);
   wdg_set_color(wdg_redirect, WDG_COLOR_WINDOW, EC_COLOR);
   wdg_set_color(wdg_redirect, WDG_COLOR_BORDER, EC_COLOR_BORDER);
   wdg_set_color(wdg_redirect, WDG_COLOR_FOCUS, EC_COLOR_FOCUS);
   wdg_set_color(wdg_redirect, WDG_COLOR_TITLE, EC_COLOR_TITLE);

   /* set the elements */
   wdg_list_set_elements(wdg_redirect, wdg_redirect_elements);

   /* add the destroy callback */
   wdg_add_destroy_key(wdg_redirect, KEY_ESC, curses_sslredir_destroy);
   
   /* add the insert and delete callback */
   wdg_list_add_callback(wdg_redirect, KEY_IC, curses_sslredir_add);
   wdg_list_add_callback(wdg_redirect, KEY_DC, curses_sslredir_del);
   wdg_list_add_callback(wdg_redirect, ' ', curses_sslredir_help);

   wdg_draw_object(wdg_redirect);

   wdg_set_focus(wdg_redirect);

}

static void curses_sslredir_destroy(void)
{
   wdg_redirect = NULL;
}

static void curses_sslredir_help(void *dummy)
{
   /* varable not used */
   (void) dummy;

   char help[] = "HELP: shortcut list:\n\n"
                 "  INSERT - insert a new redirect rule\n"
                 "  DELETE - delete a redirect rule";

   curses_message(help);
}

/*
 * dialog to add new redirect rule
 */
static void curses_sslredir_add(void *dummy)
{
   wdg_t *wdg_input;

   DEBUG_MSG("curses_sslredir_add()");

   /* unused variable */
   (void) dummy;

   wdg_create_object(&wdg_input, WDG_INPUT, 
         WDG_OBJ_WANT_FOCUS | WDG_OBJ_FOCUS_MODAL);

   wdg_set_color(wdg_input, WDG_COLOR_SCREEN, EC_COLOR);
   wdg_set_color(wdg_input, WDG_COLOR_WINDOW, EC_COLOR);
   wdg_set_color(wdg_input, WDG_COLOR_FOCUS, EC_COLOR_FOCUS);
   wdg_set_color(wdg_input, WDG_COLOR_TITLE, EC_COLOR_MENU);
   wdg_input_size(wdg_input, strlen("Destination: ") + 
         MAX_ASCII_ADDR_LEN, 6);
   wdg_input_add(wdg_input, 1, 1, "IP Version:  ", redir_proto, 5, 1);
   wdg_input_add(wdg_input, 1, 2, "Source:      ", redir_source, 
         MAX_ASCII_ADDR_LEN, 1);
   wdg_input_add(wdg_input, 1, 3, "Destination: ", redir_destination, 
         MAX_ASCII_ADDR_LEN, 1);
   wdg_input_add(wdg_input, 1, 4, "Service:     ", redir_name, 10, 1);

   wdg_input_set_callback(wdg_input, curses_sslredir_add_rule);

   wdg_draw_object(wdg_input);

   wdg_set_focus(wdg_input);


}

/*
 * callback inserting the actual rule
 */
static void curses_sslredir_add_rule(void)
{
   int ret;
   size_t len, new_len, i = 0;
   struct serv_entry *se = NULL;
   ec_redir_proto_t proto;
   char *services_available = NULL;

   DEBUG_MSG("curses_sslredir_add_rule()");

   /* check ip version string */
   if (!strcasecmp(redir_proto, "ipv4"))
      proto = EC_REDIR_PROTO_IPV4;
   else if (!strcasecmp(redir_proto, "ipv6"))
      proto = EC_REDIR_PROTO_IPV6;
   else {
      DEBUG_MSG("curses_sslredir_add_rule(): '%s' invalid IP version string",
            redir_proto);
#ifdef WITH_IPV6
      curses_message("Invalid IP version string. Use either \"ipv4\" or "
            "\"ipv6\".\n");
#else
      curses_message("Invalid IP version string. Use \"ipv4\".\n");
#endif
      return;
   }

   /* check service name */
   if (wdg_redirect_services == NULL) {
      DEBUG_MSG("curses_sslredir_add_rule(): "
            "no redirect services registered");
      INSTANT_USER_MSG("No redirect services registered. "
            "Is SSL redirection enabled in etter.conf?");
      return;
   }

   while (wdg_redirect_services[i].desc != NULL) {
      if (!strcasecmp(redir_name, wdg_redirect_services[i].desc)) {
         se = (struct serv_entry *) wdg_redirect_services[i].value;
         break;
      }
      i++;
   }

   /* redirect name not found - display available redirects */
   if (se == NULL) {
      services_available = strdup("Services available: \n");
      for (i=0; i < n_serv; i++) {
         len = strlen(services_available);
         new_len = len+strlen(wdg_redirect_services[i].desc)+4+1;
         SAFE_REALLOC(services_available, new_len);
         snprintf(services_available+len, new_len, " * %s\n", 
               wdg_redirect_services[i].desc);
      }
      curses_message(services_available);
      SAFE_FREE(services_available);
      return;
   }


   /* do the actual redirect insertion */
   ret = ec_redirect(EC_REDIR_ACTION_INSERT, se->name, proto,
         redir_source, redir_destination, se->from_port, se->to_port);

   /* inform user if redirect insertion wasn't successful */
   if (ret != E_SUCCESS) {
      DEBUG_MSG("calling ec_redirect('%s', '%s', '%s', '%s', '%s', '%d', '%d'"
            " failed", "insert", se->name, redir_proto, 
            redir_source, redir_destination, se->from_port, se->to_port);

      INSTANT_USER_MSG("Inserting redirect for %s/%s failed!\n",
            redir_proto, redir_name);
   }

   /* update redirect list */
   curses_sslredir_update();
}
/*
 * callback to delete a certain redirect rule
 */
static void curses_sslredir_del(void *dummy)
{
   struct redir_entry *re;
   int ret;

   DEBUG_MSG("curses_sslredir_del()");

   /* prevent the selection when the list is empty */
   if (dummy == NULL)
      return;

   /* remove the redirect */
   re = (struct redir_entry *)dummy;
   ret = ec_redirect(EC_REDIR_ACTION_REMOVE, re->name, re->proto,
         re->source, re->destination, re->from_port, re->to_port);


   if (ret != E_SUCCESS) {
      DEBUG_MSG("calling ec_redirect('%s', '%s', '%s', '%s', '%s', '%d', '%d'"
            " failed", "remove", re->name, 
            (re->proto == EC_REDIR_PROTO_IPV4 ? "ipv4" : "ipv6"),
            re->source, re->destination, re->from_port, re->to_port);

      INSTANT_USER_MSG("Removing redirect for %s/%s failed!\n",
            (re->proto == EC_REDIR_PROTO_IPV4 ? "ipv4" : "ipv6"), re->name);

      return;
   }

   curses_sslredir_update();
   
}

static void curses_sslredir_create_lists(void)
{
   int res, i = 0;

   DEBUG_MSG("curses_sslredir_create_lists()");

   /* free the array (if allocated */
   while (wdg_redirect_elements && wdg_redirect_elements[i].desc != NULL) {
      SAFE_FREE(wdg_redirect_elements[i].desc);
      i++;
   }
   SAFE_FREE(wdg_redirect_elements);
   n_redir = 0;

   /* walk through the redirect rules */
   ec_walk_redirects(&curses_sslredir_add_list);

   /* services are only gathered once */
   if (wdg_redirect_services != NULL)
      return;

   /* walk through the registered services */
   res = ec_walk_redirect_services(&curses_sslredir_add_service);
   if (res == -E_NOTFOUND) {
      SAFE_CALLOC(wdg_redirect_elements, 1, sizeof(struct wdg_list));
      wdg_redirect_elements->desc = "No rules found. "
         "Redirects may be not enabled in etter.conf?";
   }

}

static void curses_sslredir_add_list(struct redir_entry *re)
{
   /* enlarge the array */
   SAFE_REALLOC(wdg_redirect_elements, (n_redir+1) * sizeof(struct wdg_list));

   /* fill the element */
   SAFE_CALLOC(wdg_redirect_elements[n_redir].desc, MAX_DESC_LEN, 
         sizeof(char));

   snprintf(wdg_redirect_elements[n_redir].desc, MAX_DESC_LEN,
         "%s %30s %30s %s", 
         (re->proto == EC_REDIR_PROTO_IPV4 ? "ipv4" : "ipv6"),
         re->source,
         re->destination,
         re->name);

   wdg_redirect_elements[n_redir].value = re;

   n_redir++;

   /* allocate new entry in list to move the NULL element */
   SAFE_REALLOC(wdg_redirect_elements, (n_redir+1) * sizeof(struct wdg_list));
   wdg_redirect_elements[n_redir].desc = NULL;
   wdg_redirect_elements[n_redir].value = NULL;
}

/* 
 * populate array for available services 
 */
static void curses_sslredir_add_service(struct serv_entry *se)
{
   DEBUG_MSG("curses_sslredir_add_service()");

   /* enlarge the array */
   SAFE_REALLOC(wdg_redirect_services, (n_serv+1) * sizeof(struct wdg_list));

   /* fill the element */
   SAFE_CALLOC(wdg_redirect_services[n_serv].desc, MAX_DESC_LEN, 
         sizeof(char));

   snprintf(wdg_redirect_services[n_serv].desc, MAX_DESC_LEN, "%s", se->name);

   wdg_redirect_services[n_serv].value = se;

   n_serv++;

   /* allocate new entry in list to move the NULL element */
   SAFE_REALLOC(wdg_redirect_services, (n_serv+1) * sizeof(struct wdg_list));
   wdg_redirect_services[n_serv].desc = NULL;
   wdg_redirect_services[n_serv].value = NULL;
}

/*
 * refresh redirects list
 */
static void curses_sslredir_update(void)
{
   int i = 0;
   DEBUG_MSG("curses_sslredir_update()");

   /* rebuild array */
   while (wdg_redirect_elements && wdg_redirect_elements[i].desc != NULL) {
      SAFE_FREE(wdg_redirect_elements[i].desc);
      i++;
   }
   SAFE_FREE(wdg_redirect_elements);

   n_redir = 0;
   ec_walk_redirects(&curses_sslredir_add_list);

   /* NULL terminate the array in case it's empty */
   if (wdg_redirect_elements == NULL) {
      SAFE_CALLOC(wdg_redirect_elements, 1, sizeof(struct wdg_list));
      wdg_redirect_elements[0].desc = NULL;
      wdg_redirect_elements[0].value = NULL;
   }

   /* refresh list widget */
   wdg_list_set_elements(wdg_redirect, wdg_redirect_elements);
   wdg_list_refresh(wdg_redirect);

}



/* EOF */

// vim:ts=3:expandtab

