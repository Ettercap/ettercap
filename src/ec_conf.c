/*
    ettercap -- configuration (etter.conf) manipulation module

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
#include <ec_conf.h>
#include <ec_file.h>
#include <ec_dissect.h>

/* globals */
   
/* used only to keep track of how many dissector are loaded */
int number_of_dissectors;
int number_of_ports;
   
static struct conf_entry privs[] = {
   { "ec_uid", NULL },
   { "ec_gid", NULL },
   { NULL, NULL },
};

static struct conf_entry mitm[] = {
   { "arp_storm_delay", NULL },
   { "arp_poison_delay", NULL },
   { "arp_poison_smart", NULL },
   { "arp_poison_warm_up", NULL },
   { "arp_poison_icmp", NULL },
   { "arp_poison_reply", NULL },
   { "arp_poison_request", NULL },
   { "arp_poison_equal_mac", NULL },
   { "dhcp_lease_time", NULL },
   { "port_steal_delay", NULL },
   { "port_steal_send_delay", NULL },
#ifdef WITH_IPV6
   { "ndp_poison_warm_up", NULL },
   { "ndp_poison_delay", NULL },
   { "ndp_poison_send_delay", NULL },
   { "ndp_poison_icmp", NULL },
   { "ndp_poison_equal_mac", NULL},
   { "icmp6_probe_delay", NULL },
#endif
   { NULL, NULL },
};

static struct conf_entry connections[] = {
   { "connection_timeout", NULL },
   { "connection_idle", NULL },
   { "connection_buffer", NULL },
   { "connect_timeout", NULL },
   { NULL, NULL },
};

static struct conf_entry stats[] = {
   { "sampling_rate", NULL },
   { NULL, NULL },
};

static struct conf_entry misc[] = {
   { "close_on_eof", NULL },
   { "store_profiles", NULL },
   { "aggressive_dissectors", NULL },
   { "skip_forwarded_pcks", NULL },
   { "checksum_warning", NULL },
   { "checksum_check", NULL },
   { "submit_fingerprint", NULL },
   { "sniffing_at_startup", NULL },
   { "geoip_support_enable", NULL },
   { "gtkui_prefer_dark_theme", NULL },
   { NULL, NULL },
};

static struct conf_entry curses[] = {
   { "color_bg", NULL },
   { "color_fg", NULL },
   { "color_join1", NULL },
   { "color_join2", NULL },
   { "color_border", NULL },
   { "color_title", NULL },
   { "color_focus", NULL },
   { "color_menu_bg", NULL },
   { "color_menu_fg", NULL },
   { "color_window_bg", NULL },
   { "color_window_fg", NULL },
   { "color_selection_fg", NULL },
   { "color_selection_bg", NULL },
   { "color_error_bg", NULL },
   { "color_error_fg", NULL },
   { "color_error_border", NULL },
   { NULL, NULL },
};

static struct conf_entry strings[] = {
   { "redir_command_on", NULL },
   { "redir_command_off", NULL },
#ifdef WITH_IPV6
   { "redir6_command_on", NULL },
   { "redir6_command_off", NULL },
#endif
   { "remote_browser", NULL },
   { "utf8_encoding", NULL },
   { "geoip_data_file", NULL },
   { "geoip_data_file_v6", NULL },
   { NULL, NULL },
};

/* this is fake, dissector use a different registration */
static struct conf_entry dissectors[] = {
   { "fake", &number_of_dissectors },
   { NULL, NULL },
};

static struct conf_section sections[] = {
   { "privs", privs},
   { "mitm", mitm},
   { "connections", connections},
   { "stats", stats},
   { "misc", misc},
   { "dissectors", dissectors},
   { "curses", curses},
   { "strings", strings},
   { NULL, NULL },
};


/* protos */

static void init_structures(void);
static void set_pointer(struct conf_entry *entry, const char *name, void *ptr);
static void sanity_checks(void);

static void set_dissector(char *name, char *values, int lineno);
static struct conf_entry * search_section(char *title);
static void * search_entry(struct conf_entry *section, char *name);

/************************************************/

/*
 * since EC_GBL_CONF is in the heap, it is not constant
 * so we have to initialize it here and not in the
 * structure definition
 */

static void init_structures(void)
{
   int i = 0, j = 0;
   
   DEBUG_MSG("init_structures");
   
   set_pointer(privs, "ec_uid", &EC_GBL_CONF->ec_uid);
   set_pointer(privs, "ec_gid", &EC_GBL_CONF->ec_gid);
   set_pointer(mitm, "arp_storm_delay", &EC_GBL_CONF->arp_storm_delay);
   set_pointer(mitm, "arp_poison_smart", &EC_GBL_CONF->arp_poison_smart);
   set_pointer(mitm, "arp_poison_warm_up", &EC_GBL_CONF->arp_poison_warm_up);
   set_pointer(mitm, "arp_poison_delay", &EC_GBL_CONF->arp_poison_delay);
   set_pointer(mitm, "arp_poison_icmp", &EC_GBL_CONF->arp_poison_icmp);
   set_pointer(mitm, "arp_poison_reply", &EC_GBL_CONF->arp_poison_reply);
   set_pointer(mitm, "arp_poison_request", &EC_GBL_CONF->arp_poison_request);
   set_pointer(mitm, "arp_poison_equal_mac", &EC_GBL_CONF->arp_poison_equal_mac);
   set_pointer(mitm, "dhcp_lease_time", &EC_GBL_CONF->dhcp_lease_time);
   set_pointer(mitm, "port_steal_delay", &EC_GBL_CONF->port_steal_delay);
   set_pointer(mitm, "port_steal_send_delay", &EC_GBL_CONF->port_steal_send_delay);
#ifdef WITH_IPV6
   set_pointer(mitm, "ndp_poison_warm_up", &EC_GBL_CONF->ndp_poison_warm_up);
   set_pointer(mitm, "ndp_poison_delay", &EC_GBL_CONF->ndp_poison_delay);
   set_pointer(mitm, "ndp_poison_send_delay", &EC_GBL_CONF->ndp_poison_send_delay);
   set_pointer(mitm, "ndp_poison_icmp", &EC_GBL_CONF->ndp_poison_icmp);
   set_pointer(mitm, "ndp_poison_equal_mac", &EC_GBL_CONF->ndp_poison_equal_mac);
   set_pointer(mitm, "icmp6_probe_delay", &EC_GBL_CONF->icmp6_probe_delay);
#endif

   set_pointer(connections, "connection_timeout", &EC_GBL_CONF->connection_timeout);
   set_pointer(connections, "connection_idle", &EC_GBL_CONF->connection_idle);
   set_pointer(connections, "connection_buffer", &EC_GBL_CONF->connection_buffer);
   set_pointer(connections, "connect_timeout", &EC_GBL_CONF->connect_timeout);
   set_pointer(stats, "sampling_rate", &EC_GBL_CONF->sampling_rate);
   set_pointer(misc, "close_on_eof", &EC_GBL_CONF->close_on_eof);
   set_pointer(misc, "store_profiles", &EC_GBL_CONF->store_profiles);
   set_pointer(misc, "aggressive_dissectors", &EC_GBL_CONF->aggressive_dissectors);
   set_pointer(misc, "skip_forwarded_pcks", &EC_GBL_CONF->skip_forwarded);
   set_pointer(misc, "checksum_warning", &EC_GBL_CONF->checksum_warning);
   set_pointer(misc, "checksum_check", &EC_GBL_CONF->checksum_check);
   set_pointer(misc, "submit_fingerprint", &EC_GBL_CONF->submit_fingerprint);
   set_pointer(misc, "sniffing_at_startup", &EC_GBL_CONF->sniffing_at_startup);
   set_pointer(misc, "geoip_support_enable", &EC_GBL_CONF->geoip_support_enable);
   set_pointer(misc, "gtkui_prefer_dark_theme", &EC_GBL_CONF->gtkui_prefer_dark_theme);
   set_pointer(curses, "color_bg", &EC_GBL_CONF->colors.bg);
   set_pointer(curses, "color_fg", &EC_GBL_CONF->colors.fg);
   set_pointer(curses, "color_join1", &EC_GBL_CONF->colors.join1);
   set_pointer(curses, "color_join2", &EC_GBL_CONF->colors.join2);
   set_pointer(curses, "color_border", &EC_GBL_CONF->colors.border);
   set_pointer(curses, "color_title", &EC_GBL_CONF->colors.title);
   set_pointer(curses, "color_focus", &EC_GBL_CONF->colors.focus);
   set_pointer(curses, "color_menu_bg", &EC_GBL_CONF->colors.menu_bg);
   set_pointer(curses, "color_menu_fg", &EC_GBL_CONF->colors.menu_fg);
   set_pointer(curses, "color_window_bg", &EC_GBL_CONF->colors.window_bg);
   set_pointer(curses, "color_window_fg", &EC_GBL_CONF->colors.window_fg);
   set_pointer(curses, "color_selection_bg", &EC_GBL_CONF->colors.selection_bg);
   set_pointer(curses, "color_selection_fg", &EC_GBL_CONF->colors.selection_fg);
   set_pointer(curses, "color_error_bg", &EC_GBL_CONF->colors.error_bg);
   set_pointer(curses, "color_error_fg", &EC_GBL_CONF->colors.error_fg);
   set_pointer(curses, "color_error_border", &EC_GBL_CONF->colors.error_border);
   /* special case for strings */
   set_pointer(strings, "redir_command_on", &EC_GBL_CONF->redir_command_on);
   set_pointer(strings, "redir_command_off", &EC_GBL_CONF->redir_command_off);
#ifdef WITH_IPV6
   set_pointer(strings, "redir6_command_on", &EC_GBL_CONF->redir6_command_on);
   set_pointer(strings, "redir6_command_off", &EC_GBL_CONF->redir6_command_off);
#endif
   set_pointer(strings, "remote_browser", &EC_GBL_CONF->remote_browser);
   set_pointer(strings, "utf8_encoding", &EC_GBL_CONF->utf8_encoding);
   set_pointer(strings, "geoip_data_file", &EC_GBL_CONF->geoip_data_file);
   set_pointer(strings, "geoip_data_file_v6", &EC_GBL_CONF->geoip_data_file_v6);

   /* sanity check */
   do {
      do {
         if (sections[i].entries[j].value == NULL) {
            DEBUG_MSG("INVALID init: %s %s", sections[i].entries[j].name, sections[i].title);
            BUG("check the debug file...");
         }
      } while (sections[i].entries[++j].name != NULL);
      j = 0;
   } while (sections[++i].title != NULL);
}

/* 
 * associate the pointer to a struct
 */

static void set_pointer(struct conf_entry *entry, const char *name, void *ptr)
{
   int i = 0;

   /* search the name */
   do {
      /* found ! set the pointer */
      if (!strcmp(entry[i].name, name))
         entry[i].value = ptr;
      
   } while (entry[++i].name != NULL);
}

static void sanity_checks()
{
   // sampling_rate cannot be equal to 0, since we divide by it
   if (EC_GBL_CONF->sampling_rate == 0)
      EC_GBL_CONF->sampling_rate = 50;
}

/*
 * load the configuration from etter.conf file
 */

void load_conf(void)
{
   FILE *fc;
   char line[256];
   char *p, *q, **tmp;
   int lineno = 0;
   size_t tmplen;
   struct conf_entry *curr_section = NULL;
   void *value = NULL;

   /* initialize the structures */
   init_structures();
   
   DEBUG_MSG("load_conf");
  
   /* the user has specified an alternative config file */
   if (EC_GBL_CONF->file) {
      DEBUG_MSG("load_conf: alternative config: %s", EC_GBL_CONF->file);
      fc = fopen(EC_GBL_CONF->file, FOPEN_READ_TEXT);
      ON_ERROR(fc, NULL, "Cannot open %s", EC_GBL_CONF->file);
   } else {
      /* errors are handled by the function */
      fc = open_data("etc", ETTER_CONF, FOPEN_READ_TEXT);
      ON_ERROR(fc, NULL, "Cannot open %s", ETTER_CONF);
   }
  
   /* read the file */
   while (fgets(line, sizeof(line), fc) != 0) {
      
      /* update the line count */
      lineno++;
      
      /* trim out the comments */
      if ((p = strchr(line, '#')))
         *p = '\0';
      
      /* trim out the new line */
      if ((p = strchr(line, '\n')))
         *p = '\0';

      q = line;
      
      /* trim the initial spaces */
      while (q < line + sizeof(line) && *q == ' ')
         q++;
      
      /* skip empty lines */
      if (line[0] == '\0' || *q == '\0')
         continue;
      
      /* here starts a new section [...] */
      if (*q == '[') {
         
         /* remove the square brackets */
         if ((p = strchr(line, ']')))
            *p = '\0';
         else
            FATAL_ERROR("Missing ] in %s line %d", ETTER_CONF, lineno);
         
         p = q + 1;
         
         DEBUG_MSG("load_conf: SECTION: %s", p);

         /* get the pointer to the right structure */
         if ( (curr_section = search_section(p)) == NULL)
            FATAL_ERROR("Invalid section in %s line %d", ETTER_CONF, lineno);
         
         /* read the next line */
         continue;
      }
   
      /* variable outside a section */
      if (curr_section == NULL)
         FATAL_ERROR("Entry outside a section in %s line %d", ETTER_CONF, lineno);
      
      /* sanity check */
      if (!strchr(q, '='))
         FATAL_ERROR("Parse error %s line %d", ETTER_CONF, lineno);
      
      p = q;

      /* split the entry name from the value */
      do {
         if (*p == ' ' || *p == '='){
            *p = '\0';
            break;
         }
      } while (p++ < line + sizeof(line) );
      
      /* move p to the value */
      p++;
      do {
         if (*p != ' ' && *p != '=')
            break;
      } while (p++ < line + sizeof(line) );
      
      /* 
       * if it is the "dissector" section,
       * do it in a different way
       */
      if (curr_section == dissectors) {
         set_dissector(q, p, lineno);
         continue;
      }
     
      /* search the entry name */
      if ( (value = search_entry(curr_section, q)) == NULL)
         FATAL_ERROR("Invalid entry in %s line %d", ETTER_CONF, lineno);
   
      /* strings must be handled in a different way */
      if (curr_section == strings) {
         /* trim the quotes */
         if (*p == '"')
            p++;
         
         /* set the string value */ 
         tmp = (char **)value;
         *tmp = strdup(p);
         
         /* trim the ending quotes */
         p = *tmp;
         tmplen = strlen(*tmp);
         do {
            if (*p == '"') {
               *p = 0;
               break;
            }
         } while (p++ < *tmp + tmplen );
         
         DEBUG_MSG("load_conf: \tENTRY: %s  [%s]", q, *tmp);
      } else {
         /* set the integer value */ 
         *(int *)value = strtol(p, (char **)NULL, 10);
         DEBUG_MSG("load_conf: \tENTRY: %s  %d", q, *(int *)value);
      }
   }

   sanity_checks();
   fclose(fc);
}

/* 
 * returns the pointer to the struct
 * named "title"
 */
static struct conf_entry * search_section(char *title)
{
   int i = 0;
  
   do {
      /* the section was found */ 
      if (!strcasecmp(sections[i].title, title))
         return sections[i].entries;
      
   } while (sections[++i].title != NULL);

   return NULL;
}

/* 
 * returns the pointer to the value
 * named "name" of the sections "section"
 */

static void * search_entry(struct conf_entry *section, char *name)
{
   int i = 0;
  
   do {
      /* the section was found */ 
      if (!strcasecmp(section[i].name, name))
         return section[i].value;
      
   } while (section[++i].name != NULL);

   return NULL;
}

/*
 * handle the special case of dissectors 
 */
static void set_dissector(char *name, char *values, int lineno)
{
   char *p, *q = values;
   u_int32 value;
   int first = 0;

   /* remove trailing spaces */
   if ((p = strchr(values, ' ')) != NULL)
      *p = '\0';
   
   /* expand multiple ports dissectors */
   for(p=strsep(&values, ","); p != NULL; p=strsep(&values, ",")) {
      /* get the value for the port */
      value = atoi(p);
      //DEBUG_MSG("load_conf: \tDISSECTOR: %s\t%d", name, value);

      /* count the dissectors and the port monitored */
      if (value) {
         number_of_ports++;
         if (first == 0) {
            number_of_dissectors++;
            first = 1;
         }
      }
    
      /* the first value replaces all the previous */
      if (p == q) {
         if (dissect_modify(MODE_REP, name, value) != E_SUCCESS)
            fprintf(stderr, "Dissector \"%s\" not supported (%s line %d)\n", name, ETTER_CONF, lineno);
      } else {
         /* the other values have to be added */
         if (dissect_modify(MODE_ADD, name, value) != E_SUCCESS)
            fprintf(stderr, "Dissector \"%s\" not supported (%s line %d)\n", name, ETTER_CONF, lineno);
      }
      
   }

}


/*
 * print the number of dissectors loaded 
 */
void conf_dissectors(void)
{
   USER_MSG("%4d protocol dissectors\n", number_of_dissectors);   
   USER_MSG("%4d ports monitored\n", number_of_ports);   
}

/* EOF */

// vim:ts=3:expandtab

