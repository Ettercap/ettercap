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

    $Id: ec_conf.c,v 1.1 2003/06/21 13:58:42 alor Exp $
*/

#include <ec.h>
#include <ec_conf.h>
#include <ec_file.h>

/* globals */

static int dummy;

static struct conf_entry privs[] = {
   { "ec_uid", NULL },
   { NULL, NULL },
};

static struct conf_entry net[] = {
   { "arp_storm_delay", NULL },
   { "arp_poison_delay", NULL },
   { "arp_poison_warm_up", NULL },
   { NULL, NULL },
};

static struct conf_entry connections[] = {
   { "connection_timeout", NULL },
   { NULL, NULL },
};

static struct conf_entry stats[] = {
   { "sampling_rate", NULL },
   { NULL, NULL },
};

static struct conf_entry dissectors[] = {
   { "ftp", &dummy },
   { "pop", &dummy },
   { "dns", &dummy },
   { NULL, NULL },
};

static struct conf_section sections[] = {
   { "privs", (struct conf_entry *)&privs},
   { "net", (struct conf_entry *)&net},
   { "connections", (struct conf_entry *)&connections},
   { "stats", (struct conf_entry *)&stats},
   { "dissectors", (struct conf_entry *)&dissectors},
   { NULL, NULL },
};


/* protos */

void load_conf(void);
static void init_structures(void);
static void set_pointer(struct conf_entry *entry, char *name, int *ptr);

static struct conf_entry * search_section(char *title);
static int * search_entry(struct conf_entry *section, char *name);

/************************************************/

/*
 * since GBL_CONF is in the heap, it is not constant
 * so we have to initialize it here and not in the
 * structure definition
 */

static void init_structures(void)
{
   int i = 0, j = 0;
   
   DEBUG_MSG("init_structures");
   
   set_pointer((struct conf_entry *)&privs, "ec_uid", &GBL_CONF->ec_uid);
   set_pointer((struct conf_entry *)&net, "arp_storm_delay", &GBL_CONF->arp_storm_delay);
   set_pointer((struct conf_entry *)&net, "arp_poison_warm_up", &GBL_CONF->arp_poison_warm_up);
   set_pointer((struct conf_entry *)&net, "arp_poison_delay", &GBL_CONF->arp_poison_delay);
   set_pointer((struct conf_entry *)&connections, "connection_timeout", &GBL_CONF->connection_timeout);
   set_pointer((struct conf_entry *)&stats, "sampling_rate", &GBL_CONF->sampling_rate);

   /* sanity check */
   do {
      do {
         BUG_ON(sections[i].entries[j].value == NULL);
      } while (sections[i].entries[++j].name != NULL);
      j = 0;
   } while (sections[++i].title != NULL);
}

/* 
 * associate the pointer to a struct
 */

static void set_pointer(struct conf_entry *entry, char *name, int *ptr)
{
   int i = 0;

   /* search the name */
   do {
      /* found ! set the pointer */
      if (!strcmp(entry[i].name, name))
         entry[i].value = ptr;
      
   } while (entry[++i].name != NULL);
}

/*
 * load the configuration from etter.conf file
 */

void load_conf(void)
{
   FILE *fc;
   char line[128];
   char *p;
   int lineno = 0;
   struct conf_entry *curr_section = NULL;
   int *value = NULL;

   /* initialize the structures */
   init_structures();
   
   DEBUG_MSG("load_conf");
   
   /* errors are handled by the function */
   fc = open_data("etc", ETTER_CONF, "r");
  
   /* read the file */
   while (fgets(line, 128, fc) != 0) {
      
      /* update the line count */
      lineno++;
      
      /* trim out the comments */
      if ((p = strchr(line, '#')))
         *p = '\0';
      
      /* trim out the new line */
      if ((p = strchr(line, '\n')))
         *p = '\0';

      /* skip empty lines */
      if (line[0] == '\0' || line[0] == ' ')
         continue;

      /* here starts a new section [...] */
      if (line[0] == '[') {
         
         /* remove the square brackets */
         if ((p = strchr(line, ']')))
            *p = '\0';
         else
            FATAL_ERROR("Missing ] in %s line %d", ETTER_CONF, lineno);
         
         p = line + 1;
         
         DEBUG_MSG("load_conf: SECTION: %s", p);

         if ( (curr_section = search_section(p)) == NULL)
            FATAL_ERROR("Invalid section in %s line %d", ETTER_CONF, lineno);
        
         /* read the next line */
         continue;
      }

      if (curr_section == NULL)
         FATAL_ERROR("Entry outside a section in %s line %d", ETTER_CONF, lineno);
      
      /* sanity check */
      if (!strchr(line, '='))
         FATAL_ERROR("Parse error %s line %d", ETTER_CONF, lineno);
      
      /* remove the spaces or '=' */
      p = line;
      do {
         if (*p == ' ' || *p == '='){
            *p = '\0';
            break;
         }
      } while (p++ < line + sizeof(line) );
      
      /* search the entry name */
      if ( (value = search_entry(curr_section, line)) == NULL)
         FATAL_ERROR("Invalid entry in %s line %d", ETTER_CONF, lineno);
     
      /* move p to the integer value */
      p++;
      do {
         if (*p != ' ' && *p != '=')
            break;
      } while (p++ < line + sizeof(line) );
     
      *value = strtol(p, (char **)NULL, 10);
      
      DEBUG_MSG("load_conf: \tENTRY: %s  %d", line, *value);

   }
   
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

static int * search_entry(struct conf_entry *section, char *name)
{
   int i = 0;
  
   do {
      /* the section was found */ 
      if (!strcasecmp(section[i].name, name))
         return section[i].value;
      
   } while (section[++i].name != NULL);

   return NULL;
}

/* EOF */

// vim:ts=3:expandtab

