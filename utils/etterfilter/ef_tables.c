/*
    etterfilter -- offset tables handling

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

    $Header: /home/drizzt/dev/sources/ettercap.cvs/ettercap_ng/utils/etterfilter/ef_tables.c,v 1.1 2003/09/08 21:03:03 alor Exp $
*/

#include <ef.h>
#include <ec_file.h>

#include <ctype.h>

/* globals */

struct off_entry {
   char *name;
   u_int8 level;
   u_int16 offset;
   u_int8 size;
   SLIST_ENTRY(off_entry) next;
};

struct table_entry {
   char * name;
   SLIST_HEAD (, off_entry) offsets;
   SLIST_ENTRY(table_entry) next;
};

static SLIST_HEAD (, table_entry) table_head;

/* protos */

void load_tables(void);
static void add_virtualpointer(char *name, u_int8 level, char *offname, u_int16 offset, u_int8 size);
void get_virtualpointer(char *name, char *offname, u_int8 *level, u_int16 *offset, u_int8 *size);

/*******************************************/

/* 
 * parse the config file 
 */
void load_tables(void)
{
   struct table_entry *t;
   FILE *fc;
   char line[128];
   int lineno = 0, ntables = 0;
   char *p, *q, *end;
   char *name = NULL, *oname = NULL;
   u_int8 level = 0, size = 0;
   u_int16 offset = 0;
   

   /* errors are handled by the function */
   fc = open_data("etc", "etterfilter.conf", "r");

   /* read the file */
   while (fgets(line, 128, fc) != 0) {
     
      /* pointer to the end of the line */
      end = line + strlen(line);
      
      /* count the lines */
      lineno++;

      /* trim out the comments */
      if ((p = strchr(line, '#')))
         *p = '\0';

      /* trim out the new line */
      if ((p = strchr(line, '\n')))
         *p = '\0';

      /* skip empty lines */
      if (line[0] == '\0')
         continue;
      
      /* eat the empty spaces */
      for (q = line; *q == ' ' && q < end; q++);

      /* begin of a new section */
      if (*q == '[') {
         SAFE_FREE(name);
         
         /* get the name in the brackets [ ] */
         if ((p = strchr(q, ']')))
            *p = '\0';
         else
            FATAL_ERROR("Parse error in etterfilter.conf on line %d", lineno);

         name = strdup(q + 1);
         ntables++;
         
         /* get the level in the next brackets [ ] */
         q = p + 1;
         if ((p = strchr(q, ']')))
            *p = '\0';
         else
            FATAL_ERROR("Parse error in etterfilter.conf on line %d", lineno);

         level = atoi(q + 1);

         continue;
      }
      
      /* parse the offsets and add them to the table */
      oname = strtok(q, ":");
      q = strtok(NULL, ":");
      if ((p = strchr(q, ' ')) || (p = strchr(q, '=')))
         *p = '\0';
      else
         FATAL_ERROR("Parse error in etterfilter.conf on line %d", lineno);

      /* get the size */
      size = atoi(q);
      
      /* get the offset */
      for (q = p; !isdigit((int)*q) && q < end; q++);
      
      offset = atoi(q);

      /* add to the table */
      add_virtualpointer(name, level, oname, offset, size);
   }

   /* print some nice informations */
   fprintf(stdout, "\n%3d protocol tables loaded:\n", ntables);
   fprintf(stdout, "\t");
   SLIST_FOREACH(t, &table_head, next)
      fprintf(stdout, "%s", t->name);
   fprintf(stdout, "\n\n");
   
}

/*
 * add a new virtual pointer to the table
 */
static void add_virtualpointer(char *name, u_int8 level, char *offname, u_int16 offset, u_int8 size)
{
   (void)table_head;

   //printf("%s %d %s %d %d\n", name, level, offname, offset, size);
}

/*
 * get a virtual pointer from the table
 */
void get_virtualpointer(char *name, char *offname, u_int8 *level, u_int16 *offset, u_int8 *size)
{
   (void)table_head;
}

/* EOF */

// vim:ts=3:expandtab

