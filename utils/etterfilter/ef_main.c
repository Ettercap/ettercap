/*
    etterfilter -- filter compiler for ettercap content filtering engine

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

#include <ef.h>
#include <ef_functions.h>
#include <ec_libettercap.h>

#include <stdarg.h>

#define EF_GBL_FREE(x) do{ if (x != NULL) { free(x); x = NULL; } }while(0)

/* globals */

extern FILE * yyin;           /* from scanner */
extern int yyparse (void);    /* from parser */

/* global options */
struct ec_globals *ec_gbls;
struct ef_globals *ef_gbls;

/*******************************************/

int main(int argc, char *argv[])
{
   int ret_value = 0;
   libettercap_init(PROGRAM, EC_VERSION);
   ef_globals_alloc();
   select_text_interface();
   libettercap_ui_init();
   /* etterfilter copyright */
   USER_MSG("\n" EC_COLOR_BOLD "%s %s" EC_COLOR_END " copyright %s %s\n\n", 
                      PROGRAM, EC_VERSION, EC_COPYRIGHT, EC_AUTHORS);
 
   /* initialize the line number */
   EF_GBL->lineno = 1;
  
   /* getopt related parsing...  */
   parse_options(argc, argv);

   /* set the input for source file */
   if (EF_GBL_OPTIONS->source_file) {
      yyin = fopen(EF_GBL_OPTIONS->source_file, "r");
      if (yyin == NULL)
         FATAL_ERROR("Input file not found !");
   } else {
      FATAL_ERROR("No source file.");
   }

   /* no buffering */
   setbuf(yyin, NULL);
   setbuf(stdout, NULL);
   setbuf(stderr, NULL);

   
   /* load the tables in etterfilter.tbl */
   load_tables();
   /* load the constants in etterfilter.cnt */
   load_constants();

   /* print the message */
   USER_MSG("\n Parsing source file \'%s\' ", EF_GBL_OPTIONS->source_file);

   ef_debug(1, "\n");

   /* begin the parsing */
   if (yyparse() == 0)
      USER_MSG(" done.\n\n");
   else
      USER_MSG("\n\nThe script contains errors...\n\n");
  
   /* write to file */
   ret_value = write_output();
   if (ret_value == -E_NOTHANDLED)
      FATAL_ERROR("Cannot write output file (%s): the filter is not correctly handled.", EF_GBL_OPTIONS->output_file);
   else if (ret_value == -E_INVALID)
      FATAL_ERROR("Cannot write output file (%s): the filter format is not correct. ", EF_GBL_OPTIONS->output_file);

   ef_exit(0);
}


/*
 * print debug information
 */
void ef_debug(u_char level, const char *message, ...)
{ 
   va_list ap;
   
   /* if not in debug don't print anything */
   if (EF_GBL_OPTIONS->debug < level)
      return;

   /* print the message */ 
   va_start(ap, message);
   vfprintf (stderr, message, ap);
   fflush(stderr);
   va_end(ap);
   
}

void ef_globals_alloc(void)
{

   SAFE_CALLOC(ef_gbls, 1, sizeof(struct ef_globals));

   return;
}

void ef_globals_free(void)
{
   SAFE_FREE(ef_gbls->source_file);
   SAFE_FREE(ef_gbls->output_file);
   SAFE_FREE(ef_gbls);

   return;

}

void ef_exit(int code)
{
   libettercap_ui_cleanup();
   ef_globals_free();
   exit(code);
}

/* EOF */

// vim:ts=3:expandtab

