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

    $Id: ef_main.c,v 1.10 2003/09/19 16:47:51 alor Exp $
*/

#include <ef.h>
#include <ef_functions.h>
#include <ec_version.h>

/* globals */

extern FILE * yyin;           /* from scanner */
extern int yyparse (void);    /* from parser */

/* global options */
struct globals gbls;


/*******************************************/

int main(int argc, char *argv[])
{

   /* etterfilter copyright */
   fprintf(stderr, "\n\033[01m\033[1m%s %s\033[0m copyright %s %s\n\n",
                      GBL_PROGRAM, EC_VERSION, EC_COPYRIGHT, EC_AUTHORS);
  
  
   /* getopt related parsing...  */
   parse_options(argc, argv);

   /* set the input for source file */
   if (GBL_OPTIONS.source_file) {
      yyin = fopen(GBL_OPTIONS.source_file, "r");
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
   fprintf(stdout, "\nCompiling source file %s...\n\n", GBL_OPTIONS.source_file);


   /* begin the parsing */
   if (yyparse() == 0)
      fprintf(stdout, "\nDone.\n\n");
   else
      fprintf(stdout, "\nThe script contains errors...\n\n");
      
  
   /* write to file */
   // write_output();

   return 0;
}



/* EOF */

// vim:ts=3:expandtab

