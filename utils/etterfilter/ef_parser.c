/*
    etterfilter -- parsing utilities

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

    $Header: /home/drizzt/dev/sources/ettercap.cvs/ettercap_ng/utils/etterfilter/ef_parser.c,v 1.1 2003/08/28 19:55:20 alor Exp $
*/


#include <ef.h>
#include <ec_version.h>
#include <ec_format.h>
#include <ef_functions.h>

#ifdef HAVE_GETOPT_H
   #include <getopt.h>
#else
   #include <missing/getopt.h>
#endif

/* protos... */

static void ef_usage(void);
void parse_options(int argc, char **argv);


/*********************************************/

void ef_usage(void)
{

   fprintf(stdout, "\nUsage: %s [OPTIONS] logfile\n", GBL_PROGRAM);

   fprintf(stdout, "\nGeneral Options:\n");
   
   fprintf(stdout, "\nStandard Options:\n");
   fprintf(stdout, "  -v, --version               prints the version and exit\n");
   fprintf(stdout, "  -h, --help                  this help screen\n");

   fprintf(stdout, "\n\n");

   exit(0);
}


void parse_options(int argc, char **argv)
{
   int c;

   static struct option long_options[] = {
      { "help", no_argument, NULL, 'h' },
      { "version", no_argument, NULL, 'v' },
      
      { "test", no_argument, NULL, 't' },
      
      { 0 , 0 , 0 , 0}
   };

   
   optind = 0;

   while ((c = getopt_long (argc, argv, "htv", long_options, (int *)0)) != EOF) {

      switch (c) {

         case 't':
                  GBL_OPTIONS.test = 1;
                  break;
                  
         case 'h':
                  ef_usage();
                  break;

         case 'v':
                  printf("%s %s\n", GBL_PROGRAM, EC_VERSION);
                  exit(0);
                  break;

         case ':': // missing parameter
            fprintf(stdout, "\nTry `%s --help' for more options.\n\n", GBL_PROGRAM);
            exit(0);
         break;

         case '?': // unknown option
            fprintf(stdout, "\nTry `%s --help' for more options.\n\n", GBL_PROGRAM);
            exit(0);
         break;
      }
   }

   /* the source file to be compiled */
   if (argv[optind]) {
      GBL_OPTIONS.source_file = strdup(argv[optind]);
   }
   
   /* XXX - check for incompatible options */
   
   
   return;
}



/* EOF */

// vim:ts=3:expandtab

