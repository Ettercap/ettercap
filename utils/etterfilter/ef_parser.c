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

    $Id: ef_parser.c,v 1.4 2003/09/19 16:47:51 alor Exp $
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

   fprintf(stdout, "\nUsage: %s [OPTIONS] filterfile\n", GBL_PROGRAM);

   fprintf(stdout, "\nGeneral Options:\n");
   fprintf(stdout, "  -o, --output <file>         output file (default is filter.ef)\n");
   fprintf(stdout, "  -t, --test <file>           test the file (debug mode)\n");
   
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
      
      { "test", required_argument, NULL, 't' },
      { "output", required_argument, NULL, 'o' },
      
      { 0 , 0 , 0 , 0}
   };

   
   optind = 0;

   while ((c = getopt_long (argc, argv, "o:ht:v", long_options, (int *)0)) != EOF) {

      switch (c) {

         case 't':
                  test_filter(optarg);
                  break;
                  
         case 'o':
                  GBL_OPTIONS.output_file = strdup(optarg);
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

