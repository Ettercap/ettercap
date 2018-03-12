/*
    etterlog -- parsing utilities

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


#include <el.h>
#include <ec_format.h>
#include <el_functions.h>

#include <ctype.h>

#ifdef HAVE_GETOPT_H
   #include <getopt.h>
#else
   #include <missing/getopt.h>
#endif

/* protos... */

static void el_usage(void);

/*******************************************/

void el_usage(void)
{

   fprintf(stdout, "\nUsage: %s [OPTIONS] logfile\n", PROGRAM);

   fprintf(stdout, "\nGeneral Options:\n");
   fprintf(stdout, "  -a, --analyze               analyze a log file and return useful infos\n");
   fprintf(stdout, "  -c, --connections           display the table of connections\n");
   fprintf(stdout, "  -f, --filter <TARGET>       print packets only from this target\n");
   fprintf(stdout, "  -t, --proto <proto>         display only this proto (default is all)\n");
   fprintf(stdout, "  -F, --filcon <CONN>         print packets only from this connection \n");
   fprintf(stdout, "  -s, --only-source           print packets only from the source\n");
   fprintf(stdout, "  -d, --only-dest             print packets only from the destination\n");
   fprintf(stdout, "  -r, --reverse               reverse the target/connection matching\n");
   fprintf(stdout, "  -n, --no-headers            skip header information between packets\n");
   fprintf(stdout, "  -m, --show-mac              show mac addresses in the headers\n");
   fprintf(stdout, "  -k, --color                 colorize the output\n");
   fprintf(stdout, "  -l, --only-local            show only local hosts parsing info files\n");
   fprintf(stdout, "  -L, --only-remote           show only remote hosts parsing info files\n");
   
   fprintf(stdout, "\nSearch Options:\n");
   fprintf(stdout, "  -e, --regex <regex>         display only packets that match the regex\n");
   fprintf(stdout, "  -u, --user <user>           search for info about the user <user>\n");
   fprintf(stdout, "  -p, --passwords             print only accounts information\n");
   fprintf(stdout, "  -i, --show-client           show client address in the password profiles\n");
   fprintf(stdout, "  -I, --client <ip>           search for pass from a specific client\n");
   
   fprintf(stdout, "\nEditing Options:\n");
   fprintf(stdout, "  -C, --concat                concatenate more files into one single file\n");
   fprintf(stdout, "  -o, --outfile <file>        the file used as output for concatenation\n");
   fprintf(stdout, "  -D, --decode                used to extract files from connections\n");
   
   fprintf(stdout, "\nVisualization Method:\n");
   fprintf(stdout, "  -B, --binary                print packets as they are\n");
   fprintf(stdout, "  -X, --hex                   print packets in hex mode\n");
   fprintf(stdout, "  -A, --ascii                 print packets in ascii mode (default)\n");
   fprintf(stdout, "  -T, --text                  print packets in text mode\n");
   fprintf(stdout, "  -E, --ebcdic                print packets in ebcdic mode\n");
   fprintf(stdout, "  -H, --html                  print packets in html mode\n");
   fprintf(stdout, "  -U, --utf8 <encoding>       print packets in uft-8 using the <encoding>\n");
   fprintf(stdout, "  -Z, --zero                  do not print packets, only headers\n");
   fprintf(stdout, "  -x, --xml                   print host infos in xml format\n");
   
   fprintf(stdout, "\nStandard Options:\n");
   fprintf(stdout, "  -v, --version               prints the version and exit\n");
   fprintf(stdout, "  -h, --help                  this help screen\n");

   fprintf(stdout, "\n\n");

   el_exit(0);
}


void parse_options(int argc, char **argv)
{
   int c;

   static struct option long_options[] = {
      { "help", no_argument, NULL, 'h' },
      { "version", no_argument, NULL, 'v' },
      
      { "binary", no_argument, NULL, 'B' },
      { "hex", no_argument, NULL, 'X' },
      { "ascii", no_argument, NULL, 'A' },
      { "text", no_argument, NULL, 'T' },
      { "ebcdic", no_argument, NULL, 'E' },
      { "html", no_argument, NULL, 'H' },
      { "utf8", required_argument, NULL, 'U' },
      { "zero", no_argument, NULL, 'Z' },
      { "xml", no_argument, NULL, 'x' },
      
      { "analyze", no_argument, NULL, 'a' },
      { "connections", no_argument, NULL, 'c' },
      { "filter", required_argument, NULL, 'f' },
      { "filcon", required_argument, NULL, 'F' },
      { "no-headers", no_argument, NULL, 'n' },
      { "only-source", no_argument, NULL, 's' },
      { "only-dest", no_argument, NULL, 'd' },
      { "show-mac", no_argument, NULL, 'm' },
      { "show-client", no_argument, NULL, 'i' },
      { "color", no_argument, NULL, 'k' },
      { "reverse", no_argument, NULL, 'r' },
      { "proto", required_argument, NULL, 't' },
      { "only-local", required_argument, NULL, 'l' },
      { "only-remote", required_argument, NULL, 'L' },
      
      { "outfile", required_argument, NULL, 'o' },
      { "concat", no_argument, NULL, 'C' },
      { "decode", no_argument, NULL, 'D' },
      
      { "user", required_argument, NULL, 'u' },
      { "regex", required_argument, NULL, 'e' },
      { "passwords", no_argument, NULL, 'p' },
      { "client", required_argument, NULL, 'I' },
      
      { 0 , 0 , 0 , 0}
   };

   
   optind = 0;

   while ((c = getopt_long (argc, argv, "AaBCcDdEe:F:f:HhiI:kLlmno:prsTt:U:u:vXxZ", long_options, (int *)0)) != EOF) {

      switch (c) {

         case 'a':
                  EL_GBL_OPTIONS->analyze = 1;
                  break;
                  
         case 'c':
                  EL_GBL_OPTIONS->connections = 1;
                  break;
                  
         case 'D':
                  EL_GBL_OPTIONS->connections = 1;
                  EL_GBL_OPTIONS->decode = 1;
                  NOT_IMPLEMENTED();
                  break;
         
         case 'f':
#ifdef WITH_IPV6
                  if (!strncmp(optarg, "///", 3) &&
                        strlen(optarg) == 3)
                     EL_GBL_TARGET->scan_all = 1;
#else
                  if (!strncmp(optarg, "//", 2) &&
                        strlen(optarg) == 2)
                     EL_GBL_TARGET->scan_all = 1;
#endif
                  compile_target(optarg, EL_GBL_TARGET);

                  break;

         case 'F':
                  filcon_compile(optarg);
                  break;
                  
         case 's':
                  EL_GBL_OPTIONS->only_source = 1;
                  break;
                  
         case 'd':
                  EL_GBL_OPTIONS->only_dest = 1;
                  break;
                  
         case 'k':
                  EL_GBL_OPTIONS->color = 1;
                  break;
                     
         case 'r':
                  EL_GBL_OPTIONS->reverse = 1;
                  break;
                  
         case 't':
                  EL_GBL_TARGET->proto = strdup(optarg);
                  break;
                  
         case 'n':
                  EL_GBL_OPTIONS->no_headers = 1;
                  break;
                  
         case 'm':
                  EL_GBL_OPTIONS->showmac = 1;
                  break;
                  
         case 'i':
                  EL_GBL_OPTIONS->showclient = 1;
                  break;
                  
         case 'I':
                  if (ip_addr_pton(optarg, &EL_GBL->client) != E_SUCCESS) {
                     FATAL_ERROR("Invalid client ip address");
                     return;                    
                  }
                  break;

         case 'l':
                  EL_GBL_OPTIONS->only_local = 1;
                  break;
         
         case 'L':
                  EL_GBL_OPTIONS->only_remote = 1;
                  break;
                  
         case 'u':
                  EL_GBL->user = strdup(optarg);
                  break;
                  
         case 'p':
                  EL_GBL_OPTIONS->passwords = 1;
                  break;

         case 'e':
                  EL_GBL_OPTIONS->regex = 1;
                  set_display_regex(optarg);
                  break;
                 
         case 'o':
                  EL_GBL_LOGFILE = strdup(optarg);
                  break;
                  
         case 'C':
                  EL_GBL_OPTIONS->concat = 1;
                  break;
                  
         case 'B':
                  EL_GBL->format = &bin_format;
                  break;
                  
         case 'X':
                  EL_GBL->format = &hex_format;
                  break;
                  
         case 'A':
                  EL_GBL->format = &ascii_format;
                  break;
                  
         case 'T':
                  EL_GBL->format = &text_format;
                  break;
                  
         case 'E':
                  EL_GBL->format = &ebcdic_format;
                  break;
                  
         case 'H':
                  EL_GBL->format = &html_format;
                  break;
                  
         case 'U':
                  set_utf8_encoding((u_char*)optarg);
                  EL_GBL->format = &utf8_format;
                  break;
                  
         case 'Z':
                  EL_GBL->format = &zero_format;
                  break;
                  
         case 'x':
                  EL_GBL_OPTIONS->xml = 1;
                  break;
                  
         case 'h':
                  el_usage();
                  break;

         case 'v':
                  printf("%s %s\n", PROGRAM, EC_VERSION);
                  el_exit(0);
                  break;

         case ':': // missing parameter
            fprintf(stdout, "\nTry `%s --help' for more options.\n\n", PROGRAM);
            el_exit(0);
         break;

         case '?': // unknown option
            fprintf(stdout, "\nTry `%s --help' for more options.\n\n", PROGRAM);
            el_exit(0);
         break;
      }
   }

   /* file concatenation */
   if (EL_GBL_OPTIONS->concat) {
      if (argv[optind] == NULL)
         FATAL_ERROR("You MUST specify at least one logfile");
   
      /* this function does not return */
      concatenate(optind, argv);
   }

   /* normal file operation */
   if (argv[optind])
      open_log(argv[optind]);
   else
      FATAL_ERROR("You MUST specify a logfile\n");
  
   /* default to ASCII view */ 
   if (EL_GBL->format == NULL)
      EL_GBL->format = &ascii_format;

   return;
}


/* EOF */


// vim:ts=3:expandtab

