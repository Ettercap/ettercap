/*
    ettercap -- parsing utilities

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

    $Header: /home/drizzt/dev/sources/ettercap.cvs/ettercap_ng/src/ec_parser.c,v 1.25 2003/06/10 10:39:37 alor Exp $
*/


#include <ec.h>
#include <ec_interfaces.h>
#include <ec_sniff.h>
#include <ec_send.h>
#include <ec_log.h>
#include <ec_format.h>

#include <ctype.h>

#ifdef HAVE_GETOPT_H
   #include <getopt.h>
#else
   #include <missing/getopt.h>
#endif

/* protos... */

static void ec_usage(void);
void parse_options(int argc, char **argv);

int expand_token(char *s, u_int max, void (*func)(void *t, int n), void *t );
int match_pattern(const char *s, const char *pattern);

//-----------------------------------

void ec_usage(void)
{

   fprintf(stdout, "\nUsage: %s [OPTIONS] [TARGET1] [TARGET2]\n", GBL_PROGRAM);

   fprintf(stdout, "\nTARGET is in the format MAC/IPs/PORTs (see the man for further detail)\n");
   
   fprintf(stdout, "\nSniffing options:\n");
   fprintf(stdout, "  -A, --arp-poison            perform ARP poisoning while sniff\n");
   fprintf(stdout, "  -B, --bridge <IFACE>        use bridged sniff (needs 2 ifaces)\n");
   fprintf(stdout, "  -p, --nopromisc             do not put the iface in promisc mode\n");
   fprintf(stdout, "  -r, --read <file>           read data from pcapfile <file>\n");
   fprintf(stdout, "  -f, --pcapfilter <string>   set the pcap filter <string>\n");
   fprintf(stdout, "  -R, --reversed              use reversed TARGET matching\n");
   fprintf(stdout, "  -t, --proto <proto>         sniff only this proto (default is all)\n");
   
   fprintf(stdout, "\nUser Interface Type:\n");
   fprintf(stdout, "  -C, --console               use console only GUI\n");
   fprintf(stdout, "       -q, --quiet                 do not display packet contents\n");
   fprintf(stdout, "  -N, --ncurses               use ncurses GUI (default)\n");
   fprintf(stdout, "  -G, --gtk                   use GTK+ GUI\n");
   fprintf(stdout, "  -D, --daemon                daemonize ettercap (no GUI)\n");
   
   fprintf(stdout, "\nLogging options:\n");
   fprintf(stdout, "  -w, --write <file>          write sniffed data to pcapfile <file>\n");
   fprintf(stdout, "  -L, --log <logfile>         log all the traffic to this <logfile>\n");
   fprintf(stdout, "  -l, --log-info <logfile>    log only passive infos to this <logfile>\n");
   fprintf(stdout, "  -c, --compress              use gzip compression on log files\n");
   fprintf(stdout, "  -e, --regex <regex>         log only packets matching this regex\n");
   
   fprintf(stdout, "\nGeneral options:\n");
   fprintf(stdout, "  -i, --iface <iface>         use this network interface\n");
   fprintf(stdout, "  -n, --netmask <netmask>     force this <netmask> on iface\n");
   fprintf(stdout, "  -P, --plugin <plugin>       launch this <plugin>\n");
   fprintf(stdout, "  -d, --dns                   resolves ip addresses into hostnames\n");
   fprintf(stdout, "  -z, --silent                do not perform the initial ARP scan\n");
   fprintf(stdout, "  -Z, --scan-delay <msec>     set the scanning delay to <msec>\n");
   fprintf(stdout, "  -j, --load-hosts <file>     load the hosts list from <file>\n");
   fprintf(stdout, "  -k, --save-hosts <file>     save the hosts list to <file>\n");
   fprintf(stdout, "  -V, --visual <format>       set the visualization format\n");
   
   fprintf(stdout, "\nStandard options:\n");
   fprintf(stdout, "  -v, --version               prints the version and exit\n");
   fprintf(stdout, "  -h, --help                  this help screen\n");

   fprintf(stdout, "\n\n");

   clean_exit(0);
}


void parse_options(int argc, char **argv)
{
   int c;

   static struct option long_options[] = {
      { "help", no_argument, NULL, 'h' },
      { "version", no_argument, NULL, 'v' },
      
      { "iface", required_argument, NULL, 'i' },
      { "netmask", required_argument, NULL, 'n' },
      { "write", required_argument, NULL, 'w' },
      { "read", required_argument, NULL, 'r' },
      { "pcapfilter", required_argument, NULL, 'f' },
      
      { "reversed", no_argument, NULL, 'R' },
      { "proto", required_argument, NULL, 't' },
      
      { "plugin", required_argument, NULL, 'P' },
      
      { "quiet", no_argument, NULL, 'q' },
      { "silent", no_argument, NULL, 'z' },
      { "dns", no_argument, NULL, 'd' },
      { "scan-delay", required_argument, NULL, 'Z' },
      { "load-hosts", required_argument, NULL, 'j' },
      { "save-hosts", required_argument, NULL, 'k' },
      { "visual", required_argument, NULL, 'V' },
      
      { "log", required_argument, NULL, 'L' },
      { "log-info", required_argument, NULL, 'l' },
      { "compress", no_argument, NULL, 'c' },
      { "regex", required_argument, NULL, 'e' },
      
      { "console", no_argument, NULL, 'C' },
      { "ncurses", no_argument, NULL, 'N' },
      { "gtk", no_argument, NULL, 'G' },
      { "daemon", no_argument, NULL, 'D' },
      
      { "arp-poison", no_argument, NULL, 'A' },
      { "bridge", required_argument, NULL, 'B' },
      { "promisc", no_argument, NULL, 'p' },
      
      { 0 , 0 , 0 , 0}
   };

   for (c = 0; c < argc; c++)
      DEBUG_MSG("parse_options -- [%d] [%s]", c, argv[c]);

   
/* OPTIONS INITIALIZATION */
   
   GBL_PCAP->promisc = 1;
   GBL_FORMAT = &ascii_format;

/* OPTIONS INITIALIZED */
   
   optind = 0;

   while ((c = getopt_long (argc, argv, "AB:CchDde:f:Ghi:j:k:L:l:Nn:P:pqiRr:t:V:vw:Z:z", long_options, (int *)0)) != EOF) {

      switch (c) {

         case 'A':
                  set_arp_sniff();
                  NOT_IMPLEMENTED();
                  break;
                  
         case 'B':
                  GBL_OPTIONS->iface_bridge = strdup(optarg);
                  set_bridge_sniff();
                  break;
                  
         case 'p':
                  GBL_PCAP->promisc = 0;
                  break;
                 
         case 'C':
                  set_console_interface();
                  break;
                  
         case 'N':
                  NOT_IMPLEMENTED();
                  break;
                  
         case 'G':
                  NOT_IMPLEMENTED();
                  break;
         
         case 'D':
                  set_daemon_interface();
                  break;
                  
         case 'R':
                  GBL_OPTIONS->reversed = 1;
                  break;
                  
         case 't':
                  GBL_OPTIONS->proto = strdup(optarg);
                  break;
                  
         case 'P':
                  GBL_OPTIONS->plugin = strdup(optarg);
                  break;
                  
         case 'i':
                  GBL_OPTIONS->iface = strdup(optarg);
                  break;
         
         case 'n':
                  GBL_OPTIONS->netmask = strdup(optarg);
                  break;
                  
         case 'r':
                  /* we don't want to scan the lan while reading from file */
                  GBL_OPTIONS->silent = 1;
                  GBL_OPTIONS->read = 1;
                  GBL_OPTIONS->dumpfile = strdup(optarg);
                  break;
                 
         case 'w':
                  GBL_OPTIONS->write = 1;
                  GBL_OPTIONS->dumpfile = strdup(optarg);
                  break;
                  
         case 'f':
                  GBL_PCAP->filter = strdup(optarg);
                  break;
                  
         case 'L':
                  if (set_loglevel(LOG_PACKET, optarg) == -EFATAL)
                     clean_exit(-EFATAL);
                  break;

         case 'l':
                  if (set_loglevel(LOG_INFO, optarg) == -EFATAL)
                     clean_exit(-EFATAL);
                  break;
                  
         case 'c':
                  GBL_OPTIONS->compress = 1;
                  break;
                  
         case 'e':
                  if (set_logregex(optarg) == -EFATAL)
                     clean_exit(-EFATAL);
                  break;
                  
         case 'q':
                  GBL_OPTIONS->quiet = 1;
                  break;
                  
         case 'z':
                  GBL_OPTIONS->silent = 1;
                  break;
                  
         case 'd':
                  GBL_OPTIONS->resolve = 1;
                  break;
                  
         case 'Z':
                  GBL_OPTIONS->scan_delay = atoi(optarg);
                  /* at least one millisecond */
                  if (GBL_OPTIONS->scan_delay == 0)
                     GBL_OPTIONS->scan_delay = 1;
                  break;
                  
         case 'j':
                  GBL_OPTIONS->silent = 1;
                  GBL_OPTIONS->load_hosts = 1;
                  GBL_OPTIONS->hostsfile = strdup(optarg);
                  break;
                  
         case 'k':
                  GBL_OPTIONS->save_hosts = 1;
                  GBL_OPTIONS->hostsfile = strdup(optarg);
                  break;
                  
         case 'V':
                  /* the global visualization method */
                  set_format(optarg);
                  break;
                  
         case 'h':
                  ec_usage();
                  break;

         case 'v':
                  printf("%s %s\n", GBL_PROGRAM, GBL_VERSION);
                  clean_exit(0);
                  break;

         case ':': // missing parameter
            fprintf(stdout, "\nTry `%s --help' for more options.\n\n", GBL_PROGRAM);
            clean_exit(-1);
         break;

         case '?': // unknown option
            fprintf(stdout, "\nTry `%s --help' for more options.\n\n", GBL_PROGRAM);
            clean_exit(-1);
         break;
      }
   }

   DEBUG_MSG("parse_options: options parsed");
   
   /* TARGET1 and TARGET2 parsing */
   if (argv[optind]) {
      GBL_OPTIONS->target1 = strdup(argv[optind]);
      DEBUG_MSG("TARGET1: %s", GBL_OPTIONS->target1);
      
      if (argv[optind+1]) {
         GBL_OPTIONS->target2 = strdup(argv[optind+1]);
         DEBUG_MSG("TARGET2: %s", GBL_OPTIONS->target2);
      }
   }
   /* if not specified default to // */
   if (!GBL_OPTIONS->target1)   
      GBL_OPTIONS->target1 = strdup("//");
   
   if (!GBL_OPTIONS->target2)   
      GBL_OPTIONS->target2 = strdup("//");
 
   /* create the list form the TARGET format (MAC/IPrange/PORTrange) */
   compile_display_filter();
   
   DEBUG_MSG("parse_options: targets parsed");
   
   /* check for other options */
   
   if (GBL_SNIFF->start == NULL)
      set_unified_sniff();
   
   if (GBL_OPTIONS->write && GBL_OPTIONS->read)
      FATAL_ERROR("You cannote dump and read at the same time...");
   
   if (GBL_OPTIONS->read && GBL_PCAP->filter)
      FATAL_ERROR("Cannot read from file and set a filter on interface");
   
   if (GBL_OPTIONS->read && GBL_SNIFF->type != SM_UNIFIED )
      FATAL_ERROR("You can read from a file ONLY in unified sniffing mode !");

   if (GBL_UI->init == NULL)
      FATAL_ERROR("Please select an User Interface");
   
   if (GBL_SNIFF->type == SM_BRIDGED && GBL_PCAP->promisc == 0)
      FATAL_ERROR("During bridged sniffing the iface must be in promisc mode !");
   
   if (GBL_OPTIONS->quiet && GBL_UI->type != UI_CONSOLE)
      FATAL_ERROR("The quiet option is useful only with Console UI");
  
   if (GBL_OPTIONS->load_hosts && GBL_OPTIONS->save_hosts)
      FATAL_ERROR("Cannot load and save at the same time the hosts list...");
  
      
   /* XXX - check for incompatible options */
   
   DEBUG_MSG("parse_options: options combination looks good");
   
   return;
}


/*
 * This function parses the input in the form [1-3,17,5-11]
 * and fill the structure with expanded numbers.
 */

int expand_token(char *s, u_int max, void (*func)(void *t, int n), void *t )
{
   char *str = strdup(s);
   char *p, *q, r;
   char *end;
   u_int a = 0, b = 0;
   
   DEBUG_MSG("expand_token %s", s);
   
   p = str;
   end = p + strlen(p);
   
   while (p < end) {
      q = p;
      
      /* find the end of the first digit */
      while ( isdigit((int)*q) && q++ < end);
      
      r = *q;   
      *q = 0;
      /* get the first digit */
      a = atoi(p);
      if (a > max) 
         FATAL_MSG("Out of range (%d) !!", max);
      
      /* it is a range ? */
      if ( r == '-') {
         p = ++q;
         /* find the end of the range */
         while ( isdigit((int)*q) && q++ < end);
         *q = 0;
         if (*p == '\0') 
            FATAL_MSG("Invalid range !!");
         /* get the second digit */
         b = atoi(p);
         if (b > max) 
            FATAL_MSG("Out of range (%d)!!", max);
         if (b < a)
            FATAL_MSG("Invalid decrementing range !!");
      } else {
         /* it is not a range */
         b = a; 
      } 
      
      /* process the range and invoke the callback */
      for(; a <= b; a++) {
         func(t, a);
      }
      
      if (q == end) break;
      else  p = q + 1;      
   }
  
   SAFE_FREE(str);
   
   return ESUCCESS;
}

/* Pattern matching code from OpenSSH. */
int match_pattern(const char *s, const char *pattern)
{
   for (;;) {
      if (!*pattern) 
         return (!*s);

      if (*pattern == '*') {
         pattern++;
         
         if (*pattern != '?' && *pattern != '*') {
            
            for (; *s; s++) {
               if (*s == *pattern && match_pattern(s + 1, pattern + 1))
                  return (1);
            }
            return (0);
         }
         
         for (; *s; s++) {
            if (match_pattern(s, pattern))
               return (1);
         }
         return (0);
      }
      
      if (!*s) 
         return (0);
      
      if (*pattern != '?' && *pattern != *s)
         return (0);
      
      s++;
      pattern++;
   }
   /* NOTREACHED */
}




/* EOF */


// vim:ts=3:expandtab

