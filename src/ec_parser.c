/*
    ettercap -- parsing utilities

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

    $Header: /home/drizzt/dev/sources/ettercap.cvs/ettercap_ng/src/ec_parser.c,v 1.1 2003/03/08 13:53:38 alor Exp $
*/


#include <ec.h>
#include <ec_interfaces.h>
#include <ec_sniff.h>
#include <ec_send.h>

#include <ctype.h>

#ifdef HAVE_GETOPT_H
   #include <getopt.h>
#else
   #include <missing/getopt.h>
#endif

/* protos... */

static void ec_usage(void);
void parse_options(int argc, char **argv);

void expand_token(char *s, u_int max, void (*func)(void *t, int n), void *t );

//-----------------------------------

void ec_usage(void)
{

   fprintf(stdout, "\nUsage: %s [OPTIONS] [TARGET1] [TARGET2]\n", GBL_PROGRAM);

   fprintf(stdout, "\nTARGET is in the format MAC:IP:PORT (see the man for further detail)\n");
   
   fprintf(stdout, "\nSniffing Method:\n");
   fprintf(stdout, "  -S, --sniff                 use classical sniff\n");
   fprintf(stdout, "  -A, --arp-poison            use ARP poisoning sniff\n");
   fprintf(stdout, "  -B, --bridge <IFACE>        use bridged sniff (needs 2 ifaces)\n");
   fprintf(stdout, "  -p, --nopromisc             do not put the iface in promisc mode\n");
   
   fprintf(stdout, "\nInterface Type:\n");
   fprintf(stdout, "  -C, --console               use console only GUI\n");
   fprintf(stdout, "  -N, --ncurses               use ncurses GUI (default)\n");
   fprintf(stdout, "  -G, --gtk                   use GTK+ GUI\n");
   fprintf(stdout, "  -D, --daemon                daemonize ettercap (no GUI)\n");
   
   fprintf(stdout, "\nGeneral options:\n");
   fprintf(stdout, "  -i, --iface <iface>         use this network interface\n");
   fprintf(stdout, "  -d, --dump <file>           dump sniffed data to <file>\n");
   fprintf(stdout, "  -r, --read <file>           load data from <file>\n\n");
   fprintf(stdout, "  -R, --reversed              use reversed TARGET matching\n\n");
   fprintf(stdout, "  -v, --version               prints the version and exit\n");
   fprintf(stdout, "  -h, --help                  this help screen\n");

   fprintf(stdout, "\n\n");

   exit (0);
}


void parse_options(int argc, char **argv)
{
   int c;

   static struct option long_options[] = {
      { "help", no_argument, NULL, 'h' },
      { "version", no_argument, NULL, 'v' },
      
      { "iface", required_argument, NULL, 'i' },
      { "dump", required_argument, NULL, 'd' },
      { "read", required_argument, NULL, 'r' },
      { "reversed", no_argument, NULL, 'R' },
      
      { "console", no_argument, NULL, 'C' },
      { "ncurses", no_argument, NULL, 'N' },
      { "gtk", no_argument, NULL, 'G' },
      { "daemon", no_argument, NULL, 'D' },
      
      { "sniff", no_argument, NULL, 'S' },
      { "arp-poison", no_argument, NULL, 'A' },
      { "bridge", required_argument, NULL, 'B' },
      { "promisc", no_argument, NULL, 'p' },
      
      { 0 , 0 , 0 , 0}
   };

   for (c = 0; c < argc; c++)
      DEBUG_MSG("parse_options -- [%d] [%s]", c, argv[c]);

   
   /* OPTIONS INITIALIZATION */
   GBL_PCAP->promisc = 1;

   
   optind = 0;

   while ((c = getopt_long (argc, argv, "AB:ChDd:Gi:NpiRr:Sv", long_options, (int *)0)) != EOF) {

      switch (c) {

         case 'S':
                  set_classic_sniff();
                  break;
         
         case 'A':
                  GBL_PCAP->promisc = 0;
                  NOT_IMPLEMENTED();
                  break;
                  
         case 'B':
                  GBL_OPTIONS->iface_bridge = strdup(optarg);
                  set_bridge_sniff();
                  NOT_IMPLEMENTED();
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
                  GBL_OPTIONS->daemonized = 1;
                  NOT_IMPLEMENTED();
                  break;
                  
         case 'i':
                  GBL_OPTIONS->iface = strdup(optarg);
                  break;
                  
         case 'r':
                  GBL_OPTIONS->read = 1;
                  GBL_OPTIONS->dumpfile = strdup(optarg);
                  break;
         
         case 'R':
                  GBL_OPTIONS->reversed = 1;
                  break;
                 
         case 'd':
                  GBL_OPTIONS->dump = 1;
                  GBL_OPTIONS->dumpfile = strdup(optarg);
                  break;
                  
         case 'h':
                  ec_usage();
                  break;

         case 'v':
                  printf("%s %s\n", GBL_PROGRAM, GBL_VERSION);
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
 
   /* create the list form the TARGET format (MAC:IPrange:PORTrange) */
   compile_display_filter();
   
   /* check for other options */
   
   if (GBL_OPTIONS->dump && GBL_OPTIONS->read)
      FATAL_MSG("You cannote dump and read at the same time...");

   if (GBL_SNIFF->start == NULL)
      FATAL_MSG("Select at least one sniffing method");

#define R(a,b,c) (a & b) | ((a ^ b) & c)     // returns true if more than one was selected
//   if ( R(GBL_OPTIONS->classic_sniff, GBL_OPTIONS->arp_sniff, GBL_OPTIONS->bridged_sniff) )
//      FATAL_MSG("Select ONLY ONE sniffing method.");
#undef R
  
   if (GBL_OPTIONS->read && GBL_SNIFF->type != SM_CLASSIC )
      FATAL_MSG("You can read froma a file ONLY in classic sniffing mode !");
   
   if (GBL_SNIFF->type == SM_BRIDGED && GBL_PCAP->promisc == 0)
      FATAL_MSG("During bridged sniffing the iface must be in promisc mode !");
   
   if (GBL_OPTIONS->iface_bridge && !strcmp(GBL_OPTIONS->iface_bridge, GBL_OPTIONS->iface))
      FATAL_MSG("Bridged iface must be different from %s !!", GBL_OPTIONS->iface);
   
   /* XXX - check for incompatible options */
   
   return;
}


/*
 * This function parses the input in the form [1-3,17,5-11]
 * and fill the structure with expanded numbers.
 */

void expand_token(char *s, u_int max, void (*func)(void *t, int n), void *t )
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
      
      /* process the range */
      for(; a <= b; a++) {
         func(t, a);
      }
      
      if (q == end) break;
      else  p = q + 1;      
   }
  
   SAFE_FREE(str);
}

/* EOF */


// vim:ts=3:expandtab

