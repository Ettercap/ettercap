/*
    etterlog -- parsing utilities

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

    $Header: /home/drizzt/dev/sources/ettercap.cvs/ettercap_ng/utils/etterlog/el_parser.c,v 1.1 2003/03/25 18:43:15 alor Exp $
*/


#include <el.h>
#include <ec_version.h>
#include <el_functions.h>

#include <ctype.h>

#ifdef HAVE_GETOPT_H
   #include <getopt.h>
#else
   #include <missing/getopt.h>
#endif

/* protos... */

static void el_usage(void);
void parse_options(int argc, char **argv);

void expand_token(char *s, u_int max, void (*func)(void *t, int n), void *t );
int match_pattern(const char *s, const char *pattern);

//-----------------------------------

void el_usage(void)
{

   fprintf(stdout, "\nUsage: %s [OPTIONS] logfile\n", GBL_PROGRAM);

   fprintf(stdout, "\nGeneral Options:\n");
   fprintf(stdout, "  -a, --analyze               analyze a log file and return useful infos\n\n");
   
   fprintf(stdout, "\nVisualization Method:\n");
   fprintf(stdout, "  -x, --hex                   print the packet in hex mode\n\n");
   
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
      
      { "hex", no_argument, NULL, 'x' },
      
      { 0 , 0 , 0 , 0}
   };

   
   optind = 0;

   while ((c = getopt_long (argc, argv, "ahxv", long_options, (int *)0)) != EOF) {

      switch (c) {

         case 'a':
                  GBL.analyze = 1;
                  break;
         
         case 'h':
                  el_usage();
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

   if (argv[optind])
      open_log(argv[optind]);
   else
      FATAL_MSG("You MUST specify a logfile");
   
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

