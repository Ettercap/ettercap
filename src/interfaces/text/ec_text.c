/*
    ettercap -- text only GUI

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

#include <ec.h>
#include <ec_poll.h>
#include <ec_ui.h>
#include <ec_threads.h>
#include <ec_hook.h>
#include <ec_interfaces.h>
#include <ec_format.h>
#include <ec_plugins.h>
#include <ec_text.h>
#include <ec_scan.h>
#include <ec_mitm.h>

#ifdef OS_WINDOWS
   #include <missing/termios_mingw.h>
#else
   #include <termios.h>
#endif

/* globals */

struct termios old_tc;
struct termios new_tc;


/* proto */

void text_interface(void);
static void text_init(void);
static void text_cleanup(void);
static void text_msg(const char *msg);
static void text_error(const char *msg);
static void text_fatal_error(const char *msg);
static void text_input(const char *title, char *input, size_t n, void (*callback)(void));
static void text_help(void);
static int text_progress(char *title, int value, int max);
static void text_run_plugin(void);
static void text_run_filter(void);
static void text_stats(void);
static void text_stop_cont(void);
static void text_hosts_list(void);
static void text_profile_list(void);
static void text_visualization(void);
static void text_redirects(void);

/*******************************************/


void set_text_interface(void)
{
   struct ui_ops ops;

   /* wipe the struct */
   memset(&ops, 0, sizeof(ops));

   /* register the functions */
   ops.init = &text_init;
   ops.start = &text_interface;
   ops.cleanup = &text_cleanup;
   ops.msg = &text_msg;
   ops.error = &text_error;
   ops.fatal_error = &text_fatal_error;
   ops.input = &text_input;
   ops.progress = &text_progress;
   ops.type = UI_TEXT;
   
   ui_register(&ops);
   
   /*
    * add the hook to dispatcher to print the
    * packets in the right format
    */
   hook_add(HOOK_DISPATCHER, text_print_packet);
}

/*
 * set the terminal as non blocking 
 */

static void text_init(void)
{
   /* taken from readchar.c, by M. Andreoli (2000) */
   
   tcgetattr(0, &old_tc);
   new_tc = old_tc;
   new_tc.c_lflag &= ~(ECHO | ICANON);   /* raw output */
   new_tc.c_cc[VTIME] = 1;

   tcsetattr(0, TCSANOW, &new_tc);
}

/*
 * reset to the previous state
 */

static void text_cleanup(void)
{
   /* flush the last user messages */
   ui_msg_flush(MSG_ALL);

   fprintf(stdout, "\n");
   
   tcsetattr(0, TCSANOW, &old_tc);
}

/*
 * print a USER_MSG()
 */

static void text_msg(const char *msg)
{
   /* avoid implicit format bugs */
   fprintf(stdout, "%s", msg);
   /* allow non buffered messages */
   fflush(stdout);
}


/*
 * print an error
 */
static void text_error(const char *msg)
{
   /* avoid implicit format bugs */
   fprintf(stdout, "\nFATAL: %s\n\n", msg);
   /* allow non buffered messages */
   fflush(stdout);
}


/*
 * handle a fatal error and exit
 */
static void text_fatal_error(const char *msg)
{
   /* avoid implicit format bugs */
   fprintf(stdout, "\n"EC_COLOR_RED"FATAL: "EC_COLOR_END"%s\n\n", msg);
   /* allow non buffered messages */
   fflush(stdout);

   /* restore console settings */
   tcsetattr(0, TCSANOW, &old_tc);

   /* exit without calling atexit() */
   _exit(-1);
}


/*
 * display the 'title' and get the 'input' from the user
 */
static void text_input(const char *title, char *input, size_t n, void (*callback)(void))
{
   char *p;
   
   /* display the title */
   fprintf(stdout, "%s", title);
   fflush(stdout);

   /* repristinate the buffer input */
   tcsetattr(0, TCSANOW, &old_tc);

   /* wipe the buffer */
   memset(input, 0, n); 
   
   /* get the user input */
   fgets(input, n, stdin);

   /* trim the \n */
   if ((p = strrchr(input, '\n')) != NULL)
      *p = '\0';
   else {
      /* 
       * eat the input until \n 
       * this will happen if the user has entered
       * more chars than n
       */
      while(getc(stdin) != '\n');
   }

   /* disable buffered input */
   tcsetattr(0, TCSANOW, &new_tc);

   /* 
    * call the supplied function
    * the callee is aware of the buffer to be used
    */
   if (callback != NULL)
      callback();
}

/* 
 * implement the progress bar 
 */
static int text_progress(char *title, int value, int max)
{
   float percent;
   int i;
   
   /* variable not used */
   (void) title;
  
   /* calculate the percent */
   percent = (float)(value)*100/(max);
            
   /* 
    * we use stderr to avoid scrambling of 
    * logfile generated by: ./ettercap -T > logfile 
    */
         
   switch(value % 4) {
      case 0:
         fprintf(stderr, "\r| |");
      break;
      case 1:
         fprintf(stderr, "\r/ |");
      break;
      case 2:
         fprintf(stderr, "\r- |");
      break;
      case 3:
         fprintf(stderr, "\r\\ |");
      break;
   }

   /* fill the bar */
   for (i=0; i < percent/2; i++)
      fprintf(stderr, "=");

   fprintf(stderr, ">");

   /* fill the empty part of the bar */
   for(; i < 50; i++)
      fprintf(stderr, " ");
                              
   fprintf(stderr, "| %6.2f %%", percent );

   fflush(stderr);

   if (value == max) {
      fprintf(stderr, "\r* |==================================================>| 100.00 %%\n\n");
      return UI_PROGRESS_FINISHED;
   }
                     
   return UI_PROGRESS_UPDATED;
}


/* the interface */

void text_interface(void)
{
   struct plugin_list *plugin, *tmp;

   DEBUG_MSG("text_interface");
   
   LIST_FOREACH_SAFE(plugin, &EC_GBL_OPTIONS->plugins, next, tmp) {
      /* check if the specified plugin exists */
      if (search_plugin(plugin->name) != E_SUCCESS) {
         plugin->exists = false;
         USER_MSG("Sorry, plugin '%s' can not be found - skipping!\n\n", 
               plugin->name);
      }

   }

   /* build the list of active hosts */
   build_hosts_list();

   /* start the mitm attack */
   mitm_start();
   
   /* start the sniffing method */
   EXECUTE(EC_GBL_SNIFF->start);
  
   /* it is difficult to be interactive while reading from file... */
   if (!EC_GBL_OPTIONS->read) {
      USER_MSG("\nText only Interface activated...\n");
      USER_MSG("Hit 'h' for inline help\n\n");
   }
   
   /* flush all the messages */
   ui_msg_flush(MSG_ALL);
  
   /* if we have to activate a plugin */
   if (!LIST_EMPTY(&EC_GBL_OPTIONS->plugins)) {
      /* 
       * execute the plugin and close the interface if 
       * the plugin was not found or it has completed
       * its execution
       */
      LIST_FOREACH_SAFE(plugin, &EC_GBL_OPTIONS->plugins, next, tmp) {
          if (plugin->exists && text_plugin(plugin->name) != PLUGIN_RUNNING)
             /* skip plugin */
             USER_MSG("Plugin '%s' can not be started - skipping!\n\n", 
                   plugin->name);
      }
   }

   /* neverending loop for user input */
   LOOP {
   
      CANCELLATION_POINT();
      
      /* if there is a pending char to be read */
      if (ec_poll_in(fileno(stdin), 10) || ec_poll_buffer(EC_GBL_OPTIONS->script)) {
         
         char ch = 0;

         /* get the input from the stdin or the buffer */
         if (ec_poll_buffer(EC_GBL_OPTIONS->script))
            ch = getchar_buffer(&EC_GBL_OPTIONS->script);
         else
            ch = getchar();
         
         switch(ch) {
            case 'H':
            case 'h':
               text_help();
               break;
            case 'P':
            case 'p':
               text_run_plugin();
               break;
            case 'F':
            case 'f':
               text_run_filter();
               break;
            case 'S':
            case 's':
               text_stats();
               break;
            case 'L':
            case 'l':
               text_hosts_list();
               break;
            case 'V':
            case 'v':
               text_visualization();
               break;
            case 'O':
            case 'o':
               text_profile_list();
               break;
            case 'C':
            case 'c':
               text_connections();
               break;
            case ' ':
               text_stop_cont();
               break;
            case 'R':
            case 'r':
               text_redirects();
               break;
            case 'Q':
            case 'q':
               USER_MSG("Closing text interface...\n\n");
               return;
               break;
         }
                                                                           
      }

      /* print pending USER_MSG messages */
      ui_msg_flush(INT_MAX);
                                 
   }
  
   /* NOT REACHED */
   
}

/* print the help screen */

static void text_help(void)
{
   fprintf(stderr, "\nInline help:\n\n");
   fprintf(stderr, " [vV]      - change the visualization mode\n");
   fprintf(stderr, " [pP]      - activate a plugin\n");
   fprintf(stderr, " [fF]      - (de)activate a filter\n");
   fprintf(stderr, " [lL]      - print the hosts list\n");
   fprintf(stderr, " [oO]      - print the profiles list\n");
   fprintf(stderr, " [cC]      - print the connections list\n");
   fprintf(stderr, " [rR]      - adjust SSL intercept rules\n");
   fprintf(stderr, " [sS]      - print interfaces statistics\n");
   fprintf(stderr, " [<space>] - stop/cont printing packets\n");
   fprintf(stderr, " [qQ]      - quit\n\n");
}
               
/* 
 * stops or continues to print packets
 * it is another way to control the -q option
 */

static void text_stop_cont(void)
{
   /* revert the quiet option */   
   EC_GBL_OPTIONS->quiet = (EC_GBL_OPTIONS->quiet) ? 0 : 1; 

   if (EC_GBL_OPTIONS->quiet)
      fprintf(stderr, "\nPacket visualization stopped...\n");
   else
      fprintf(stderr, "\nPacket visualization restarted...\n");
}


/*
 * display a list of plugin, and prompt 
 * the user for a plugin to run.
 */
static void text_run_plugin(void)
{
   char name[20];
   int restore = 0;
   char *p;

#ifndef HAVE_PLUGINS
   fprintf(stderr, "Plugin support was not compiled in...");
   return;
#endif
   
   /* there are no plugins */
   if (text_plugin("list") == -E_NOTFOUND)
      return;
   
   /* stop the visualization while the plugin interface is running */
   if (!EC_GBL_OPTIONS->quiet) {
      text_stop_cont();
      restore = 1;
   }
   
   /* print the messages created by text_plugin */
   ui_msg_flush(MSG_ALL);
      
   /* repristinate the buffer input */
   tcsetattr(0, TCSANOW, &old_tc);

   fprintf(stdout, "Plugin name (0 to quit): ");
   fflush(stdout);
   
   /* get the user input */
   fgets(name, 20, stdin);

   /* trim the \n */
   if ((p = strrchr(name, '\n')) != NULL)
      *p = '\0';
  
   /* disable buffered input */
   tcsetattr(0, TCSANOW, &new_tc);
   
   if (!strcmp(name, "0")) {
      if (restore)
         text_stop_cont();
      return;
   }

   /* run the plugin */
   text_plugin(name);
   
   /* continue the visualization */
   if (restore)
      text_stop_cont();
   
}


static int text_print_filter_cb(struct filter_list *l, void *arg) {
   int *i = (int *)arg;
   fprintf(stdout, "[%d (%d)]: %s\n", (*i)++, l->enabled, l->name);
   return 1;
}

static int text_toggle_filter_cb(struct filter_list *l, void *arg) {
   int *number = (int *)arg;
   if (!--(*number)) {
      /* we reached the item */
      l->enabled = ! l->enabled;
      return 0; /* no need to traverse the list any further */
   }
   return 1;
}

/*
 * display the list of loaded filters and
 * allow the user to enable or disable them
 */
static void text_run_filter(void) {
   int restore = 0;
   /* stop the visualization while the plugin interface is running */
   if (!EC_GBL_OPTIONS->quiet) {
      text_stop_cont();
      restore = 1;
   }
   ui_msg_flush(MSG_ALL);

   fprintf(stderr, "\nLoaded etterfilter scripts:\n\n");
   while(1) {
      char input[20];
      int i = 1;
      int number = -1;

      /* repristinate the buffer input */
      tcsetattr(0, TCSANOW, &old_tc);

      filter_walk_list( text_print_filter_cb, &i );
      int c;
      do {
         fprintf(stdout, "\nEnter a number to enable/disable filter (0 to quit): ");
         /* get the user input */
         fgets(input, 19, stdin);
         number = -1;
         c=sscanf(input, "%d", &number);
         if(c!=1)
            fprintf(stdout, "\nYou need to enter a number, please try again.");
      } while(c!=1);
      if (number == 0) {
         break;
      } else if (number > 0) {
         filter_walk_list( text_toggle_filter_cb, &number );
      }
   };

   /* disable buffered input */
   tcsetattr(0, TCSANOW, &new_tc);

   /* continue the visualization */
   if (restore)
      text_stop_cont();
}

/*
 * print the interface statistics 
 */
static void text_stats(void)
{
   DEBUG_MSG("text_stats (pcap) : %" PRIu64 " %" PRIu64 " %" PRIu64,
                                                EC_GBL_STATS->ps_recv,
                                                EC_GBL_STATS->ps_drop,
                                                EC_GBL_STATS->ps_ifdrop);
   DEBUG_MSG("text_stats (BH) : [%lu][%lu] p/s -- [%lu][%lu] b/s", 
         EC_GBL_STATS->bh.rate_adv, EC_GBL_STATS->bh.rate_worst, 
         EC_GBL_STATS->bh.thru_adv, EC_GBL_STATS->bh.thru_worst); 
   
   DEBUG_MSG("text_stats (TH) : [%lu][%lu] p/s -- [%lu][%lu] b/s", 
         EC_GBL_STATS->th.rate_adv, EC_GBL_STATS->th.rate_worst, 
         EC_GBL_STATS->th.thru_adv, EC_GBL_STATS->th.thru_worst); 
   
   DEBUG_MSG("text_stats (queue) : %lu %lu", EC_GBL_STATS->queue_curr, EC_GBL_STATS->queue_max); 
  
   
   fprintf(stdout, "\n Received packets    : %8" PRIu64 "\n", EC_GBL_STATS->ps_recv);
   fprintf(stdout,   " Dropped packets     : %8" PRIu64 "  %.2f %%\n", EC_GBL_STATS->ps_drop,
         (EC_GBL_STATS->ps_recv) ? (float)EC_GBL_STATS->ps_drop * 100 / EC_GBL_STATS->ps_recv : 0 );
   fprintf(stdout,   " Forwarded           : %8" PRIu64 "  bytes: %8" PRIu64 "\n\n",
           EC_GBL_STATS->ps_sent, EC_GBL_STATS->bs_sent);
   
   fprintf(stdout,   " Current queue len   : %lu/%lu\n", EC_GBL_STATS->queue_curr, EC_GBL_STATS->queue_max);
   fprintf(stdout,   " Sampling rate       : %d\n\n", EC_GBL_CONF->sampling_rate);
   
   fprintf(stdout,   " Bottom Half received packet : pck: %8" PRIu64 "  byte: %8" PRIu64 "\n",
         EC_GBL_STATS->bh.pck_recv, EC_GBL_STATS->bh.pck_size);
   fprintf(stdout,   " Top Half received packet    : pck: %8" PRIu64 "  byte: %8" PRIu64 "\n",
         EC_GBL_STATS->th.pck_recv, EC_GBL_STATS->th.pck_size);
   fprintf(stdout,   " Interesting packets         : %.2f %%\n\n",
         (EC_GBL_STATS->bh.pck_recv) ? (float)EC_GBL_STATS->th.pck_recv * 100 / EC_GBL_STATS->bh.pck_recv : 0 );

   fprintf(stdout,   " Bottom Half packet rate : worst: %8lu  adv: %8lu p/s\n", 
         EC_GBL_STATS->bh.rate_worst, EC_GBL_STATS->bh.rate_adv);
   fprintf(stdout,   " Top Half packet rate    : worst: %8lu  adv: %8lu p/s\n\n", 
         EC_GBL_STATS->th.rate_worst, EC_GBL_STATS->th.rate_adv);
   
   fprintf(stdout,   " Bottom Half throughput  : worst: %8lu  adv: %8lu b/s\n", 
         EC_GBL_STATS->bh.thru_worst, EC_GBL_STATS->bh.thru_adv);
   fprintf(stdout,   " Top Half throughput     : worst: %8lu  adv: %8lu b/s\n\n", 
         EC_GBL_STATS->th.thru_worst, EC_GBL_STATS->th.thru_adv);
}

/*
 * prints the hosts list
 */

static void text_hosts_list(void)
{
   struct hosts_list *hl;
   char ip[MAX_ASCII_ADDR_LEN];
   char mac[MAX_ASCII_ADDR_LEN];
   int i = 1;

   fprintf(stdout, "\n\nHosts list:\n\n");
   
   /* print the list */
   LIST_FOREACH(hl, &EC_GBL_HOSTLIST, next) {
      
      ip_addr_ntoa(&hl->ip, ip);
      mac_addr_ntoa(hl->mac, mac);
     
      if (hl->hostname)
         fprintf(stdout, "%d)\t%s\t%s\t%s\n", i++, ip, mac, hl->hostname);
      else
         fprintf(stdout, "%d)\t%s\t%s\n", i++, ip, mac);
         
   }

   fprintf(stdout, "\n\n");

}

/* 
 * prompt the user for the visualization mode
 */

static void text_visualization(void)
{
   char format[16];
   int restore = 0;
   
   /* stop the visualization while the plugin interface is running */
   if (!EC_GBL_OPTIONS->quiet) {
      text_stop_cont();
      restore = 1;
   }
   
   /* repristinate the buffere input */
   tcsetattr(0, TCSANOW, &old_tc);

   fprintf(stdout, "\n\nVisualization format: ");
   fflush(stdout);
   
   scanf("%15s", format);
  
   /* disable buffered input */
   tcsetattr(0, TCSANOW, &new_tc);
  
   /* set the format */
   set_format(format);   
   
   /* continue the packet printing */
   if (restore)
      text_stop_cont();
}


/*
 * enter the profile interface 
 */

static void text_profile_list(void)
{
   int restore = 0;
   
   /* stop the visualization while the profiles interface is running */
   if (!EC_GBL_OPTIONS->quiet) {
      text_stop_cont();
      restore = 1;
   }

   /* execute the profiles interface */
   text_profiles();

   /* continue the visualization */
   if (restore)
      text_stop_cont();
}

/* 
 * print all redirect rules and ask user to add or delete
 */
static void text_redirects(void)
{
   char input[20];
   int restore = 0, num, ret;
   char *p, cmd;

   
   /* print registered entries */
   text_redirect_print();

   /* stop the virtualization while the redirect interface is running */
   if (!EC_GBL_OPTIONS->quiet) {
      text_stop_cont();
      restore = 1;
   }
   /* print all pending user messages */
   ui_msg_flush(MSG_ALL);

   tcsetattr(0, TCSANOW, &old_tc);

   /* print instructions */
   fprintf(stdout, "'d <number>' to delete or 'i' to insert new redirect "
         "(0 to quit): ");
   fflush(stdout);

   /* get user input */
   fgets(input, 20, stdin);

   do {
      /* remote trailing line feed */
      if ((p = strrchr(input, '\n')) != NULL)
         *p = 0;

      ret = sscanf(input, "%c %d", &cmd, &num);

      if (ret == 1 && tolower(cmd) == 'i') {
         text_redirect_add();

         /* print registered entries */
         text_redirect_print();


      }
      else if (ret == 2 && tolower(cmd) == 'd') {
         text_redirect_del(num);

         /* print registered entries */
         text_redirect_print();
      }
      else if (!strcmp(input, "0") || !strcmp(input, "exit"))
         break;

      else
         INSTANT_USER_MSG("Invalid input\n");
      
      /* print instructions */
      fprintf(stdout, "'d <number>' to delete or 'i' to insert new redirect "
            "(0 to quit): ");
      fflush(stdout);

   } while (fgets(input, 20, stdin) != NULL);


   /* disable buffered input */
   tcsetattr(0, TCSANOW, &new_tc);

   if (restore)
      text_stop_cont();
}
/* EOF */

// vim:ts=3:expandtab

