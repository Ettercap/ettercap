/*
    ettercap -- text GUI for plugin management

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

    $Id: ec_text_plugin.c,v 1.2 2003/10/12 15:27:07 alor Exp $
*/

#include <ec.h>
#include <ec_poll.h>
#include <ec_ui.h>
#include <ec_threads.h>
#include <ec_plugins.h>

/* proto */

int text_plugin(char *plugin);
void text_plugin_list(char active, struct plugin_ops *ops);

/*******************************************/


/* the interface */

int text_plugin(char *plugin)
{
   int type;

   DEBUG_MSG("text_interface");
   
   /*
    * if the plugin name is "list", print the 
    * plugin list and exit
    */
   if (!strcasecmp(plugin, "list")) {
      /* delete any previous message */
      ui_msg_purge_all();

      USER_MSG("\nAvailable plugins :\n\n");
      type = plugin_list_print(PLP_MIN, PLP_MAX, &text_plugin_list);
      if (type == -ENOTFOUND) {
         USER_MSG("No plugin found !\n\n");
         return -ENOTFOUND;
      }
      
      USER_MSG("\n\n");
      /* 
       * return an error, so the text interface 
       * ends and returns to main
       */
      return -EINVALID;
   }
   
   /* what type of plugin are we loading ? */
   type = plugin_get_type(plugin);

   if (type == -ENOTFOUND)
      FATAL_MSG("%s plugin can not be found !", plugin);
   
   if (plugin_is_activated(plugin) == 0)
      INSTANT_USER_MSG("Activating %s plugin [%s]...\n\n", (type == PL_HOOK) ? "hook" : "standalone" , plugin);
   else
      INSTANT_USER_MSG("Deactivating %s plugin [%s]...\n\n", (type == PL_HOOK) ? "hook" : "standalone" , plugin);
  
   switch(type) {
      case PL_HOOK:
         /* if the plugin is active, stop it */
         if (plugin_is_activated(plugin) == 1)
            plugin_fini(plugin);
         else
            /* else activate it */
            plugin_init(plugin);

         USER_MSG("Done.\n\n");
         /* return running so the text interface remains active */
         return PLUGIN_RUNNING;
         break;

      case PL_STANDALONE:
         /*
          * pay attention on this !
          * if the plugin init does not return,
          * we are blocked here. So it is encouraged
          * to write plugins which spawn a thread
          * and immediately return
          */
         if (plugin_init(plugin) == PLUGIN_FINISHED) {
            USER_MSG("Done.\n\n");
            return PLUGIN_FINISHED;
         }
         break;
   }

   
   LOOP {
   
      CANCELLATION_POINT();
      
      /* if there is a pending char to be read */
      if ( ec_poll_read(fileno(stdin), 1) ) {
         
         char ch = 0;
         ch = getchar();
         switch(ch) {
            case 'H':
            case 'h':
               USER_MSG("\n Plugin [%s] is running...\n\n", plugin);
               USER_MSG("  [PLUGINS] Inline help:\n\n");
               USER_MSG("   [qQ]  - quit (terminate the plugin)\n\n");
               break;
            
            case 'Q':
            case 'q':
               /* finalize the plugin and exit */
               plugin_fini(plugin);
               return PLUGIN_FINISHED;
               break;
         }
                                                                           
      }

      /* print pending USER_MSG messages */
      ui_msg_flush(10);
                                 
   }
  
   /* NOT REACHED */
}

/*
 * callback function for displaying the plugin list 
 */
void text_plugin_list(char active, struct plugin_ops *ops)
{
   USER_MSG("[%d][%10s] %15s %4s  %s\n", active, 
         (ops->type == PL_HOOK) ? "hook" : "standalone",
         ops->name, ops->version, ops->info);  
}

/* EOF */

// vim:ts=3:expandtab

