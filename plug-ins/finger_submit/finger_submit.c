/*
    finger_submit -- ettercap plugin -- submit a fingerprint to ettercap website

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


#include <ec.h>                        /* required for global variables */
#include <ec_plugins.h>                /* required for plugin ops */
#include <ec_fingerprint.h>

#include <stdlib.h>
#include <string.h>

/* globals */


/* protos */
int plugin_load(void *);
static int finger_submit_init(void *);
static int finger_submit_fini(void *);
static int finger_submit_unload(void *);


/* plugin operations */

struct plugin_ops finger_submit_ops = { 
   /* ettercap version MUST be the global EC_VERSION */
   .ettercap_version =  EC_VERSION,                        
   /* the name of the plugin */
   .name =              "finger_submit",  
    /* a short description of the plugin (max 50 chars) */                    
   .info =              "Submit a fingerprint to ettercap's website",  
   /* the plugin version. */
   .version =           "1.0",   
   /* activation function */
   .init =              &finger_submit_init,
   /* deactivation function */                     
   .fini =              &finger_submit_fini,
   /* clean-up function */
   .unload =            &finger_submit_unload,
};

/**********************************************************/

/* this function is called on plugin load */
int plugin_load(void *handle) 
{
   return plugin_register(handle, &finger_submit_ops);
}

/******************* STANDARD FUNCTIONS *******************/

static int finger_submit_init(void *dummy) 
{
   char host[HOST_LEN + 1];
   char page[PAGE_LEN + 1];
   char finger[FINGER_LEN + 1];
   char os[OS_LEN + 1];
   
   /* variable not used */
   (void) dummy;

   /* don't display messages while operating */
   EC_GBL_OPTIONS->quiet = 1;
 
   memset(host, 0, sizeof(host));
   memset(page, 0, sizeof(page));
   memset(finger, 0, sizeof(finger));
   memset(os, 0, sizeof(os));
   
   /* get the user input */
   ui_input("Remote website (enter for default " DEFAULT_HOST " website) ('quit' to exit) : ", host, sizeof(host), NULL);
   /* exit on user request */
   if (!strcasecmp(host, "quit"))
      return PLUGIN_FINISHED;
   
   if(!strcmp(host, ""))
      strcpy(host, DEFAULT_HOST);

   ui_input("Remote webpage (enter for default " DEFAULT_PAGE " page) ('quit' to exit) : ", page, sizeof(page), NULL);
   
   /* exit on user request */
   if (!strcasecmp(page, "quit"))
      return PLUGIN_FINISHED;
   
   if(!strcmp(page, ""))
      strcpy(page, DEFAULT_PAGE);

   /* get the user input */
   ui_input("Fingerprint      ('quit' to exit) : ", finger, sizeof(finger), NULL);
   
   /* exit on user request */
   if (!strcasecmp(finger, "quit") || !strcmp(finger, ""))
      return PLUGIN_FINISHED;
   
   ui_input("Operating System ('quit' to exit) : ", os, sizeof(os), NULL);

   /* exit on user request */
   if (!strcasecmp(os, "quit") || !strcmp(os, ""))
      return PLUGIN_FINISHED;
   
   USER_MSG("\n");

   /* send the fingerprint */
   fingerprint_submit(host, page, finger, os);

   /* flush all the messages */
   ui_msg_flush(MSG_ALL);
   
   return PLUGIN_FINISHED;
}


static int finger_submit_fini(void *dummy) 
{
   /* variable not used */
   (void) dummy;

   return PLUGIN_FINISHED;
}

static int finger_submit_unload(void *dummy)
{
   /* variable not used */
   (void) dummy;

   return PLUGIN_UNLOADED;
}


/* EOF */

// vim:ts=3:expandtab
 
