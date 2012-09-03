/*
    dynamic_ruby -- ettercap plugin -- it does nothig !
                                only demostrates how to write a plugin !

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

    $Id: dynamic_ruby.c,v 1.10 2004/03/19 13:55:02 alor Exp $
*/


#include <ec.h>                        /* required for global variables */
#include <ec_plugins.h>                /* required for plugin ops */
#include <ec_threads.h>
#include <ec_hook.h>

// #include "ruby_swig.h"
#include "ruby.h"

#include <stdlib.h>
#include <string.h>

/* prototypes is required for -Wmissing-prototypes */

/* 
 * this function must be present.
 * it is the entry point of the plugin 
 */
int plugin_load(void *);

/* additional functions */
static int dynamic_ruby_init(void *);
static int dynamic_ruby_fini(void *);
static EC_THREAD_FUNC(ettercap_ruby_thread);

void Init_ettercap(void);

// swig_type_info* _p_swigt__p_packet_object;

/* plugin operations */

struct plugin_ops dynamic_ruby_ops = { 
   /* ettercap version MUST be the global EC_VERSION */
   .ettercap_version =  EC_VERSION,                        
   /* the name of the plugin */
   .name =              "dynamic_ruby",  
    /* a short description of the plugin (max 50 chars) */                    
   .info =              "A plugin template (for developers)",  
   /* the plugin version. */ 
   .version =           "3.0",   
   /* activation function */
   .init =              &dynamic_ruby_init,
   /* deactivation function */                     
   .fini =              &dynamic_ruby_fini,
};

int running = 0;

/**********************************************************/

/* this function is called on plugin load */
int plugin_load(void *handle) 
{
   DEBUG_MSG("dynamic_ruby plugin load function");
   /*
    *  in this fuction we MUST call the registration procedure that will set
    *  up the plugin according to the plugin_ops structure.
    *  the returned value MUST be the same as plugin_register()
    *  the opaque pointer params MUST be passed to plugin_register()
    */
   return plugin_register(handle, &dynamic_ruby_ops);
}

/*********************************************************/

static int dynamic_ruby_init(void *dynamic_ruby) 
{
   /* the control is given to this function
    * and ettercap is suspended until its return.
    * 
    * you can create a thread and return immediately
    * and then kill it in the fini function.
    *
    * you can also set an hook point with
    * hook_add(), in this case you have to set the
    * plugin type to PL_HOOK.
    */

    USER_MSG("DYNAMIC_RUBY: plugin running...\n");

    int fake_argc = 2;
    char *fake_argv[] = {
      "ettercap_plugin",
      "-e;"
    };

    RUBY_INIT_STACK;
    ruby_init();
    ruby_options(fake_argc, fake_argv);
    //ruby_init_loadpath();
    running = 1;
    //VALUE filename = rb_str_new2("/home/mike/code/ettercap-script/plug-ins/dynamic/ruby/examples/hello2.rb");

    //int state = 0;
    //rb_load_protect(filename, 0, &state);
    ec_thread_new("ettercap_ruby_thread", "Ettercap ruby loop thread", &ettercap_ruby_thread, NULL);

    // creates a thread within the VM.
    rb_eval_string("load '/home/mike/code/ettercap-script/plug-ins/dynamic/ruby/examples/hello2.rb'");
    USER_MSG("DYNAMIC_RUBY: thread started...\n");

    //hook_add(HOOK_PROTO_DNS, &dynamic_ruby_handle_dns);
    //hook_add(HOOK_PROTO_HTTP, &dynamic_ruby_handle_http);
    //hook_add(HOOK_PACKET_ETH, &dynamic_ruby_handle_eth);
   /* return PLUGIN_FINISHED if the plugin has terminated
    * its execution.
    * return PLUGIN_RUNNING if it has spawned a thread or it
    * is hooked to an ettercap hookpoint and
    * it needs to be deactivated with the fini method.
    */
    return PLUGIN_RUNNING;
}


static int dynamic_ruby_fini(void *dynamic_ruby) 
{
   /* 
    * called to terminate a plugin.
    * usually to kill threads created in the 
    * init function or to remove hook added 
    * previously.
    */
    USER_MSG("DYNAMIC_RUBY: plugin finalization. Shutting down ruby VM\n");
    rb_eval_string("Ettercap.sig_queue.push(1); Ettercap.thread.join(2); Ettercap.thread.kill");
    rb_thread_schedule();
    /*
    int i = 0;
    running = 0;
    // Wait up to 2 seconds for ruby process to exit 
    for (i = 0; i < 10; i++) {
      if (running == -1)
        break;

      USER_MSG("DYNAMIC_RUBY: Waiting for ruby finalization...\n");
      usleep(200000);
    }
    */

    USER_MSG("DYNAMIC_RUBY: Killing threads...\n");
    pthread_t pid;
    while(!pthread_equal(EC_PTHREAD_NULL, pid = ec_thread_getpid("ettercap_ruby_thread"))) {
      ec_thread_destroy(pid);
    }
    ruby_cleanup(0);
    USER_MSG("DYNAMIC_RUBY: Done!.\n");
    //hook_del(HOOK_PROTO_DNS, &dynamic_ruby_handle_dns);
    //hook_del(HOOK_PROTO_HTTP, &dynamic_ruby_handle_http);
    //hook_del(HOOK_PACKET_ETH, &dynamic_ruby_handle_eth);
    return PLUGIN_FINISHED;
}

void run_the_rubies()
{
    //rb_eval_string("load '/home/mike/code/ettercap-script/plug-ins/dynamic/ruby/examples/hello2.rb'");
    //rb_eval_string("require 'rubygems'");
    /*
    char* options[] = {"", "/home/mike/code/ettercap-script/plug-ins/dynamic/ruby/examples/hello2.rb"};
    void* node = ruby_options(2, options);
    ruby_run_node(node);
    */
    //Init_ettercap();
    //rb_load_file("/home/mike/code/ettercap-script/plug-ins/dynamic/ruby/examples/hello2.rb");


    //rb_eval_string("load 'hello2.rb'");
    while (running == 1){
      CANCELLATION_POINT();
      // We sleep inside of ruby so that we cn process hooks immediately.
      rb_eval_string("sleep 1; GC.start");
      USER_MSG("DYNAMIC_RUBY: looping...\n");
    }
    USER_MSG("DYNAMIC_RUBY: Thread killed. cleaning up...\n");
    //int ret = ruby_cleanup(0);
    //printf("ruby_cleanup(0) == %d\n", ret);

    running = -1;
}

static EC_THREAD_FUNC(ettercap_ruby_thread)
{

    USER_MSG("DYNAMIC_RUBY: in thread\n");
    run_the_rubies();
    return NULL;

}
/* EOF */

// vim:ts=3:expandtab



