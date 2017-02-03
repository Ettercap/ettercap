#include <ec.h>                        /* required for global variables */
#include <ec_plugins.h>                /* required for plugin ops */
#include <ec_hook.h>

#include <stdlib.h>
#include <string.h>


int plugin_load(void *);

static int umsg_test_init(void *);
static int umsg_test_fini(void *);
void umsg_test_fn(struct packet_object *po);


struct plugin_ops umsg_test_ops = { 
   .ettercap_version =  EC_VERSION,                        
   .name =              "umsg_test",  
   .info =              "A plugin to test a possible bug in USER_MSG",  
   .version =           "1.0",   
   .init =              &umsg_test_init,
   .fini =              &umsg_test_fini,
};

/**********************************************************/

/* this function is called on plugin load */
int plugin_load(void *handle) 
{
   DEBUG_MSG("umsg_test plugin load function");
   return plugin_register(handle, &umsg_test_ops);
}

/*********************************************************/

static int umsg_test_init(void *umsg_test) 
{

   (void) umsg_test;

   USER_MSG("UMSG_TEST: plugin running...\n");
   hook_add(HOOK_PACKET_IP, &umsg_test_fn);
   hook_add(HOOK_PACKET_IP6, &umsg_test_fn);
   return PLUGIN_RUNNING;
}


static int umsg_test_fini(void *umsg_test) 
{

   (void) umsg_test;

   hook_del(HOOK_PACKET_IP, &umsg_test_fn);
   hook_del(HOOK_PACKET_IP6, &umsg_test_fn);
   USER_MSG("UMSG_TEST: plugin finalization\n");
   return PLUGIN_FINISHED;
}

void umsg_test_fn(struct packet_object *po){
	static int count = 0;
	u_char test[] = "here is the test string";
	USER_MSG("received packet %d:  %p\n", count,po);
	USER_MSG("here is another string to speed this up %d %d %d\n", count, count, count);
	USER_MSG("here is a string with a string inside of it: %s\n",test);
	USER_MSG("received packet %d:  %p\n", count,po);
	USER_MSG("here is another string to speed this up %d %d %d\n", count, count, count);
	USER_MSG("here is a string with a string inside of it: %s\n",test);
	USER_MSG("received packet %d:  %p\n", count,po);
	USER_MSG("here is another string to speed this up %d %d %d\n", count, count, count);
	USER_MSG("here is a string with a string inside of it: %s\n",test);

	count++;


}


// vim:ts=3:expandtab

