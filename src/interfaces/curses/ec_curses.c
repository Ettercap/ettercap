/*
    ettercap -- curses GUI

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

    $Id: ec_curses.c,v 1.30 2003/12/28 17:19:56 alor Exp $
*/

#include <ec.h>
#include <wdg.h>

#include <ec_curses.h>
#include <ec_capture.h>
#include <ec_log.h>

/* globals */

static wdg_t *sysmsg_win;
static char tag_unoff[] = " ";
static char tag_promisc[] = "*";
static char tag_compress[] = " ";

static char *logfile;

/* proto */

void set_curses_interface(void);
void curses_interface(void);
void curses_flush_msg(void);

void curses_message(const char *msg);
   
static void curses_init(void);
static void curses_cleanup(void);
static void curses_msg(const char *msg);
static void curses_error(const char *msg);
static void curses_fatal_error(const char *msg);
static void curses_input(const char *title, char *input, size_t n);
void curses_input_call(const char *title, char *input, size_t n, void (*callback)(void));
static void curses_progress(char *title, int value, int max);

static void curses_setup(void);
static void curses_exit(void);

static void toggle_unoffensive(void);
static void toggle_nopromisc(void);
static void toggle_compress(void);

static void curses_file_open(void);
static void read_pcapfile(char *path, char *file);
static void curses_file_write(void);
static void write_pcapfile(void);
static void curses_unified_sniff(void);
static void curses_bridged_sniff(void);
static void bridged_sniff(void);
static void curses_pcap_filter(void);

static void curses_log_all(void);
static void log_all(void);
static void curses_log_info(void);
static void log_info(void);
static void curses_log_msg(void);
static void log_msg(void);

/*******************************************/


void set_curses_interface(void)
{
   struct ui_ops ops;

   /* wipe the struct */
   memset(&ops, 0, sizeof(ops));

   /* register the functions */
   ops.init = &curses_init;
   ops.start = &curses_interface;
   ops.cleanup = &curses_cleanup;
   ops.msg = &curses_msg;
   ops.error = &curses_error;
   ops.fatal_error = &curses_fatal_error;
   ops.input = &curses_input;
   ops.progress = &curses_progress;
   ops.type = UI_CURSES;
   
   ui_register(&ops);
   
}


/*
 * set the terminal as non blocking 
 */
static void curses_init(void)
{
   DEBUG_MSG("curses_init");

   /* init the widgets library */
   wdg_init();

   /* 
    * we have to set it because we ask user interaction
    * during this function.
    * we cant wait to return to set the flag...
    */
   GBL_UI->initialized = 1;

   DEBUG_MSG("curses_init: screen %dx%d colors: %d", (int)current_screen.cols, (int)current_screen.lines,
                                                     (int)(current_screen.flags & WDG_SCR_HAS_COLORS));

   /* initialize the colors */
   wdg_init_color(EC_COLOR, GBL_CONF->colors.fg, GBL_CONF->colors.bg);
   wdg_init_color(EC_COLOR_BORDER, GBL_CONF->colors.border, GBL_CONF->colors.bg);
   wdg_init_color(EC_COLOR_TITLE, GBL_CONF->colors.title, GBL_CONF->colors.bg);
   wdg_init_color(EC_COLOR_FOCUS, GBL_CONF->colors.focus, GBL_CONF->colors.bg);
   wdg_init_color(EC_COLOR_MENU, GBL_CONF->colors.menu_fg, GBL_CONF->colors.menu_bg);
   wdg_init_color(EC_COLOR_WINDOW, GBL_CONF->colors.window_fg, GBL_CONF->colors.window_bg);
   wdg_init_color(EC_COLOR_SELECTION, GBL_CONF->colors.selection_fg, GBL_CONF->colors.selection_bg);
   wdg_init_color(EC_COLOR_ERROR, GBL_CONF->colors.error_fg, GBL_CONF->colors.error_bg);
   wdg_init_color(EC_COLOR_ERROR_BORDER, GBL_CONF->colors.error_border, GBL_CONF->colors.error_bg);

   /* set the screen color */
   wdg_screen_color(EC_COLOR);
   
   /* call the setup interface */
   curses_setup();

   /* reached only after the setup interface has quit */
}

/*
 * exit from the setup interface 
 */
static void curses_exit(void)
{
   DEBUG_MSG("curses_exit");
   wdg_cleanup();
   clean_exit(0);
}

/*
 * reset to the previous state
 */
static void curses_cleanup(void)
{
   DEBUG_MSG("curses_cleanup");

   wdg_cleanup();
}

/*
 * this function is called on idle loop in wdg
 */
void curses_flush_msg(void)
{
   ui_msg_flush(MSG_ALL);
}

/*
 * print a USER_MSG() extracting it from the queue
 */
static void curses_msg(const char *msg)
{

   /* if the object does not exist yet */
   if (sysmsg_win == NULL)
      return;

   wdg_scroll_print(sysmsg_win, (char *)msg);
}


/*
 * print an error
 */
static void curses_error(const char *msg)
{
   wdg_t *dlg;
   
   DEBUG_MSG("curses_error: %s", msg);

   /* create the dialog */
   wdg_create_object(&dlg, WDG_DIALOG, WDG_OBJ_WANT_FOCUS | WDG_OBJ_FOCUS_MODAL);
   
   wdg_set_title(dlg, "ERROR:", WDG_ALIGN_LEFT);
   wdg_set_color(dlg, WDG_COLOR_SCREEN, EC_COLOR);
   wdg_set_color(dlg, WDG_COLOR_WINDOW, EC_COLOR_ERROR);
   wdg_set_color(dlg, WDG_COLOR_FOCUS, EC_COLOR_ERROR_BORDER);
   wdg_set_color(dlg, WDG_COLOR_TITLE, EC_COLOR_ERROR);

   /* set the message */
   wdg_dialog_text(dlg, WDG_OK, msg);
   wdg_draw_object(dlg);
   
   wdg_set_focus(dlg);
}


/*
 * handle a fatal error and exit
 */
static void curses_fatal_error(const char *msg)
{
   /* cleanup the curses mode */
   wdg_cleanup();

   fprintf(stderr, "FATAL ERROR: %s\n\n\n", msg);

   clean_exit(-1);
}


/*
 * get an input from the user blocking
 */
static void curses_input(const char *title, char *input, size_t n)
{
   wdg_t *in;

   wdg_create_object(&in, WDG_INPUT, WDG_OBJ_WANT_FOCUS | WDG_OBJ_FOCUS_MODAL);
   wdg_set_color(in, WDG_COLOR_SCREEN, EC_COLOR);
   wdg_set_color(in, WDG_COLOR_WINDOW, EC_COLOR);
   wdg_set_color(in, WDG_COLOR_FOCUS, EC_COLOR_FOCUS);
   wdg_set_color(in, WDG_COLOR_TITLE, EC_COLOR_MENU);
   wdg_input_size(in, strlen(title) + n, 3);
   wdg_input_add(in, 1, 1, title, input, n);
   wdg_draw_object(in);
      
   wdg_set_focus(in);
                     
   NOT_IMPLEMENTED();
}

/*
 * get an input from the user with a callback
 */
void curses_input_call(const char *title, char *input, size_t n, void (*callback)(void))
{
   wdg_t *in;

   wdg_create_object(&in, WDG_INPUT, WDG_OBJ_WANT_FOCUS | WDG_OBJ_FOCUS_MODAL);
   wdg_set_color(in, WDG_COLOR_SCREEN, EC_COLOR);
   wdg_set_color(in, WDG_COLOR_WINDOW, EC_COLOR);
   wdg_set_color(in, WDG_COLOR_FOCUS, EC_COLOR_FOCUS);
   wdg_set_color(in, WDG_COLOR_TITLE, EC_COLOR_MENU);
   wdg_input_size(in, strlen(title) + n, 3);
   wdg_input_add(in, 1, 1, title, input, n);
   wdg_input_set_callback(in, callback);
   wdg_draw_object(in);
      
   wdg_set_focus(in);
}


/* 
 * implement the progress bar 
 */
static void curses_progress(char *title, int value, int max)
{
   static wdg_t *per = NULL;
   
   /* the first time, create the object */
   if (per == NULL) {
      wdg_create_object(&per, WDG_PERCENTAGE, WDG_OBJ_WANT_FOCUS | WDG_OBJ_FOCUS_MODAL);
      
      wdg_set_title(per, title, WDG_ALIGN_CENTER);
      wdg_set_color(per, WDG_COLOR_SCREEN, EC_COLOR);
      wdg_set_color(per, WDG_COLOR_WINDOW, EC_COLOR);
      wdg_set_color(per, WDG_COLOR_FOCUS, EC_COLOR_FOCUS);
      wdg_set_color(per, WDG_COLOR_TITLE, EC_COLOR_MENU);
      
      wdg_draw_object(per);
      
      wdg_set_focus(per);
      
   } 
   
   /* the subsequent calls have to only update the object */
   wdg_percentage_set(per, value, max);
   wdg_update_screen();

   /* 
    * the object is self-destructing... 
    * so we have only to set the pointer to null
    */
   if (value == max)
      per = NULL;
}

/*
 * print a message
 */
void curses_message(const char *msg)
{
   wdg_t *dlg;
   
   DEBUG_MSG("curses_message: %s", msg);

   /* create the dialog */
   wdg_create_object(&dlg, WDG_DIALOG, WDG_OBJ_WANT_FOCUS | WDG_OBJ_FOCUS_MODAL);
   
   wdg_set_color(dlg, WDG_COLOR_SCREEN, EC_COLOR);
   wdg_set_color(dlg, WDG_COLOR_WINDOW, EC_COLOR);
   wdg_set_color(dlg, WDG_COLOR_FOCUS, EC_COLOR_FOCUS);
   wdg_set_color(dlg, WDG_COLOR_TITLE, EC_COLOR_TITLE);

   /* set the message */
   wdg_dialog_text(dlg, WDG_OK, msg);
   wdg_draw_object(dlg);
   
   wdg_set_focus(dlg);
}


/* the interface */

void curses_interface(void)
{
   DEBUG_MSG("curses_interface");
   
   /* which interface do we have to display ? */
   if (GBL_OPTIONS->read)
      curses_sniff_offline();
   else
      curses_sniff_live();
   

   /* destroy the previously allocated object */
   wdg_destroy_object(&sysmsg_win);
}

static void toggle_unoffensive(void)
{
   if (GBL_OPTIONS->unoffensive) {
      tag_unoff[0] = ' ';
      GBL_OPTIONS->unoffensive = 0;
   } else {
      tag_unoff[0] = '*';
      GBL_OPTIONS->unoffensive = 1;
   }
}

static void toggle_nopromisc(void)
{
   if (GBL_PCAP->promisc) {
      tag_promisc[0] = ' ';
      GBL_PCAP->promisc = 0;
   } else {
      tag_promisc[0] = '*';
      GBL_PCAP->promisc = 1;
   }
}

static void toggle_compress(void)
{
   if (GBL_OPTIONS->compress) {
      tag_compress[0] = ' ';
      GBL_OPTIONS->compress = 0;
   } else {
      tag_compress[0] = '*';
      GBL_OPTIONS->compress = 1;
   }
}

/*
 * display the initial menu to setup global options
 * at startup.
 */
static void curses_setup(void)
{
   wdg_t *menu;
   
   struct wdg_menu file[] = { {"File",           "F", NULL},
                              {"Open...",         "", curses_file_open},
                              {"Dump to file...", "", curses_file_write},
                              {"-",               "", NULL},
                              {"Exit",            "", curses_exit},
                              {NULL, NULL, NULL},
                            };
   
   struct wdg_menu live[] = { {"Sniff",              "S", NULL},
                              {"Unified sniffing...", "", curses_unified_sniff},
                              {"Bridged sniffing...", "", curses_bridged_sniff},
                              {"-",                   "", NULL},
                              {"Set pcap filter...",  "", curses_pcap_filter},
                              {NULL, NULL, NULL},
                            };
   
   struct wdg_menu options[] = { {"Options",      "O",         NULL},
                                 {"Unoffensive",  tag_unoff,   toggle_unoffensive},
                                 {"Promisc mode", tag_promisc, toggle_nopromisc},
                                 {NULL, NULL, NULL},
                               };
   
   struct wdg_menu logging[] = { {"Logging",                     "L", NULL},
                                 {"Log all packets and infos...", "", curses_log_all},
                                 {"Log only infos...",            "", curses_log_info},
                                 {"-",                            "", NULL},
                                 {"Log user messages...",         "", curses_log_msg},
                                 {"-",                            "", NULL},
                                 {"Compressed file",    tag_compress, toggle_compress},
                                 {NULL, NULL, NULL},
                               };
   
   DEBUG_MSG("curses_setup");
   
   wdg_create_object(&menu, WDG_MENU, WDG_OBJ_WANT_FOCUS | WDG_OBJ_ROOT_OBJECT);
   
   wdg_set_title(menu, GBL_VERSION, WDG_ALIGN_RIGHT);
   wdg_set_color(menu, WDG_COLOR_SCREEN, EC_COLOR);
   wdg_set_color(menu, WDG_COLOR_WINDOW, EC_COLOR_MENU);
   wdg_set_color(menu, WDG_COLOR_FOCUS, EC_COLOR_FOCUS);
   wdg_set_color(menu, WDG_COLOR_TITLE, EC_COLOR_TITLE);
   wdg_menu_add(menu, file);
   wdg_menu_add(menu, live);
   wdg_menu_add(menu, options);
   wdg_menu_add(menu, logging);
   wdg_draw_object(menu);
   
   DEBUG_MSG("curses_setup: menu created");

   /* create the bottom windows for user messages */
   wdg_create_object(&sysmsg_win, WDG_SCROLL, WDG_OBJ_WANT_FOCUS);
   
   wdg_set_title(sysmsg_win, "User messages:", WDG_ALIGN_LEFT);
   wdg_set_size(sysmsg_win, 0, SYSMSG_WIN_SIZE, 0, 0);
   wdg_set_color(sysmsg_win, WDG_COLOR_SCREEN, EC_COLOR);
   wdg_set_color(sysmsg_win, WDG_COLOR_WINDOW, EC_COLOR);
   wdg_set_color(sysmsg_win, WDG_COLOR_BORDER, EC_COLOR_BORDER);
   wdg_set_color(sysmsg_win, WDG_COLOR_FOCUS, EC_COLOR_FOCUS);
   wdg_set_color(sysmsg_win, WDG_COLOR_TITLE, EC_COLOR_TITLE);
   wdg_scroll_set_lines(sysmsg_win, 500);
   wdg_draw_object(sysmsg_win);
 
   /* give the focus to the menu */
   wdg_set_focus(menu);
   
   DEBUG_MSG("curses_setup: sysmsg created");
   
   /* give the control to the interface */
   wdg_events_handler('U');
   
   wdg_destroy_object(&menu);
   
   DEBUG_MSG("curses_setup: end");
}

/*
 * display the file open dialog
 */
static void curses_file_open(void)
{
   wdg_t *fop;
   
   DEBUG_MSG("curses_file_open");
   
   wdg_create_object(&fop, WDG_FILE, WDG_OBJ_WANT_FOCUS | WDG_OBJ_FOCUS_MODAL);
   
   wdg_set_title(fop, "Select a pcap file...", WDG_ALIGN_LEFT);
   wdg_set_color(fop, WDG_COLOR_SCREEN, EC_COLOR);
   wdg_set_color(fop, WDG_COLOR_WINDOW, EC_COLOR_MENU);
   wdg_set_color(fop, WDG_COLOR_FOCUS, EC_COLOR_FOCUS);
   wdg_set_color(fop, WDG_COLOR_TITLE, EC_COLOR_TITLE);

   wdg_file_set_callback(fop, read_pcapfile);
   
   wdg_draw_object(fop);
   
   wdg_set_focus(fop);
}

static void read_pcapfile(char *path, char *file)
{
   char errbuf[128];
   
   DEBUG_MSG("read_pcapfile %s/%s", path, file);
   
   SAFE_CALLOC(GBL_OPTIONS->dumpfile, strlen(path)+strlen(file)+2, sizeof(char));

   sprintf(GBL_OPTIONS->dumpfile, "%s/%s", path, file);

   /* check if the file is good */
   if (is_pcap_file(GBL_OPTIONS->dumpfile, errbuf) != ESUCCESS) {
      ui_error("%s", errbuf);
      SAFE_FREE(GBL_OPTIONS->dumpfile);
      return;
   }
   
   /* set the options for reading from file */
   GBL_OPTIONS->silent = 1;
   GBL_OPTIONS->unoffensive = 1;
   GBL_OPTIONS->write = 0;
   GBL_OPTIONS->read = 1;
   
   /* exit the setup interface, and go to the primary one */
   wdg_exit();
}

/*
 * display the write file menu
 */
static void curses_file_write(void)
{
#define FILE_LEN  40
   
   DEBUG_MSG("curses_file_write");
   
   SAFE_CALLOC(GBL_OPTIONS->dumpfile, FILE_LEN, sizeof(char));

   curses_input_call("Output file :", GBL_OPTIONS->dumpfile, FILE_LEN, write_pcapfile);
}

static void write_pcapfile(void)
{
   FILE *f;
   
   DEBUG_MSG("write_pcapfile");
   
   /* check if the file is writeable */
   f = fopen(GBL_OPTIONS->dumpfile, "w");
   if (f == NULL) {
      ui_error("Cannot write %s", GBL_OPTIONS->dumpfile);
      SAFE_FREE(GBL_OPTIONS->dumpfile);
      return;
   }
 
   /* if ok, delete it */
   fclose(f);
   unlink(GBL_OPTIONS->dumpfile);

   /* set the options for writing to a file */
   GBL_OPTIONS->write = 1;
   GBL_OPTIONS->read = 0;
   
   /* exit the setup interface, and go to the primary one */
   wdg_exit();
}

/*
 * display the interface selection dialog
 */
static void curses_unified_sniff(void)
{
   char err[PCAP_ERRBUF_SIZE];
   
#define IFACE_LEN  10
   
   DEBUG_MSG("curses_unified_sniff");
   
   SAFE_CALLOC(GBL_OPTIONS->iface, IFACE_LEN, sizeof(char));
   strncpy(GBL_OPTIONS->iface, pcap_lookupdev(err), IFACE_LEN - 1);

   /* calling wdg_exit will go to the next interface :) */
   curses_input_call("Network interface :", GBL_OPTIONS->iface, IFACE_LEN, wdg_exit);
}

/*
 * display the interface selection for bridged sniffing
 */
static void curses_bridged_sniff(void)
{
   wdg_t *in;
   char err[PCAP_ERRBUF_SIZE];
   
   DEBUG_MSG("curses_bridged_sniff");
   
   SAFE_CALLOC(GBL_OPTIONS->iface, IFACE_LEN, sizeof(char));
   strncpy(GBL_OPTIONS->iface, pcap_lookupdev(err), IFACE_LEN - 1);
   
   SAFE_CALLOC(GBL_OPTIONS->iface_bridge, IFACE_LEN, sizeof(char));

   wdg_create_object(&in, WDG_INPUT, WDG_OBJ_WANT_FOCUS | WDG_OBJ_FOCUS_MODAL);
   wdg_set_color(in, WDG_COLOR_SCREEN, EC_COLOR);
   wdg_set_color(in, WDG_COLOR_WINDOW, EC_COLOR);
   wdg_set_color(in, WDG_COLOR_FOCUS, EC_COLOR_FOCUS);
   wdg_set_color(in, WDG_COLOR_TITLE, EC_COLOR_MENU);
   wdg_input_size(in, strlen("Second network interface :") + IFACE_LEN, 4);
   wdg_input_add(in, 1, 1, "First network interface  :", GBL_OPTIONS->iface, IFACE_LEN);
   wdg_input_add(in, 1, 2, "Second network interface :", GBL_OPTIONS->iface_bridge, IFACE_LEN);
   wdg_input_set_callback(in, bridged_sniff);
   
   wdg_draw_object(in);
      
   wdg_set_focus(in);
}

static void bridged_sniff(void)
{
   set_bridge_sniff();
   
   wdg_exit();
}

/*
 * display the pcap filter dialog
 */
static void curses_pcap_filter(void)
{
#define PCAP_FILTER_LEN  50
   
   DEBUG_MSG("curses_pcap_filter");
   
   SAFE_CALLOC(GBL_PCAP->filter, PCAP_FILTER_LEN, sizeof(char));

   /* 
    * no callback, the filter is set but we have to return to
    * the interface for other user input
    */
   curses_input_call("Pcap filter :", GBL_PCAP->filter, PCAP_FILTER_LEN, NULL);
}

/*
 * display the log dialog 
 */
static void curses_log_all(void)
{
   DEBUG_MSG("curses_log_all");

   /* make sure to free if already set */
   SAFE_FREE(logfile);
   SAFE_CALLOC(logfile, FILE_LEN, sizeof(char));

   curses_input_call("Log File :", logfile, FILE_LEN, log_all);
}

static void log_all(void)
{
   set_loglevel(LOG_PACKET, logfile);
   SAFE_FREE(logfile);
}

/*
 * display the log dialog 
 */
static void curses_log_info(void)
{
   DEBUG_MSG("curses_log_info");

   /* make sure to free if already set */
   SAFE_FREE(logfile);
   SAFE_CALLOC(logfile, FILE_LEN, sizeof(char));

   curses_input_call("Log File :", logfile, FILE_LEN, log_info);
}

static void log_info(void)
{
   set_loglevel(LOG_INFO, logfile);
   SAFE_FREE(logfile);
}

/*
 * display the log dialog 
 */
static void curses_log_msg(void)
{
   DEBUG_MSG("curses_log_msg");

   /* make sure to free if already set */
   SAFE_FREE(logfile);
   SAFE_CALLOC(logfile, FILE_LEN, sizeof(char));

   curses_input_call("Log File :", logfile, FILE_LEN, log_msg);
}

static void log_msg(void)
{
   set_msg_loglevel(LOG_TRUE, logfile);
   SAFE_FREE(logfile);
}

/* EOF */

// vim:ts=3:expandtab

