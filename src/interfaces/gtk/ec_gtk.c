/*
    ettercap -- GTK+ GUI

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

    $Id: ec_gtk.c,v 1.3 2004/02/27 18:31:46 daten Exp $
*/

#include <ec.h>

#include <ec_gtk.h>
#include <ec_capture.h>
#include <ec_version.h>

#include <pcap.h>

/* globals */

GtkWidget *window = NULL;   /* main window */
GtkWidget *main_menu = NULL;

static GtkWidget     *textview = NULL;
static GtkTextBuffer *msgbuffer = NULL;
static GtkTextMark   *endmark = NULL;
static GtkAccelGroup *accel_group = NULL;

/* proto */

void set_gtk_interface(void);
void gui_start(void);

void gui_message(const char *msg);
void gui_input(const char *title, char *input, size_t n);
void gui_input_call(const char *title, char *input, size_t n, void (*callback)(void));
   
static void gui_init(void);
static void gui_cleanup(void);
static void gui_msg(const char *msg);
static void gui_error(const char *msg);
static void gui_fatal_error(const char *msg);
static gboolean gui_flush_msg(gpointer data);
static void gui_progress(char *title, int value, int max);

static void gui_setup(void);
static void gui_exit(void);

static void toggle_unoffensive(void);
static void toggle_nopromisc(void);

static void gui_file_open(void);
static void read_pcapfile(char *file);
static void gui_file_write(void);
static void write_pcapfile(void);
static void gui_unified_sniff(void);
static void gui_bridged_sniff(void);
static void bridged_sniff(void);
static void gui_pcap_filter(void);


/***#****************************************/

void set_gtk_interface(void)
{
   struct ui_ops ops;

   /* wipe the struct */
   memset(&ops, 0, sizeof(ops));

   /* register the functions */
   ops.init = &gui_init;
   ops.start = &gui_start;
   ops.cleanup = &gui_cleanup;
   ops.msg = &gui_msg;
   ops.error = &gui_error;
   ops.fatal_error = &gui_fatal_error;
   ops.input = &gui_input;
   ops.progress = &gui_progress;
   ops.type = UI_GTK;
   
   ui_register(&ops);
   
}


/*
 * prepare GTK, create the menu/messages window, enter the first loop 
 */
static void gui_init(void)
{
   DEBUG_MSG("gtk_init");

   g_thread_init(NULL);
   gdk_threads_init();
   if(!gtk_init_check(0, NULL)) {
   	DEBUG_MSG("GTK+ failed to initialize.");
	   return;
   }

   gui_setup();

   /* gui init loop, calling gtk_main_quit will cause
    * this to exit so we can proceed to the main loop
    * later. */
   gdk_threads_enter();
   gtk_main();
   gdk_threads_leave();

   /* remove the keyboard shortcuts for the setup menus */
   gtk_window_remove_accel_group(GTK_WINDOW (window), accel_group);

   GBL_UI->initialized = 1;
}

/*
 * exit ettercap 
 */
static void gui_exit(void)
{
   DEBUG_MSG("gtk_exit");

   gtk_main_quit();
   clean_exit(0);
}

/*
 * reset to the previous state
 */
static void gui_cleanup(void)
{
   DEBUG_MSG("gtk_cleanup");

   
}

/*
 * print a USER_MSG() extracting it from the queue
 */
static void gui_msg(const char *msg)
{
   GtkTextIter iter;

   DEBUG_MSG("gui_msg: %s", msg);

   gtk_text_buffer_get_end_iter(msgbuffer, &iter);
   gtk_text_buffer_insert(msgbuffer, &iter, msg, -1);
   gtk_text_view_scroll_to_mark(GTK_TEXT_VIEW (textview), 
                                endmark, 0, FALSE, 0, 0);
   return;
}

/* flush pending messages */
gboolean gui_flush_msg(gpointer data)
{
   ui_msg_flush(MSG_ALL);

   return(TRUE);
}

/*
 * print an error
 */
static void gui_error(const char *msg)
{
   GtkWidget *dialog;
   
   DEBUG_MSG("gui_error: %s", msg);

   dialog = gtk_message_dialog_new(GTK_WINDOW (window), GTK_DIALOG_MODAL, 
                                   GTK_MESSAGE_ERROR, GTK_BUTTONS_OK, "%s", msg);
   gtk_window_set_position(GTK_WINDOW (dialog), GTK_WIN_POS_CENTER);

   /* blocking - displays dialog waits for user to click OK */
   gtk_dialog_run(GTK_DIALOG (dialog));

   gtk_widget_destroy(dialog);
   return;
}


/*
 * handle a fatal error and exit
 */
static void gui_fatal_error(const char *msg)
{
   /* if the gui is working at this point
      display the message in a dialog */
   if(window)
      gui_error(msg);

   /* also dump it to console in case ettercap was started in an xterm */
   fprintf(stderr, "FATAL ERROR: %s\n\n\n", msg);

   clean_exit(-1);
}


/*
 * get an input from the user blocking
 */
void gui_input(const char *title, char *input, size_t n)
{
   GtkWidget *dialog, *entry, *label, *hbox, *image;

   dialog = gtk_dialog_new_with_buttons(EC_PROGRAM" Input", GTK_WINDOW (window),
                                        GTK_DIALOG_MODAL, GTK_STOCK_OK, GTK_RESPONSE_OK, 
                                        GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL, NULL);
   gtk_dialog_set_has_separator(GTK_DIALOG (dialog), FALSE);
   gtk_container_set_border_width(GTK_CONTAINER (dialog), 5);
  
   hbox = gtk_hbox_new (FALSE, 6);
   gtk_box_pack_start (GTK_BOX (GTK_DIALOG (dialog)->vbox), hbox, FALSE, FALSE, 0);
  
   image = gtk_image_new_from_stock (GTK_STOCK_DIALOG_QUESTION, GTK_ICON_SIZE_DIALOG);
   gtk_misc_set_alignment (GTK_MISC (image), 0.5, 0.0);
   gtk_box_pack_start (GTK_BOX (hbox), image, FALSE, FALSE, 0);
   
   label = gtk_label_new (title);
   gtk_label_set_line_wrap (GTK_LABEL (label), TRUE);
   gtk_label_set_selectable (GTK_LABEL (label), TRUE);
   gtk_box_pack_start (GTK_BOX (hbox), label, TRUE, TRUE, 0);
         
   entry = gtk_entry_new_with_max_length(n);
   if(input)
      gtk_entry_set_text(GTK_ENTRY (entry), input);
   gtk_box_pack_start(GTK_BOX (hbox), entry, FALSE, FALSE, 5);
  
   gtk_widget_show_all (hbox);

   if(gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_OK) {

      strncpy(input, gtk_entry_get_text(GTK_ENTRY (entry)), n);

   }
   gtk_widget_destroy(dialog);
}

/*
 * get an input from the user with a callback
 */
void gui_input_call(const char *title, char *input, size_t n, void (*callback)(void))
{
   GtkWidget *dialog, *entry, *label, *hbox, *image;

   dialog = gtk_dialog_new_with_buttons(EC_PROGRAM" Input", GTK_WINDOW (window),
                                        GTK_DIALOG_MODAL, GTK_STOCK_OK, GTK_RESPONSE_OK,
                                        GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL, NULL);
   gtk_dialog_set_has_separator(GTK_DIALOG (dialog), FALSE);
   gtk_container_set_border_width(GTK_CONTAINER (dialog), 5);
   
   hbox = gtk_hbox_new (FALSE, 6);
   gtk_box_pack_start (GTK_BOX (GTK_DIALOG (dialog)->vbox), hbox, FALSE, FALSE, 0);
   
   image = gtk_image_new_from_stock (GTK_STOCK_DIALOG_QUESTION, GTK_ICON_SIZE_DIALOG);
   gtk_misc_set_alignment (GTK_MISC (image), 0.5, 0.0);
   gtk_box_pack_start (GTK_BOX (hbox), image, FALSE, FALSE, 0);
   
   label = gtk_label_new (title);
   gtk_label_set_line_wrap (GTK_LABEL (label), TRUE);
   gtk_label_set_selectable (GTK_LABEL (label), TRUE);
   gtk_box_pack_start (GTK_BOX (hbox), label, TRUE, TRUE, 0);
   
   entry = gtk_entry_new_with_max_length(n);
   if(input)
      gtk_entry_set_text(GTK_ENTRY (entry), input); 
   gtk_box_pack_start(GTK_BOX (hbox), entry, FALSE, FALSE, 5);
   
   gtk_widget_show_all (hbox);

   if(gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_OK) {

      strncpy(input, gtk_entry_get_text(GTK_ENTRY (entry)), n);

      if(callback != NULL)
         callback();
   }
   gtk_widget_destroy(dialog);
}


/* 
 * show or update the progress bar
 */
static void gui_progress(char *title, int value, int max)
{
   static GtkWidget *dialog = NULL;
   static GtkWidget *pbar = NULL;
   
   /* the first time, create the object */
   if (pbar == NULL) {
      dialog = gtk_window_new(GTK_WINDOW_TOPLEVEL);
      gtk_window_set_title(GTK_WINDOW (dialog), EC_PROGRAM);
      gtk_window_set_modal(GTK_WINDOW (dialog), TRUE);
      gtk_window_set_position(GTK_WINDOW (dialog), GTK_WIN_POS_CENTER);
      gtk_container_set_border_width(GTK_CONTAINER (dialog), 5);
    
      pbar = gtk_progress_bar_new();
      gtk_container_add(GTK_CONTAINER (dialog), pbar);
      gtk_widget_show(pbar);

      gtk_widget_show(dialog);
   } 
   
   /* the subsequent calls have to only update the object */
   gtk_progress_bar_set_text(GTK_PROGRESS_BAR (pbar), title);
   gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR (pbar), (gdouble)((gdouble)value / (gdouble)max));

   /* a nasty little loop that lets gtk update the progress bar immediately */
   while (gtk_events_pending ())
      gtk_main_iteration ();

   /* 
    * when 100%, destroy it
    */
   if (value == max) {
      gtk_widget_hide(dialog);
      gtk_widget_destroy(pbar);
      gtk_widget_destroy(dialog);
      dialog = NULL;
      pbar = NULL;
   }

}

/*
 * print a message
 */
void gui_message(const char *msg)
{
   GtkWidget *dialog;
   
   DEBUG_MSG("gui_message: %s", msg);

   dialog = gtk_message_dialog_new(GTK_WINDOW (window), GTK_DIALOG_MODAL, 
                                   GTK_MESSAGE_INFO, GTK_BUTTONS_OK, "%s", msg);
   gtk_window_set_position(GTK_WINDOW (dialog), GTK_WIN_POS_CENTER);

   /* blocking - displays dialog waits for user to click OK */
   gtk_dialog_run(GTK_DIALOG (dialog));

   gtk_widget_destroy(dialog);
   return;
}


/*
 * Create the main interface and enter the second loop
 */

void gui_start(void)
{
   guint idle_flush;

   DEBUG_MSG("gtk_start");

   idle_flush = gtk_timeout_add(500, gui_flush_msg, NULL);
   
   /* which interface do we have to display ? */
   if (GBL_OPTIONS->read)
      gui_sniff_offline();
   else
      gui_sniff_live();
   
   /* the main gui loop, once this exits the gui will be destroyed */
   gdk_threads_enter();
   gtk_main();
   gdk_threads_leave();

   gtk_timeout_remove(idle_flush);
}

static void toggle_unoffensive(void)
{
   if (GBL_OPTIONS->unoffensive) {
      GBL_OPTIONS->unoffensive = 0;
   } else {
      GBL_OPTIONS->unoffensive = 1;
   }
}

static void toggle_nopromisc(void)
{
   if (GBL_PCAP->promisc) {
      GBL_PCAP->promisc = 0;
   } else {
      GBL_PCAP->promisc = 1;
   }
}

/*
 * display the initial menu to setup global options
 * at startup.
 */
static void gui_setup(void)
{
   GtkTextIter iter;
   GtkWidget *item, *vbox, *scroll;
   GtkItemFactory *item_factory;
   char title[50];

   GtkItemFactoryEntry file_menu[] = {
      { "/_File",         "<shift>F",   NULL,           0, "<Branch>" },
      { "/File/_Open",    "<control>O", gui_file_open,  0, "<StockItem>", GTK_STOCK_OPEN },
      { "/File/_Save",    "<control>S", gui_file_write, 0, "<StockItem>", GTK_STOCK_SAVE },
      { "/File/sep1",     NULL,         NULL,           0, "<Separator>" },
      { "/File/E_xit",    "<control>x", gui_exit,       0, "<StockItem>", GTK_STOCK_QUIT },
      { "/_Sniff",        "<shift>S",   NULL,           0, "<Branch>" },
      { "/Sniff/Unified sniffing...",  "<shift>U", gui_unified_sniff, 0, "<StockItem>", GTK_STOCK_DND },
      { "/Sniff/Bridged sniffing...",  "<shift>B", gui_bridged_sniff, 0, "<StockItem>", GTK_STOCK_DND_MULTIPLE },
      { "/Sniff/sep2",    NULL,         NULL,           0, "<Separator>" },
      { "/Sniff/Set pcap filter...",    "p",       gui_pcap_filter,   0, "<StockItem>", GTK_STOCK_PREFERENCES },
      { "/_Options",                    "<shift>O", NULL, 0, "<Branch>" },
      { "/Options/Unoffensive", NULL, toggle_unoffensive, 0, "<ToggleItem>" },
      { "/Options/Promisc mode", NULL, toggle_nopromisc,  0, "<ToggleItem>" }
   };
   gint nmenu_items = sizeof (file_menu) / sizeof (file_menu[0]);
   
   DEBUG_MSG("gui_setup");

   /* create menu window */
   window = gtk_window_new (GTK_WINDOW_TOPLEVEL);
   snprintf(title, 50, "%s %s", EC_PROGRAM, EC_VERSION);
   gtk_window_set_title(GTK_WINDOW (window), title);
   gtk_window_set_default_size(GTK_WINDOW (window), 450, 175);
   g_signal_connect (G_OBJECT (window), "delete_event", G_CALLBACK (gui_exit), NULL);

   accel_group = gtk_accel_group_new ();
   item_factory = gtk_item_factory_new (GTK_TYPE_MENU_BAR, "<main>", accel_group);
   gtk_item_factory_create_items (item_factory, nmenu_items, file_menu, NULL);

   vbox = gtk_vbox_new(FALSE, 0);
   gtk_container_add(GTK_CONTAINER (window), vbox);
   gtk_widget_show(vbox);

   main_menu = gtk_item_factory_get_widget (item_factory, "<main>");
   gtk_box_pack_start(GTK_BOX(vbox), main_menu, FALSE, FALSE, 0);
   gtk_window_add_accel_group (GTK_WINDOW (window), accel_group);
   gtk_widget_show(main_menu);

   item = gtk_item_factory_get_item(item_factory, "/Options/Promisc mode");
   gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM (item), (GBL_PCAP->promisc)?TRUE:FALSE);

   item = gtk_item_factory_get_item(item_factory, "/Options/Unoffensive");
   gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM (item), (GBL_OPTIONS->unoffensive)?TRUE:FALSE);

   scroll = gtk_scrolled_window_new(NULL, NULL);
   gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW (scroll),
                                  GTK_POLICY_NEVER, GTK_POLICY_ALWAYS);
   gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW (scroll), GTK_SHADOW_IN);
   gtk_box_pack_end(GTK_BOX(vbox), scroll, TRUE, TRUE, 0);
   gtk_widget_show(scroll);

   textview = gtk_text_view_new();
   gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW (textview), GTK_WRAP_WORD);
   gtk_text_view_set_editable(GTK_TEXT_VIEW (textview), FALSE);
   gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW (textview), FALSE);
   gtk_container_add(GTK_CONTAINER (scroll), textview);
   gtk_widget_show(textview);

   msgbuffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW (textview));
   gtk_text_buffer_get_end_iter(msgbuffer, &iter);
   endmark = gtk_text_buffer_create_mark(msgbuffer, "end", &iter, FALSE);

   gtk_widget_show(window);

   DEBUG_MSG("gtk_setup: end");
}

/*
 * display the file open dialog
 */
static void gui_file_open(void)
{
   GtkWidget *dialog;
   char *filename;
   int response = 0;

   DEBUG_MSG("gtk_file_open");

   dialog = gtk_file_selection_new ("Select a pcap file...");

   response = gtk_dialog_run (GTK_DIALOG (dialog));

   if (response == GTK_RESPONSE_OK) {
      gtk_widget_hide(dialog);
      filename = gtk_file_selection_get_filename (GTK_FILE_SELECTION (dialog));
      /* destroy needs to come before read_pcapfile so gtk_main_quit
         can reside inside read_pcapfile, which is why destroy is here
         twice and not after the if() block */
      gtk_widget_destroy (dialog);

      read_pcapfile (filename);
   } else {
      gtk_widget_destroy (dialog);
   }
}

static void read_pcapfile(char *file)
{
   char errbuf[128];
   
   DEBUG_MSG("read_pcapfile %s", file);
   
   SAFE_CALLOC(GBL_OPTIONS->dumpfile, strlen(file)+1, sizeof(char));

   sprintf(GBL_OPTIONS->dumpfile, "%s", file);

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

   gtk_main_quit();
}

/*
 * display the write file menu
 */
static void gui_file_write(void)
{
#define FILE_LEN  40
   
   DEBUG_MSG("gtk_file_write");
   
   SAFE_CALLOC(GBL_OPTIONS->dumpfile, FILE_LEN, sizeof(char));

   gui_input_call("Output file :", GBL_OPTIONS->dumpfile, FILE_LEN, write_pcapfile);
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
   gtk_main_quit();
}

/*
 * display the interface selection dialog
 */
static void gui_unified_sniff(void)
{
   char err[PCAP_ERRBUF_SIZE];
   
#define IFACE_LEN  10
   
   DEBUG_MSG("gtk_unified_sniff");
   
   SAFE_CALLOC(GBL_OPTIONS->iface, IFACE_LEN, sizeof(char));
   strncpy(GBL_OPTIONS->iface, pcap_lookupdev(err), IFACE_LEN - 1);

   /* calling gtk_main_quit will go to the next interface :) */
   gui_input_call("Network interface :", GBL_OPTIONS->iface, IFACE_LEN, gtk_main_quit);
}

/*
 * display the interface selection for bridged sniffing
 */
static void gui_bridged_sniff(void)
{
   GtkWidget *dialog, *vbox, *hbox, *image;
   GtkWidget *hbox_big, *label, *entry1, *entry2;
   char err[PCAP_ERRBUF_SIZE];

   DEBUG_MSG("gtk_bridged_sniff");

   dialog = gtk_dialog_new_with_buttons("Bridged Sniffing", GTK_WINDOW (window),
                                        GTK_DIALOG_MODAL, GTK_STOCK_OK, GTK_RESPONSE_OK,
                                        GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL, NULL);
   gtk_container_set_border_width(GTK_CONTAINER (dialog), 5);
   gtk_dialog_set_has_separator(GTK_DIALOG (dialog), FALSE);

   hbox_big = gtk_hbox_new (FALSE, 5);
   gtk_box_pack_start (GTK_BOX (GTK_DIALOG (dialog)->vbox), hbox_big, FALSE, FALSE, 0);
   gtk_widget_show(hbox_big);

   image = gtk_image_new_from_stock (GTK_STOCK_DIALOG_QUESTION, GTK_ICON_SIZE_DIALOG);
   gtk_misc_set_alignment (GTK_MISC (image), 0.5, 0.1);
   gtk_box_pack_start (GTK_BOX (hbox_big), image, FALSE, FALSE, 5);
   gtk_widget_show(image);

   vbox = gtk_vbox_new (FALSE, 2);
   gtk_container_set_border_width(GTK_CONTAINER (vbox), 5);
   gtk_box_pack_start (GTK_BOX (hbox_big), vbox, TRUE, TRUE, 0);
   gtk_widget_show(vbox);

   hbox = gtk_hbox_new(FALSE, 0);
   gtk_box_pack_start(GTK_BOX (vbox), hbox, TRUE, TRUE, 0);
   gtk_widget_show(hbox);

   label = gtk_label_new ("First network interface  : ");
   gtk_misc_set_alignment(GTK_MISC (label), 0, 0.5);
   gtk_box_pack_start(GTK_BOX (hbox), label, TRUE, TRUE, 0);
   gtk_widget_show(label);

   entry1 = gtk_entry_new_with_max_length(IFACE_LEN);
   gtk_entry_set_width_chars (GTK_ENTRY (entry1), 6);
   gtk_entry_set_text (GTK_ENTRY (entry1), pcap_lookupdev(err));
   gtk_box_pack_start(GTK_BOX (hbox), entry1, FALSE, FALSE, 0);
   gtk_widget_show(entry1);

   hbox = gtk_hbox_new(FALSE, 0);
   gtk_box_pack_start(GTK_BOX (vbox), hbox, TRUE, TRUE, 0);
   gtk_widget_show(hbox);

   label = gtk_label_new ("Second network interface : ");
   gtk_misc_set_alignment(GTK_MISC (label), 0, 0.5);
   gtk_box_pack_start(GTK_BOX (hbox), label, TRUE, TRUE, 0);
   gtk_widget_show(label);

   entry2 = gtk_entry_new_with_max_length(IFACE_LEN);
   gtk_entry_set_width_chars (GTK_ENTRY (entry2), 6);
   gtk_box_pack_start(GTK_BOX (hbox), entry2, FALSE, FALSE, 0);
   gtk_widget_show(entry2);

   if (gtk_dialog_run (GTK_DIALOG (dialog)) == GTK_RESPONSE_OK) {
      gtk_widget_hide(dialog);

      SAFE_CALLOC(GBL_OPTIONS->iface, IFACE_LEN, sizeof(char));
      SAFE_CALLOC(GBL_OPTIONS->iface_bridge, IFACE_LEN, sizeof(char));

      strncpy(GBL_OPTIONS->iface, gtk_entry_get_text(GTK_ENTRY (entry1)), IFACE_LEN);
      strncpy(GBL_OPTIONS->iface_bridge, gtk_entry_get_text(GTK_ENTRY (entry2)), IFACE_LEN);
      bridged_sniff();
   }

   gtk_widget_destroy(dialog);
}

static void bridged_sniff(void)
{
   set_bridge_sniff();
   
   gtk_main_quit();
}

/*
 * display the pcap filter dialog
 */
static void gui_pcap_filter(void)
{
#define PCAP_FILTER_LEN  50
   
   DEBUG_MSG("gtk_pcap_filter");
   
   SAFE_CALLOC(GBL_PCAP->filter, PCAP_FILTER_LEN, sizeof(char));

   /* 
    * no callback, the filter is set but we have to return to
    * the interface for other user input
    */
   gui_input_call("Pcap filter :", GBL_PCAP->filter, PCAP_FILTER_LEN, NULL);
}

/* EOF */

// vim:ts=3:expandtab

