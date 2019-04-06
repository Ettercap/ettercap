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

*/

#include <ec.h>
#include <ec_gtk3.h>
#include <ec_format.h>
#include <ec_utils.h>
#include <ec_encryption.h>

/* proto */

static void gtkui_set_regex(void);
static void gtkui_set_wifikey(void);

static void gtkui_stop_stats(void);
static void gtkui_stats_detach(GtkWidget *child);
static void gtkui_stats_attach(void);
static gboolean refresh_stats(gpointer data);

/* globals */

#define VLEN 8
static char vmethod[VLEN] = "ascii";
#define RLEN 50
static char vregex[RLEN];
#define WLEN 70
static char wkey[WLEN];
static guint stats_idle; /* for removing the idle call */
/* for stats window */
static GtkWidget *stats_window, *packets_recv, *packets_drop, *packets_forw, 
                 *queue_len, *sample_rate, *recv_bottom, *recv_top, *interesting, 
                 *rate_bottom, *rate_top, *through_bottom, *through_top;

/*******************************************/


/* 
 * If this option is being activated,
 * it runs through the current hosts list and triggeres 
 * name resolution in the background. 
 * That way subsequent actions benefits from the filled cache
 */
void toggle_resolve(GSimpleAction *action, GVariant *value, gpointer data)
{
   char name[MAX_HOSTNAME_LEN];
   struct hosts_list *hl;

   (void) data;

   g_simple_action_set_state(action, value);

   /* resolution already set */
   if (EC_GBL_OPTIONS->resolve) {
      EC_GBL_OPTIONS->resolve = 0;
      resolv_thread_fini();
      return;
   } 

   DEBUG_MSG("toggle_resolve: activate name resolution");

   /* set the option and activate resolution threads */
   EC_GBL_OPTIONS->resolve = 1;
   resolv_thread_init();

   /* run through the current hosts list and trigger resolution */
   LIST_FOREACH(hl, &EC_GBL_HOSTLIST, next) {
      if (hl->hostname)
         continue;
      host_iptoa(&hl->ip, name);
   }

   /* actually refresh the host list */
   EC_GBL_UI->update(UI_UPDATE_HOSTLIST);
}

/*
 * display the statistics windows
 */
void gtkui_show_stats(GSimpleAction *action, GVariant *value, gpointer data)
{
   GtkWidget *grid, *label;

   (void) action;
   (void) value;
   (void) data;

   DEBUG_MSG("gtkui_show_stats");

   /* if the object already exist, set the focus to it */
   if (stats_window) {
      /* show stats window */
      if(GTK_IS_WINDOW (stats_window))
         gtk_window_present(GTK_WINDOW (stats_window));
      else
         gtkui_page_present(stats_window);
      return;
   }
   
   stats_window = gtkui_page_new("Statistics", &gtkui_stop_stats, &gtkui_stats_detach);

   /* alright, this is a lot of code but it'll keep everything lined up nicely */
   grid = gtk_grid_new();
   gtk_grid_set_column_homogeneous(GTK_GRID(grid), TRUE);
   gtk_grid_set_column_spacing(GTK_GRID(grid), 10);
   gtk_container_add(GTK_CONTAINER (stats_window), grid);

   label = gtk_label_new( "Received packets:");
   gtk_label_set_selectable(GTK_LABEL (label), TRUE);
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), label, GTK_POS_LEFT, GTK_POS_TOP, 1, 1);
   packets_recv = gtk_label_new("      ");
   gtk_label_set_selectable(GTK_LABEL (packets_recv), TRUE);
   gtk_widget_set_halign(packets_recv, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), packets_recv, GTK_POS_LEFT+1, GTK_POS_TOP, 1, 1);

   label        = gtk_label_new("Dropped packets:");
   gtk_label_set_selectable(GTK_LABEL (label), TRUE);
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), label, GTK_POS_LEFT, GTK_POS_TOP+1, 1, 1);
   packets_drop = gtk_label_new("      ");
   gtk_label_set_selectable(GTK_LABEL (packets_drop), TRUE);
   gtk_widget_set_halign(packets_drop, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), packets_drop, GTK_POS_LEFT+1, GTK_POS_TOP+1, 1, 1);

   label        = gtk_label_new("Forwarded packets:");
   gtk_label_set_selectable(GTK_LABEL (label), TRUE);
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), label, GTK_POS_LEFT, GTK_POS_TOP+2, 1, 1);
   packets_forw = gtk_label_new("       0  bytes:        0 ");
   gtk_label_set_selectable(GTK_LABEL (packets_forw), TRUE);
   gtk_widget_set_halign(packets_forw, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), packets_forw, GTK_POS_LEFT+1, GTK_POS_TOP+2, 1 ,1);

   label        = gtk_label_new("Current queue length:");
   gtk_label_set_selectable(GTK_LABEL (label), TRUE);
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), label, GTK_POS_LEFT, GTK_POS_TOP+3, 1, 1);
   queue_len    = gtk_label_new("0/0 ");
   gtk_label_set_selectable(GTK_LABEL (queue_len), TRUE);
   gtk_widget_set_halign(queue_len, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), queue_len, GTK_POS_LEFT+1, GTK_POS_TOP+3, 1, 1);

   label        = gtk_label_new("Sampling rate:");
   gtk_label_set_selectable(GTK_LABEL (label), TRUE);
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), label, GTK_POS_LEFT, GTK_POS_TOP+4, 1, 1);
   sample_rate  = gtk_label_new("0     ");
   gtk_label_set_selectable(GTK_LABEL (sample_rate), TRUE);
   gtk_widget_set_halign(sample_rate, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), sample_rate, GTK_POS_LEFT+1, GTK_POS_TOP+4, 1, 1);

   label        = gtk_label_new("Bottom Half received packet:");
   gtk_label_set_selectable(GTK_LABEL (label), TRUE);
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), label, GTK_POS_LEFT, GTK_POS_TOP+5, 1, 1);
   recv_bottom  = gtk_label_new("pck:        0  bytes:        0");
   gtk_label_set_selectable(GTK_LABEL (recv_bottom), TRUE);
   gtk_widget_set_halign(recv_bottom, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), recv_bottom, GTK_POS_LEFT+1 ,GTK_POS_TOP+5, 1, 1);

   label        = gtk_label_new("Top Half received packet:");
   gtk_label_set_selectable(GTK_LABEL (label), TRUE);
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), label, GTK_POS_LEFT, GTK_POS_TOP+6, 1, 1);
   recv_top     = gtk_label_new("pck:        0  bytes:        0");
   gtk_label_set_selectable(GTK_LABEL (recv_top), TRUE);
   gtk_widget_set_halign(recv_top, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), recv_top, GTK_POS_LEFT+1, GTK_POS_TOP+6, 1, 1);

   label        = gtk_label_new("Interesting packets:");
   gtk_label_set_selectable(GTK_LABEL (label), TRUE);
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), label, GTK_POS_LEFT, GTK_POS_TOP+7, 1, 1);
   interesting  = gtk_label_new("0.00 %");
   gtk_label_set_selectable(GTK_LABEL (interesting), TRUE);
   gtk_widget_set_halign(interesting, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), interesting, GTK_POS_LEFT+1, GTK_POS_TOP+7, 1, 1);

   label        = gtk_label_new("Bottom Half packet rate:");
   gtk_label_set_selectable(GTK_LABEL (label), TRUE);
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), label, GTK_POS_LEFT, GTK_POS_TOP+8, 1, 1);
   rate_bottom  = gtk_label_new("worst:        0  adv:        0 b/s");
   gtk_label_set_selectable(GTK_LABEL (rate_bottom), TRUE);
   gtk_widget_set_halign(rate_bottom, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), rate_bottom, GTK_POS_LEFT+1, GTK_POS_TOP+8, 1, 1);

   label        = gtk_label_new("Top Half packet rate:");
   gtk_label_set_selectable(GTK_LABEL (label), TRUE);
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), label, GTK_POS_LEFT, GTK_POS_TOP+9, 1, 1);
   rate_top     = gtk_label_new("worst:        0  adv:        0 b/s");
   gtk_label_set_selectable(GTK_LABEL (rate_top), TRUE);
   gtk_widget_set_halign(rate_top, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), rate_top, GTK_POS_LEFT+1, GTK_POS_TOP+9, 1, 1);

   label        = gtk_label_new("Bottom Half throughput:");
   gtk_label_set_selectable(GTK_LABEL (label), TRUE);
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), label, GTK_POS_LEFT, GTK_POS_TOP+10, 1, 1);
   through_bottom = gtk_label_new("worst:        0  adv:        0 b/s");
   gtk_label_set_selectable(GTK_LABEL (through_bottom), TRUE);
   gtk_widget_set_halign(through_bottom, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), through_bottom, GTK_POS_LEFT+1, GTK_POS_TOP+10, 1, 1);

   label        = gtk_label_new("Top Half throughput:");
   gtk_label_set_selectable(GTK_LABEL (label), TRUE);
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), label, GTK_POS_LEFT, GTK_POS_TOP+11, 1, 1);
   through_top  = gtk_label_new("worst:        0  adv:        0 b/s");
   gtk_label_set_selectable(GTK_LABEL (through_top), TRUE);
   gtk_widget_set_halign(through_top, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), through_top, GTK_POS_LEFT+1, GTK_POS_TOP+11, 1, 1);

   gtk_widget_show_all(grid);
   gtk_widget_show(stats_window);
  
   /* display the stats */
   refresh_stats(NULL); 

   /* refresh the stats window every 200 ms */
   /* GTK has a gtk_idle_add also but it calls too much and uses 100% cpu */
   stats_idle = g_timeout_add(200, refresh_stats, NULL);
}

static void gtkui_stats_detach(GtkWidget *child)
{
   stats_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
   gtk_window_set_title(GTK_WINDOW (stats_window), "Statistics");
   gtk_container_set_border_width(GTK_CONTAINER (stats_window), 10);
   g_signal_connect (G_OBJECT (stats_window), "delete_event", G_CALLBACK (gtkui_stop_stats), NULL);

   /* make <ctrl>d shortcut turn the window back into a tab */
   gtkui_page_attach_shortcut(stats_window, gtkui_stats_attach);
   
   gtk_container_add(GTK_CONTAINER (stats_window), child);

   gtk_window_present(GTK_WINDOW (stats_window));
}

static void gtkui_stats_attach(void)
{
   gtkui_stop_stats();
   gtkui_show_stats(NULL, NULL, NULL);
}

static void gtkui_stop_stats(void)
{
   DEBUG_MSG("gtk_stop_stats");
   g_source_remove(stats_idle);

   gtk_widget_destroy(stats_window);
   stats_window = NULL;
}

static gboolean refresh_stats(gpointer data)
{
   char line[50];

   /* variable not used */
   (void) data;

   /* if not focused don't refresh it */
   /* this also removes the idle call, but should 
      only occur if the window isn't visible */
   if (!gtk_widget_get_visible(stats_window))
      return FALSE;

   snprintf(line, 50, "%8"PRIu64, EC_GBL_STATS->ps_recv);
   gtk_label_set_text(GTK_LABEL (packets_recv), line);
   snprintf(line, 50, "%8"PRIu64"  %.2f %%", EC_GBL_STATS->ps_drop, 
         (EC_GBL_STATS->ps_recv) ? (float)EC_GBL_STATS->ps_drop * 100 / EC_GBL_STATS->ps_recv : 0 );
   gtk_label_set_text(GTK_LABEL (packets_drop), line);
   snprintf(line, 50, "%8"PRIu64"  bytes: %8"PRIu64" ", EC_GBL_STATS->ps_sent, EC_GBL_STATS->bs_sent);
   gtk_label_set_text(GTK_LABEL (packets_forw), line);
   snprintf(line, 50, "%lu/%lu ", EC_GBL_STATS->queue_curr, EC_GBL_STATS->queue_max);
   gtk_label_set_text(GTK_LABEL (queue_len), line);
   snprintf(line, 50, "%d ", EC_GBL_CONF->sampling_rate);
   gtk_label_set_text(GTK_LABEL (sample_rate), line);
   snprintf(line, 50, "pck: %8"PRIu64"  bytes: %8"PRIu64, 
         EC_GBL_STATS->bh.pck_recv, EC_GBL_STATS->bh.pck_size);
   gtk_label_set_text(GTK_LABEL (recv_bottom), line);
   snprintf(line, 50, "pck: %8"PRIu64"  bytes: %8"PRIu64, 
         EC_GBL_STATS->th.pck_recv, EC_GBL_STATS->th.pck_size);
   gtk_label_set_text(GTK_LABEL (recv_top), line);
   snprintf(line, 50, "%.2f %%",
         (EC_GBL_STATS->bh.pck_recv) ? (float)EC_GBL_STATS->th.pck_recv * 100 / EC_GBL_STATS->bh.pck_recv : 0 );
   gtk_label_set_text(GTK_LABEL (interesting), line);
   snprintf(line, 50, "worst: %8lu  adv: %8lu p/s", 
         EC_GBL_STATS->bh.rate_worst, EC_GBL_STATS->bh.rate_adv);
   gtk_label_set_text(GTK_LABEL (rate_bottom), line);
   snprintf(line, 50, "worst: %8lu  adv: %8lu p/s", 
         EC_GBL_STATS->th.rate_worst, EC_GBL_STATS->th.rate_adv);
   gtk_label_set_text(GTK_LABEL (rate_top), line);
   snprintf(line, 50, "worst: %8lu  adv: %8lu b/s", 
         EC_GBL_STATS->bh.thru_worst, EC_GBL_STATS->bh.thru_adv);
   gtk_label_set_text(GTK_LABEL (through_bottom), line);
   snprintf(line, 50, "worst: %8lu  adv: %8lu b/s", 
         EC_GBL_STATS->th.thru_worst, EC_GBL_STATS->th.thru_adv);
   gtk_label_set_text(GTK_LABEL (through_top), line);

   return(TRUE);
}

/*
 * change the visualization method 
 */
void gtkui_vis_method(GSimpleAction *action, GVariant *value, gpointer data)
{
   GtkWidget *dialog, *button, *prev, *vbox, *content_area;
   GSList *curr = NULL;
   gint active = 0, response = 0;
   GtkTreeModel *model;
   GtkTreeIter iter;
   GtkListStore *lang_list = NULL;
   GtkCellRenderer *cell = NULL;
   GtkWidget *hbox, *lang_combo, *label;
   char encoding[50], def_lang[75];
   const char *local_lang, *selected_lang;

   (void) action;
   (void) value;
   (void) data;

   DEBUG_MSG("gtk_vis_method");

   dialog = gtk_dialog_new_with_buttons("Visualization method...", GTK_WINDOW (window), 
               GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT | GTK_DIALOG_USE_HEADER_BAR,
               "_Cancel", GTK_RESPONSE_CANCEL, 
               "_OK",     GTK_RESPONSE_OK, 
               NULL);
   gtk_container_set_border_width(GTK_CONTAINER(dialog), 10);

   content_area = gtk_dialog_get_content_area(GTK_DIALOG(dialog));

   vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
   gtk_container_add(GTK_CONTAINER(content_area), vbox);

   button = gtk_radio_button_new_with_label(NULL, 
               "Print the packets in hex format.");
   gtk_box_pack_start(GTK_BOX(vbox), button, FALSE, FALSE, 0);
   if(strcmp(vmethod, "hex") == 0)
      gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON (button), TRUE);
   prev = button;

   button = gtk_radio_button_new_with_label_from_widget(GTK_RADIO_BUTTON (prev),
               "Print only \"printable\" characters, the others are displayed as dots '.'");
   gtk_box_pack_start(GTK_BOX(vbox), button, FALSE, FALSE, 0);
   if(strcmp(vmethod, "ascii") == 0)
      gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON (button), TRUE);
   prev = button;

   button = gtk_radio_button_new_with_label_from_widget(GTK_RADIO_BUTTON (prev),
               "Print only the \"printable\" characters and skip the others.");
   gtk_box_pack_start(GTK_BOX(vbox), button, FALSE, FALSE, 0);
   if(strcmp(vmethod, "text") == 0)
      gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON (button), TRUE);
   prev = button;

   button = gtk_radio_button_new_with_label_from_widget(GTK_RADIO_BUTTON (prev),
               "Convert an EBCDIC text to ASCII.");
   gtk_box_pack_start(GTK_BOX(vbox), button, FALSE, FALSE, 0);
   if(strcmp(vmethod, "ebcdic") == 0)
      gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON (button), TRUE);
   prev = button;

   button = gtk_radio_button_new_with_label_from_widget(GTK_RADIO_BUTTON (prev),
               "Strip all the html tags from the text. A tag is every string between < and >.");
   gtk_box_pack_start(GTK_BOX(vbox), button, FALSE, FALSE, 0);
   if(strcmp(vmethod, "html") == 0)
      gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON (button), TRUE);
   prev = button;

/* start UTF8 */
   button = gtk_radio_button_new_with_label_from_widget(GTK_RADIO_BUTTON (prev),
               "Convert the data from the encoding specified below to UTF8 before displaying it.");
   gtk_box_pack_start(GTK_BOX(vbox), button, FALSE, FALSE, 0);
   if(strcmp(vmethod, "utf8") == 0)
      gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON (button), TRUE);
   prev = button;

   hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
   gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);

   label = gtk_label_new ("Character encoding : ");
   gtk_box_pack_start (GTK_BOX (hbox), label, FALSE, FALSE, 0);

   /* Fill a list of available encodings */
   lang_list = gtk_list_store_new(1, G_TYPE_STRING);

   /* get the system's default encoding, and if it's not UTF8, add it to the list */
   if(!g_get_charset(&local_lang)) {
      snprintf(def_lang, 75, "%s (System Default)", local_lang);
      gtk_list_store_append(lang_list, &iter);
      gtk_list_store_set(lang_list, &iter, 0, def_lang, -1);
   }

   /* some other common encodings */
   gtk_list_store_append(lang_list, &iter);
   gtk_list_store_set(lang_list, &iter, 0, "UTF-8", -1);
   gtk_list_store_append(lang_list, &iter);
   gtk_list_store_set(lang_list, &iter, 0, "EBCDIC-US (IBM)", -1);
   gtk_list_store_append(lang_list, &iter);
   gtk_list_store_set(lang_list, &iter, 0, "ISO-8859-15 (Western Europe)", -1);
   gtk_list_store_append(lang_list, &iter);
   gtk_list_store_set(lang_list, &iter, 0, "ISO-8859-2 (Central Europe)", -1);
   gtk_list_store_append(lang_list, &iter);
   gtk_list_store_set(lang_list, &iter, 0, "ISO-8859-7 (Greek)", -1);
   gtk_list_store_append(lang_list, &iter);
   gtk_list_store_set(lang_list, &iter, 0, "ISO-8859-8 (Hebrew)", -1);
   gtk_list_store_append(lang_list, &iter);
   gtk_list_store_set(lang_list, &iter, 0, "ISO-8859-9 (Turkish)", -1);
   gtk_list_store_append(lang_list, &iter);
   gtk_list_store_set(lang_list, &iter, 0, "ISO-2022-JP (Japanese)", -1);
   gtk_list_store_append(lang_list, &iter);
   gtk_list_store_set(lang_list, &iter, 0, "SJIS (Japanese)", -1);
   gtk_list_store_append(lang_list, &iter);
   gtk_list_store_set(lang_list, &iter, 0, "CP949 (Korean)", -1);
   gtk_list_store_append(lang_list, &iter);
   gtk_list_store_set(lang_list, &iter, 0, "CP1251 (Cyrillic)", -1);
   gtk_list_store_append(lang_list, &iter);
   gtk_list_store_set(lang_list, &iter, 0, "CP1256 (Arabic)", -1);
   gtk_list_store_append(lang_list, &iter);
   gtk_list_store_set(lang_list, &iter, 0, "GB18030 (Chinese)", -1);

   /* make a drop down box and assign the list to it */
   lang_combo = gtk_combo_box_new();
   gtk_combo_box_set_model(GTK_COMBO_BOX(lang_combo), GTK_TREE_MODEL(lang_list));

   /* list is stored in the widget, can safely free this copy */
   g_object_unref(lang_list);
/* end UTF8 */

   cell = gtk_cell_renderer_text_new();
   gtk_cell_layout_pack_start(GTK_CELL_LAYOUT(lang_combo), cell, TRUE);
   gtk_cell_layout_set_attributes(GTK_CELL_LAYOUT(lang_combo), cell, "text", 0, NULL);
   gtk_combo_box_set_active(GTK_COMBO_BOX(lang_combo), 0);
   gtk_box_pack_start (GTK_BOX(hbox), lang_combo, TRUE, TRUE, 0);
      
   gtk_widget_show_all(vbox);

   response = gtk_dialog_run(GTK_DIALOG (dialog));
   if(response == GTK_RESPONSE_OK) {
      gtk_widget_hide(dialog);

      /* see which button was clicked */
      active = 0;
      for(curr = gtk_radio_button_get_group(GTK_RADIO_BUTTON (button)); curr; curr = curr->next) {
         active++;
         if(gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (curr->data)))
            break;
      }

      /* set vmethod string */
      int i=0;
      memset(vmethod, 0, VLEN);

      switch(active) {
         case 6: strncpy(vmethod, "hex", 4); break;
         case 5: strncpy(vmethod, "ascii", 6); break; 
         case 4: strncpy(vmethod, "text", 5); break;
         case 3: strncpy(vmethod, "ebcdic", 7); break;
         case 2: strncpy(vmethod, "html", 5); break;
         case 1: /* utf8 */
            /* copy first word from encoding choice */
            gtk_combo_box_get_active_iter(GTK_COMBO_BOX(lang_combo), &iter);
            model = gtk_combo_box_get_model(GTK_COMBO_BOX(lang_combo));
            gtk_tree_model_get(model, &iter, 0, &selected_lang, -1);
            i=sscanf(selected_lang, "%[^ ]", encoding);
            BUG_IF(i!=1);
            if(strlen(encoding) > 0) {
               strncpy(vmethod, "utf8", 5);
               set_utf8_encoding(encoding);
               break;
            }
            /* fall through */
         default: strncpy(vmethod, "ascii", 6);
      }

      set_format(vmethod);
   }

   gtk_widget_destroy(dialog);
}

/*
 * set the visualization regex 
 */
void gtkui_vis_regex(GSimpleAction *action, GVariant *value, gpointer data)
{
   (void) action;
   (void) value;
   (void) data;

   DEBUG_MSG("gtk_vis_regex");

   gtkui_input("Visualization regex :", vregex, RLEN, gtkui_set_regex);
}

static void gtkui_set_regex(void)
{
   set_regex(vregex);
}

/*
 * set the Wifi key
 */
void gtkui_wifi_key(GSimpleAction *action, GVariant *value, gpointer data)
{
   (void) action;
   (void) value;
   (void) data;

   DEBUG_MSG("gtk_wifi_key");

   gtkui_input("WiFi key :", wkey, WLEN, gtkui_set_wifikey);
}

static void gtkui_set_wifikey(void)
{
   wifi_key_prepare(wkey);
}

/* EOF */

// vim:ts=3:expandtab

