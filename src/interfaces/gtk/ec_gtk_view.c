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

    $Id: ec_gtk_view.c,v 1.1 2004/02/27 03:34:33 daten Exp $
*/

#include <ec.h>
#include <ec_gtk.h>
#include <ec_format.h>

/* proto */

void gui_show_stats(void);
void toggle_resolve(void);
void gui_vis_method(void);

static void gui_stop_stats(void);
static gboolean refresh_stats(gpointer data);

extern void gui_show_profiles(void);
extern void gui_show_connections(void);

/* globals */

#define VLEN 8
static char vmethod[VLEN];
static guint stats_idle; /* for removing the idle call */
/* for stats window */
static GtkWidget *stats_window, *packets_recv, *packets_drop, *packets_forw, 
                 *queue_len, *sample_rate, *recv_bottom, *recv_top, *interesting, 
                 *rate_bottom, *rate_top, *through_bottom, *through_top;

/*******************************************/


void toggle_resolve(void)
{
   if (GBL_OPTIONS->resolve) {
      GBL_OPTIONS->resolve = 0;
   } else {
      GBL_OPTIONS->resolve = 1;
   }
}

/*
 * display the statistics windows
 */
void gui_show_stats(void)
{
   GtkWidget *table, *label;

   DEBUG_MSG("gui_show_stats");

   /* if the object already exist, set the focus to it */
   if (stats_window) {
      /* if window was hidden, we have to start the refresh callback again */
      if (!GTK_WIDGET_VISIBLE(stats_window))
         stats_idle = gtk_timeout_add(200, refresh_stats, NULL);

      /* show stats window */
      gtk_window_present(GTK_WINDOW (stats_window));
      return;
   }
   
   stats_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
   gtk_window_set_title(GTK_WINDOW (stats_window), "Statistics");
   gtk_container_set_border_width(GTK_CONTAINER (stats_window), 10);
   g_signal_connect (G_OBJECT (stats_window), "delete_event", G_CALLBACK (gui_stop_stats), NULL);

   /* alright, this is a lot of code but it'll keep everything lined up nicely */
   /* if you need to add a row, don't forget to increase the number in gtk_table_new */
   table = gtk_table_new(12, 2, FALSE); /* rows, cols, size */
   gtk_table_set_col_spacings(GTK_TABLE (table), 10);
   gtk_container_add(GTK_CONTAINER (stats_window), table);

   packets_recv = gtk_label_new("      ");
   gtk_label_set_selectable(GTK_LABEL (packets_recv), TRUE);
   gtk_misc_set_alignment(GTK_MISC (packets_recv), 0, 0.5);
   gtk_table_attach_defaults(GTK_TABLE(table), packets_recv, 1, 2, 0, 1);
   label        = gtk_label_new( "Received packets:");
   gtk_label_set_selectable(GTK_LABEL (label), TRUE);
   gtk_misc_set_alignment(GTK_MISC (label), 0, 0.5);
   gtk_table_attach_defaults(GTK_TABLE(table), label, 0, 1, 0, 1);

   packets_drop = gtk_label_new("      ");
   gtk_label_set_selectable(GTK_LABEL (packets_drop), TRUE);
   gtk_misc_set_alignment(GTK_MISC (packets_drop), 0, 0.5);
   gtk_table_attach_defaults(GTK_TABLE(table), packets_drop, 1, 2, 1, 2);
   label        = gtk_label_new("Dropped packets:");
   gtk_label_set_selectable(GTK_LABEL (label), TRUE);
   gtk_misc_set_alignment(GTK_MISC (label), 0, 0.5);
   gtk_table_attach_defaults(GTK_TABLE(table), label, 0, 1, 1, 2);

   packets_forw = gtk_label_new("       0  bytes:        0 ");
   gtk_label_set_selectable(GTK_LABEL (packets_forw), TRUE);
   gtk_misc_set_alignment(GTK_MISC (packets_forw), 0, 0.5);
   gtk_table_attach_defaults(GTK_TABLE(table), packets_forw, 1, 2, 2, 3);
   label        = gtk_label_new("Forwarded packets:");
   gtk_label_set_selectable(GTK_LABEL (label), TRUE);
   gtk_misc_set_alignment(GTK_MISC (label), 0, 0.5);
   gtk_table_attach_defaults(GTK_TABLE(table), label, 0, 1, 2, 3);

   queue_len    = gtk_label_new("0/0 ");
   gtk_label_set_selectable(GTK_LABEL (queue_len), TRUE);
   gtk_misc_set_alignment(GTK_MISC (queue_len), 0, 0.5);
   gtk_table_attach_defaults(GTK_TABLE(table), queue_len, 1, 2, 3, 4);
   label        = gtk_label_new("Current queue length:");
   gtk_label_set_selectable(GTK_LABEL (label), TRUE);
   gtk_misc_set_alignment(GTK_MISC (label), 0, 0.5);
   gtk_table_attach_defaults(GTK_TABLE(table), label, 0, 1, 3, 4);

   sample_rate  = gtk_label_new("0     ");
   gtk_label_set_selectable(GTK_LABEL (sample_rate), TRUE);
   gtk_misc_set_alignment(GTK_MISC (sample_rate), 0, 0.5);
   gtk_table_attach_defaults(GTK_TABLE(table), sample_rate, 1, 2, 4, 5);
   label        = gtk_label_new("Sampling rate:");
   gtk_label_set_selectable(GTK_LABEL (label), TRUE);
   gtk_misc_set_alignment(GTK_MISC (label), 0, 0.5);
   gtk_table_attach_defaults(GTK_TABLE(table), label, 0, 1, 4, 5);

   recv_bottom  = gtk_label_new("pck:        0  bytes:        0");
   gtk_label_set_selectable(GTK_LABEL (recv_bottom), TRUE);
   gtk_misc_set_alignment(GTK_MISC (recv_bottom), 0, 0.5);
   gtk_table_attach_defaults(GTK_TABLE(table), recv_bottom, 1, 2, 5, 6);
   label        = gtk_label_new("Bottom Half received packet:");
   gtk_label_set_selectable(GTK_LABEL (label), TRUE);
   gtk_misc_set_alignment(GTK_MISC (label), 0, 0.5);
   gtk_table_attach_defaults(GTK_TABLE(table), label, 0, 1, 5, 6);

   recv_top     = gtk_label_new("pck:        0  bytes:        0");
   gtk_label_set_selectable(GTK_LABEL (recv_top), TRUE);
   gtk_misc_set_alignment(GTK_MISC (recv_top), 0, 0.5);
   gtk_table_attach_defaults(GTK_TABLE(table), recv_top, 1, 2, 6, 7);
   label        = gtk_label_new("Top Half received packet:");
   gtk_label_set_selectable(GTK_LABEL (label), TRUE);
   gtk_misc_set_alignment(GTK_MISC (label), 0, 0.5);
   gtk_table_attach_defaults(GTK_TABLE(table), label, 0, 1, 6, 7);

   interesting  = gtk_label_new("0.00 %");
   gtk_label_set_selectable(GTK_LABEL (interesting), TRUE);
   gtk_misc_set_alignment(GTK_MISC (interesting), 0, 0.5);
   gtk_table_attach_defaults(GTK_TABLE(table), interesting, 1, 2, 7, 8);
   label        = gtk_label_new("Interesting packets:");
   gtk_label_set_selectable(GTK_LABEL (label), TRUE);
   gtk_misc_set_alignment(GTK_MISC (label), 0, 0.5);
   gtk_table_attach_defaults(GTK_TABLE(table), label, 0, 1, 7, 8);

   rate_bottom  = gtk_label_new("worst:        0  adv:        0 b/s");
   gtk_label_set_selectable(GTK_LABEL (rate_bottom), TRUE);
   gtk_misc_set_alignment(GTK_MISC (rate_bottom), 0, 0.5);
   gtk_table_attach_defaults(GTK_TABLE(table), rate_bottom, 1, 2, 8, 9);
   label        = gtk_label_new("Bottom Half packet rate:");
   gtk_label_set_selectable(GTK_LABEL (label), TRUE);
   gtk_misc_set_alignment(GTK_MISC (label), 0, 0.5);
   gtk_table_attach_defaults(GTK_TABLE(table), label, 0, 1, 8, 9);

   rate_top     = gtk_label_new("worst:        0  adv:        0 b/s");
   gtk_label_set_selectable(GTK_LABEL (rate_top), TRUE);
   gtk_misc_set_alignment(GTK_MISC (rate_top), 0, 0.5);
   gtk_table_attach_defaults(GTK_TABLE(table), rate_top, 1, 2, 9, 10);
   label        = gtk_label_new("Top Half packet rate:");
   gtk_label_set_selectable(GTK_LABEL (label), TRUE);
   gtk_misc_set_alignment(GTK_MISC (label), 0, 0.5);
   gtk_table_attach_defaults(GTK_TABLE(table), label, 0, 1, 9, 10);

   through_bottom = gtk_label_new("worst:        0  adv:        0 b/s");
   gtk_label_set_selectable(GTK_LABEL (through_bottom), TRUE);
   gtk_misc_set_alignment(GTK_MISC (through_bottom), 0, 0.5);
   gtk_table_attach_defaults(GTK_TABLE(table), through_bottom, 1, 2, 10, 11);
   label        = gtk_label_new("Bottom Half throughput:");
   gtk_label_set_selectable(GTK_LABEL (label), TRUE);
   gtk_misc_set_alignment(GTK_MISC (label), 0, 0.5);
   gtk_table_attach_defaults(GTK_TABLE(table), label, 0, 1, 10, 11);

   through_top  = gtk_label_new("worst:        0  adv:        0 b/s");
   gtk_label_set_selectable(GTK_LABEL (through_top), TRUE);
   gtk_misc_set_alignment(GTK_MISC (through_top), 0, 0.5);
   gtk_table_attach_defaults(GTK_TABLE(table), through_top, 1, 2, 11, 12);
   label        = gtk_label_new("Top Half throughput:");
   gtk_label_set_selectable(GTK_LABEL (label), TRUE);
   gtk_misc_set_alignment(GTK_MISC (label), 0, 0.5);
   gtk_table_attach_defaults(GTK_TABLE(table), label, 0, 1, 11, 12);

   gtk_widget_show_all(table);
   gtk_widget_show(stats_window);
  
   /* display the stats */
   refresh_stats(NULL); 

   /* refresh the stats window every 200 ms */
   /* GTK has a gtk_idle_add also but it calls too much and uses 100% cpu */
   stats_idle = gtk_timeout_add(200, refresh_stats, NULL);
}

static void gui_stop_stats(void)
{
   DEBUG_MSG("gtk_stop_stats");
   gtk_timeout_remove(stats_idle);

   gtk_widget_hide(stats_window);
}

static gboolean refresh_stats(gpointer data)
{
   char line[50];

   /* if not focused don't refresh it */
   /* this also removes the idle call, but should 
      only occur if the window isn't visible */
   if (!GTK_WIDGET_VISIBLE(stats_window))
      return FALSE;

   snprintf(line, 50, "%8lld", GBL_STATS->ps_recv);
   gtk_label_set_text(GTK_LABEL (packets_recv), line);
   snprintf(line, 50, "%8lld  %.2f %%", GBL_STATS->ps_drop, 
         (GBL_STATS->ps_recv) ? (float)GBL_STATS->ps_drop * 100 / GBL_STATS->ps_recv : 0 );
   gtk_label_set_text(GTK_LABEL (packets_drop), line);
   snprintf(line, 50, "%8lld  bytes: %8lld ", GBL_STATS->ps_sent, GBL_STATS->bs_sent);
   gtk_label_set_text(GTK_LABEL (packets_forw), line);
   snprintf(line, 50, "%d/%d ", GBL_STATS->queue_curr, GBL_STATS->queue_max);
   gtk_label_set_text(GTK_LABEL (queue_len), line);
   snprintf(line, 50, "%d ", GBL_CONF->sampling_rate);
   gtk_label_set_text(GTK_LABEL (sample_rate), line);
   snprintf(line, 50, "pck: %8lld  bytes: %8lld", 
         GBL_STATS->bh.pck_recv, GBL_STATS->bh.pck_size);
   gtk_label_set_text(GTK_LABEL (recv_bottom), line);
   snprintf(line, 50, "pck: %8lld  bytes: %8lld", 
         GBL_STATS->th.pck_recv, GBL_STATS->th.pck_size);
   gtk_label_set_text(GTK_LABEL (recv_top), line);
   snprintf(line, 50, "%.2f %%",
         (GBL_STATS->bh.pck_recv) ? (float)GBL_STATS->th.pck_recv * 100 / GBL_STATS->bh.pck_recv : 0 );
   gtk_label_set_text(GTK_LABEL (interesting), line);
   snprintf(line, 50, "worst: %8d  adv: %8d p/s", 
         GBL_STATS->bh.rate_worst, GBL_STATS->bh.rate_adv);
   gtk_label_set_text(GTK_LABEL (rate_bottom), line);
   snprintf(line, 50, "worst: %8d  adv: %8d p/s", 
         GBL_STATS->th.rate_worst, GBL_STATS->th.rate_adv);
   gtk_label_set_text(GTK_LABEL (rate_top), line);
   snprintf(line, 50, "worst: %8d  adv: %8d b/s", 
         GBL_STATS->bh.thru_worst, GBL_STATS->bh.thru_adv);
   gtk_label_set_text(GTK_LABEL (through_bottom), line);
   snprintf(line, 50, "worst: %8d  adv: %8d b/s", 
         GBL_STATS->th.thru_worst, GBL_STATS->th.thru_adv);
   gtk_label_set_text(GTK_LABEL (through_top), line);

   return(TRUE);
}

/*
 * change the visualization method 
 */
void gui_vis_method(void)
{
   GtkWidget *dialog, *button, *prev, *vbox;
   GSList *curr = NULL;
   gint active = 0, response = 0;


   DEBUG_MSG("gtk_vis_method");

   dialog = gtk_dialog_new_with_buttons("Visualization method...", GTK_WINDOW (window), 
               GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
               GTK_STOCK_OK, GTK_RESPONSE_OK, 
               GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL, NULL);
   gtk_container_set_border_width(GTK_CONTAINER(dialog), 10);

   vbox = GTK_DIALOG (dialog)->vbox;

   button = gtk_radio_button_new_with_label(NULL, 
               "hex     Print the packets in hex format.");
   gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dialog)->vbox), button, FALSE, FALSE, 0);
   prev = button;

   button = gtk_radio_button_new_with_label_from_widget(GTK_RADIO_BUTTON (prev),
               "ascii   Print only \"printable\" characters, the others are displayed as dots '.'");
   gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dialog)->vbox), button, FALSE, FALSE, 0);
   prev = button;

   button = gtk_radio_button_new_with_label_from_widget(GTK_RADIO_BUTTON (prev),
               "text    Print only the \"printable\" characters and skip the others.");
   gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dialog)->vbox), button, FALSE, FALSE, 0);
   prev = button;

   button = gtk_radio_button_new_with_label_from_widget(GTK_RADIO_BUTTON (prev),
               "ebcdic  Convert an EBCDIC text to ASCII.");
   gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dialog)->vbox), button, FALSE, FALSE, 0);
   prev = button;

   button = gtk_radio_button_new_with_label_from_widget(GTK_RADIO_BUTTON (prev),
               "html    Strip all the html tags from the text. A tag is every string between < and >.");
   gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dialog)->vbox), button, FALSE, FALSE, 0);

   gtk_widget_show_all(GTK_DIALOG(dialog)->vbox);

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
      switch(active) {
         case 1: strcpy(vmethod, "hex"); break;
         case 2: strcpy(vmethod, "ascii"); break; 
         case 3: strcpy(vmethod, "text"); break;
         case 4: strcpy(vmethod, "ebcdic"); break;
         case 5: strcpy(vmethod, "html"); break;
         default: strcpy(vmethod, "ascii");
      }

      set_format(vmethod);
   }

   gtk_widget_destroy(dialog);
}

/* EOF */

// vim:ts=3:expandtab

