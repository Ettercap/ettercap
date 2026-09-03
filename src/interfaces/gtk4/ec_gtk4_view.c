/*
    ettercap -- GTK4 GUI -- statistics and visualization settings

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
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include <ec.h>
#include <ec_gtk4.h>
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
                 *queue_len, *sample_rate, *recv_bottom, *recv_top,
                 *interesting, *rate_bottom, *rate_top, *through_bottom,
                 *through_top;

/*******************************************/

/*
 * If this option is being activated,
 * it runs through the current hosts list and triggers
 * name resolution in the background.
 * That way subsequent actions benefit from the filled cache
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

/*******************************************/
/* statistics                                                              */
/*******************************************/

/*
 * The GTK3 version spelled out six lines per statistic -- create the label,
 * make it selectable, align it, attach it, then the same again for the value
 * -- twelve times over, about 100 lines of it. The rows differ only in their
 * caption and initial value.
 */
static GtkWidget *stats_row(GtkWidget *grid, int row, const char *caption,
      const char *initial)
{
   GtkWidget *label, *value;

   label = gtk_label_new(caption);
   gtk_label_set_selectable(GTK_LABEL(label), TRUE);
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), label, 0, row, 1, 1);

   value = gtk_label_new(initial);
   gtk_label_set_selectable(GTK_LABEL(value), TRUE);
   gtk_widget_set_halign(value, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), value, 1, row, 1, 1);

   return value;
}

/*
 * display the statistics window
 */
void gtkui_show_stats(GSimpleAction *action, GVariant *value, gpointer data)
{
   GtkWidget *grid;
   int row = 0;

   (void) action;
   (void) value;
   (void) data;

   DEBUG_MSG("gtkui_show_stats");

   /* if the object already exists, set the focus to it */
   if (stats_window) {
      if (GTK_IS_WINDOW(stats_window))
         gtk_window_present(GTK_WINDOW(stats_window));
      else
         gtkui_page_present(stats_window);
      return;
   }

   stats_window = gtkui_page_new("Statistics", &gtkui_stop_stats,
         &gtkui_stats_detach);

   grid = gtk_grid_new();
   gtk_grid_set_column_homogeneous(GTK_GRID(grid), TRUE);
   gtk_grid_set_column_spacing(GTK_GRID(grid), 10);
   gtk_widget_set_margin_top(grid, 10);
   gtk_widget_set_margin_bottom(grid, 10);
   gtk_widget_set_margin_start(grid, 10);
   gtk_widget_set_margin_end(grid, 10);
   gtk_box_append(GTK_BOX(stats_window), grid);

   packets_recv   = stats_row(grid, row++, "Received packets:", "      ");
   packets_drop   = stats_row(grid, row++, "Dropped packets:", "      ");
   packets_forw   = stats_row(grid, row++, "Forwarded packets:",
                              "       0  bytes:        0 ");
   queue_len      = stats_row(grid, row++, "Current queue length:", "0/0 ");
   sample_rate    = stats_row(grid, row++, "Sampling rate:", "0     ");
   recv_bottom    = stats_row(grid, row++, "Bottom Half received packet:",
                              "pck:        0  bytes:        0");
   recv_top       = stats_row(grid, row++, "Top Half received packet:",
                              "pck:        0  bytes:        0");
   interesting    = stats_row(grid, row++, "Interesting packets:", "0.00 %");
   rate_bottom    = stats_row(grid, row++, "Bottom Half packet rate:",
                              "worst:        0  adv:        0 b/s");
   rate_top       = stats_row(grid, row++, "Top Half packet rate:",
                              "worst:        0  adv:        0 b/s");
   through_bottom = stats_row(grid, row++, "Bottom Half throughput:",
                              "worst:        0  adv:        0 b/s");
   through_top    = stats_row(grid, row++, "Top Half throughput:",
                              "worst:        0  adv:        0 b/s");

   gtkui_page_present(stats_window);

   /* display the stats */
   refresh_stats(NULL);

   /* refresh the stats window every 200 ms */
   stats_idle = g_timeout_add(200, refresh_stats, NULL);
}

static void gtkui_stats_detach(GtkWidget *child)
{
   stats_window = gtk_window_new();
   gtk_window_set_title(GTK_WINDOW(stats_window), "Statistics");
   g_signal_connect(stats_window, "close-request",
         G_CALLBACK(gtkui_stop_stats), NULL);

   /* make <ctrl>d shortcut turn the window back into a tab */
   gtkui_page_attach_shortcut(stats_window, gtkui_stats_attach);

   gtk_window_set_child(GTK_WINDOW(stats_window), child);

   gtk_window_present(GTK_WINDOW(stats_window));
}

static void gtkui_stats_attach(void)
{
   gtkui_stop_stats();
   gtkui_show_stats(NULL, NULL, NULL);
}

static void gtkui_stop_stats(void)
{
   DEBUG_MSG("gtk_stop_stats");

   if (stats_idle != 0) {
      g_source_remove(stats_idle);
      stats_idle = 0;
   }

   if (stats_window == NULL)
      return;

   if (GTK_IS_WINDOW(stats_window))
      gtk_window_destroy(GTK_WINDOW(stats_window));
   else
      gtkui_page_close(stats_window, NULL);

   stats_window = NULL;
}

static gboolean refresh_stats(gpointer data)
{
   char line[50];

   (void) data;

   /*
    * If the window has gone, stop the timer -- and do it before touching
    * any of the labels. The GTK3 version tested gtk_widget_get_visible()
    * on stats_window without first checking it was still non-NULL.
    */
   if (stats_window == NULL)
      return FALSE;

   /* if not focused don't refresh it */
   if (!gtk_widget_get_visible(stats_window))
      return FALSE;

   snprintf(line, 50, "%8"PRIu64, EC_GBL_STATS->ps_recv);
   gtk_label_set_text(GTK_LABEL(packets_recv), line);

   snprintf(line, 50, "%8"PRIu64"  %.2f %%", EC_GBL_STATS->ps_drop,
         (EC_GBL_STATS->ps_recv)
            ? (float)EC_GBL_STATS->ps_drop * 100 / EC_GBL_STATS->ps_recv : 0);
   gtk_label_set_text(GTK_LABEL(packets_drop), line);

   snprintf(line, 50, "%8"PRIu64"  bytes: %8"PRIu64" ",
         EC_GBL_STATS->ps_sent, EC_GBL_STATS->bs_sent);
   gtk_label_set_text(GTK_LABEL(packets_forw), line);

   snprintf(line, 50, "%lu/%lu ", EC_GBL_STATS->queue_curr,
         EC_GBL_STATS->queue_max);
   gtk_label_set_text(GTK_LABEL(queue_len), line);

   snprintf(line, 50, "%d ", EC_GBL_CONF->sampling_rate);
   gtk_label_set_text(GTK_LABEL(sample_rate), line);

   snprintf(line, 50, "pck: %8"PRIu64"  bytes: %8"PRIu64,
         EC_GBL_STATS->bh.pck_recv, EC_GBL_STATS->bh.pck_size);
   gtk_label_set_text(GTK_LABEL(recv_bottom), line);

   snprintf(line, 50, "pck: %8"PRIu64"  bytes: %8"PRIu64,
         EC_GBL_STATS->th.pck_recv, EC_GBL_STATS->th.pck_size);
   gtk_label_set_text(GTK_LABEL(recv_top), line);

   snprintf(line, 50, "%.2f %%",
         (EC_GBL_STATS->bh.pck_recv)
            ? (float)EC_GBL_STATS->th.pck_recv * 100 / EC_GBL_STATS->bh.pck_recv
            : 0);
   gtk_label_set_text(GTK_LABEL(interesting), line);

   snprintf(line, 50, "worst: %8lu  adv: %8lu p/s",
         EC_GBL_STATS->bh.rate_worst, EC_GBL_STATS->bh.rate_adv);
   gtk_label_set_text(GTK_LABEL(rate_bottom), line);

   snprintf(line, 50, "worst: %8lu  adv: %8lu p/s",
         EC_GBL_STATS->th.rate_worst, EC_GBL_STATS->th.rate_adv);
   gtk_label_set_text(GTK_LABEL(rate_top), line);

   snprintf(line, 50, "worst: %8lu  adv: %8lu b/s",
         EC_GBL_STATS->bh.thru_worst, EC_GBL_STATS->bh.thru_adv);
   gtk_label_set_text(GTK_LABEL(through_bottom), line);

   snprintf(line, 50, "worst: %8lu  adv: %8lu b/s",
         EC_GBL_STATS->th.thru_worst, EC_GBL_STATS->th.thru_adv);
   gtk_label_set_text(GTK_LABEL(through_top), line);

   return TRUE;
}

/*******************************************/
/* visualization method                                                    */
/*******************************************/

/*
 * The visualization methods, in the order they are offered.
 *
 * The GTK3 code worked out which radio button was active by walking the
 * group list and counting -- then mapped that count to a name with a switch
 * whose cases ran 6,5,4,3,2,1 because GtkRadioButton prepends to its group.
 * Anyone inserting a method in the middle had to renumber the switch. The
 * table below is the order on screen and the order of the values; there is
 * no second numbering to keep in step.
 */
static const struct {
   const char *name;
   const char *description;
} vis_methods[] = {
   {"hex",    "Print the packets in hex format."},
   {"ascii",  "Print only \"printable\" characters, the others are displayed as dots '.'"},
   {"text",   "Print only the \"printable\" characters and skip the others."},
   {"ebcdic", "Convert an EBCDIC text to ASCII."},
   {"html",   "Strip all the html tags from the text. A tag is every string between < and >."},
   {"utf8",   "Convert the data from the encoding specified below to UTF8 before displaying it."},
};

#define VIS_UTF8_INDEX (G_N_ELEMENTS(vis_methods) - 1)

static const char *const encodings[] = {
   "UTF-8",
   "EBCDIC-US (IBM)",
   "ISO-8859-15 (Western Europe)",
   "ISO-8859-2 (Central Europe)",
   "ISO-8859-7 (Greek)",
   "ISO-8859-8 (Hebrew)",
   "ISO-8859-9 (Turkish)",
   "ISO-2022-JP (Japanese)",
   "SJIS (Japanese)",
   "CP949 (Korean)",
   "CP1251 (Cyrillic)",
   "CP1256 (Arabic)",
   "GB18030 (Chinese)",
   NULL
};

struct vis_ctx {
   GtkWidget *buttons[G_N_ELEMENTS(vis_methods)];
   GtkWidget *lang_combo;
};

static void on_vis_response(gboolean confirmed, gpointer data)
{
   struct vis_ctx *ctx = data;
   guint i, selected = 1; /* default: ascii */
   char encoding[50];

   if (!confirmed)
      return;

   for (i = 0; i < G_N_ELEMENTS(vis_methods); i++) {
      if (gtk_check_button_get_active(GTK_CHECK_BUTTON(ctx->buttons[i]))) {
         selected = i;
         break;
      }
   }

   memset(vmethod, 0, VLEN);

   if (selected == VIS_UTF8_INDEX) {
      GtkStringObject *obj = gtk_drop_down_get_selected_item(
            GTK_DROP_DOWN(ctx->lang_combo));
      const char *selected_lang =
         obj != NULL ? gtk_string_object_get_string(obj) : NULL;

      /* copy first word from encoding choice */
      if (selected_lang != NULL &&
          sscanf(selected_lang, "%49[^ ]", encoding) == 1 &&
          strlen(encoding) > 0) {
         strncpy(vmethod, "utf8", VLEN - 1);
         /* set_utf8_encoding takes u_char *; the cast was implicit (and
          * warned about) in the GTK3 original */
         set_utf8_encoding((u_char *)encoding);
         set_format(vmethod);
         return;
      }
      /* no usable encoding -- fall back to ascii, as the GTK3 code did */
      selected = 1;
   }

   strncpy(vmethod, vis_methods[selected].name, VLEN - 1);
   set_format(vmethod);
}

/*
 * change the visualization method
 */
void gtkui_vis_method(GSimpleAction *action, GVariant *value, gpointer data)
{
   struct vis_ctx *ctx;
   GtkWidget *vbox, *hbox, *label;
   GtkStringList *langs;
   const char *local_lang;
   char def_lang[75];
   guint i;

   (void) action;
   (void) value;
   (void) data;

   DEBUG_MSG("gtk_vis_method");

   SAFE_CALLOC(ctx, 1, sizeof(struct vis_ctx));

   vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);

   for (i = 0; i < G_N_ELEMENTS(vis_methods); i++) {
      ctx->buttons[i] = gtk_check_button_new_with_label(
            vis_methods[i].description);
      if (i > 0)
         gtk_check_button_set_group(GTK_CHECK_BUTTON(ctx->buttons[i]),
               GTK_CHECK_BUTTON(ctx->buttons[0]));
      if (!strcmp(vmethod, vis_methods[i].name))
         gtk_check_button_set_active(GTK_CHECK_BUTTON(ctx->buttons[i]), TRUE);
      gtk_box_append(GTK_BOX(vbox), ctx->buttons[i]);
   }

   /*
    * GtkDropDown over a GtkStringList replaces the GtkComboBox +
    * GtkListStore + GtkCellRendererText + cell-layout wiring the GTK3 code
    * needed for what is, in the end, a list of strings.
    */
   langs = gtk_string_list_new(encodings);

   /* the system's default encoding first, if it is not already UTF-8 */
   if (!g_get_charset(&local_lang)) {
      snprintf(def_lang, sizeof(def_lang), "%s (System Default)", local_lang);
      gtk_string_list_splice(langs, 0, 0, (const char *[]){def_lang, NULL});
   }

   ctx->lang_combo = gtk_drop_down_new(G_LIST_MODEL(langs), NULL);
   gtk_drop_down_set_selected(GTK_DROP_DOWN(ctx->lang_combo), 0);
   gtk_widget_set_hexpand(ctx->lang_combo, TRUE);

   hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
   label = gtk_label_new("Character encoding : ");
   gtk_box_append(GTK_BOX(hbox), label);
   gtk_box_append(GTK_BOX(hbox), ctx->lang_combo);
   gtk_box_append(GTK_BOX(vbox), hbox);

   gtkui_dialog_confirm("Visualization method...", NULL, vbox,
         on_vis_response, ctx, g_free);
}

/*******************************************/

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
