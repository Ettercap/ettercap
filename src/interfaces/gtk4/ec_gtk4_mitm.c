/*
    ettercap -- GTK4 GUI -- MITM attack dialogs

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
#include <ec_mitm.h>

/* globals */
#define PARAMS_LEN 512
static char params[PARAMS_LEN + 1];

/* proto */
static void gtkui_start_mitm(void);

/*
 * The five attack dialogs came in two shapes under GTK3, each repeated with
 * only its labels changed:
 *
 *   - two check boxes whose states select words in a parameter string
 *     (ARP, port stealing, NDP)
 *   - a short grid of entries concatenated into a parameter string
 *     (ICMP redirect, DHCP spoofing)
 *
 * Both are captured once here. Each dialog builds its widgets, then hands a
 * small context to gtkui_dialog_confirm() and assembles `params` in the
 * response callback -- the async replacement for the gtk_dialog_run() the
 * GTK3 code blocked on.
 */

/*******************************************/
/* two-checkbox attacks                                                    */
/*******************************************/

struct toggle_ctx {
   const char *prefix;   /* "arp", "port", "ndp" */
   const char *word1;    /* word contributed by button1 when active */
   const char *word2;    /* word contributed by button2 when active */
   GtkWidget *button1;
   GtkWidget *button2;
};

static void on_toggle_response(gboolean confirmed, gpointer data)
{
   struct toggle_ctx *ctx = data;
   const char *w1 = "", *comma = "", *w2 = "";

   if (!confirmed)
      return;

   if (gtk_check_button_get_active(GTK_CHECK_BUTTON(ctx->button1)))
      w1 = ctx->word1;

   if (gtk_check_button_get_active(GTK_CHECK_BUTTON(ctx->button2))) {
      if (*w1 != '\0')
         comma = ",";
      w2 = ctx->word2;
   }

   snprintf(params, PARAMS_LEN + 1, "%s:%s%s%s", ctx->prefix, w1, comma, w2);
   gtkui_start_mitm();
}

static void toggle_attack(const char *title, const char *prefix,
      const char *label1, const char *word1, gboolean default1,
      const char *label2, const char *word2)
{
   struct toggle_ctx *ctx;
   GtkWidget *box;

   SAFE_CALLOC(ctx, 1, sizeof(struct toggle_ctx));
   ctx->prefix = prefix;
   ctx->word1 = word1;
   ctx->word2 = word2;

   ctx->button1 = gtk_check_button_new_with_label(label1);
   gtk_check_button_set_active(GTK_CHECK_BUTTON(ctx->button1), default1);
   ctx->button2 = gtk_check_button_new_with_label(label2);

   box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
   gtk_box_append(GTK_BOX(box), ctx->button1);
   gtk_box_append(GTK_BOX(box), ctx->button2);

   gtkui_dialog_confirm(title, "Optional parameters", box,
         on_toggle_response, ctx, g_free);
}

void gtkui_arp_poisoning(GSimpleAction *action, GVariant *value, gpointer data)
{
   (void) action;
   (void) value;
   (void) data;

   DEBUG_MSG("gtk_arp_poisoning");

   toggle_attack("MITM Attack: ARP Poisoning", "arp",
         "Sniff remote connections.", "remote", TRUE,
         "Only poison one-way.", "oneway");
}

void gtkui_port_stealing(GSimpleAction *action, GVariant *value, gpointer data)
{
   (void) action;
   (void) value;
   (void) data;

   DEBUG_MSG("gtk_port_stealing");

   toggle_attack("MITM Attack: Port Stealing", "port",
         "Sniff remote connections.", "remote", FALSE,
         "Propagate to other switches.", "tree");
}

#ifdef WITH_IPV6
void gtkui_ndp_poisoning(GSimpleAction *action, GVariant *value, gpointer data)
{
   (void) action;
   (void) value;
   (void) data;

   DEBUG_MSG("gtk_ndp_poisoning");

   toggle_attack("MITM Attack: NDP Poisoning", "ndp",
         "Sniff remote connections.", "remote", TRUE,
         "Only poison one-way.", "oneway");
}
#endif

/*******************************************/
/* entry-grid attacks                                                      */
/*******************************************/

struct fields_ctx {
   const char *prefix;
   guint n;
   GtkWidget *entries[3];
};

static void on_fields_response(gboolean confirmed, gpointer data)
{
   struct fields_ctx *ctx = data;
   const char *v[3] = { "", "", "" };
   guint i;

   if (!confirmed)
      return;

   for (i = 0; i < ctx->n; i++)
      v[i] = gtk_editable_get_text(GTK_EDITABLE(ctx->entries[i]));

   /* the fields are joined with '/', matching the mitm parameter grammar */
   if (ctx->n == 2)
      snprintf(params, PARAMS_LEN + 1, "%s:%s/%s", ctx->prefix, v[0], v[1]);
   else
      snprintf(params, PARAMS_LEN + 1, "%s:%s/%s/%s", ctx->prefix,
            v[0], v[1], v[2]);

   gtkui_start_mitm();
}

static GtkWidget *fields_grid(struct fields_ctx *ctx, const char *const *labels,
      const int *maxlen, guint n)
{
   GtkWidget *grid;
   guint i;

   grid = gtk_grid_new();
   gtk_grid_set_row_spacing(GTK_GRID(grid), 5);
   gtk_grid_set_column_spacing(GTK_GRID(grid), 5);
   gtk_widget_set_margin_top(grid, 8);
   gtk_widget_set_margin_bottom(grid, 8);
   gtk_widget_set_margin_start(grid, 8);
   gtk_widget_set_margin_end(grid, 8);

   ctx->n = n;
   for (i = 0; i < n; i++) {
      GtkWidget *label = gtk_label_new(labels[i]);
      gtk_widget_set_halign(label, GTK_ALIGN_START);
      gtk_grid_attach(GTK_GRID(grid), label, 0, i, 1, 1);

      ctx->entries[i] = gtk_entry_new();
      if (maxlen[i] > 0)
         gtk_entry_set_max_length(GTK_ENTRY(ctx->entries[i]), maxlen[i]);
      gtk_grid_attach(GTK_GRID(grid), ctx->entries[i], 1, i, 1, 1);
   }

   return grid;
}

void gtkui_icmp_redir(GSimpleAction *action, GVariant *value, gpointer data)
{
   struct fields_ctx *ctx;
   GtkWidget *grid;
   const char *labels[] = { "MAC Address", "IP Address" };
   const int maxlen[] = { ETH_ASCII_ADDR_LEN, IP6_ASCII_ADDR_LEN };

   (void) action;
   (void) value;
   (void) data;

   DEBUG_MSG("gtk_icmp_redir");

   SAFE_CALLOC(ctx, 1, sizeof(struct fields_ctx));
   ctx->prefix = "icmp";
   grid = fields_grid(ctx, labels, maxlen, 2);

   gtkui_dialog_confirm("MITM Attack: ICMP Redirect", "Gateway Information",
         grid, on_fields_response, ctx, g_free);
}

void gtkui_dhcp_spoofing(GSimpleAction *action, GVariant *value, gpointer data)
{
   struct fields_ctx *ctx;
   GtkWidget *grid;
   const char *labels[] = { "IP Pool (optional)", "Netmask", "DNS Server IP" };
   const int maxlen[] = { 0, IP6_ASCII_ADDR_LEN, IP6_ASCII_ADDR_LEN };

   (void) action;
   (void) value;
   (void) data;

   DEBUG_MSG("gtk_dhcp_spoofing");

   SAFE_CALLOC(ctx, 1, sizeof(struct fields_ctx));
   ctx->prefix = "dhcp";
   grid = fields_grid(ctx, labels, maxlen, 3);

   gtkui_dialog_confirm("MITM Attack: DHCP Spoofing", "Server Information",
         grid, on_fields_response, ctx, g_free);
}

/*******************************************/

/*
 * start the mitm attack by passing the name and parameters
 */
static void gtkui_start_mitm(void)
{
   DEBUG_MSG("gtk_start_mitm");

   mitm_set(params);
   mitm_start();
}

/*
 * stop all the mitm attack(s)
 *
 * The GTK3 version put up a "Stopping..." dialog and then hand-pumped the
 * main loop with gtk_events_pending()/gtk_main_iteration() so the dialog
 * would paint before the blocking mitm_stop() ran. GTK4 removed both -- and
 * reentering the loop from a handler was always fragile. mitm_stop() is
 * quick enough that a toast afterward is the honest report; there is no work
 * to show progress for.
 */
void gtkui_mitm_stop(GSimpleAction *action, GVariant *value, gpointer data)
{
   (void) action;
   (void) value;
   (void) data;

   DEBUG_MSG("gtk_mitm_stop");

   mitm_stop();

   gtkui_message("MITM attack(s) stopped");
}

/* EOF */

// vim:ts=3:expandtab
