/*
    ettercap -- GTK4 GUI -- collected passive profiles

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
#include <ec_profiles.h>
#include <ec_manuf.h>
#include <ec_services.h>
#include <ec_geoip.h>

/* proto */
static void gtkui_profiles_detach(GtkWidget *child);
static void gtkui_profiles_attach(void);
static void gtkui_kill_profiles(void);
static gboolean refresh_profiles(gpointer data);
static void gtkui_profile_detail(void);
static void gtkui_profiles_local(void);
static void gtkui_profiles_remote(void);
static void gtkui_profiles_convert(void);
static void gtkui_profiles_dump(void);
static void dump_profiles(void);
static struct host_profile *gtkui_profile_selected(void);

/* globals */
static char *logfile = NULL;
static GtkWidget  *profiles_window = NULL;
static GtkWidget  *profiles_view = NULL;
static GListStore *ls_profiles = NULL;      /* of EcProfileItem */
static GtkSingleSelection *profiles_selection = NULL;
static guint profiles_idle;

/*******************************************/
/* EcProfileItem                                                           */
/*******************************************/

#define EC_TYPE_PROFILE_ITEM (ec_profile_item_get_type())
G_DECLARE_FINAL_TYPE(EcProfileItem, ec_profile_item, EC, PROFILE_ITEM, GObject)

struct _EcProfileItem {
   GObject parent_instance;
   char *active;
   char *ip;
   char *name;
   char *country;
   struct host_profile *hp;   /* the profile this row tracks; not owned */
};

G_DEFINE_FINAL_TYPE(EcProfileItem, ec_profile_item, G_TYPE_OBJECT)

enum { PPROP_0, PPROP_ACTIVE, PPROP_IP, PPROP_NAME, PPROP_COUNTRY, N_PPROPS };
static GParamSpec *profile_props[N_PPROPS];

static void ec_profile_item_finalize(GObject *object)
{
   EcProfileItem *self = EC_PROFILE_ITEM(object);

   g_free(self->active);
   g_free(self->ip);
   g_free(self->name);
   g_free(self->country);

   G_OBJECT_CLASS(ec_profile_item_parent_class)->finalize(object);
}

static void ec_profile_item_get_property(GObject *object, guint id,
      GValue *value, GParamSpec *pspec)
{
   EcProfileItem *self = EC_PROFILE_ITEM(object);

   switch (id) {
      case PPROP_ACTIVE:  g_value_set_string(value, self->active); break;
      case PPROP_IP:      g_value_set_string(value, self->ip); break;
      case PPROP_NAME:    g_value_set_string(value, self->name); break;
      case PPROP_COUNTRY: g_value_set_string(value, self->country); break;
      default: G_OBJECT_WARN_INVALID_PROPERTY_ID(object, id, pspec);
   }
}

static void ec_profile_item_set_property(GObject *object, guint id,
      const GValue *value, GParamSpec *pspec)
{
   EcProfileItem *self = EC_PROFILE_ITEM(object);
   char **field;

   switch (id) {
      case PPROP_ACTIVE:  field = &self->active; break;
      case PPROP_IP:      field = &self->ip; break;
      case PPROP_NAME:    field = &self->name; break;
      case PPROP_COUNTRY: field = &self->country; break;
      default: G_OBJECT_WARN_INVALID_PROPERTY_ID(object, id, pspec); return;
   }

   g_free(*field);
   *field = g_value_dup_string(value);
}

static void ec_profile_item_class_init(EcProfileItemClass *klass)
{
   GObjectClass *object_class = G_OBJECT_CLASS(klass);

   object_class->finalize = ec_profile_item_finalize;
   object_class->get_property = ec_profile_item_get_property;
   object_class->set_property = ec_profile_item_set_property;

   profile_props[PPROP_ACTIVE] = g_param_spec_string("active", NULL, NULL,
         NULL, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS);
   profile_props[PPROP_IP] = g_param_spec_string("ip", NULL, NULL, NULL,
         G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS);
   profile_props[PPROP_NAME] = g_param_spec_string("name", NULL, NULL, NULL,
         G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS);
   profile_props[PPROP_COUNTRY] = g_param_spec_string("country", NULL, NULL,
         NULL, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS);

   g_object_class_install_properties(object_class, N_PPROPS, profile_props);
}

static void ec_profile_item_init(EcProfileItem *self)
{
   (void) self;
}

/*******************************************/
/* column view                                                             */
/*******************************************/

static void on_prof_setup(GtkListItemFactory *factory, GtkListItem *item,
      gpointer data)
{
   GtkWidget *label = gtk_label_new(NULL);

   (void) factory;
   (void) data;

   gtk_label_set_xalign(GTK_LABEL(label), 0.0);
   gtk_list_item_set_child(item, label);
}

static void on_prof_bind(GtkListItemFactory *factory, GtkListItem *item,
      gpointer data)
{
   const char *property = data;
   GtkWidget *label = gtk_list_item_get_child(item);
   GObject *obj = gtk_list_item_get_item(item);
   GBinding *binding;

   (void) factory;

   if (obj == NULL || label == NULL)
      return;

   binding = g_object_bind_property(obj, property, label, "label",
         G_BINDING_SYNC_CREATE);
   g_object_set_data(G_OBJECT(item), "binding", binding);
}

static void on_prof_unbind(GtkListItemFactory *factory, GtkListItem *item,
      gpointer data)
{
   GBinding *binding = g_object_get_data(G_OBJECT(item), "binding");

   (void) factory;
   (void) data;

   if (binding != NULL) {
      g_binding_unbind(binding);
      g_object_set_data(G_OBJECT(item), "binding", NULL);
   }
}

static void add_prof_column(GtkColumnView *view, const char *title,
      const char *property, gboolean expand)
{
   GtkListItemFactory *factory;
   GtkColumnViewColumn *column;
   GtkExpression *expression;
   GtkSorter *sorter;

   factory = gtk_signal_list_item_factory_new();
   g_signal_connect(factory, "setup", G_CALLBACK(on_prof_setup), NULL);
   g_signal_connect(factory, "bind", G_CALLBACK(on_prof_bind),
         (gpointer)property);
   g_signal_connect(factory, "unbind", G_CALLBACK(on_prof_unbind), NULL);

   column = gtk_column_view_column_new(title, factory);
   gtk_column_view_column_set_resizable(column, TRUE);
   gtk_column_view_column_set_expand(column, expand);

   expression = gtk_property_expression_new(EC_TYPE_PROFILE_ITEM, NULL,
         property);
   sorter = GTK_SORTER(gtk_string_sorter_new(expression));
   gtk_column_view_column_set_sorter(column, sorter);
   g_object_unref(sorter);

   gtk_column_view_append_column(view, column);
   g_object_unref(column);
}

/*******************************************/

/*
 * the auto-refreshing list of profiles
 */
void gtkui_show_profiles(GSimpleAction *action, GVariant *value, gpointer data)
{
   GtkWidget *scrolled, *vbox, *hbox, *button, *popover;
   GtkGesture *gesture;
   GSimpleActionGroup *actions;
   GMenu *menu;

   (void) action;
   (void) value;
   (void) data;

   DEBUG_MSG("gtk_show_profiles");

   if (profiles_window) {
      if (GTK_IS_WINDOW(profiles_window))
         gtk_window_present(GTK_WINDOW(profiles_window));
      else
         gtkui_page_present(profiles_window);
      return;
   }

   profiles_window = gtkui_page_new("Profiles", &gtkui_kill_profiles,
         &gtkui_profiles_detach);

   vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
   gtk_widget_set_vexpand(vbox, TRUE);
   gtk_box_append(GTK_BOX(profiles_window), vbox);

   refresh_profiles(NULL);

   profiles_view = gtk_column_view_new(NULL);
   profiles_selection = gtk_single_selection_new(
         G_LIST_MODEL(g_object_ref(ls_profiles)));
   gtk_column_view_set_model(GTK_COLUMN_VIEW(profiles_view),
         GTK_SELECTION_MODEL(profiles_selection));

   add_prof_column(GTK_COLUMN_VIEW(profiles_view), " ", "active", FALSE);
   add_prof_column(GTK_COLUMN_VIEW(profiles_view), "IP Address", "ip", FALSE);
   add_prof_column(GTK_COLUMN_VIEW(profiles_view), "Hostname", "name", TRUE);
#ifdef HAVE_GEOIP
   add_prof_column(GTK_COLUMN_VIEW(profiles_view), "Country", "country", FALSE);
#endif

   g_signal_connect(profiles_view, "activate",
         G_CALLBACK(gtkui_profile_detail), NULL);

   scrolled = gtk_scrolled_window_new();
   gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled),
         GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
   gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scrolled), profiles_view);
   gtk_widget_set_vexpand(scrolled, TRUE);
   gtk_box_append(GTK_BOX(vbox), scrolled);

   /* buttons */
   hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
   gtk_widget_set_margin_top(hbox, 6);
   gtk_widget_set_margin_bottom(hbox, 6);
   gtk_widget_set_margin_start(hbox, 6);
   gtk_widget_set_margin_end(hbox, 6);
   gtk_box_append(GTK_BOX(vbox), hbox);

   button = gtk_button_new_with_mnemonic("Purge _Local");
   gtk_widget_set_hexpand(button, TRUE);
   g_signal_connect(button, "clicked",
         G_CALLBACK(gtkui_profiles_local), NULL);
   gtk_box_append(GTK_BOX(hbox), button);

   button = gtk_button_new_with_mnemonic("Purge _Remote");
   gtk_widget_set_hexpand(button, TRUE);
   g_signal_connect(button, "clicked",
         G_CALLBACK(gtkui_profiles_remote), NULL);
   gtk_box_append(GTK_BOX(hbox), button);

   button = gtk_button_new_with_mnemonic("_Convert to Host List");
   gtk_widget_set_hexpand(button, TRUE);
   g_signal_connect(button, "clicked",
         G_CALLBACK(gtkui_profiles_convert), NULL);
   gtk_box_append(GTK_BOX(hbox), button);

   button = gtk_button_new_with_mnemonic("_Dump to File");
   gtk_widget_set_hexpand(button, TRUE);
   g_signal_connect_swapped(button, "clicked",
         G_CALLBACK(gtkui_profiles_dump), NULL);
   gtk_box_append(GTK_BOX(hbox), button);

   /*
    * context menu: gtkui_profile_detail takes no arguments, so its action
    * is connected swapped rather than cast into a GActionEntry slot (which
    * would be undefined behaviour)
    */
   actions = g_simple_action_group_new();
   {
      GSimpleAction *a = g_simple_action_new("detail", NULL);
      g_signal_connect_swapped(a, "activate",
            G_CALLBACK(gtkui_profile_detail), NULL);
      g_action_map_add_action(G_ACTION_MAP(actions), G_ACTION(a));
      g_object_unref(a);
   }
   gtk_widget_insert_action_group(profiles_view, "profile",
         G_ACTION_GROUP(actions));

   menu = g_menu_new();
   g_menu_append(menu, "Profile Details", "profile.detail");
   popover = gtk_popover_menu_new_from_model(G_MENU_MODEL(menu));
   gtk_widget_set_parent(popover, profiles_view);
   gtk_popover_set_has_arrow(GTK_POPOVER(popover), FALSE);
   gtk_widget_set_halign(popover, GTK_ALIGN_START);

   gesture = gtk_gesture_click_new();
   gtk_gesture_single_set_button(GTK_GESTURE_SINGLE(gesture),
         GDK_BUTTON_SECONDARY);
   g_signal_connect_swapped(gesture, "pressed",
         G_CALLBACK(gtk_popover_popup), popover);
   gtk_widget_add_controller(profiles_view, GTK_EVENT_CONTROLLER(gesture));

   g_object_unref(actions);
   g_object_unref(menu);

   /* refresh the list every 1000 ms */
   profiles_idle = g_timeout_add(1000, refresh_profiles, NULL);

   gtkui_page_present(profiles_window);
}

static void gtkui_profiles_detach(GtkWidget *child)
{
   profiles_window = gtk_window_new();
   gtk_window_set_title(GTK_WINDOW(profiles_window),
         "Collected passive profiles");
   gtk_window_set_default_size(GTK_WINDOW(profiles_window), 400, 300);
   g_signal_connect(profiles_window, "close-request",
         G_CALLBACK(gtkui_kill_profiles), NULL);

   gtkui_page_attach_shortcut(profiles_window, gtkui_profiles_attach);

   gtk_window_set_child(GTK_WINDOW(profiles_window), child);

   gtk_window_present(GTK_WINDOW(profiles_window));
}

static void gtkui_profiles_attach(void)
{
   gtkui_kill_profiles();
   gtkui_show_profiles(NULL, NULL, NULL);
}

static void gtkui_kill_profiles(void)
{
   DEBUG_MSG("gtk_kill_profiles");

   if (profiles_idle != 0) {
      g_source_remove(profiles_idle);
      profiles_idle = 0;
   }

   if (profiles_window == NULL)
      return;

   if (GTK_IS_WINDOW(profiles_window))
      gtk_window_destroy(GTK_WINDOW(profiles_window));
   else
      gtkui_page_close(profiles_window, NULL);

   profiles_window = NULL;
   profiles_view = NULL;
   profiles_selection = NULL;
}

/*
 * Find the row already tracking a given profile, or NULL.
 */
static EcProfileItem *find_profile_item(struct host_profile *hp)
{
   guint i, n = g_list_model_get_n_items(G_LIST_MODEL(ls_profiles));

   for (i = 0; i < n; i++) {
      EcProfileItem *item = g_list_model_get_item(G_LIST_MODEL(ls_profiles), i);
      gboolean match = (item->hp == hp);
      g_object_unref(item);
      if (match)
         return g_list_model_get_item(G_LIST_MODEL(ls_profiles), i);
   }

   return NULL;
}

static gboolean profile_has_account(struct host_profile *hp)
{
   struct open_port *o;
   struct active_user *u;

   LIST_FOREACH(o, &hp->open_ports_head, next)
      LIST_FOREACH(u, &o->users_list_head, next)
         return TRUE;

   return FALSE;
}

/*
 * Fill in the hostname column, resolving in the background if needed.
 */
static void set_profile_hostname(EcProfileItem *item, struct host_profile *hp)
{
   char name[MAX_HOSTNAME_LEN];

   if (strcmp(hp->hostname, "")) {
      g_object_set(item, "name", hp->hostname, NULL);
      return;
   }

   if (host_iptoa(&hp->L3_addr, name) == -E_NOMATCH) {
      struct resolv_object *ro;

      g_object_set(item, "name", "resolving...", NULL);

      SAFE_CALLOC(ro, 1, sizeof(struct resolv_object));
      ro->item = g_object_ref(G_OBJECT(item));
      ro->property = "name";
      ro->ip = &hp->L3_addr;
      g_timeout_add(1000, gtkui_iptoa_deferred, ro);
   } else {
      strncpy(hp->hostname, name, MAX_HOSTNAME_LEN - 1);
      hp->hostname[MAX_HOSTNAME_LEN - 1] = '\0';
      g_object_set(item, "name", hp->hostname, NULL);
   }
}

/*
 * Reconcile the list model with EC_GBL_PROFILES.
 *
 * Kept as a reconcile rather than a rebuild -- exactly as the GTK3 code did,
 * and for the same reason -- so the selection and scroll position survive
 * the once-a-second refresh. Existing rows are updated in place; new
 * profiles are appended.
 */
static gboolean refresh_profiles(gpointer data)
{
   struct host_profile *hcurr;
   char tmp[MAX_ASCII_ADDR_LEN];
#ifdef HAVE_GEOIP
   char country[MAX_GEOIP_STR_LEN];
#endif

   (void) data;

   if (ls_profiles == NULL)
      ls_profiles = g_list_store_new(EC_TYPE_PROFILE_ITEM);

   TAILQ_FOREACH(hcurr, &EC_GBL_PROFILES, next) {
      EcProfileItem *item = find_profile_item(hcurr);
      gboolean found = profile_has_account(hcurr);

      if (item != NULL) {
         /* update in place */
         g_object_set(item, "active", found ? "X" : " ", NULL);
         set_profile_hostname(item, hcurr);
         g_object_unref(item);
         continue;
      }

      /* otherwise, add a new row */
      item = g_object_new(EC_TYPE_PROFILE_ITEM, NULL);
      item->hp = hcurr;
      item->active = g_strdup(found ? "X" : " ");
      item->ip = g_strdup(ip_addr_ntoa(&hcurr->L3_addr, tmp));
      item->name = g_strdup("");
      item->country = g_strdup("");

#ifdef HAVE_GEOIP
      if (EC_GBL_CONF->geoip_support_enable) {
         g_free(item->country);
         item->country = g_strdup(geoip_get_by_ip(&hcurr->L3_addr,
               GEOIP_CNAME, country, MAX_GEOIP_STR_LEN));
      }
#endif

      g_list_store_append(ls_profiles, item);
      set_profile_hostname(item, hcurr);
      g_object_unref(item);
   }

   return TRUE;
}

/*******************************************/
/* detail dialog                                                           */
/*******************************************/

/*
 * A grid that fills itself down its rows. The GTK3 code tracked `row`
 * by hand through ~200 lines; a tiny helper keeps the attach calls honest.
 */
struct detail_grid {
   GtkWidget *grid;
   int row;
};

static void detail_heading(struct detail_grid *g, const char *text)
{
   GtkWidget *label = gtk_label_new(NULL);
   char *markup = g_markup_printf_escaped("<span weight=\"bold\">%s</span>",
         text);

   gtk_label_set_markup(GTK_LABEL(label), markup);
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_widget_set_margin_top(label, 10);
   gtk_grid_attach(GTK_GRID(g->grid), label, 0, g->row++, 3, 1);
   g_free(markup);
}

static GtkWidget *detail_field(struct detail_grid *g, const char *caption,
      const char *value)
{
   GtkWidget *label;

   label = gtk_label_new(caption);
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(g->grid), label, 0, g->row, 1, 1);

   label = gtk_label_new(value);
   gtk_label_set_selectable(GTK_LABEL(label), TRUE);
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(g->grid), label, 1, g->row, 2, 1);

   g->row++;
   return label;
}

static void gtkui_profile_detail(void)
{
   AdwDialog *dialog;
   GtkWidget *toolbar, *header, *scrolled;
   struct detail_grid g;
   struct host_profile *h;
   struct open_port *o;
   struct active_user *u;
   char tmp[MAX_ASCII_ADDR_LEN];
   char os[OS_LEN + 1];
   char *str;
#ifdef HAVE_GEOIP
   char country[MAX_GEOIP_STR_LEN];
#endif

   DEBUG_MSG("gtkui_profile_detail");

   h = gtkui_profile_selected();
   if (h == NULL)
      return;

   memset(os, 0, sizeof(os));

   g.grid = gtk_grid_new();
   g.row = 0;
   gtk_grid_set_row_spacing(GTK_GRID(g.grid), 5);
   gtk_grid_set_column_spacing(GTK_GRID(g.grid), 5);
   gtk_widget_set_margin_top(g.grid, 8);
   gtk_widget_set_margin_bottom(g.grid, 8);
   gtk_widget_set_margin_start(g.grid, 8);
   gtk_widget_set_margin_end(g.grid, 8);

   /* Host Information */
   detail_heading(&g, "Host Information:");
   detail_field(&g, "IP address:", ip_addr_ntoa(&h->L3_addr, tmp));

   if (EC_GBL_OPTIONS->resolve) {
      GtkWidget *name_label = detail_field(&g, "Hostname:", h->hostname);

      if (!strcmp(h->hostname, "")) {
         if (host_iptoa(&h->L3_addr, h->hostname) == -E_NOMATCH) {
            struct resolv_object *ro;

            gtk_label_set_text(GTK_LABEL(name_label), "resolving...");

            /*
             * A GtkLabel is a GObject with a "label" property, so the same
             * deferred-resolution helper the list views use fills it in --
             * no separate label-versus-store code path, which is what the
             * GTK3 resolv_object carried a `type` field to switch on.
             * Holding a reference keeps the label alive even if the dialog
             * is closed before resolution completes.
             */
            SAFE_CALLOC(ro, 1, sizeof(struct resolv_object));
            ro->item = g_object_ref(G_OBJECT(name_label));
            ro->property = "label";
            ro->ip = &h->L3_addr;
            g_timeout_add(1000, gtkui_iptoa_deferred, ro);
         }
      }
   }

#ifdef HAVE_GEOIP
   if (EC_GBL_CONF->geoip_support_enable)
      detail_field(&g, "Location:",
            geoip_get_by_ip(&h->L3_addr, GEOIP_CNAME, country,
               MAX_GEOIP_STR_LEN));
#endif

   if (h->type & FP_HOST_LOCAL || h->type == FP_UNKNOWN) {
      detail_field(&g, "MAC address:", mac_addr_ntoa(h->L2_addr, tmp));
      detail_field(&g, "Manufacturer:", manuf_search((const char *)h->L2_addr));
   }

   /* Connectivity information */
   detail_heading(&g, "Connectivity Information:");

   str = g_strdup_printf("%d", h->distance);
   detail_field(&g, "Distance:", str);
   g_free(str);

   {
      const char *type = "unknown";

      if (h->type & FP_GATEWAY)            type = "GATEWAY";
      else if (h->type & FP_HOST_LOCAL)    type = "LAN host";
      else if (h->type & FP_ROUTER)        type = "REMOTE ROUTER";
      else if (h->type & FP_HOST_NONLOCAL) type = "REMOTE host";

      detail_field(&g, "Type:", type);
   }

   /* OS and service information */
   detail_heading(&g, "OS and Service Information:");

   if (h->os)
      detail_field(&g, "Observed OS:", h->os);

   detail_field(&g, "Fingerprint:", (const char *)h->fingerprint);

   /*
    * The GTK3 code had a bug here: the `if (fingerprint_search(...) ==
    * E_SUCCESS)` block created the OS label and then unconditionally
    * overwrote it with the "unknown fingerprint" string -- and there was no
    * else branch, so a matched fingerprint was reported as unknown. Restored
    * to the evident intent: the match on success, the nearest on failure.
    */
   if (fingerprint_search((const char *)h->fingerprint, os) == E_SUCCESS) {
      detail_field(&g, "Operating System:", os);
   } else {
      str = g_strdup_printf(
            "unknown fingerprint (please submit it)\nNearest one is: %s", os);
      detail_field(&g, "Operating System:", str);
      g_free(str);
   }

   LIST_FOREACH(o, &h->open_ports_head, next) {
      str = g_strdup_printf("%s %d",
            (o->L4_proto == NL_TYPE_TCP) ? "TCP" : "UDP", ntohs(o->L4_addr));
      {
         GtkWidget *label = gtk_label_new("Port:");
         gtk_widget_set_halign(label, GTK_ALIGN_START);
         gtk_grid_attach(GTK_GRID(g.grid), label, 0, g.row, 1, 1);

         label = gtk_label_new(str);
         gtk_label_set_selectable(GTK_LABEL(label), TRUE);
         gtk_widget_set_halign(label, GTK_ALIGN_START);
         gtk_grid_attach(GTK_GRID(g.grid), label, 1, g.row, 1, 1);
      }
      g_free(str);

      str = g_strdup_printf("%s [%s]",
            service_search(o->L4_addr, o->L4_proto),
            (o->banner) ? o->banner : "");
      {
         GtkWidget *label = gtk_label_new(str);
         gtk_label_set_selectable(GTK_LABEL(label), TRUE);
         gtk_widget_set_halign(label, GTK_ALIGN_START);
         gtk_grid_attach(GTK_GRID(g.grid), label, 2, g.row, 1, 1);
      }
      g_free(str);
      g.row++;

      LIST_FOREACH(u, &o->users_list_head, next) {
         detail_field(&g, u->failed ? "Account: *" : "Account:",
               (str = g_strdup_printf("%s / %s (%s)", u->user, u->pass,
                  ip_addr_ntoa(&u->client, tmp))));
         g_free(str);

         if (u->info)
            detail_field(&g, "Info:", u->info);
      }
   }

   scrolled = gtk_scrolled_window_new();
   gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled),
         GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
   gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scrolled), g.grid);
   gtk_widget_set_vexpand(scrolled, TRUE);

   header = adw_header_bar_new();
   adw_header_bar_set_title_widget(ADW_HEADER_BAR(header),
         adw_window_title_new("Profile Details", NULL));

   toolbar = adw_toolbar_view_new();
   adw_toolbar_view_add_top_bar(ADW_TOOLBAR_VIEW(toolbar), header);
   adw_toolbar_view_set_content(ADW_TOOLBAR_VIEW(toolbar), scrolled);

   dialog = adw_dialog_new();
   adw_dialog_set_title(dialog, "Profile Details");
   adw_dialog_set_content_width(dialog, 500);
   adw_dialog_set_content_height(dialog, 500);
   adw_dialog_set_child(dialog, toolbar);

   adw_dialog_present(dialog, window);
}

/*******************************************/

static void gtkui_profiles_local(void)
{
   profile_purge_local();
   if (ls_profiles)
      g_list_store_remove_all(ls_profiles);
}

static void gtkui_profiles_remote(void)
{
   profile_purge_remote();
   if (ls_profiles)
      g_list_store_remove_all(ls_profiles);
}

static void gtkui_profiles_convert(void)
{
   profile_convert_to_hostlist();
   gtkui_refresh_host_list(NULL);
   gtkui_message("The hosts list was populated with local profiles");
}

static void gtkui_profiles_dump(void)
{
   DEBUG_MSG("gtkui_profiles_dump");

   /* make sure to free if already set */
   SAFE_FREE(logfile);
   SAFE_CALLOC(logfile, 50, sizeof(char));

   gtkui_input("Log File :", logfile, 50, dump_profiles);
}

static void dump_profiles(void)
{
   /* dump the profiles */
   if (profile_dump_to_file(logfile) == E_SUCCESS)
      gtkui_message("Profiles dumped to file");
}

static struct host_profile *gtkui_profile_selected(void)
{
   EcProfileItem *item;

   if (profiles_selection == NULL)
      return NULL;

   item = gtk_single_selection_get_selected_item(profiles_selection);
   return item != NULL ? item->hp : NULL;
}

/* EOF */

// vim:ts=3:expandtab
