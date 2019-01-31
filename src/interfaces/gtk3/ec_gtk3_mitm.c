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
#include <ec_mitm.h>

/* proto */

static void gtkui_start_mitm(void);

/* globals */

#define PARAMS_LEN   512

static char params[PARAMS_LEN+1];

/*******************************************/

void gtkui_arp_poisoning(GSimpleAction *action, GVariant *value, gpointer data)
{
   GtkWidget *dialog, *vbox, *hbox, *image, *button1, *button2, *frame, *content_area;
   gint response = 0;
   gboolean remote = FALSE;

   (void) action;
   (void) value;
   (void) data;

   DEBUG_MSG("gtk_arp_poisoning");
//   not needed, the \0 is already appended from snprintf
//   memset(params, '\0', PARAMS_LEN+1);

   dialog = gtk_dialog_new_with_buttons("MITM Attack: ARP Poisoning", 
         GTK_WINDOW (window), 
         GTK_DIALOG_MODAL|GTK_DIALOG_USE_HEADER_BAR, 
         "_Cancel", GTK_RESPONSE_CANCEL, 
         "_OK",     GTK_RESPONSE_OK, 
         NULL);
   gtk_container_set_border_width(GTK_CONTAINER (dialog), 5);
#if !GTK_CHECK_VERSION(2, 22, 0)
   gtk_dialog_set_has_separator(GTK_DIALOG (dialog), FALSE);
#endif

   hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
   content_area = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
   gtk_container_add(GTK_CONTAINER(content_area), hbox);
   gtk_widget_show(hbox);

   image = gtk_image_new_from_icon_name("dialog-question", GTK_ICON_SIZE_DIALOG);
   gtk_box_pack_start (GTK_BOX (hbox), image, FALSE, FALSE, 5);
   gtk_widget_show(image);

   frame = gtk_frame_new("Optional parameters");
   gtk_container_set_border_width(GTK_CONTAINER (frame), 5);
   gtk_box_pack_start (GTK_BOX (hbox), frame, TRUE, TRUE, 0);
   gtk_widget_show(frame);

   vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
   gtk_container_set_border_width(GTK_CONTAINER (vbox), 5);
   gtk_container_add(GTK_CONTAINER (frame), vbox);
   gtk_widget_show(vbox);

   button1 = gtk_check_button_new_with_label("Sniff remote connections.");
   gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON (button1), TRUE);
   gtk_box_pack_start(GTK_BOX (vbox), button1, FALSE, FALSE, 0);
   gtk_widget_show(button1);

   button2 = gtk_check_button_new_with_label("Only poison one-way.");
   gtk_box_pack_start(GTK_BOX (vbox), button2, FALSE, FALSE, 0);
   gtk_widget_show(button2);

   response = gtk_dialog_run(GTK_DIALOG(dialog));
   if(response == GTK_RESPONSE_OK) {
      gtk_widget_hide(dialog);
      const char *s_remote = "", *comma = "", *s_oneway = "";

      if(gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (button1))) {
        s_remote="remote";
        remote = TRUE;
      }

      if(gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (button2))) {
         if(remote)
           comma = ",";
         s_oneway = "oneway";
      } 

      snprintf(params, PARAMS_LEN+1, "arp:%s%s%s", s_remote, comma, s_oneway);
      gtkui_start_mitm();
   }

   gtk_widget_destroy(dialog);

   /* a simpler method:
      gtkui_input_call("Parameters :", params + strlen("arp:"), PARAMS_LEN - strlen("arp:"), gtkui_start_mitm);
    */
}

void gtkui_icmp_redir(GSimpleAction *action, GVariant *value, gpointer data)
{
   GtkWidget *dialog, *grid, *hbox, *image, *label, *entry1, *entry2, *frame, *content_area;
   gint response = 0;

   (void) action;
   (void) value;
   (void) data;

   DEBUG_MSG("gtk_icmp_redir");

   dialog = gtk_dialog_new_with_buttons("MITM Attack: ICMP Redirect", 
         GTK_WINDOW (window), 
         GTK_DIALOG_MODAL|GTK_DIALOG_USE_HEADER_BAR, 
         "_Cancel", GTK_RESPONSE_CANCEL, 
         "_OK",     GTK_RESPONSE_OK, 
         NULL);
   gtk_container_set_border_width(GTK_CONTAINER (dialog), 5);
#if !GTK_CHECK_VERSION(2, 22, 0)
   gtk_dialog_set_has_separator(GTK_DIALOG (dialog), FALSE);
#endif

   hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
   content_area = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
   gtk_container_add(GTK_CONTAINER(content_area), hbox);
   gtk_widget_show(hbox);

   image = gtk_image_new_from_icon_name("dialog-question", GTK_ICON_SIZE_DIALOG);
   gtk_box_pack_start (GTK_BOX (hbox), image, FALSE, FALSE, 5);
   gtk_widget_show(image);

   frame = gtk_frame_new("Gateway Information");
   gtk_container_set_border_width(GTK_CONTAINER (frame), 5);
   gtk_box_pack_start (GTK_BOX (hbox), frame, TRUE, TRUE, 0);
   gtk_widget_show(frame);

   grid = gtk_grid_new();
   gtk_grid_set_row_spacing(GTK_GRID(grid), 5);
   gtk_grid_set_column_spacing(GTK_GRID(grid), 5);
   gtk_container_set_border_width(GTK_CONTAINER (grid), 8);
   gtk_container_add(GTK_CONTAINER (frame), grid);
   gtk_widget_show(grid);


   label = gtk_label_new("MAC Address");
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), label, GTK_POS_LEFT, GTK_POS_TOP, 1, 1);
   gtk_widget_show(label);

   entry1 = gtk_entry_new();
   gtk_entry_set_max_length(GTK_ENTRY (entry1), ETH_ASCII_ADDR_LEN);
   gtk_grid_attach(GTK_GRID(grid), entry1, GTK_POS_LEFT+1, GTK_POS_TOP, 1, 1);
   gtk_widget_show(entry1);

   label = gtk_label_new("IP Address");
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), label, GTK_POS_LEFT, GTK_POS_TOP+1, 1, 1);
   gtk_widget_show(label);

   entry2 = gtk_entry_new();
   gtk_entry_set_max_length(GTK_ENTRY (entry2), IP6_ASCII_ADDR_LEN);
   gtk_grid_attach(GTK_GRID(grid), entry2, GTK_POS_LEFT+1, GTK_POS_TOP+1, 1, 1);
   gtk_widget_show(entry2);

   response = gtk_dialog_run(GTK_DIALOG(dialog));
   if(response == GTK_RESPONSE_OK) {
      gtk_widget_hide(dialog);

//      memset(params, '\0', PARAMS_LEN);

      snprintf(params, PARAMS_LEN+1, "icmp:%s/%s",  gtk_entry_get_text(GTK_ENTRY(entry1)),
                       gtk_entry_get_text(GTK_ENTRY(entry2)));

      gtkui_start_mitm();
   }

   gtk_widget_destroy(dialog);

   /* a simpler method:
      gtkui_input_call("Parameters :", params + strlen("icmp:"), PARAMS_LEN - strlen("icmp:"), gtkui_start_mitm);
    */
}

void gtkui_port_stealing(GSimpleAction *action, GVariant *value, gpointer data)
{
   GtkWidget *dialog, *vbox, *hbox, *image, *button1, *button2, *frame, *content_area;
   gint response = 0;
   gboolean remote = FALSE;
   
   (void) action;
   (void) value;
   (void) data;

   DEBUG_MSG("gtk_port_stealing"); 
      
   dialog = gtk_dialog_new_with_buttons("MITM Attack: Port Stealing", 
         GTK_WINDOW (window), 
         GTK_DIALOG_MODAL|GTK_DIALOG_USE_HEADER_BAR, 
         "_Cancel", GTK_RESPONSE_CANCEL, 
         "_OK",     GTK_RESPONSE_OK, 
         NULL);
   gtk_container_set_border_width(GTK_CONTAINER (dialog), 5);
#if !GTK_CHECK_VERSION(2, 22, 0)
   gtk_dialog_set_has_separator(GTK_DIALOG (dialog), FALSE);
#endif
         
   hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
   content_area = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
   gtk_container_add(GTK_CONTAINER(content_area), hbox);
   gtk_widget_show(hbox);
         
   image = gtk_image_new_from_icon_name("dialog-question", GTK_ICON_SIZE_DIALOG);
   gtk_box_pack_start (GTK_BOX (hbox), image, FALSE, FALSE, 5);
   gtk_widget_show(image);
      
   frame = gtk_frame_new("Optional parameters");
   gtk_container_set_border_width(GTK_CONTAINER (frame), 5);
   gtk_box_pack_start (GTK_BOX (hbox), frame, TRUE, TRUE, 0);
   gtk_widget_show(frame);

   vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
   gtk_container_set_border_width(GTK_CONTAINER (vbox), 5);
   gtk_container_add(GTK_CONTAINER (frame), vbox);
   gtk_widget_show(vbox);

   button1 = gtk_check_button_new_with_label("Sniff remote connections.");
   gtk_box_pack_start(GTK_BOX (vbox), button1, FALSE, FALSE, 0);
   gtk_widget_show(button1);
   
   button2 = gtk_check_button_new_with_label("Propagate to other switches.");
   gtk_box_pack_start(GTK_BOX (vbox), button2, FALSE, FALSE, 0);
   gtk_widget_show(button2);

   response = gtk_dialog_run(GTK_DIALOG(dialog));
   if(response == GTK_RESPONSE_OK) {    
      gtk_widget_hide(dialog);          
      const char *s_remote= "", *tree = "", *comma = "";

      if(gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (button1))) {
         s_remote="remote";
         remote = TRUE;
      }
   
      if(gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (button2))) {
         if(remote)
            comma = ",";
         tree = "tree";
      }
  
      snprintf(params, PARAMS_LEN+1, "port:%s%s%s", s_remote, comma, tree); 
      gtkui_start_mitm();
   }

   gtk_widget_destroy(dialog);

   /* a simpler method: 
      gtkui_input_call("Parameters :", params + strlen("port:"), PARAMS_LEN - strlen("port:"), gtkui_start_mitm);
    */
}

void gtkui_dhcp_spoofing(GSimpleAction *action, GVariant *value, gpointer data)
{
   GtkWidget *dialog, *grid, *hbox, *image, *label, *entry1, *entry2, *entry3, *frame, *content_area;
   gint response = 0;
   
   (void) action;
   (void) value;
   (void) data;

   DEBUG_MSG("gtk_dhcp_spoofing");
//   memset(params, '\0', PARAMS_LEN+1);
   
   dialog = gtk_dialog_new_with_buttons("MITM Attack: DHCP Spoofing", 
         GTK_WINDOW (window), 
         GTK_DIALOG_MODAL|GTK_DIALOG_USE_HEADER_BAR, 
         "_Cancel", GTK_RESPONSE_CANCEL, 
         "_OK",     GTK_RESPONSE_OK, 
         NULL);
   gtk_container_set_border_width(GTK_CONTAINER (dialog), 5);
#if !GTK_CHECK_VERSION(2, 22, 0)
   gtk_dialog_set_has_separator(GTK_DIALOG (dialog), FALSE);
#endif

   hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
   content_area = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
   gtk_container_add(GTK_CONTAINER(content_area), hbox);
   gtk_widget_show(hbox);
   
   image = gtk_image_new_from_icon_name("dialog-question", GTK_ICON_SIZE_DIALOG);
   gtk_box_pack_start (GTK_BOX (hbox), image, FALSE, FALSE, 5);
   gtk_widget_show(image);

   frame = gtk_frame_new("Server Information");
   gtk_container_set_border_width(GTK_CONTAINER (frame), 5);
   gtk_box_pack_start (GTK_BOX (hbox), frame, TRUE, TRUE, 0);
   gtk_widget_show(frame);
      
   grid = gtk_grid_new();
   gtk_grid_set_row_spacing(GTK_GRID(grid), 5);
   gtk_grid_set_column_spacing(GTK_GRID(grid), 5);
   gtk_container_set_border_width(GTK_CONTAINER (grid), 8);
   gtk_container_add(GTK_CONTAINER (frame), grid);
   gtk_widget_show(grid);

   label = gtk_label_new("IP Pool (optional)");
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), label, GTK_POS_LEFT, GTK_POS_TOP, 1, 1);
   gtk_widget_show(label);

   entry1 = gtk_entry_new(); 
   gtk_grid_attach(GTK_GRID(grid), entry1, GTK_POS_LEFT+1, GTK_POS_TOP, 1, 1);
   gtk_widget_show(entry1);
   
   label = gtk_label_new("Netmask"); 
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), label, GTK_POS_LEFT, GTK_POS_TOP+1, 1, 1);
   gtk_widget_show(label);

   entry2 = gtk_entry_new();
   gtk_entry_set_max_length(GTK_ENTRY (entry2), IP6_ASCII_ADDR_LEN);
   gtk_grid_attach(GTK_GRID(grid), entry2, GTK_POS_LEFT+1, GTK_POS_TOP+1, 1, 1);
   gtk_widget_show(entry2);

   label = gtk_label_new("DNS Server IP");   
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), label, GTK_POS_LEFT, GTK_POS_TOP+2, 1, 1);
   gtk_widget_show(label);

   entry3 = gtk_entry_new();
   gtk_entry_set_max_length(GTK_ENTRY (entry3), IP6_ASCII_ADDR_LEN);
   gtk_grid_attach(GTK_GRID(grid), entry3, GTK_POS_LEFT+1, GTK_POS_TOP+2, 1, 1);
   gtk_widget_show(entry3);

   response = gtk_dialog_run(GTK_DIALOG(dialog));
   if(response == GTK_RESPONSE_OK) {
      gtk_widget_hide(dialog);
//      memset(params, '\0', PARAMS_LEN);

      snprintf(params, PARAMS_LEN+1, "dhcp:%s/%s/%s", gtk_entry_get_text(GTK_ENTRY(entry1)),
                       gtk_entry_get_text(GTK_ENTRY(entry2)), gtk_entry_get_text(GTK_ENTRY(entry3)));

      DEBUG_MSG("ec_gtk_dhcp: DHCP MITM %s", params);
      gtkui_start_mitm();
   }

   gtk_widget_destroy(dialog);

   /* a simpler method:
      gtkui_input_call("Parameters :", params + strlen("dhcp:"), PARAMS_LEN - strlen("dhcp:"), gtkui_start_mitm);
   */
}

#ifdef WITH_IPV6
void gtkui_ndp_poisoning(GSimpleAction *action, GVariant *value, gpointer data)
{
   GtkWidget *dialog, *vbox, *hbox, *image, *button1, *button2, *frame, *content_area;
   gint response = 0;
   gboolean remote = FALSE;

   (void) action;
   (void) value;
   (void) data;

   DEBUG_MSG("gtk_ndp_poisoning");
//   not needed, the \0 is already appended from snprintf
//   memset(params, '\0', PARAMS_LEN+1);

   dialog = gtk_dialog_new_with_buttons("MITM Attack: NDP Poisoning", 
         GTK_WINDOW (window), 
         GTK_DIALOG_MODAL|GTK_DIALOG_USE_HEADER_BAR, 
         "_Cancel", GTK_RESPONSE_CANCEL, 
         "_OK",     GTK_RESPONSE_OK, 
         NULL);
   gtk_container_set_border_width(GTK_CONTAINER (dialog), 5);
#if !GTK_CHECK_VERSION(2, 22, 0)
   gtk_dialog_set_has_separator(GTK_DIALOG (dialog), FALSE);
#endif

   hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
   content_area = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
   gtk_container_add(GTK_CONTAINER(content_area), hbox);
   gtk_widget_show(hbox);

   image = gtk_image_new_from_icon_name("dialog-question", GTK_ICON_SIZE_DIALOG);
   gtk_box_pack_start (GTK_BOX (hbox), image, FALSE, FALSE, 5);
   gtk_widget_show(image);

   frame = gtk_frame_new("Optional parameters");
   gtk_container_set_border_width(GTK_CONTAINER (frame), 5);
   gtk_box_pack_start (GTK_BOX (hbox), frame, TRUE, TRUE, 0);
   gtk_widget_show(frame);

   vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
   gtk_container_set_border_width(GTK_CONTAINER (vbox), 5);
   gtk_container_add(GTK_CONTAINER (frame), vbox);
   gtk_widget_show(vbox);

   button1 = gtk_check_button_new_with_label("Sniff remote connections.");
   gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON (button1), TRUE);
   gtk_box_pack_start(GTK_BOX (vbox), button1, FALSE, FALSE, 0);
   gtk_widget_show(button1);

   button2 = gtk_check_button_new_with_label("Only poison one-way.");
   gtk_box_pack_start(GTK_BOX (vbox), button2, FALSE, FALSE, 0);
   gtk_widget_show(button2);

   response = gtk_dialog_run(GTK_DIALOG(dialog));
   if(response == GTK_RESPONSE_OK) {
      gtk_widget_hide(dialog);
      const char *s_remote = "", *comma = "", *s_oneway = "";

      if(gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (button1))) {
         s_remote="remote";
         remote = TRUE;
      }

      if(gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (button2))) {
         if(remote)
            comma = ",";

         s_oneway = "oneway";
      } 

      snprintf(params, PARAMS_LEN+1, "ndp:%s%s%s", 
            s_remote, comma, s_oneway);
      gtkui_start_mitm();
   }

   gtk_widget_destroy(dialog);

   /* a simpler method:
      gtkui_input_call("Parameters :", params + strlen("ndp:"), PARAMS_LEN - strlen("ndp:"), gtkui_start_mitm);
    */
}
#endif


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
 */
void gtkui_mitm_stop(GSimpleAction *action, GVariant *value, gpointer data)
{
   GtkWidget *dialog;
   
   (void) action;
   (void) value;
   (void) data;

   DEBUG_MSG("gtk_mitm_stop");

   /* create the dialog */
   dialog = gtkui_message_dialog(GTK_WINDOW (window), 
         GTK_DIALOG_MODAL|GTK_DIALOG_USE_HEADER_BAR,
         GTK_MESSAGE_INFO, GTK_BUTTONS_NONE, "Stopping the mitm attack...");
   gtk_window_set_position(GTK_WINDOW (dialog), GTK_WIN_POS_CENTER_ON_PARENT);
   gtk_window_set_resizable(GTK_WINDOW (dialog), FALSE);
   gtk_widget_queue_draw(dialog);
   gtk_widget_show_now(dialog);

   /* for GTK to display the dialog now */
   while (gtk_events_pending ())
      gtk_main_iteration ();

   /* stop the mitm process */
   mitm_stop();

   gtk_widget_destroy(dialog);
   
   gtkui_message("MITM attack(s) stopped");
}

/* EOF */

// vim:ts=3:expandtab

