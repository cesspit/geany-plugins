/*
 *      dbm_android_device_dialog.c
 *      
 *      Copyright 2010 Alexander Petukhov <devel(at)apetukhov.ru>
 *      
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *      
 *      This program is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *      GNU General Public License for more details.
 *      
 *      You should have received a copy of the GNU General Public License
 *      along with this program; if not, write to the Free Software
 *      Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *      MA 02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
	#include "config.h"
#endif
#include <geanyplugin.h>
extern GeanyFunctions	*geany_functions;
extern GeanyData		*geany_data;

#include "pixbuf.h"

#define ARROW_PADDING 7

/* Devices tree view columns */
enum
{
   PIXBUF,
   DESC,
   DEVICE,
   N_COLUMNS
};

static GtkWidget *use_default_activity = NULL;
static GtkWidget *use_for_future = NULL;
static GtkWidget *activities_combo = NULL;

static int default_activity;
static GtkWidget *devices = NULL;
static GtkWidget *device_frame = NULL;

static GtkWidget *dialog = NULL;
static GtkWidget *box = NULL;
static GtkWidget *content_area = NULL;

static GtkTreeSelection *selection = NULL;
	
static void on_use_default_click(GtkButton *button, gpointer user_data)
{
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(button)))
	{
		gtk_combo_box_set_active(GTK_COMBO_BOX(activities_combo), default_activity);
		gtk_widget_set_sensitive(activities_combo, FALSE);
	}
	else
	{
		gtk_widget_set_sensitive(activities_combo, TRUE);
	}
}

gchar* dbm_android_devices_dialog_get_activity()
{
	gchar *activity = NULL;

	GtkTreeIter iter;
	gtk_combo_box_get_active_iter(GTK_COMBO_BOX(activities_combo), &iter);
	GtkTreeModel *model = gtk_combo_box_get_model(GTK_COMBO_BOX(activities_combo));

	gtk_tree_model_get (model,
		&iter,
		0, &activity,
		-1);
	
	return activity;
}

gboolean dbm_android_devices_dialog_get_use_as_default()
{
	return gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(use_for_future));
}

gchar* dbm_android_devices_dialog_get_device()
{
	GtkTreeModel *model = gtk_tree_view_get_model(GTK_TREE_VIEW(devices));
	GList *selected_rows = gtk_tree_selection_get_selected_rows(selection, &model);

	gchar *device = NULL;

	if (selected_rows)
	{
		GtkTreePath *path = (GtkTreePath*)selected_rows->data;

		GtkTreeIter iter;
		gtk_tree_model_get_iter(model, &iter, path);
		gtk_tree_model_get(model,
			&iter,
			DEVICE, &device,
			-1);

		g_list_foreach (selected_rows, (GFunc) gtk_tree_path_free, NULL);
		g_list_free (selected_rows);
	}

	return device;
}

/*
 * create devices dialog
 */
GtkWidget* dbm_android_devices_dialog_init(GList *devices_online, GList *activities, int activity, const gchar *manifest)
{
	default_activity = activity;
	
	 dialog = gtk_dialog_new_with_buttons(
		_("Select a device to debug on"),
		NULL,
		GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
	    GTK_STOCK_CANCEL,
	    GTK_RESPONSE_REJECT,
	    GTK_STOCK_OK,
	    GTK_RESPONSE_ACCEPT,
	    NULL);

	content_area = gtk_dialog_get_content_area (GTK_DIALOG (dialog));

	box = gtk_vbox_new(FALSE, 0);

	GtkWidget *hbox = gtk_hbox_new(FALSE, 0);
	GtkWidget *label = gtk_label_new(_("Device list:"));
	//gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 0);
	//gtk_box_pack_start(GTK_BOX(box), hbox, FALSE, FALSE, 6);

	GtkListStore *store = gtk_list_store_new (
		N_COLUMNS,
		GDK_TYPE_PIXBUF,
		G_TYPE_STRING,
		G_TYPE_STRING
	);
		
	GtkTreeModel *model = GTK_TREE_MODEL(store);
	devices = gtk_tree_view_new_with_model (model);

	/* creating columns */
	GtkTreeViewColumn	*column;

	GtkCellRenderer *renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new();
	gtk_tree_view_column_pack_end(column, renderer, TRUE);
	gtk_tree_view_column_set_attributes(column, renderer, "markup", DESC, NULL);	
	GtkCellRenderer *icon_renderer = gtk_cell_renderer_pixbuf_new ();
	g_object_set(icon_renderer, "width", gdk_pixbuf_get_width(android_pixbuf) + 2 * ARROW_PADDING, NULL);
	gtk_tree_view_column_pack_end(column, icon_renderer, FALSE);
	gtk_tree_view_column_set_attributes(column, icon_renderer, "pixbuf", PIXBUF, NULL);	

	gtk_tree_view_append_column (GTK_TREE_VIEW (devices), column);

	gtk_tree_view_set_headers_visible(GTK_TREE_VIEW(devices), FALSE);

	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(devices));
	gtk_tree_selection_set_mode(selection, GTK_SELECTION_SINGLE);

	GtkTreePath *first_path = gtk_tree_path_new_first(); 
	gtk_tree_selection_select_path(selection, first_path);
	gtk_tree_path_free(first_path);

	device_frame = gtk_frame_new(NULL);
	//gtk_frame_set_label(GTK_FRAME(device_frame), _("Device list:"));
	//gtk_frame_set_shadow_type(GTK_FRAME(device_frame), GTK_SHADOW_ETCHED_OUT);
	gtk_container_add(GTK_CONTAINER(device_frame), devices);
	gtk_box_pack_start(GTK_BOX(box), device_frame, TRUE, TRUE, 5);

	GList *liter = devices_online;
	while (liter)
	{
		gchar *caption = g_strdup_printf("<span size=\"larger\" weight=\"bold\">%s</span>\nrunning", (gchar*)liter->data);
		GtkTreeIter iter;
		gtk_list_store_append (store, &iter);
		gtk_list_store_set (store, &iter,
					PIXBUF, android_pixbuf,
					DESC, caption,
					DEVICE, g_strdup((gchar*)liter->data),
					-1);
		g_free(caption);
		liter = liter->next;
	}

/*
	if (avds)
	{
		while (avds)
		{
			avd *emulator = (avd*)avds->data; 
			gchar *caption = g_strdup_printf("<span size=\"larger\" weight=\"bold\">%s \"%s\"</span>\n%s (%s)",
				_("Start a new emulator: "), emulator->name->str, emulator->target->str, emulator->abi->str);
			GtkTreeIter iter;
			gtk_list_store_append (store, &iter);
			gtk_list_store_set (store, &iter,
						PIXBUF, break_pixbuf,
						DESC, caption,
						-1);
			g_free(caption);
			avds = avds->next;
		}
		avds = g_list_first(avds);
	}
*/



/*
	GtkWidget *use_device = gtk_radio_button_new_with_label(NULL, _("Choose running device"));
	gtk_box_pack_start(GTK_BOX(box), use_device, FALSE, FALSE, 0);

	GtkWidget *device_frame = gtk_frame_new(NULL);
	gtk_frame_set_shadow_type(GTK_FRAME(device_frame), GTK_SHADOW_IN);
	GtkWidget *device_list = gtk_tree_view_new();
	gtk_container_add(GTK_CONTAINER(device_frame), device_list);
	gtk_box_pack_start(GTK_BOX(box), device_frame, TRUE, TRUE, 0);

	GtkWidget *start_emulator = gtk_radio_button_new_with_label(gtk_radio_button_get_group(GTK_RADIO_BUTTON(use_device)), _("Start new emulator"));
	gtk_box_pack_start(GTK_BOX(box), start_emulator, FALSE, FALSE, 0);
	
	GtkWidget *emulator_list = gtk_tree_view_new();
	gtk_box_pack_start(GTK_BOX(box), emulator_list, TRUE, TRUE, 0);

*/

	//GtkWidget *separator = gtk_hseparator_new();
	//gtk_box_pack_start(GTK_BOX(box), separator, FALSE, FALSE, 0);

	GtkListStore *activities_store = gtk_list_store_new(1, G_TYPE_STRING);
	while (activities)
	{
		GtkTreeIter iter;
		gtk_list_store_append (activities_store, &iter);
		gtk_list_store_set (activities_store, &iter,
					0, (const gchar*)activities->data,
					-1);
		activities = activities->next;
	}
	activities = g_list_first(activities);

	use_default_activity = gtk_check_button_new_with_label(_("Use default launch activity"));
	g_signal_connect(G_OBJECT(use_default_activity), "clicked", G_CALLBACK (on_use_default_click), NULL);
	gtk_box_pack_start(GTK_BOX(box), use_default_activity, FALSE, FALSE, 0);

	activities_combo = gtk_combo_box_new_with_model(GTK_TREE_MODEL(activities_store));

	GtkCellRenderer *cell = gtk_cell_renderer_text_new();
	gtk_cell_layout_pack_start( GTK_CELL_LAYOUT(activities_combo), cell, TRUE );
	gtk_cell_layout_set_attributes( GTK_CELL_LAYOUT(activities_combo), cell, "text", 0, NULL );

	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(use_default_activity), TRUE);
	gtk_widget_set_sensitive(activities_combo, FALSE);
	gtk_combo_box_set_active(GTK_COMBO_BOX(activities_combo), default_activity);

	gtk_box_pack_start(GTK_BOX(box), activities_combo, FALSE, FALSE, 3);

	hbox = gtk_hbox_new(FALSE, 0);
	label = gtk_label_new(_("Use a selected device for future debug sessions"));
	use_for_future = gtk_check_button_new();
	gtk_box_pack_end(GTK_BOX(hbox), use_for_future, FALSE, FALSE, 0);
	gtk_box_pack_end(GTK_BOX(hbox), label, FALSE, FALSE, 0);

	gtk_box_pack_start(GTK_BOX(box), hbox, FALSE, FALSE, 4);

	gtk_container_add(GTK_CONTAINER(content_area), box);

	gtk_window_set_skip_taskbar_hint(GTK_WINDOW(dialog), FALSE);
	gtk_window_set_skip_pager_hint(GTK_WINDOW(dialog), FALSE);

	gtk_widget_show_all (dialog);

	return dialog;
}

