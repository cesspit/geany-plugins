/*
 *      dbm_android.c
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

#include <stdlib.h>
#include <string.h>
#include <stdlib.h>

#include <unistd.h>

#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <libxml/xmlreader.h>

#ifdef HAVE_CONFIG_H
	#include "config.h"
#endif
#include <geanyplugin.h>
extern GeanyFunctions	*geany_functions;
extern GeanyData		*geany_data;

#include "dbm_android_device_dialog.h"
#include "breakpoint.h"
#include "debug_module.h"

#define MODULE_FEATURES MF_ASYNC_BREAKS

/* GDB spawn flags */
#define COMMAND_SPAWN_FLAGS \
	G_SPAWN_SEARCH_PATH | \
	G_SPAWN_DO_NOT_REAP_CHILD | \
	G_SPAWN_STDERR_TO_DEV_NULL

#define DEVICE_LIST_MARKER "List of devices attached "

#define AVD_LIST_MARKER "Available Android Virtual Devices:"
#define AVD_LIST_SPACER "---------"

#define AVD_NAME_MARKER "    Name: "
#define AVD_PATH_MARKER "    Path: "
#define AVD_TARGET_MARKER "  Target: "
#define AVD_ABI_MARKER "     ABI: "
#define AVD_SKIN_MARKER "    Skin: "
#define AVD_SDCARD_MARKER "  Sdcard: "

#define ANDROID_MANIFEST_FILE "AndroidManifest.xml"

#define IS_OPENING_TAG(reader, tagname) ( 									\
	XML_READER_TYPE_ELEMENT == xmlTextReaderNodeType(reader) &&	\
	!strcmp((const char*)xmlTextReaderConstName(reader), tagname)		\
)
#define IS_CLOSING_TAG(reader, tagname) ( 									\
	XML_READER_TYPE_END_ELEMENT == xmlTextReaderNodeType(reader) &&	\
	!strcmp((const char*)xmlTextReaderConstName(reader), tagname)		\
)

#define RUN_MARKER "> "
#define BREAK_MARKER "Breakpoint hit:"
#define STEP_COMPLETED_MARKER "Step completed:"

#define ACTION_MAIN "android.intent.action.MAIN"

#define LOCAL_DEBUG_PORT 29882


typedef gboolean (*async_read_callback)(GIOChannel * src, GIOCondition cond, gpointer data);
typedef gboolean (*command_exit_callback)(GPid pid, gint status, gpointer data);

/* callbacks to use for messaging, error reporting and state change alerting */
static dbg_callbacks* dbg_cbs = NULL;

/* async command runtime  stuff */
static GPid ac_pid = 0;
static GSource *ac_src = NULL;

/* async command IO stuff */
static guint ac_io_id;
static GIOChannel *ac_io_output_channel;

/* jdb runtime  stuff */
static GPid jdb_pid = 0;
static GSource *jdb_src = NULL;

/* jdb IO stuff */
static guint jdb_io_id;//, jdb_io_error_id;

static GIOChannel *jdb_io_input_channel;
static GIOChannel *jdb_io_output_channel;
//static GIOChannel *jdb_io_error_channel;

/* adb devices */
static GList *devices_online = NULL;

static gchar *device = NULL;
static gchar *activity = NULL;

static int device_port = 0;
static int local_port = 0;

static gboolean use_last = FALSE;

static gchar *target = NULL;
static gchar *manifest = NULL;
static gchar *root_path = NULL;
static gchar *src_path = NULL;

static GList *activities = NULL;
static int default_activity_index = 0;

void dealloc_module_data()
{
	g_list_foreach(activities, (GFunc)g_free, NULL);
	g_list_free(activities);
	activities = NULL;

	g_free(manifest);
	manifest = NULL;

	g_free(target);
	target = NULL;

	g_free(root_path);
	root_path = NULL;

	g_free(src_path);
	src_path = NULL;

	g_free(device);
	device = NULL;

	g_free(activity);
	activity = NULL;
}

static GList* get_activities_from_manifest(const gchar *file, int *default_index, gchar **error)
{
	GList *_activities = NULL;
	
	xmlTextReaderPtr reader = xmlReaderForFile(file, NULL, 0);
	if (reader != NULL)
	{
		int ret = xmlTextReaderRead(reader);
		while (ret == 1)
		{
			const xmlChar *name = xmlTextReaderConstName(reader);

			if (name != NULL)
			{
				if (IS_OPENING_TAG(reader, "activity"))
				{
					const xmlChar *activity_name = xmlTextReaderGetAttribute(reader, (const xmlChar*)"android:name");
					_activities = g_list_append(_activities, g_strdup((const gchar*)(activity_name + 1)));

					ret = xmlTextReaderRead(reader);
					while (ret == 1 && !(IS_CLOSING_TAG(reader, "activity")))
					{
						if (IS_OPENING_TAG(reader, "action"))
						{
							const xmlChar *action = xmlTextReaderGetAttribute(reader, (const xmlChar*)"android:name");
							if (!strcmp((const char*)action, ACTION_MAIN))
							{
								*default_index = g_list_length(_activities) - 1;
							}
						}
						ret = xmlTextReaderRead(reader);
					}
					if (ret != 1)
					{
						if (_activities)
						{
							g_list_foreach(_activities, (GFunc)g_free, NULL);
							g_list_free(_activities);
							_activities = NULL;
						}
						*error = g_strdup_printf(_("Failed to parse \"%s\""), file);
					}
				}
			}

			ret = xmlTextReaderRead(reader);
		}

		xmlFreeTextReader(reader);

		if (ret != 0)
		{
			if (_activities)
			{
				g_list_foreach(_activities, (GFunc)g_free, NULL);
				g_list_free(_activities);
				_activities = NULL;
			}
			*error = g_strdup_printf(_("Failed to parse \"%s\""), file);
		}
	}
	else
	{
		*error = g_strdup_printf(_("Failed to parse \"%s\""), file);
	}

	return _activities;
}

static GList* read_until_prompt(gchar **thread_name, int *thread_id)
{
	GList* lines = NULL;

	static GString *line = NULL;
	while(TRUE)
	{
		gchar next_char; gsize count = 0;
		GIOStatus status = g_io_channel_read_chars(jdb_io_output_channel, &next_char, 1, &count, NULL);

		if ('<' == next_char && !line)
		{
			GString *prompt = g_string_new("");
			do
			{
				status = g_io_channel_read_chars(jdb_io_output_channel, &next_char, 1, &count, NULL);
				prompt = g_string_append_c(prompt, next_char);
			}
			while('>' != next_char);

			if (thread_id)
			{
				*thread_id = atoi(prompt->str);
			}

			// space
			status = g_io_channel_read_chars(jdb_io_output_channel, &next_char, 1, &count, NULL);
			prompt = g_string_set_size(prompt, 0);
			
			do
			{
				status = g_io_channel_read_chars(jdb_io_output_channel, &next_char, 1, &count, NULL);
				prompt = g_string_append_c(prompt, next_char);
			}
			while(' ' != next_char);

			if (thread_name)
			{
				*thread_name = g_strdup(prompt->str);
			}

			g_string_free(prompt, TRUE);

			break;
		}
		else
		{
			if ('\n' == next_char)
			{
				if (line)
				{
					lines = g_list_append(lines, g_strdup(line->str));
					g_string_free(line, TRUE);
					line = NULL;
				}
			}
			else
			{
				if (!line)
				{
					line = g_string_new("");
				}
				line = g_string_append_c(line, next_char);
			}
		}
	}

	return lines;
}

/*
 * shutdown GIOChannel
 */
static void shutdown_channel(GIOChannel ** ch)
{
	if (*ch)
	{
		GError *err = NULL;
		gint fd = g_io_channel_unix_get_fd(*ch);
		g_io_channel_shutdown(*ch, TRUE, &err);
		g_io_channel_unref(*ch);
		*ch = NULL;
		if (fd >= 0)
		{
			close(fd);
		}
	}
}

static void close_ac_pid()
{
	g_spawn_close_pid(ac_pid);
	ac_pid = 0;
}

static void remove_ac_callbacks()
{
	g_source_remove(ac_io_id);
	ac_io_id = 0;

	shutdown_channel(&ac_io_output_channel);
	ac_io_output_channel = NULL;

	g_source_destroy(ac_src);
	ac_src = NULL;
}

static void remove_jdb_callbacks()
{
	g_source_remove(jdb_io_id);
	jdb_io_id = 0;

	shutdown_channel(&jdb_io_input_channel);
	jdb_io_output_channel = NULL;

	shutdown_channel(&jdb_io_input_channel);
	jdb_io_output_channel = NULL;

	//g_source_remove(jdb_io_error_id);
	//jdb_io_error_id = 0;

	//shutdown_channel(&jdb_io_error_channel);
	//jdb_io_error_channel = NULL;

	g_source_destroy(jdb_src);
	ac_src = NULL;
}

static gboolean start_async_command(const gchar *message, const gchar *command,  async_read_callback on_read_cb, GChildWatchFunc on_exit_cb)
{
	dbg_cbs->send_message(message, "grey");
	
	gchar **args = g_strsplit(command, " ", 0);
	GError *err = NULL;
	gint ac_in, ac_out;

	gboolean spawned = g_spawn_async_with_pipes(NULL, (gchar**)args, NULL, COMMAND_SPAWN_FLAGS, NULL,  NULL, &ac_pid, &ac_in, &ac_out, NULL, &err);
	g_strfreev(args);

	if (!spawned)
	{
		GString *msg = g_string_new("");
		g_string_printf(msg, _("Failed to execute: \"%s\""), command);
		dbg_cbs->report_error(msg->str);
		g_string_free(msg, TRUE);
	}
	else
	{
		if (on_read_cb)
		{
			/* create GDB GIO chanel */
			ac_io_output_channel = g_io_channel_unix_new(ac_out);
			
			/* connect read callback to the output chanel */
			ac_io_id = g_io_add_watch(ac_io_output_channel, G_IO_IN, on_read_cb, NULL);
		}

		if (on_exit_cb)
		{
			ac_src = g_child_watch_source_new(ac_pid);
			g_child_watch_add(ac_pid, on_exit_cb, NULL);
		}
	}

	return spawned;
}

void write_to_jdb_chanel(const gchar *line)
{
	GIOStatus st;
	GError *err = NULL;
	gsize count;
	
	char command[1000];
	sprintf(command, "%s\n", line);
	
	while (strlen(command))
	{
		st = g_io_channel_write_chars(jdb_io_input_channel, command, strlen(command), &count, &err);
		strcpy(command, command + count);
		if (err || (st == G_IO_STATUS_ERROR) || (st == G_IO_STATUS_EOF))
		{
#ifdef DEBUG_OUTPUT
			dbg_cbs->send_message(err->message, "red");
#endif
			break;
		}
	}

	st = g_io_channel_flush(jdb_io_input_channel, &err);
	if (err || (st == G_IO_STATUS_ERROR) || (st == G_IO_STATUS_EOF))
	{
#ifdef DEBUG_OUTPUT
		dbg_cbs->send_message(err->message, "red");
#endif
	}
}

void jdb_process_line(gchar *line)
{
	if (!g_strcmp0(line, RUN_MARKER))
	{
		dbg_cbs->send_message("RUN_MARKER", "red");
		dbg_cbs->set_run();
	}
	else if (	g_str_has_prefix(line, BREAK_MARKER) ||
		g_str_has_prefix(line, STEP_COMPLETED_MARKER) )
	{
		g_source_remove(jdb_io_id);

		dbg_cbs->send_message("BREAK_MARKER | STEP_COMPLETED_MARKER", "red");

		GList *rest_output = read_until_prompt(NULL, NULL);
		g_list_foreach(rest_output, (GFunc)g_free, NULL);
		g_list_free(rest_output);

		dbg_cbs->set_stopped();
	}
	else
	{
		dbg_cbs->send_message("OTHER_LINE", "red");
	}
}

static gboolean on_jdb_error_read(GIOChannel * src, GIOCondition cond, gpointer data)
{
	GError *error = NULL;

	gchar first_char; gsize _read = 0;
	GIOStatus status = g_io_channel_read_chars(jdb_io_output_channel, &first_char, 1, &_read, &error);
	if (G_IO_STATUS_NORMAL != status)
	{
		dbg_cbs->send_message("G_IO_STATUS_NORMAL != status - at first char", "red");
	}
	else
	{
		if ('\n' == first_char)
		{
		}
		else
		{
		}
	}

	return TRUE;
}

static gboolean on_jdb_read(GIOChannel * src, GIOCondition cond, gpointer data)
{
	GError *error = NULL;
	static GString *line = NULL;

	gchar first_char; gsize _read = 0;
	GIOStatus status = g_io_channel_read_chars(jdb_io_output_channel, &first_char, 1, &_read, &error);
	if (G_IO_STATUS_NORMAL != status)
	{
		dbg_cbs->send_message("G_IO_STATUS_NORMAL != status - at first char", "red");
	}
	else
	{
		if ('\n' == first_char)
		{
			dbg_cbs->send_message("LINE", "red");
			if (line)
			{
				gchar *msg = g_strdup_printf("Processing line \"%s\"", line->str);
				dbg_cbs->send_message(msg, "red");
				g_free(msg);

				jdb_process_line(line->str);
				g_string_free(line, TRUE);
				line = NULL;
			}
		}
		else
		{
			gchar *msg = g_strdup_printf("CHAR: %c", first_char);
			dbg_cbs->send_message(msg, "green");
			g_free(msg);

			if (!line)
			{
				line = g_string_new("");
			}
			line = g_string_append_c(line, first_char);

			if (!strcmp(line->str, "> > "))
			{
				int x = 0;//	write_to_jdb_chanel("\n");
				x++;
			}
		}

		//g_io_channel_flush(jdb_io_output_channel, NULL);
	}

	return TRUE;
}

static void on_jdb_exit(GPid pid, gint status, gpointer data)
{
	remove_jdb_callbacks();

	if (status)
	{
		gchar *error = g_strdup_printf(_("Command \"%s\" exited with status %i"), "", status);
		dbg_cbs->report_error(error);
		g_free(error);

		dealloc_module_data();
	}

	dbg_cbs->set_exited(0);
}

static gboolean callback_function(GIOChannel * src, GIOCondition cond, gpointer data)
{
	GError *error = NULL;

	gchar chars[15];
	gsize _read = 0;
	GIOStatus status = g_io_channel_read_chars(src, &chars[0], 14, &_read, &error);
	if (G_IO_STATUS_NORMAL != status)
	{
		dbg_cbs->send_message("G_IO_STATUS_NORMAL != status - at first char", "red");
	}
	else
	{
		chars[14] = '\0';
		dbg_cbs->send_message(&chars[0], "red");

		
		
	}

	return TRUE;
}

void start_jdb()
{
	GInetAddress *inet_address = g_inet_address_new_from_string("127.0.0.1");
	GSocketAddress *socket_address = g_inet_socket_address_new(inet_address, local_port);

	GSocket *socket;
	GError *err = NULL;
	socket = g_socket_new(G_SOCKET_FAMILY_IPV4,
					G_SOCKET_TYPE_STREAM,
					G_SOCKET_PROTOCOL_TCP,
					&err);
	g_assert(err == NULL);

	gboolean res = g_socket_connect(socket, socket_address, NULL, &err);

	if (res)
	{
		int fd = g_socket_get_fd(socket);
		GIOChannel* channel = g_io_channel_unix_new(fd);
		guint source = g_io_add_watch(channel, G_IO_IN, (GIOFunc)callback_function, NULL);
								
		g_io_channel_unref(channel);

		g_socket_send(socket, "JDWP-Handshake", 14, NULL, &err);
	}

}

void start_jdb1()
{
	gchar *command = g_strdup_printf("jdb -attach localhost:%i -sourcepath ./src", local_port);

	dbg_cbs->send_message(command, "blue");

	gchar **args = g_strsplit(command, " ", 0);
	GError *err = NULL;
	gint in, out;//, error;

	gboolean spawned = g_spawn_async_with_pipes(NULL, (gchar**)args, NULL, COMMAND_SPAWN_FLAGS, NULL,  NULL, &jdb_pid, &in, &out, NULL, &err);
	g_strfreev(args);

	if (!spawned || err)
	{
		GString *msg = g_string_new("");
		g_string_printf(msg, _("Failed to execute: \"%s\""), command);
		dbg_cbs->report_error(msg->str);
		g_string_free(msg, TRUE);
	}
	else
	{
		/* create JDB GIO chanel */
		jdb_io_input_channel = g_io_channel_unix_new(in);
		jdb_io_output_channel = g_io_channel_unix_new(out);
		//jdb_io_error_channel = g_io_channel_unix_new(error);

		g_io_channel_set_encoding(jdb_io_output_channel, NULL, NULL);
		g_io_channel_set_buffered(jdb_io_output_channel, FALSE);

		//g_io_channel_set_encoding(jdb_io_error_channel, NULL, NULL);
		//g_io_channel_set_buffered(jdb_io_error_channel, FALSE);

		/* connect read callback to the output chanel */
		jdb_io_id = g_io_add_watch(jdb_io_output_channel, G_IO_IN, on_jdb_read, NULL);
		//jdb_io_error_id = g_io_add_watch(jdb_io_error_channel, G_IO_IN, on_jdb_error_read, NULL);

		jdb_src = g_child_watch_source_new(ac_pid);
		g_child_watch_add(jdb_pid, on_jdb_exit, NULL);
	}

	g_free(command);
}

static void on_port_forward_exit(GPid pid, gint status, gpointer data)
{
	remove_ac_callbacks();
	close_ac_pid();

	if (status)
	{
		gchar *error = g_strdup_printf(_("Command \"%s\" exited with status %i"), "", status);
		dbg_cbs->report_error(error);
		g_free(error);

		dealloc_module_data();

		dbg_cbs->set_exited(0);
	}
	else
	{
		start_jdb();
	}
}

static gboolean on_list_jswp_read(GIOChannel * src, GIOCondition cond, gpointer data)
{
	gchar *output;
	gsize length;

	GIOStatus status = g_io_channel_read_to_end(src, &output, &length, NULL);
	if (G_IO_STATUS_NORMAL != status)
		return TRUE;		

	*(output + length) = '\0';

	gchar **ports = g_strsplit(output, "\n", 0);
	gchar **port = ports;
	while(strlen(*(port + 1)))
	{
		port++;
	}
		
	device_port = atoi(*port);

	g_strfreev(ports);
	g_free(output);

	return TRUE;
}
static void on_list_jswp_exit(GPid pid, gint status, gpointer data)
{
	remove_ac_callbacks();
	close_ac_pid();

	if (status)
	{
		gchar *error = g_strdup_printf(_("Command \"%s\" exited with status %i"), "", status);
		dbg_cbs->report_error(error);
		g_free(error);

		dealloc_module_data();

		dbg_cbs->set_exited(0);
	}
	else
	{
		GRand *rndm = g_rand_new();
		local_port = g_rand_int_range(rndm, LOCAL_DEBUG_PORT, LOCAL_DEBUG_PORT + 100);
		g_rand_free(rndm);

		gchar *command = g_strdup_printf("adb forward tcp:%i jdwp:%i", local_port, device_port);
		start_async_command(NULL, command, NULL, on_port_forward_exit);
		g_free(command);
	}
}

static gboolean on_start_activity_read(GIOChannel * src, GIOCondition cond, gpointer data)
{
	gchar *line;
	gsize length;

	GIOStatus status = g_io_channel_read_line(src, &line, NULL, &length, NULL);
	if (G_IO_STATUS_NORMAL != status)
		return TRUE;		

	*(line + length) = '\0';

	dbg_cbs->send_message(line, "grey");

	g_free(line);

	return TRUE;
}static void on_start_activity_exit(GPid pid, gint status, gpointer data)
{
	remove_ac_callbacks();
	close_ac_pid();

	if (status)
	{
		gchar *error = g_strdup_printf(_("Command \"%s\" exited with status %i"), "", status);
		dbg_cbs->report_error(error);
		g_free(error);

		dealloc_module_data();

		dbg_cbs->set_exited(0);
	}
	else
	{
		start_async_command("Listing device debug ports ... ", "adb jdwp", on_list_jswp_read, on_list_jswp_exit);
	}
}

static gboolean on_adb_install_read(GIOChannel * src, GIOCondition cond, gpointer data)
{
	gchar *line;
	gsize length;

	GIOStatus status = g_io_channel_read_line(src, &line, NULL, &length, NULL);
	if (G_IO_STATUS_NORMAL != status)
		return TRUE;		

	*(line + length) = '\0';

	dbg_cbs->send_message(line, "grey");

	g_free(line);

	return TRUE;
}
static void on_adb_install_exit(GPid pid, gint status, gpointer data)
{
	remove_ac_callbacks();
	close_ac_pid();

	if (status)
	{
		gchar *error = g_strdup_printf(_("Command \"%s\" exited with status %i"), "", status);
		dbg_cbs->report_error(error);
		g_free(error);

		dealloc_module_data();

		dbg_cbs->set_exited(0);
	}
	else
	{
		gchar *command = g_strdup_printf("adb -s %s shell am start -D -n com.my.app/.%s", device, activity);
		gchar *message = g_strdup_printf("Starting \"%s\"...", activity);
	
		start_async_command(message, command, on_start_activity_read, on_start_activity_exit);
	
		g_free(command);
		g_free(message);
	}
}

static void on_wait_for_device_exit(GPid pid, gint status, gpointer data)
{
	remove_ac_callbacks();
	close_ac_pid();

	if (status)
	{
		gchar *error = g_strdup_printf(_("Command \"%s\" exited with status %i"), "", status);
		dbg_cbs->report_error(error);
		g_free(error);

		dealloc_module_data();

		dbg_cbs->set_exited(0);
	}
	else
	{
		gchar *command = g_strdup_printf("adb -s %s install -r %s", device, target);
		gchar *message = g_strdup_printf("Uploading \"%s\" on \"%s\" ", target, device);
	
		start_async_command(message, command, on_adb_install_read, on_adb_install_exit);
	
		g_free(command);
		g_free(message);
	}
}

static void on_adb_devices_exit(GPid pid, gint status, gpointer data)
{
	remove_ac_callbacks();
	close_ac_pid();

	if (status)
	{
		gchar *error = g_strdup_printf(_("Command \"%s\" exited with status %i"), "", status);
		dbg_cbs->report_error(error);
		g_free(error);

		dealloc_module_data();

		dbg_cbs->set_exited(0);
	}
	else
	{
		/* get a device */
		if (!devices_online)
		{
			dbg_cbs->report_error(_("No device connected"));
		}
		else
		{
			/* if have saved preferences and device and activity still present - use them, do not show dialog */
			if (device && !g_list_find_custom(devices_online, device, (GCompareFunc)g_strcmp0))
			{
				g_free(device);
				device = NULL;
			}
			if (activity && !g_list_find_custom(activities, activity, (GCompareFunc)g_strcmp0))
			{
				g_free(activity);
				activity = NULL;
			}

			if (!device || !activity)
			{
				g_free(device);
				g_free(activity);
				device = activity = NULL;
				
				GtkWidget *dialog = dbm_android_devices_dialog_init(devices_online, activities, default_activity_index, target);
				int responce = gtk_dialog_run(GTK_DIALOG(dialog));

				if (GTK_RESPONSE_ACCEPT == responce)
				{
					device = dbm_android_devices_dialog_get_device();
					activity = dbm_android_devices_dialog_get_activity();

					use_last = dbm_android_devices_dialog_get_use_as_default();
				}
				gtk_widget_destroy (dialog);
			}
		}

		if (device)
		{
			gchar *command = g_strdup_printf("adb -s %s wait-for-device", device);
			start_async_command("querying a device", command, NULL, on_wait_for_device_exit);
			g_free(command);
		}
		else
		{
			dealloc_module_data();
			dbg_cbs->set_exited(0);
		}
	}

	g_list_foreach(devices_online, (GFunc)g_free, NULL);
	g_list_free(devices_online);
	devices_online = NULL;
}

static gboolean on_adb_devices_read(GIOChannel * src, GIOCondition cond, gpointer data)
{
	gchar *line;
	gsize length;
	
	if (G_IO_STATUS_NORMAL != g_io_channel_read_line(src, &line, NULL, &length, NULL))
		return TRUE;		

	*(line + length) = '\0';

	if (!length)
	{
		ac_src = g_child_watch_source_new(ac_pid);
		g_child_watch_add(ac_pid, on_adb_devices_exit, NULL);
	}
	else
	{
		const gchar *color;
		if (!strcmp(line, DEVICE_LIST_MARKER))
		{
			color = "grey";
		}
		else if ('*' == line[0])
		{
			color = "brown";
		}
		else
		{
			color = "blue";
		}
		dbg_cbs->send_message(line, color);

		if ('*' != line[0] && strcmp(line, DEVICE_LIST_MARKER))
		{
			gchar **words = g_strsplit(line, "\t", 0);
			gchar *device_online = g_strdup(words[0]);

			GString *msg = g_string_new("");
			g_string_printf(msg, _("Device found: %s"), device_online);
			dbg_cbs->send_message(msg->str, "blue");

			devices_online = g_list_append(devices_online, device_online);
			
			g_strfreev(words);	
			g_string_free(msg, TRUE);
		}
	}

	g_free(line);

	return TRUE;
}

static void on_adb_kill_server_exit(GPid pid, gint status, gpointer data)
{
	close_ac_pid();

	if (status)
	{
		gchar *error = g_strdup_printf(_("Command \"%s\" exited with status %i"), "", status);
		dbg_cbs->report_error(error);
		g_free(error);

		dealloc_module_data();

		dbg_cbs->set_exited(0);
	}
	else
	{
		start_async_command(_("Getting device list ..."), "adb devices", on_adb_devices_read, NULL);
	}
}

static gboolean run (const gchar* _target, const gchar* commandline, GList* env, GList *witer, GList *biter, const gchar* terminal_device, dbg_callbacks* callbacks)
{
	dbg_cbs = callbacks;

	target = g_strdup(_target);

	root_path = g_path_get_dirname(target);
	if (root_path)
	{
		gchar *tmp = g_path_get_dirname(root_path);
		g_free(root_path);
		root_path = tmp;

		if (root_path)
		{
			manifest = g_build_filename(root_path, G_DIR_SEPARATOR_S, ANDROID_MANIFEST_FILE, NULL);
		}

		src_path = g_strdup_printf("%s/src", root_path);
		
	}
	
	if (!root_path || !manifest)
	{
		gchar *msg = g_strdup_printf(_("Target \"%s\" doesn't seem to reside in a proper Android project tree"), target);
		dbg_cbs->report_error(msg);
		g_free(msg);
	}
	else
	{
		gchar *error = NULL;
		activities = get_activities_from_manifest(manifest, &default_activity_index, &error);
		if (error)
		{
			dbg_cbs->report_error(error);
			g_free(error);
		}
		else
		{
			//start_async_command(_("Killing adb sever ..."), "adb kill-server", NULL, on_adb_kill_server_exit);
			start_async_command(_("Getting device list ..."), "adb devices", on_adb_devices_read, NULL);
		}
	}

	return FALSE;
}

static void restart ()
{
}

static void stop ()
{
	if (ac_pid)
	{
	}
	else if (jdb_pid)
	{
		write_to_jdb_chanel("quit");
	}
}

static void resume ()
{
	write_to_jdb_chanel("cont");
	jdb_io_id = g_io_add_watch(jdb_io_output_channel, G_IO_IN, on_jdb_read, NULL);
}

static void step_over ()
{
	write_to_jdb_chanel("next");
	jdb_io_id = g_io_add_watch(jdb_io_output_channel, G_IO_IN, on_jdb_read, NULL);
}

static void step_into ()
{
	write_to_jdb_chanel("stepi");
	jdb_io_id = g_io_add_watch(jdb_io_output_channel, G_IO_IN, on_jdb_read, NULL);
}

static void step_out ()
{
	write_to_jdb_chanel("step up");
	jdb_io_id = g_io_add_watch(jdb_io_output_channel, G_IO_IN, on_jdb_read, NULL);
}

static void execute_until(const gchar *file, int line)
{
}

static gboolean set_break (breakpoint* bp, break_set_activity bsa)
{
	return FALSE;
}

static gboolean remove_break (breakpoint* bp)
{
	return FALSE;
}

static GList* get_stack ()
{
	GList* stack = NULL;

	write_to_jdb_chanel("where");

	GList *output = read_until_prompt(NULL, NULL);
	while(output)
	{
		gchar *line = (gchar*)output->data;
		
		gchar **parts = g_strsplit(line, " ", 0);

		gchar *java_path = g_strdup(parts[3]); 

		gchar *dot = java_path;
		while((dot = strchr(dot, '.')))
		{
			*dot = G_DIR_SEPARATOR;
			if (g_ascii_isupper(*(dot + 1)))
			{
				dot = strchr(dot, '.');

				if (strlen(dot) < 5)
				{
					*dot = '\0';
					gchar *tmp = g_strdup_printf("%s.%s", java_path, "java");
					g_free(java_path);
					java_path = tmp;					
				}
				else
				{
					strcpy(dot + 1, "java");
				}

				break;
			}
		}

		frame *f = malloc(sizeof(frame));

		gchar *filepath = g_strdup_printf("%s/%s", src_path, java_path);
		
		f->have_source = g_file_test(filepath, G_FILE_TEST_IS_REGULAR);
		
		strcpy(f->address, "");
		strcpy(f->function, "");
		strcpy(f->file, f->have_source ? filepath : java_path);

		g_free(java_path);

		if (strcmp("(native", parts[4]))
		{
			gchar **slices1 = g_strsplit(parts[4], ":", 0);
			gchar *str_line = slices1[1];
			*strrchr(str_line, ')') = '\0';

			gchar **slices2 = g_strsplit(str_line, "\302\240", 0);
			gchar *num = g_strjoinv(NULL, slices2);

			f->line = atoi(num);

			g_strfreev(slices2);
			g_free(num);
		}
		else
		{
			f->line = 0;
		}			

		g_strfreev(parts);

		stack = g_list_append(stack, f);

		output = output->next;
	}

	output = g_list_first(output);
	g_list_foreach(output, (GFunc)g_free, NULL);
	g_list_free(output);

	
	return stack;
}

static GList* get_autos ()
{
	return NULL;
}

static GList* get_watches ()
{
	return NULL;
}

static GList* get_files ()
{
	return NULL;
}

static GList* get_children (gchar* path)
{
	return NULL;
}
static variable* add_watch(gchar* expression)
{
	return NULL;
}

static void remove_watch(gchar* path)
{
}

static gchar* evaluate_expression(gchar *expression)
{
	return NULL;
}

static gboolean request_interrupt ()
{
	return FALSE;
}

static gchar* error_message ()
{
	return NULL;
}

module_features features;

/*
 * define GDB debug module 
 */
DBG_MODULE_DEFINE(android);
