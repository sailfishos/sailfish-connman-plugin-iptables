/*
 *  Connection Manager D-Bus iptables 
 *
 *  Copyright (C) 2017 Jolla Ltd. All rights reserved.
 *  Contact: Jussi Laakkonen <jussi.laakkonen@jolla.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 */

#ifndef __SAILFISH_IPTABLES_DBUS_H_
#define __SAILFISH_IPTABLES_DBUS_H_

#include <stdbool.h>
#include <string.h>
#include <dbus/dbus.h>
#include <glib.h>

#include <connman/log.h>
#include <connman/plugin.h>
#include <connman/dbus.h>
#include <connman/exposed_api.h>
#include <connman/gdbus_external.h>

#define SAILFISH_IPTABLES_DBUS_INTERFACE	"org.sailfishos.connman.mdm.iptables"
#define SAILFISH_IPTABLES_DBUS_PATH			"/org/sailfishos/connman/mdm/iptables"

// SIGNALS 

#define SAILFISH_IPTABLES_SIGNAL_INIT		"Initialize"
#define SAILFISH_IPTABLES_SIGNAL_STOP		"Shutdown"
#define SAILFISH_IPTABLES_SIGNAL_LOAD		"FirewallLoaded"
#define SAILFISH_IPTABLES_SIGNAL_SAVE		"FirewallSaved"
#define SAILFISH_IPTABLES_SIGNAL_CLEAR		"FirewallCleared"
#define SAILFISH_IPTABLES_SIGNAL_POLICY		"PolicyChanged"
#define SAILFISH_IPTABLES_SIGNAL_RULE		"RuleChanged"

#ifdef __cplusplus
extern "C" {
#endif

gint sailfish_iptables_dbus_register();

gint sailfish_iptables_dbus_unregister();

DBusMessage* sailfish_iptables_dbus_signal(const gchar* signal,
	gint first_arg_type, ...);

DBusMessage* sailfish_iptables_dbus_method_return(DBusMessage* message,
	gint first_arg_type, ...);

void sailfish_iptables_dbus_send_signal(DBusMessage *signal);


/* These prototypes are connected to dbus */

DBusMessage* sailfish_iptables_save_firewall(DBusConnection *connection,
			DBusMessage *message, void *user_data);
					
DBusMessage* sailfish_iptables_load_firewall(DBusConnection *connection,
			DBusMessage *message, void *user_data);

DBusMessage* sailfish_iptables_clear_firewall(DBusConnection *connection,
			DBusMessage *message, void *user_data);

DBusMessage* sailfish_iptables_version(DBusConnection *connection,
			DBusMessage *message, void *user_data);
			
DBusMessage* sailfish_iptables_change_input_policy(
			DBusConnection *connection,	DBusMessage *message, void *user_data);

DBusMessage* sailfish_iptables_change_output_policy(
			DBusConnection *connection,	DBusMessage *message, void *user_data);

// ALLOW INCOMING
DBusMessage* sailfish_iptables_allow_incoming_ip(
			DBusConnection *connection,	DBusMessage *message, void *user_data);

DBusMessage* sailfish_iptables_allow_incoming_ip_port(
			DBusConnection *connection, DBusMessage *message, void *user_data);
			
DBusMessage* sailfish_iptables_allow_incoming_ip_port_range(
			DBusConnection *connection, DBusMessage *message, void *user_data);

DBusMessage* sailfish_iptables_allow_incoming_ip_service(
			DBusConnection *connection, DBusMessage *message, void *user_data);
			
DBusMessage* sailfish_iptables_allow_incoming_port(
			DBusConnection *connection, DBusMessage *message, void *user_data);
			
DBusMessage* sailfish_iptables_allow_incoming_port_range(
			DBusConnection *connection, DBusMessage *message, void *user_data);

DBusMessage* sailfish_iptables_allow_incoming_service(
			DBusConnection *connection, DBusMessage *message, void *user_data);

// ALLOW OUTGOING
DBusMessage* sailfish_iptables_allow_outgoing_ip(
			DBusConnection *connection, DBusMessage *message, void *user_data);
			
DBusMessage* sailfish_iptables_allow_outgoing_ip_port(
			DBusConnection *connection, DBusMessage *message, void *user_data);

DBusMessage* sailfish_iptables_allow_outgoing_ip_port_range(
			DBusConnection *connection, DBusMessage *message, void *user_data);

DBusMessage* sailfish_iptables_allow_outgoing_port(
			DBusConnection *connection, DBusMessage *message, void *user_data);

DBusMessage* sailfish_iptables_allow_outgoing_port_range(
			DBusConnection *connection, DBusMessage *message, void *user_data);

DBusMessage* sailfish_iptables_allow_outgoing_ip_service(
			DBusConnection *connection, DBusMessage *message, void *user_data);

DBusMessage* sailfish_iptables_allow_outgoing_service(
			DBusConnection *connection, DBusMessage *message, void *user_data);

// DENY INCOMING			
DBusMessage* sailfish_iptables_deny_incoming_ip(
			DBusConnection *connection, DBusMessage *message, void *user_data);

DBusMessage* sailfish_iptables_deny_incoming_ip_port(
			DBusConnection *connection,	DBusMessage *message, void *user_data);
			
DBusMessage* sailfish_iptables_deny_incoming_ip_port_range(
			DBusConnection *connection,	DBusMessage *message, void *user_data);
			
DBusMessage* sailfish_iptables_deny_incoming_port(
			DBusConnection *connection,	DBusMessage *message, void *user_data);
			
DBusMessage* sailfish_iptables_deny_incoming_port_range(
			DBusConnection *connection,	DBusMessage *message, void *user_data);

DBusMessage* sailfish_iptables_deny_incoming_ip_service(
			DBusConnection *connection, DBusMessage *message, void *user_data);

DBusMessage* sailfish_iptables_deny_incoming_service(
			DBusConnection *connection,	DBusMessage *message, void *user_data);


// DENY OUTGOING
DBusMessage* sailfish_iptables_deny_outgoing_ip(
			DBusConnection *connection,	DBusMessage *message, void *user_data);

DBusMessage* sailfish_iptables_deny_outgoing_ip_port(
			DBusConnection *connection, DBusMessage *message, void *user_data);

DBusMessage* sailfish_iptables_deny_outgoing_ip_port_range(
			DBusConnection *connection, DBusMessage *message, void *user_data);
			
DBusMessage* sailfish_iptables_deny_outgoing_port(
			DBusConnection *connection, DBusMessage *message, void *user_data);

DBusMessage* sailfish_iptables_deny_outgoing_port_range(
			DBusConnection *connection, DBusMessage *message, void *user_data);

DBusMessage* sailfish_iptables_deny_outgoing_ip_service(
			DBusConnection *connection,	DBusMessage *message, void *user_data);

DBusMessage* sailfish_iptables_deny_outgoing_service(
			DBusConnection *connection, DBusMessage *message, void *user_data);

#ifdef __cplusplus
}
#endif

#endif /* __SAILFISH_IPTABLES_DBUS_H_ */

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */
