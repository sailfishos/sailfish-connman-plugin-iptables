/*
 *
 *  Sailfish Connection Manager iptables plugin
 *
 *  Copyright (C) 2017 Jolla Ltd. All rights reserved.
 *  Contact: Jussi Laakkonen <jussi.laakkonen@jolla.com>
 *
 *  BSD 3-Clause License
 * 
 *  Copyright (c) 2017, 
 *  All rights reserved.

 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 * 
 *  * Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 
 *  * Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 
 *  * Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.

 *    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *    DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 *    FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *    DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 *    SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 *    CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 *    OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *    OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef _SAILFISH_IPTABLES_DBUS_H_
#define _SAILFISH_IPTABLES_DBUS_H_

#include <stdbool.h>
#include <string.h>
#include <dbus/dbus.h>
#include <glib.h>

#include <connman/log.h>
#include <connman/plugin.h>
#include <connman/dbus.h>
#include <connman/iptables_extension.h>
#include <connman/gdbus.h>

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

DBusMessage* sailfish_iptables_clear_iptables(DBusConnection *connection,
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
