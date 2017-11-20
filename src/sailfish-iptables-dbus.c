/*
 *
 *  Connection Manager dbus api implementation for SailfishOS
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
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */
 
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define CONNMAN_API_SUBJECT_TO_CHANGE

#include <errno.h>
#include "sailfish-iptables-dbus.h"

//#define DBG(fmt,arg...) connman_debug(fmt, ## arg)
#define ERR(fmt,arg...) connman_error(fmt, ## arg)

// Method names

#define SAILFISH_IPTABLES_GET_VERSION				"GetVersion"

#define SAILFISH_IPTABLES_ALLOW_IN_IP				"AllowIncomingIp"
#define SAILFISH_IPTABLES_ALLOW_IN_IP_PORT			"AllowIncomingIpWithPort"
#define SAILFISH_IPTABLES_ALLOW_IN_IP_PORT_RANGE	"AllowIncomingIpWithPortRange"
#define SAILFISH_IPTABLES_ALLOW_IN_PORT				"AllowIncomingPort"
#define SAILFISH_IPTABLES_ALLOW_IN_PORT_RANGE		"AllowIncomingPortRange"
#define SAILFISH_IPTABLES_ALLOW_IN_IP_SERVICE		"AllowIncomingIpWithService"
#define SAILFISH_IPTABLES_ALLOW_IN_SERVICE			"AllowIncomingService"

#define SAILFISH_IPTABLES_ALLOW_OUT_IP				"AllowOutgoingIp"
#define SAILFISH_IPTABLES_ALLOW_OUT_IP_PORT			"AllowOutgoingIpWithPort"
#define SAILFISH_IPTABLES_ALLOW_OUT_IP_PORT_RANGE	"AllowOutgoingIpWithPortRange"
#define SAILFISH_IPTABLES_ALLOW_OUT_PORT			"AllowOutgoingPort"
#define SAILFISH_IPTABLES_ALLOW_OUT_PORT_RANGE		"AllowOutgoingPortRange"
#define SAILFISH_IPTABLES_ALLOW_OUT_IP_SERVICE		"AllowOutgoingIpWithService"
#define SAILFISH_IPTABLES_ALLOW_OUT_SERVICE			"AllowOutgoingService"

#define SAILFISH_IPTABLES_DENY_IN_IP				"DenyIncomingIp"
#define SAILFISH_IPTABLES_DENY_IN_IP_PORT			"DenyIncomingIpWithPort"
#define SAILFISH_IPTABLES_DENY_IN_IP_PORT_RANGE		"DenyIncomingIpWithPortRange"
#define SAILFISH_IPTABLES_DENY_IN_PORT				"DenyIncomingPort"
#define SAILFISH_IPTABLES_DENY_IN_PORT_RANGE		"DenyIncomingPortRange"
#define SAILFISH_IPTABLES_DENY_IN_IP_SERVICE		"DenyIncomingIpWithService"
#define SAILFISH_IPTABLES_DENY_IN_SERVICE			"DenyIncomingService"

#define SAILFISH_IPTABLES_DENY_OUT_IP				"DenyOutgoingIp"
#define SAILFISH_IPTABLES_DENY_OUT_IP_PORT			"DenyOutgoingIpWithPort"
#define SAILFISH_IPTABLES_DENY_OUT_IP_PORT_RANGE	"DenyOutgoingIpWithPortRange"
#define SAILFISH_IPTABLES_DENY_OUT_PORT				"DenyOutgoingPort"
#define SAILFISH_IPTABLES_DENY_OUT_PORT_RANGE		"DenyOutgoingPortRange"
#define SAILFISH_IPTABLES_DENY_OUT_IP_SERVICE		"DenyOutgoingIpWithService"
#define SAILFISH_IPTABLES_DENY_OUT_SERVICE			"DenyOutgoingService"

#define SAILFISH_IPTABLES_CHANGE_IN_POLICY			"ChangeInputPolicy"
#define SAILFISH_IPTABLES_CHANGE_OUT_POLICY			"ChangeOutputPolicy"

#define SAILFISH_IPTABLES_SAVE_FIREWALL				"SaveFirewallToDisk"
#define SAILFISH_IPTABLES_LOAD_FIREWALL				"LoadFirewallFromDisk"
#define SAILFISH_IPTABLES_CLEAR_FIREWALL			"ClearFirewall"

#define SAILFISH_IPTABLES_RESULT				{"result", "b"}
/*
	Result codes:
	
	0 = ok
	1 = invalid IP
	2 = invalid port
	3 = invalid port range
	4 = invalid service name
	5 = invalid protocol
	6 = invalid policy
	7 = invalid file path
	8 = cannot process rule
	9 = cannot perform remove operation (rule does not exist)
*/

#define SAILFISH_IPTABLES_RESULT_TYPE			{"result", "q"}
#define SAILFISH_IPTABLES_RESULT_STRING			{"string", "s"}
#define SAILFISH_IPTABLES_RESULT_VERSION		{"version", "i"}


#define SAILFISH_IPTABLES_INPUT_ABSOLUTE_PATH	{"absolute_path","s"}
#define SAILFISH_IPTABLES_INPUT_IP				{"ip","s"}
#define SAILFISH_IPTABLES_INPUT_PORT			{"port","q"}
#define SAILFISH_IPTABLES_INPUT_PORT_STR		{"port","s"}
#define SAILFISH_IPTABLES_INPUT_SERVICE			{"service","s"}
#define SAILFISH_IPTABLES_INPUT_PROTOCOL		{"protocol","s"}
#define SAILFISH_IPTABLES_INPUT_OPERATION		{"operation","s"}
#define SAILFISH_IPTABLES_INPUT_POLICY			{"policy", "s"}

#define SAILFISH_IPTABLES_SIGNAL_POLICY_CHAIN	{"chain", "s"}
#define SAILFISH_IPTABLES_SIGNAL_POLICY_TYPE	SAILFISH_IPTABLES_INPUT_POLICY

// Signal names are defined in sailfish_iptables_dbus.h
static const GDBusSignalTable signals[] = {
		{ GDBUS_SIGNAL(
			SAILFISH_IPTABLES_SIGNAL_INIT,
			NULL)
		},
		{ GDBUS_SIGNAL(
			SAILFISH_IPTABLES_SIGNAL_STOP,
			NULL)
		},
		{ GDBUS_SIGNAL(
			SAILFISH_IPTABLES_SIGNAL_LOAD,
			NULL)
		},
		{ GDBUS_SIGNAL(
			SAILFISH_IPTABLES_SIGNAL_SAVE,
			NULL)
		},
		{ GDBUS_SIGNAL(
			SAILFISH_IPTABLES_SIGNAL_CLEAR,
			NULL)
		},
		{ GDBUS_SIGNAL(
			SAILFISH_IPTABLES_SIGNAL_POLICY,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_SIGNAL_POLICY_CHAIN, 
				SAILFISH_IPTABLES_SIGNAL_POLICY_TYPE))
		},
		{ GDBUS_SIGNAL(
			SAILFISH_IPTABLES_SIGNAL_RULE,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_IP,
				SAILFISH_IPTABLES_INPUT_PORT_STR,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION
			))
		},
		{ }
	};
	
static const GDBusMethodTable methods[] = {
		{ GDBUS_METHOD(SAILFISH_IPTABLES_SAVE_FIREWALL, 
			GDBUS_ARGS(SAILFISH_IPTABLES_INPUT_ABSOLUTE_PATH),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING),
			sailfish_iptables_save_firewall)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_LOAD_FIREWALL, 
			GDBUS_ARGS(SAILFISH_IPTABLES_INPUT_ABSOLUTE_PATH),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING),
			sailfish_iptables_load_firewall)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_CLEAR_FIREWALL, 
			NULL,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING),
			sailfish_iptables_clear_firewall)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_CHANGE_IN_POLICY, 
			GDBUS_ARGS(SAILFISH_IPTABLES_INPUT_POLICY),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_change_input_policy)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_CHANGE_OUT_POLICY, 
			GDBUS_ARGS(SAILFISH_IPTABLES_INPUT_POLICY),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_change_output_policy)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_ALLOW_IN_IP,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_IP,
				SAILFISH_IPTABLES_INPUT_OPERATION),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_allow_incoming_ip)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_ALLOW_IN_IP_PORT,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_IP,
				SAILFISH_IPTABLES_INPUT_PORT,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION
			),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_allow_incoming_ip_port)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_ALLOW_IN_IP_PORT_RANGE,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_IP,
				SAILFISH_IPTABLES_INPUT_PORT_STR,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION
			),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_allow_incoming_ip_port_range)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_ALLOW_IN_PORT,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_PORT,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION
			),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_allow_incoming_port)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_ALLOW_IN_PORT_RANGE,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_PORT_STR,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION
			),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_allow_incoming_port_range)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_ALLOW_IN_IP_SERVICE,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_IP,
				SAILFISH_IPTABLES_INPUT_SERVICE,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION
			),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_allow_incoming_ip_service)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_ALLOW_IN_SERVICE,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_SERVICE,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_allow_incoming_service)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_ALLOW_OUT_IP,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_IP,
				SAILFISH_IPTABLES_INPUT_OPERATION),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_allow_outgoing_ip)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_ALLOW_OUT_IP_PORT,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_IP,
				SAILFISH_IPTABLES_INPUT_PORT,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION
			),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_allow_outgoing_ip_port)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_ALLOW_OUT_IP_PORT_RANGE,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_IP,
				SAILFISH_IPTABLES_INPUT_PORT_STR,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION
			),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_allow_outgoing_ip_port_range)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_ALLOW_OUT_PORT,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_PORT,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION
			),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_allow_outgoing_port)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_ALLOW_OUT_PORT_RANGE,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_PORT_STR,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION
			),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_allow_outgoing_port_range)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_ALLOW_OUT_IP_SERVICE,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_IP,
				SAILFISH_IPTABLES_INPUT_SERVICE,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION
			),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_allow_outgoing_ip_service)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_ALLOW_OUT_SERVICE,
			GDBUS_ARGS(
			SAILFISH_IPTABLES_INPUT_SERVICE,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_allow_outgoing_service)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_DENY_IN_IP,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_IP,
				SAILFISH_IPTABLES_INPUT_OPERATION),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_deny_incoming_ip)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_DENY_IN_IP_PORT,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_IP,
				SAILFISH_IPTABLES_INPUT_PORT,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION
			),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_deny_incoming_ip_port)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_DENY_IN_IP_PORT_RANGE,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_IP,
				SAILFISH_IPTABLES_INPUT_PORT_STR,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION
			),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_deny_incoming_ip_port_range)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_DENY_IN_PORT,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_PORT,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION
			),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_deny_incoming_port)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_DENY_IN_PORT_RANGE,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_PORT_STR,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION
			),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_deny_incoming_port_range)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_DENY_IN_IP_SERVICE,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_IP,
				SAILFISH_IPTABLES_INPUT_SERVICE,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION
			),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_deny_incoming_ip_service)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_DENY_IN_SERVICE,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_SERVICE,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_deny_incoming_service)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_DENY_OUT_IP,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_IP,
				SAILFISH_IPTABLES_INPUT_OPERATION),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_deny_outgoing_ip)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_DENY_OUT_IP_PORT,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_IP,
				SAILFISH_IPTABLES_INPUT_PORT,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION
			),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_deny_outgoing_ip_port)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_DENY_OUT_IP_PORT_RANGE,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_IP,
				SAILFISH_IPTABLES_INPUT_PORT_STR,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION
			),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_deny_outgoing_ip_port_range)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_DENY_OUT_PORT,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_PORT,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION
			),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_deny_outgoing_port)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_DENY_OUT_PORT_RANGE,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_PORT_STR,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION
			),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_deny_outgoing_port_range)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_DENY_OUT_IP_SERVICE,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_IP,
				SAILFISH_IPTABLES_INPUT_SERVICE,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION
			),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_deny_outgoing_ip_service)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_DENY_OUT_SERVICE,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_SERVICE,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_deny_outgoing_service)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_GET_VERSION, 
			NULL,
			GDBUS_ARGS(SAILFISH_IPTABLES_RESULT_VERSION),
			sailfish_iptables_version)
		},
		{ }
	};

gint dbus_message_append_parameters_valist(DBusMessage *message,
	gint first_arg_type, va_list *params)
{
	if(message && params && first_arg_type != DBUS_TYPE_INVALID)
	{
		gint type = first_arg_type;
		DBusMessageIter iter;
		dbus_message_iter_init_append(message,&iter);
		
		while(type != DBUS_TYPE_INVALID)
		{
			const DBusBasicValue *val;
			val = va_arg(*params, const DBusBasicValue*);
			if(!dbus_message_iter_append_basic(&iter,type,&val))
				return 1;
			type = va_arg(*params,gint);
		}
	}
	return 0;
}

void sailfish_iptables_dbus_send_signal(DBusMessage *signal)
{
	DBusConnection* connman_dbus = dbus_connection_ref(
			connman_dbus_get_connection());
			
	g_dbus_send_message(connman_dbus,signal);
	dbus_connection_unref(connman_dbus);
}

DBusMessage* sailfish_iptables_dbus_signal(const gchar* signal_name,
	gint first_arg_type, ...)
{
	if(!signal_name) return NULL;
	
	DBusMessage *signal = dbus_message_new_signal(
					SAILFISH_IPTABLES_DBUS_PATH,
					SAILFISH_IPTABLES_DBUS_INTERFACE,
					signal_name);
					
	if(first_arg_type != DBUS_TYPE_INVALID && signal)
	{
		va_list params;
		va_start(params,first_arg_type);	
		
		if(dbus_message_append_parameters_valist(signal, first_arg_type, &params))
		{
			ERR("%s %s", "saifish_iptables_dbus_signal():",
				"failed to add parameters to signal");
			dbus_message_unref(signal);
			signal = NULL;
		}
		
		va_end(params);
	}
	return signal;
}

DBusMessage* sailfish_iptables_dbus_method_return(DBusMessage* message,
	gint first_arg_type, ...)
{
	if(!message) return NULL;
	
	DBusMessage *reply = dbus_message_new_method_return(message);
		
	if(first_arg_type != DBUS_TYPE_INVALID && reply)
	{
		va_list params;
		va_start(params, first_arg_type);
		
		if(dbus_message_append_parameters_valist(reply, first_arg_type, &params))
		{
			ERR("%s %s", "saifish_iptables_dbus_method_return():", 
				"failed to add parameters to reply");
			dbus_message_unref(reply);
			reply = NULL;
		}
		
		va_end(params);
	}
	
	return reply;
}

gint sailfish_iptables_dbus_register() {
	
	gint rval = 0;
	
	DBusConnection* conn = dbus_connection_ref(connman_dbus_get_connection());
	if(conn)
	{
		if(g_dbus_register_interface(conn,
			SAILFISH_IPTABLES_DBUS_PATH,
			SAILFISH_IPTABLES_DBUS_INTERFACE,
			methods,
			signals,
			NULL,
			NULL,
			NULL))
		{
			
			DBusMessage *signal = sailfish_iptables_dbus_signal(
					SAILFISH_IPTABLES_SIGNAL_INIT,
					DBUS_TYPE_INVALID, NULL);
				
			if(signal)
				sailfish_iptables_dbus_send_signal(signal);
		}
		else
		{
			DBG("%s %s", "sailfish_iptables_dbus_register():",
				"register failed");
			rval = -1;
		}
		dbus_connection_unref(conn);
	}
	else
	{
		DBG("%s %s","silfish_iptables_dbus_register():",
			"no dbus connection");
		rval = -1;
	}
	DBG("%s %s %s", "sailfish_iptables_dbus_register():",
			SAILFISH_IPTABLES_DBUS_PATH,
			SAILFISH_IPTABLES_DBUS_INTERFACE);
	return rval;
}

gint sailfish_iptables_dbus_unregister()
{
	gint rval = 0;

	DBusConnection* conn = dbus_connection_ref(connman_dbus_get_connection());
	if(conn)
	{
		if(g_dbus_unregister_interface(conn,
			SAILFISH_IPTABLES_DBUS_PATH,
			SAILFISH_IPTABLES_DBUS_INTERFACE))
		{
			DBusMessage *signal = sailfish_iptables_dbus_signal(
					SAILFISH_IPTABLES_SIGNAL_STOP,
					DBUS_TYPE_INVALID, NULL);
			if(signal)
				sailfish_iptables_dbus_send_signal(signal);
		}
		else
		{
			DBG("%s %s", "sailfish_iptables_dbus_unregister():",
				"unregsiter failed");
			rval = -1;
		}
	}
	else 
	{
		DBG("%s %s","sailfish_iptables_dbus_unregister():",
			"no dbus connection");
		rval = -1;
	}
	
	DBG("sailfish_iptables_dbus_unregister()");
	return rval;
}


