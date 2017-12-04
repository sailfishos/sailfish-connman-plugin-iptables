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
 
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define CONNMAN_API_SUBJECT_TO_CHANGE

#include <errno.h>
#include "sailfish-iptables-dbus.h"

//#define DBG(fmt,arg...) connman_debug(fmt, ## arg)
#define ERR(fmt,arg...) connman_error(fmt, ## arg)

// Method names

#define SAILFISH_IPTABLES_GET_VERSION			"GetVersion"

#define SAILFISH_IPTABLES_ALLOW_IN_IP			"AllowIncomingIp"
#define SAILFISH_IPTABLES_ALLOW_IN_IP_PORT		"AllowIncomingIpWithPort"
#define SAILFISH_IPTABLES_ALLOW_IN_IP_PORT_RANGE	"AllowIncomingIpWithPortRange"
#define SAILFISH_IPTABLES_ALLOW_IN_PORT			"AllowIncomingPort"
#define SAILFISH_IPTABLES_ALLOW_IN_PORT_RANGE		"AllowIncomingPortRange"
#define SAILFISH_IPTABLES_ALLOW_IN_IP_SERVICE		"AllowIncomingIpWithService"
#define SAILFISH_IPTABLES_ALLOW_IN_SERVICE		"AllowIncomingService"

#define SAILFISH_IPTABLES_ALLOW_OUT_IP			"AllowOutgoingIp"
#define SAILFISH_IPTABLES_ALLOW_OUT_IP_PORT		"AllowOutgoingIpWithPort"
#define SAILFISH_IPTABLES_ALLOW_OUT_IP_PORT_RANGE	"AllowOutgoingIpWithPortRange"
#define SAILFISH_IPTABLES_ALLOW_OUT_PORT		"AllowOutgoingPort"
#define SAILFISH_IPTABLES_ALLOW_OUT_PORT_RANGE		"AllowOutgoingPortRange"
#define SAILFISH_IPTABLES_ALLOW_OUT_IP_SERVICE		"AllowOutgoingIpWithService"
#define SAILFISH_IPTABLES_ALLOW_OUT_SERVICE		"AllowOutgoingService"

#define SAILFISH_IPTABLES_DENY_IN_IP			"DenyIncomingIp"
#define SAILFISH_IPTABLES_DENY_IN_IP_PORT		"DenyIncomingIpWithPort"
#define SAILFISH_IPTABLES_DENY_IN_IP_PORT_RANGE		"DenyIncomingIpWithPortRange"
#define SAILFISH_IPTABLES_DENY_IN_PORT			"DenyIncomingPort"
#define SAILFISH_IPTABLES_DENY_IN_PORT_RANGE		"DenyIncomingPortRange"
#define SAILFISH_IPTABLES_DENY_IN_IP_SERVICE		"DenyIncomingIpWithService"
#define SAILFISH_IPTABLES_DENY_IN_SERVICE		"DenyIncomingService"

#define SAILFISH_IPTABLES_DENY_OUT_IP			"DenyOutgoingIp"
#define SAILFISH_IPTABLES_DENY_OUT_IP_PORT		"DenyOutgoingIpWithPort"
#define SAILFISH_IPTABLES_DENY_OUT_IP_PORT_RANGE	"DenyOutgoingIpWithPortRange"
#define SAILFISH_IPTABLES_DENY_OUT_PORT			"DenyOutgoingPort"
#define SAILFISH_IPTABLES_DENY_OUT_PORT_RANGE		"DenyOutgoingPortRange"
#define SAILFISH_IPTABLES_DENY_OUT_IP_SERVICE		"DenyOutgoingIpWithService"
#define SAILFISH_IPTABLES_DENY_OUT_SERVICE		"DenyOutgoingService"

#define SAILFISH_IPTABLES_CHANGE_IN_POLICY		"ChangeInputPolicy"
#define SAILFISH_IPTABLES_CHANGE_OUT_POLICY		"ChangeOutputPolicy"

#define SAILFISH_IPTABLES_CLEAR_IPTABLES_TABLE		"ClearIptablesTable"

/*
	Result codes (enum sailfish_iptables_result):
	
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


#define SAILFISH_IPTABLES_INPUT_ABSOLUTE_PATH		{"absolute_path","s"}
#define SAILFISH_IPTABLES_INPUT_IP			{"ip","s"}
#define SAILFISH_IPTABLES_INPUT_PORT			{"port","q"}
#define SAILFISH_IPTABLES_INPUT_PORT_STR		{"port","s"}
#define SAILFISH_IPTABLES_INPUT_SERVICE			{"service","s"}
#define SAILFISH_IPTABLES_INPUT_PROTOCOL		{"protocol","s"}
#define SAILFISH_IPTABLES_INPUT_OPERATION		{"operation","s"}
#define SAILFISH_IPTABLES_INPUT_POLICY			{"policy", "s"}
#define SAILFISH_IPTABLES_INPUT_TABLE			{"table", "s"}

#define SAILFISH_IPTABLES_SIGNAL_POLICY_CHAIN		{"chain", "s"}
#define SAILFISH_IPTABLES_SIGNAL_POLICY_TYPE		SAILFISH_IPTABLES_INPUT_POLICY

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
		{ GDBUS_METHOD(SAILFISH_IPTABLES_CLEAR_IPTABLES_TABLE, 
			GDBUS_ARGS(SAILFISH_IPTABLES_INPUT_TABLE),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING),
			sailfish_iptables_clear_iptables)
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
	
/* New method sailfish_iptables_rule:
	IP: str / uint32
	Mask: uint8 (0-128)
	Port start: uint16
	Port end: uint16
	Protocol: uint8 (IPPROTO_TCP/UDP/SCTP))
	Operation: uint8 0/1 (add-default,remove)
	Direction: uint8 0/1 (INPUT/OUTPUT)
	Target:	uint8 0/1/2/3/4 (ACCEPT,DROP,QUEUE,RETURN,REJECT) - custom target?
	
*/

/* New method sailfish_iptables_new_custom_rule:
	IP: str / uint32
	Mask: uint8 (0-128)
	Port start: uint16
	Port end: uint16
	Protocol: uint8 (IPPROTO_TCP/UDP/SCTP))
	Operation: uint8 0/1 (add-default,remove)
	Direction: uint8 0/1 (INPUT/OUTPUT)
	Target:	str (custom chain name)
	
*/

/* New method: sailfish_iptables_new_chain
	Chain name: str
*/
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
		
		if(!dbus_message_append_args_valist(signal, first_arg_type, params))
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
			rval = 1;
		}
		dbus_connection_unref(conn);
	}
	else
	{
		DBG("%s %s","silfish_iptables_dbus_register():",
			"no dbus connection");
		rval = 1;
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
			rval = 1;
		}
	}
	else 
	{
		DBG("%s %s","sailfish_iptables_dbus_unregister():",
			"no dbus connection");
		rval = 1;
	}
	
	DBG("sailfish_iptables_dbus_unregister()");
	return rval;
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */
