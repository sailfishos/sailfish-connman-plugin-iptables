/*
 *
 *  Sailfish Connection Manager iptables plugin
 *
 *  BSD 3-Clause License
 * 
 *  Copyright (c) 2017-2018, Jolla Ltd.
 *  Contact: Jussi Laakkonen <jussi.laakkonen@jolla.com>
 *  All rights reserved.

 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 * 
 *  Redistributions of source code must retain the above copyright notice, this
 *  list of conditions and the following disclaimer.
 * 
 *  Redistributions in binary form must reproduce the above copyright notice,
 *  this list of conditions and the following disclaimer in the documentation
 *  and/or other materials provided with the distribution.
 * 
 *  Neither the name of the copyright holder nor the names of its
 *  contributors may be used to endorse or promote products derived from
 *  this software without specific prior written permission.

 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 *  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 *  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 *  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 *  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
 
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define CONNMAN_API_SUBJECT_TO_CHANGE

#include <errno.h>
#include <connman/log.h>

#include "sailfish-iptables-dbus.h"
#include "sailfish-iptables-parameters.h"
#include "sailfish-iptables-validate.h"
#include "sailfish-iptables-utils.h"
#include "sailfish-iptables-policy.h"
#include "sailfish-iptables.h"

//#define DBG(fmt,arg...) connman_debug(fmt, ## arg)
#define ERR(fmt,arg...) connman_error(fmt, ## arg)

// Method names

#define SAILFISH_IPTABLES_GET_VERSION			"GetVersion"

#define SAILFISH_IPTABLES_RULE_IP			"RuleIp"
#define SAILFISH_IPTABLES_RULE_IP_PORT			"RuleIpWithPort"
#define SAILFISH_IPTABLES_RULE_IP_PORT_RANGE		"RuleIpWithPortRange"
#define SAILFISH_IPTABLES_RULE_PORT			"RulePort"
#define SAILFISH_IPTABLES_RULE_PORT_RANGE		"RulePortRange"
#define SAILFISH_IPTABLES_RULE_IP_SERVICE		"RuleIpWithService"
#define SAILFISH_IPTABLES_RULE_SERVICE			"RuleService"

#define SAILFISH_IPTABLES_CHANGE_IN_POLICY		"ChangeInputPolicy"
#define SAILFISH_IPTABLES_CHANGE_OUT_POLICY		"ChangeOutputPolicy"
#define SAILFISH_IPTABLES_CHANGE_POLICY			"ChangePolicy"

#define SAILFISH_IPTABLES_CLEAR_IPTABLES_TABLE		"ClearIptablesTable"
#define SAILFISH_IPTABLES_CLEAR_IPTABLES_CHAINS		"ClearIptablesChains"

#define SAILFISH_IPTABLES_REGISTER_CLIENT		"Register"
#define SAILFISH_IPTABLES_UNREGISTER_CLIENT		"Unregister"

#define SAILFISH_IPTABLES_MANAGE_CHAIN			"ManageChain"

#define SAILFISH_IPTABLES_GET_IPTABLES_CONTENT		"GetIptablesContent"

/*
	Result codes (enum sailfish_iptables_result):
	
	0 = "Ok",
	1 = "Invalid IP",
	2 = "Invalid port",
	3 = "Invalid port range",
	4 = "Invalid service name",
	5 = "Invalid protocol",
	6 = "Invalid policy",
	7 = "Rule does not exist",
	8 = "Cannot process request",
	9 = "Cannot perform operation",
	10 = "Unauthorized, please try again",
	11 = "Unregister failed",
	12 = "Invalid chain name given. Chain name is reserved or does not exist."
	13 = "Invalid table name given."
	100 = "Access denied",
*/

#define SAILFISH_IPTABLES_RESULT_TYPE			{"result", "q"}
#define SAILFISH_IPTABLES_RESULT_STRING			{"string", "s"}
#define SAILFISH_IPTABLES_RESULT_VERSION		{"version", "i"}
#define SAILFISH_IPTABLES_RESULT_CHAINS			{"chains", "as"}
#define SAILFISH_IPTABLES_RESULT_RULES			{"rules", "as"}


#define SAILFISH_IPTABLES_INPUT_ABSOLUTE_PATH		{"absolute_path","s"}
#define SAILFISH_IPTABLES_INPUT_IP			{"ip","s"}
#define SAILFISH_IPTABLES_INPUT_IP_SRC			{"source_ip", "s"}
#define SAILFISH_IPTABLES_INPUT_IP_DST			{"destination_ip", "s"}
#define SAILFISH_IPTABLES_INPUT_PORT			{"port","q"}
#define SAILFISH_IPTABLES_INPUT_PORT_SRC		{"source_port","q"}
#define SAILFISH_IPTABLES_INPUT_PORT_DST		{"destination_port","q"}
#define SAILFISH_IPTABLES_INPUT_PORT_SRC_A		{"source_port_start","q"}
#define SAILFISH_IPTABLES_INPUT_PORT_SRC_B		{"source_port_end","q"}
#define SAILFISH_IPTABLES_INPUT_PORT_DST_A		{"destination_port_start","q"}
#define SAILFISH_IPTABLES_INPUT_PORT_DST_B		{"destination_port_end","q"}
#define SAILFISH_IPTABLES_INPUT_SERVICE_SRC		{"source_service","s"}
#define SAILFISH_IPTABLES_INPUT_SERVICE_DST		{"destination_service","s"}
#define SAILFISH_IPTABLES_INPUT_PROTOCOL_STR		{"protocol","s"}
#define SAILFISH_IPTABLES_INPUT_PROTOCOL		{"protocol","u"}
#define SAILFISH_IPTABLES_INPUT_OPERATION		{"operation","q"}
#define SAILFISH_IPTABLES_INPUT_POLICY_INT		{"policy", "q"}
#define SAILFISH_IPTABLES_INPUT_TABLE			{"table", "s"}
#define SAILFISH_IPTABLES_INPUT_CHAIN			{"chain", "s"}
#define SAILFISH_IPTABLES_INPUT_TARGET			{"target", "s"}

#define SAILFISH_IPTABLES_SIGNAL_POLICY_CHAIN		SAILFISH_IPTABLES_INPUT_CHAIN
#define SAILFISH_IPTABLES_SIGNAL_POLICY_TYPE		{"policy", "s"}
#define SAILFISH_IPTABLES_SIGNAL_TABLE			SAILFISH_IPTABLES_INPUT_TABLE

/* These prototypes are connected to dbus */

static DBusMessage* sailfish_iptables_register_client(
			DBusConnection* connection, DBusMessage* message, void *user_data);
			
static DBusMessage* sailfish_iptables_unregister_client(
			DBusConnection* connection, DBusMessage* message, void *user_data);

static DBusMessage* sailfish_iptables_clear_iptables_rules(
			DBusConnection *connection, DBusMessage *message, void *user_data);
			
static DBusMessage* sailfish_iptables_clear_iptables_chains(
			DBusConnection *connection, DBusMessage *message, void *user_data);
			
static DBusMessage* sailfish_iptables_get_iptables_content(
			DBusConnection *connection, DBusMessage *message, void *user_data);

static DBusMessage* sailfish_iptables_version(DBusConnection *connection,
			DBusMessage *message, void *user_data);

static DBusMessage* sailfish_iptables_change_policy(
			DBusConnection *connection,	DBusMessage *message, void *user_data);

// New api functions
static DBusMessage* sailfish_iptables_rule_ip(
			DBusConnection *connection,	DBusMessage *message, void *user_data);

static DBusMessage* sailfish_iptables_rule_ip_port(
			DBusConnection *connection,	DBusMessage *message, void *user_data);

static DBusMessage* sailfish_iptables_rule_ip_port_range(
			DBusConnection *connection,	DBusMessage *message, void *user_data);

static DBusMessage* sailfish_iptables_rule_port(
			DBusConnection *connection,	DBusMessage *message, void *user_data);

static DBusMessage* sailfish_iptables_rule_port_range(
			DBusConnection *connection,	DBusMessage *message, void *user_data);

static DBusMessage* sailfish_iptables_rule_ip_service(
			DBusConnection *connection,	DBusMessage *message, void *user_data);

static DBusMessage* sailfish_iptables_rule_service(
			DBusConnection *connection,	DBusMessage *message, void *user_data);

// Chain management
static DBusMessage* sailfish_iptables_manage_chain(
			DBusConnection *connection,	DBusMessage *message, void *user_data);

const gchar const * OP_STR[] = {"Add", "Remove", "Undefined", NULL};

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
			GDBUS_ARGS(
				SAILFISH_IPTABLES_SIGNAL_TABLE
			))
		},
		{ GDBUS_SIGNAL(
			SAILFISH_IPTABLES_SIGNAL_CLEAR_CHAINS,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_SIGNAL_TABLE
			))
		},
		{ GDBUS_SIGNAL(
			SAILFISH_IPTABLES_SIGNAL_POLICY,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_SIGNAL_TABLE,
				SAILFISH_IPTABLES_SIGNAL_POLICY_CHAIN, 
				SAILFISH_IPTABLES_SIGNAL_POLICY_TYPE))
		},
		{ GDBUS_SIGNAL(
			SAILFISH_IPTABLES_SIGNAL_CHAIN,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_SIGNAL_TABLE,
				SAILFISH_IPTABLES_SIGNAL_POLICY_CHAIN,
				SAILFISH_IPTABLES_INPUT_OPERATION
			))
		},
		{ GDBUS_SIGNAL(
			SAILFISH_IPTABLES_SIGNAL_RULE_ADD,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_TABLE,
				SAILFISH_IPTABLES_INPUT_CHAIN,
				SAILFISH_IPTABLES_INPUT_TARGET,
				SAILFISH_IPTABLES_INPUT_IP_SRC,
				SAILFISH_IPTABLES_INPUT_IP_DST,
				SAILFISH_IPTABLES_INPUT_PORT_SRC_A,
				SAILFISH_IPTABLES_INPUT_PORT_SRC_B,
				SAILFISH_IPTABLES_INPUT_PORT_DST_A,
				SAILFISH_IPTABLES_INPUT_PORT_DST_B,
				SAILFISH_IPTABLES_INPUT_PROTOCOL_STR
			))
		},
		{ GDBUS_SIGNAL(
			SAILFISH_IPTABLES_SIGNAL_RULE_REM,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_TABLE,
				SAILFISH_IPTABLES_INPUT_CHAIN,
				SAILFISH_IPTABLES_INPUT_TARGET,
				SAILFISH_IPTABLES_INPUT_IP_SRC,
				SAILFISH_IPTABLES_INPUT_IP_DST,
				SAILFISH_IPTABLES_INPUT_PORT_SRC_A,
				SAILFISH_IPTABLES_INPUT_PORT_SRC_B,
				SAILFISH_IPTABLES_INPUT_PORT_DST_A,
				SAILFISH_IPTABLES_INPUT_PORT_DST_B,
				SAILFISH_IPTABLES_INPUT_PROTOCOL_STR
			))
		},
		{ }
	};
	
static const GDBusMethodTable methods[] = {
		{ GDBUS_METHOD(SAILFISH_IPTABLES_REGISTER_CLIENT, 
			NULL,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_register_client)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_UNREGISTER_CLIENT, 
			NULL,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_unregister_client)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_CLEAR_IPTABLES_TABLE, 
			GDBUS_ARGS(SAILFISH_IPTABLES_INPUT_TABLE),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING),
			sailfish_iptables_clear_iptables_rules)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_CLEAR_IPTABLES_CHAINS, 
			GDBUS_ARGS(SAILFISH_IPTABLES_INPUT_TABLE),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING),
			sailfish_iptables_clear_iptables_chains)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_GET_IPTABLES_CONTENT, 
			GDBUS_ARGS(SAILFISH_IPTABLES_INPUT_TABLE),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING,
				SAILFISH_IPTABLES_RESULT_CHAINS,
				SAILFISH_IPTABLES_RESULT_RULES
				),
			sailfish_iptables_get_iptables_content)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_MANAGE_CHAIN, 
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_TABLE,
				SAILFISH_IPTABLES_INPUT_CHAIN,
				SAILFISH_IPTABLES_INPUT_OPERATION),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_manage_chain)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_CHANGE_POLICY, 
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_TABLE,
				SAILFISH_IPTABLES_INPUT_CHAIN,
				SAILFISH_IPTABLES_INPUT_POLICY_INT),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_change_policy)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_RULE_IP,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_TABLE,
				SAILFISH_IPTABLES_INPUT_CHAIN,
				SAILFISH_IPTABLES_INPUT_TARGET,
				SAILFISH_IPTABLES_INPUT_IP_SRC,
				SAILFISH_IPTABLES_INPUT_IP_DST,
				SAILFISH_IPTABLES_INPUT_OPERATION),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_rule_ip)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_RULE_IP_PORT,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_TABLE,
				SAILFISH_IPTABLES_INPUT_CHAIN,
				SAILFISH_IPTABLES_INPUT_TARGET,
				SAILFISH_IPTABLES_INPUT_IP_SRC,
				SAILFISH_IPTABLES_INPUT_IP_DST,
				SAILFISH_IPTABLES_INPUT_PORT_SRC,
				SAILFISH_IPTABLES_INPUT_PORT_DST,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION
			),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_rule_ip_port)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_RULE_IP_PORT_RANGE,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_TABLE,
				SAILFISH_IPTABLES_INPUT_CHAIN,
				SAILFISH_IPTABLES_INPUT_TARGET,
				SAILFISH_IPTABLES_INPUT_IP_SRC,
				SAILFISH_IPTABLES_INPUT_IP_DST,
				SAILFISH_IPTABLES_INPUT_PORT_SRC_A,
				SAILFISH_IPTABLES_INPUT_PORT_SRC_B,
				SAILFISH_IPTABLES_INPUT_PORT_DST_A,
				SAILFISH_IPTABLES_INPUT_PORT_DST_B,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION
			),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_rule_ip_port_range)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_RULE_IP_SERVICE,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_TABLE,
				SAILFISH_IPTABLES_INPUT_CHAIN,
				SAILFISH_IPTABLES_INPUT_TARGET,
				SAILFISH_IPTABLES_INPUT_IP_SRC,
				SAILFISH_IPTABLES_INPUT_IP_DST,
				SAILFISH_IPTABLES_INPUT_SERVICE_SRC,
				SAILFISH_IPTABLES_INPUT_SERVICE_DST,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION
			),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_rule_ip_service)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_RULE_PORT,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_TABLE,
				SAILFISH_IPTABLES_INPUT_CHAIN,
				SAILFISH_IPTABLES_INPUT_TARGET,
				SAILFISH_IPTABLES_INPUT_PORT_SRC,
				SAILFISH_IPTABLES_INPUT_PORT_DST,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION
			),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_rule_port)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_RULE_PORT_RANGE,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_TABLE,
				SAILFISH_IPTABLES_INPUT_CHAIN,
				SAILFISH_IPTABLES_INPUT_TARGET,
				SAILFISH_IPTABLES_INPUT_PORT_SRC_A,
				SAILFISH_IPTABLES_INPUT_PORT_SRC_B,
				SAILFISH_IPTABLES_INPUT_PORT_DST_A,
				SAILFISH_IPTABLES_INPUT_PORT_DST_B,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION
			),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_rule_port_range)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_RULE_SERVICE,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_TABLE,
				SAILFISH_IPTABLES_INPUT_CHAIN,
				SAILFISH_IPTABLES_INPUT_TARGET,
				SAILFISH_IPTABLES_INPUT_SERVICE_SRC,
				SAILFISH_IPTABLES_INPUT_SERVICE_DST,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_rule_service)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_GET_VERSION, 
			NULL,
			GDBUS_ARGS(SAILFISH_IPTABLES_RESULT_VERSION),
			sailfish_iptables_version)
		},
		{ }
	};

static void dbus_client_destroy(void *user_data)
{
	if(user_data)
	{
		client_disconnect_data *data = (client_disconnect_data*)user_data;
	
		api_data_remove_peer(data->main_data, data->client_name);
	
		client_disconnect_data_free(data);
	}
}

static void dbus_client_disconnected(DBusConnection *connection,
	void *user_data)
{
	dbus_client_destroy(user_data);
}

DBusMessage* sailfish_iptables_register_client(DBusConnection* connection,
			DBusMessage* message, void *user_data)
{
	api_data *data = (api_data*)user_data;
	api_result result = OK;
	
	DAPeer* peer = sailfish_iptables_policy_get_peer(message, data);
	
	if(peer && sailfish_iptables_policy_check_peer(data, peer,
		SAILFISH_DBUS_ACCESS_LISTEN))
	{
		dbus_client *client = dbus_client_new();

		client->peer = da_peer_ref(peer);

		client_disconnect_data* disconnect_data = client_disconnect_data_new(
			data, client);

		client->watch_id = g_dbus_add_disconnect_watch(connection,
			client->peer->name, dbus_client_disconnected, disconnect_data,
			NULL);

		if(client->watch_id)
			api_data_add_peer(data,client);
		else
		{
			dbus_client_free(client);
			client_disconnect_data_free(disconnect_data);
			result = UNAUTHORIZED; // Couldn't add -> not authorized, try again
			DBG("%s %s %s", PLUGIN_NAME,
				"sailfish_iptables_register_client failed for", peer->name);
		}
	}
	else
		result = ACCESS_DENIED;
	
	return sailfish_iptables_dbus_reply_result(message, result, NULL);
}
			
DBusMessage* sailfish_iptables_unregister_client(DBusConnection* connection,
			DBusMessage* message, void *user_data)
{
	api_data *data = (api_data*)user_data;
	api_result result = OK;
	
	const gchar* sender = dbus_message_get_sender(message);
	
	if(!api_data_remove_peer(data,sender))
		result = REMOVE_FAILED;
	
	return sailfish_iptables_dbus_reply_result(message, result, NULL);
}

DBusMessage* sailfish_iptables_clear_iptables_rules(DBusConnection *connection,
			DBusMessage *message, void *user_data)
{
	return process_request(message, &clear_iptables_rules, ARGS_CLEAR,
		user_data);
}

DBusMessage* sailfish_iptables_clear_iptables_chains(DBusConnection *connection,
			DBusMessage *message, void *user_data)
{
	return process_request(message, &clear_iptables_chains, ARGS_CLEAR_CHAINS,
		user_data);
}

DBusMessage* sailfish_iptables_get_iptables_content(DBusConnection *connection,
			DBusMessage *message, void *user_data)
{
	return process_request(message, &get_iptables_content, ARGS_GET_CONTENT,
		user_data);
}

DBusMessage* sailfish_iptables_version(DBusConnection *connection,
			DBusMessage *message, void *user_data)
{
	dbus_int32_t res = (dbus_int32_t)SAILFISH_IPTABLES_INTERFACE_VERSION;

	DBusMessage* reply = g_dbus_create_reply(message,
		DBUS_TYPE_INT32,	&res,
		DBUS_TYPE_INVALID);

	if(!reply)
		reply = g_dbus_create_error(message,DBUS_ERROR_NO_MEMORY,
			"failed to add parameters to reply.");
	return reply;
}

DBusMessage* sailfish_iptables_change_policy(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return process_request(message, &set_policy, ARGS_POLICY, user_data);
}

// Rules 
DBusMessage* sailfish_iptables_rule_ip(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return process_request(message, &add_rule_to_iptables, ARGS_IP,
		user_data);
}

DBusMessage* sailfish_iptables_rule_ip_port(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return process_request(message, &add_rule_to_iptables, ARGS_IP_PORT,
		user_data);
}

DBusMessage* sailfish_iptables_rule_ip_port_range(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return process_request(message, &add_rule_to_iptables, ARGS_IP_PORT_RANGE,
		user_data);
}

DBusMessage* sailfish_iptables_rule_port(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return process_request(message, &add_rule_to_iptables, ARGS_PORT,
		user_data);
}

DBusMessage* sailfish_iptables_rule_port_range(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return process_request(message, &add_rule_to_iptables, ARGS_PORT_RANGE,
		user_data);
}

DBusMessage* sailfish_iptables_rule_ip_service(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return process_request(message, &add_rule_to_iptables, ARGS_IP_SERVICE,
		user_data);
}

DBusMessage* sailfish_iptables_rule_service(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return process_request(message, &add_rule_to_iptables, ARGS_SERVICE,
		user_data);
}

DBusMessage* sailfish_iptables_manage_chain(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return process_request(message, &manage_chain, ARGS_CHAIN, user_data);
}

void sailfish_iptables_dbus_send_signal(DBusMessage *signal, api_data* data)
{
	DBusConnection* conn = 	connman_dbus_get_connection();

	if(conn)
	{
		// Send to all
		if(!data)
			g_dbus_send_message(conn,signal);
			
		// Send to registered clients only
		else if (g_hash_table_size(data->clients))
		{
			GHashTableIter iter;
			gpointer key = NULL;
			
			g_hash_table_iter_init(&iter, data->clients);
			
			while(g_hash_table_iter_next(&iter, &key, NULL)) {
				DBusMessage *copy = dbus_message_copy(signal);
				dbus_message_set_destination(copy, (const gchar*)key);
				g_dbus_send_message(conn, copy);
				DBG("%s %s %s", PLUGIN_NAME, 
					"sailfish_iptables_dbus_send_signal to", (const gchar*)key);
			}
			
			dbus_message_unref(signal);
		}
		
		dbus_connection_unref(conn);
	}
}

DBusMessage* sailfish_iptables_dbus_signal(const gchar* signal_name,
	gint first_arg_type, ...)
{
	if(!signal_name || !*signal_name)
		return NULL;
	
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
			ERR("%s %s %s", PLUGIN_NAME, "saifish_iptables_dbus_signal():",
				"failed to add parameters to signal");
			dbus_message_unref(signal);
			signal = NULL;
		}
		
		va_end(params);
	}
	return signal;
}

DBusMessage* sailfish_iptables_dbus_reply_result(DBusMessage *message,
	api_result result, rule_params *params)
{
	dbus_uint16_t res = (dbus_uint16_t)result;
	DBusMessage* reply = NULL;

	if(!params || !params->iptables_content)
		reply = g_dbus_create_reply(message,
			DBUS_TYPE_UINT16,	&res,
			DBUS_TYPE_INVALID);
	
	else if(params->iptables_content)
	{
		DBusMessageIter iter, array;
		GList *list_iter = NULL;
		
		reply = dbus_message_new_method_return(message);
			
		dbus_message_iter_init_append(reply, &iter);
		
		dbus_message_iter_append_basic(&iter, DBUS_TYPE_UINT16, &res);
		
		// Chains
		dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_TYPE_STRING_AS_STRING, &array);
			
		for(list_iter = params->iptables_content->chains ;
			list_iter ;
			list_iter = list_iter->next)
		{
			gchar* content = (gchar*)list_iter->data;
			dbus_message_iter_append_basic(&array, DBUS_TYPE_STRING, &content);
		}
		
		dbus_message_iter_close_container(&iter, &array);
		
		// Rules
		dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_TYPE_STRING_AS_STRING, &array);
			
		for(list_iter = params->iptables_content->rules ;
			list_iter ;
			list_iter = list_iter->next)
		{
			gchar* content = (gchar*)list_iter->data;
			dbus_message_iter_append_basic(&array, DBUS_TYPE_STRING, &content);
		}
		
		dbus_message_iter_close_container(&iter, &array);
		
		// Last
		dbus_message_append_args(reply, DBUS_TYPE_INVALID);
	}

	if(!reply)
		reply = g_dbus_create_error(message,DBUS_ERROR_NO_MEMORY,
			"failed to add parameters to reply.");
	
	rule_params_free(params);
	
	return reply;
}

DBusMessage* sailfish_iptables_dbus_signal_from_rule_params(rule_params* params)
{
	DBusMessage* signal = NULL;
	gchar *empty = EMPTY_STR;
	const gchar* signal_name = NULL;

	switch(params->args)
	{
		case ARGS_IP:
		case ARGS_IP_PORT:
		case ARGS_IP_PORT_RANGE:
		case ARGS_IP_SERVICE:
		case ARGS_PORT:
		case ARGS_PORT_RANGE:
		case ARGS_SERVICE:
			switch(params->operation)
			{
				case ADD:
					signal_name = SAILFISH_IPTABLES_SIGNAL_RULE_ADD;
					break;
				case REMOVE:
					signal_name = SAILFISH_IPTABLES_SIGNAL_RULE_REM;
					break;
				// Rules can be only added or removed
				default:
					return NULL;
			}
			signal = sailfish_iptables_dbus_signal(
				signal_name,
				DBUS_TYPE_STRING,	params->table ? &(params->table) : &empty,
				DBUS_TYPE_STRING,	params->chain ? &(params->chain) : &empty,
				DBUS_TYPE_STRING,	params->target ? &(params->target) : &empty,
				DBUS_TYPE_STRING,	params->ip_src ? &(params->ip_src) : &empty,
				DBUS_TYPE_STRING,	params->ip_dst ? &(params->ip_dst) : &empty,
				DBUS_TYPE_UINT16,	&(params->port_src[0]),
				DBUS_TYPE_UINT16,	&(params->port_src[1]),
				DBUS_TYPE_UINT16,	&(params->port_dst[0]),
				DBUS_TYPE_UINT16,	&(params->port_dst[1]),
				DBUS_TYPE_STRING,	params->protocol ? &(params->protocol) : 
					&empty,
				DBUS_TYPE_INVALID);
			break;
		case ARGS_CLEAR:
			signal = sailfish_iptables_dbus_signal(
				SAILFISH_IPTABLES_SIGNAL_CLEAR,
				DBUS_TYPE_STRING,	params->table ? &(params->table) : &empty,
				DBUS_TYPE_INVALID);
			break;
		case ARGS_CLEAR_CHAINS:
			signal = sailfish_iptables_dbus_signal(
				SAILFISH_IPTABLES_SIGNAL_CLEAR_CHAINS,
				DBUS_TYPE_STRING,	params->table ? &(params->table) : &empty,
				DBUS_TYPE_INVALID);
			break;
		case ARGS_POLICY:
			signal = sailfish_iptables_dbus_signal(
				SAILFISH_IPTABLES_SIGNAL_POLICY,
				DBUS_TYPE_STRING,	params->table ? &(params->table) : &empty,
				DBUS_TYPE_STRING,	params->chain ? &(params->chain) : &empty,
				DBUS_TYPE_STRING,	params->policy ? &(params->policy) : &empty,
				DBUS_TYPE_INVALID);
			break;
		case ARGS_CHAIN:
			signal = sailfish_iptables_dbus_signal(
				SAILFISH_IPTABLES_SIGNAL_CHAIN,
				DBUS_TYPE_STRING,	params->table ? &(params->table) : &empty,
				DBUS_TYPE_STRING,	params->chain ? &(params->chain) : &empty,
				DBUS_TYPE_UINT16,	&(params->operation),
				DBUS_TYPE_INVALID);
		default:
			break;
	}

	return signal;
}

rule_params* sailfish_iptables_dbus_get_parameters_from_msg(
	DBusMessage* message, rule_args args)
{
	rule_params *params = rule_params_new(args);
	DBusError* error = NULL;
	
	gchar *ip_src = NULL, *ip_dst = NULL, *target = NULL, *table = NULL;
	gchar *chain_name = NULL, *custom_chain_name = NULL;
	gchar *service_dst = NULL, *service_src = NULL, *service_lowercase = NULL;
	dbus_uint16_t port_dst[2] = {0};
	dbus_uint16_t port_src[2] = {0};
	dbus_uint16_t operation = 0, policy_int = 0;
	dbus_uint32_t protocol_int = 0;
	gint index = 0;
	
	gboolean rval = false;
	
	switch(params->args)
	{
		case ARGS_IP:
			rval = dbus_message_get_args(message, error,
						DBUS_TYPE_STRING, &table,
						DBUS_TYPE_STRING, &chain_name,
						DBUS_TYPE_STRING, &target,
						DBUS_TYPE_STRING, &ip_src,
						DBUS_TYPE_STRING, &ip_dst,
						DBUS_TYPE_UINT16, &operation,
						DBUS_TYPE_INVALID);
			break;
		case ARGS_IP_PORT:
			rval = dbus_message_get_args(message, error,
						DBUS_TYPE_STRING, &table,
						DBUS_TYPE_STRING, &chain_name,
						DBUS_TYPE_STRING, &target,
						DBUS_TYPE_STRING, &ip_src,
						DBUS_TYPE_STRING, &ip_dst,
						DBUS_TYPE_UINT16, &port_src,
						DBUS_TYPE_UINT16, &port_dst,
						DBUS_TYPE_UINT32, &protocol_int,
						DBUS_TYPE_UINT16, &operation,
						DBUS_TYPE_INVALID);
			break;
		case ARGS_IP_PORT_RANGE:
			rval = dbus_message_get_args(message, error,
						DBUS_TYPE_STRING, &table,
						DBUS_TYPE_STRING, &chain_name,
						DBUS_TYPE_STRING, &target,
						DBUS_TYPE_STRING, &ip_src,
						DBUS_TYPE_STRING, &ip_dst,
						DBUS_TYPE_UINT16, &(port_src[0]),
						DBUS_TYPE_UINT16, &(port_src[1]),
						DBUS_TYPE_UINT16, &(port_dst[0]),
						DBUS_TYPE_UINT16, &(port_dst[1]),
						DBUS_TYPE_UINT32, &protocol_int,
						DBUS_TYPE_UINT16, &operation,
						DBUS_TYPE_INVALID);
			break;
		case ARGS_IP_SERVICE:
			rval = dbus_message_get_args(message, error,
						DBUS_TYPE_STRING, &table,
						DBUS_TYPE_STRING, &chain_name,
						DBUS_TYPE_STRING, &target,
						DBUS_TYPE_STRING, &ip_src,
						DBUS_TYPE_STRING, &ip_dst,
						DBUS_TYPE_STRING, &service_src,
						DBUS_TYPE_STRING, &service_dst,
						DBUS_TYPE_UINT32, &protocol_int,
						DBUS_TYPE_UINT16, &operation,
						DBUS_TYPE_INVALID);
			break;
		case ARGS_PORT:
			rval = dbus_message_get_args(message, error,
						DBUS_TYPE_STRING, &table,
						DBUS_TYPE_STRING, &chain_name,
						DBUS_TYPE_STRING, &target,
						DBUS_TYPE_UINT16, &port_src,
						DBUS_TYPE_UINT16, &port_dst,
						DBUS_TYPE_UINT32, &protocol_int,
						DBUS_TYPE_UINT16, &operation,
						DBUS_TYPE_INVALID);
			break;
		case ARGS_PORT_RANGE:
			rval = dbus_message_get_args(message, error,
						DBUS_TYPE_STRING, &table,
						DBUS_TYPE_STRING, &chain_name,
						DBUS_TYPE_STRING, &target,
						DBUS_TYPE_UINT16, &(port_src[0]),
						DBUS_TYPE_UINT16, &(port_src[1]),
						DBUS_TYPE_UINT16, &(port_dst[0]),
						DBUS_TYPE_UINT16, &(port_dst[1]),
						DBUS_TYPE_UINT32, &protocol_int,
						DBUS_TYPE_UINT16, &operation,
						DBUS_TYPE_INVALID);
			break;
		case ARGS_SERVICE:
			rval = dbus_message_get_args(message, error,
						DBUS_TYPE_STRING, &table,
						DBUS_TYPE_STRING, &chain_name,
						DBUS_TYPE_STRING, &target,
						DBUS_TYPE_STRING, &service_src,
						DBUS_TYPE_STRING, &service_dst,
						DBUS_TYPE_UINT32, &protocol_int,
						DBUS_TYPE_UINT16, &operation,
						DBUS_TYPE_INVALID);
			break;
		case ARGS_CLEAR:
		case ARGS_CLEAR_CHAINS:
			rval = dbus_message_get_args(message, error,
						DBUS_TYPE_STRING, &table,
						DBUS_TYPE_INVALID);
			break;
		case ARGS_POLICY:
			rval = dbus_message_get_args(message, error,
						DBUS_TYPE_STRING, &table,
						DBUS_TYPE_STRING, &chain_name,
						DBUS_TYPE_UINT16, &policy_int,
						DBUS_TYPE_INVALID);
			break;
		case ARGS_CHAIN:
			rval = dbus_message_get_args(message, error,
						DBUS_TYPE_STRING, &table,
						DBUS_TYPE_STRING, &custom_chain_name,
						DBUS_TYPE_UINT16, &operation,
						DBUS_TYPE_INVALID);
			break;
		case ARGS_GET_CONTENT:
			rval = dbus_message_get_args(message, error,
						DBUS_TYPE_STRING, &table,
						DBUS_TYPE_INVALID);
			break;
	}
	
	if(error)
	{
		DBG("%s %s %s %s", PLUGIN_NAME, "Error,",
			!rval ? "Could not get args from dbus message" : "",
			error->message);
		rule_params_free(params);
		dbus_error_free(error);
		return NULL;
	}
	
	// Source IP (iptables -s)
	if(ip_src && g_utf8_validate(ip_src,-1,NULL) &&
		validate_ip_address(IPV4, ip_src))
	{
		if(negated_ip_address(ip_src))
		{
			params->ip_src = format_ip(IPV4, &(ip_src[1]));
			params->ip_negate_src = true;
		}
		else
			params->ip_src = format_ip(IPV4, ip_src);
	}
	
	// Destination IP (iptables -d)
	if(ip_dst && g_utf8_validate(ip_dst,-1,NULL) &&
		validate_ip_address(IPV4,ip_dst))
	{
		if(negated_ip_address(ip_dst))
		{
			params->ip_dst = format_ip(IPV4, &(ip_dst[1]));
			params->ip_negate_dst = true;
		}
		else
			params->ip_dst = format_ip(IPV4,ip_dst);
	}
	
	// Protocol number set (proto = 0, not supported, see /etc/protocols)
	// G_MAXUINT32 = all
	if(protocol_int)
		params->protocol = validate_protocol_int(protocol_int);
	
	// Service destination defined
	if(service_dst && *service_dst && g_utf8_validate(service_dst,-1,NULL))
	{
		service_lowercase = g_utf8_strdown(service_dst,-1);
		
		// Check if the service with given name can be found, port and
		// protocol can be retrieved then also
		if((params->port_dst[0] = validate_service_name(service_lowercase)))
		{
			params->service_dst	= service_lowercase;
			
			if(!params->protocol)
				params->protocol = get_protocol_for_service(params->service_dst);
		}
	}
	
	// Service source defined
	if(service_src && *service_src && g_utf8_validate(service_src,-1,NULL))
	{
		service_lowercase = g_utf8_strdown(service_src,-1);
		
		// Check if the service with given name can be found, port and
		// protocol can be retrieved then also
		if((params->port_src[0] = validate_service_name(service_lowercase)))
		{
			params->service_src	= service_lowercase;
			
			if(!params->protocol)
				params->protocol = get_protocol_for_service(
										params->service_src);
		}
	}
	
	// Check both ports
	for(index = 0; index < 2 ; index++)
	{
		if(port_dst[index] && validate_port(port_dst[index]))
		{
			params->port_dst[index] = port_dst[index];

			if(!params->protocol)
				params->protocol = get_protocol_for_port(
										params->port_dst[index]);
		}
		
		if(port_src[index] && validate_port(port_src[index]))
		{
			params->port_src[index] = port_src[index];

			if(!params->protocol)
				params->protocol = get_protocol_for_port(
										params->port_src[index]);
		}
	}
	
	// Operation is always set, if operation is UNDEFINED check_parameters()
	// will return INVALID_REQUEST
	params->operation = validate_operation(operation);
	
	// For now always default to "filter" table (SAILFISH_IPTABLES_TABLE_NAME)
	if(table && *table && g_utf8_validate(table,-1,NULL))
		params->table = g_strdup(SAILFISH_IPTABLES_TABLE_NAME);
		//params->table = g_utf8_strdown(table,-1);
	else
		params->table = g_strdup(SAILFISH_IPTABLES_TABLE_NAME);
	
	if(policy_int)
		params->policy = validate_policy_int(policy_int);
	
	// Chain from a iptables rule
	if(chain_name && *chain_name && g_utf8_validate(chain_name,-1, NULL))
		params->chain = validate_chain(params->table, chain_name);
	
	// User specified chain change
	if(custom_chain_name && *custom_chain_name && 
		g_utf8_validate(custom_chain_name,-1, NULL))
		params->chain = g_strdup_printf("%s%s", 
			SAILFISH_IPTABLES_CHAIN_PREFIX, custom_chain_name);
			
	// Target, validate_target() 
	if(target && *target && g_utf8_validate(target, -1, NULL))
		params->target = validate_target(params->table, target);
	
	return params;
}

gint sailfish_iptables_dbus_register(api_data *data) {
	
	gint rval = 0;
	
	if(!data)
		data = api_data_new();
	
	DBusConnection* conn = connman_dbus_get_connection();
	if(conn)
	{
		if(g_dbus_register_interface(conn,
			SAILFISH_IPTABLES_DBUS_PATH,
			SAILFISH_IPTABLES_DBUS_INTERFACE,
			methods,
			signals,
			NULL,
			data,
			(GDBusDestroyFunction)api_data_free))
		{
			
			DBusMessage *signal = sailfish_iptables_dbus_signal(
					SAILFISH_IPTABLES_SIGNAL_INIT,
					DBUS_TYPE_INVALID, NULL);
				
			if(signal) // Send to all
				sailfish_iptables_dbus_send_signal(signal, NULL);
		}
		else
		{
			DBG("%s %s %s", PLUGIN_NAME, "sailfish_iptables_dbus_register():",
				"register failed");
			rval = 1;
		}
		dbus_connection_unref(conn);
	}
	else
	{
		DBG("%s %s %s", PLUGIN_NAME, "sailfish_iptables_dbus_register():",
			"no dbus connection");
		rval = 1;
	}
	DBG("%s %s %s %s", PLUGIN_NAME, "sailfish_iptables_dbus_register():",
			SAILFISH_IPTABLES_DBUS_PATH,
			SAILFISH_IPTABLES_DBUS_INTERFACE);
	return rval;
}

gint sailfish_iptables_dbus_unregister()
{
	gint rval = 0;

	DBusConnection* conn = connman_dbus_get_connection();
	if(conn)
	{
		// First send the signal to all
		DBusMessage *signal = sailfish_iptables_dbus_signal(
					SAILFISH_IPTABLES_SIGNAL_STOP,
					DBUS_TYPE_INVALID, NULL);
		if(signal)
			sailfish_iptables_dbus_send_signal(signal, NULL);
			
		if(!g_dbus_unregister_interface(conn,
			SAILFISH_IPTABLES_DBUS_PATH,
			SAILFISH_IPTABLES_DBUS_INTERFACE))
		{
			DBG("%s %s %s", PLUGIN_NAME, "sailfish_iptables_dbus_unregister():",
				"unregsiter failed");
			rval = 1;
		}
		dbus_connection_unref(conn);
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
