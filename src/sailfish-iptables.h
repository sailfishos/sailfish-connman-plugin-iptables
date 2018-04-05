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

#ifndef _SAILFISH_IPTABLES_H_
#define _SAILFISH_IPTABLES_H_

#include <dbus/dbus.h>
#include <dbusaccess/dbusaccess_peer.h>
#include <dbusaccess/dbusaccess_policy.h>
#include <connman/iptables_ext.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PLUGIN_NAME "Sailfish iptables API"

#define SAILFISH_IPTABLES_INTERFACE_VERSION		3
#define SAILFISH_IPTABLES_TABLE_NAME			"filter"
#define SAILFISH_IPTABLES_CHAIN_PREFIX			"sfos_"
#define IPTABLES_CHAIN_INPUT				"INPUT"
#define IPTABLES_CHAIN_OUTPUT				"OUTPUT"
#define IPTABLES_ACCEPT					"ACCEPT"
#define IPTABLES_ACCEPT_INT				1
#define IPTABLES_DROP					"DROP"
#define IPTABLES_DROP_INT				2
#define IPTABLES_RULE_ACCEPT				" -j "IPTABLES_ACCEPT
#define IPTABLES_RULE_DROP				" -j "IPTABLES_DROP

#define IP_MASK_DELIM					"/"
#define PORT_RANGE_DELIM				":"

#define IPV4_DELIM					"."
#define IPV4_TOKENS					4

#define IPV6_DELIM					".:"
// Eight 16bit groups, but can be anything between 2 and 9 (IPv4 mapped IPv6)
#define IPV6_TOKENS					10

#define IPV4						4
#define IPV6						6
#define IPV4_MASK_MAX					32
#define IPV6_MASK_MAX					128
#define IPV4_ADDR_MIN					6
#define IPV6_ADDR_MIN					1 // "::" -> all zeroes

#define EMPTY_STR					""

// Easier to use typedef
typedef struct iptables_content connman_iptables_content;

typedef struct sailfish_iptables_dbus_client {
	DAPeer *peer;
	// TODO: own list for added rules, identify with id -> users/groups
	// with manage() access can access only these
	guint watch_id;
} dbus_client; 

typedef struct sailfish_iptables_api_data {
	GHashTable* clients;
	GList* custom_chains;
	DA_BUS da_bus;
    DAPolicy* policy;
} api_data;

typedef struct sailfish_iptables_custom_chain_item {
	gchar* table;
	GList* chains;
} custom_chain_item;

typedef struct sailfish_iptables_client_disconnect_data {
	api_data* main_data;
	gchar* client_name;
} client_disconnect_data;

typedef enum sailfish_iptables_result {
	OK = 0,
	INVALID_IP,// 1
	INVALID_PORT, // 2
	INVALID_PORT_RANGE, // 3
	INVALID_SERVICE, // 4
	INVALID_PROTOCOL, // 5
	INVALID_POLICY, // 6
	RULE_DOES_NOT_EXIST, // 7
	INVALID_REQUEST, // 8
	INVALID, // 9
	UNAUTHORIZED, // 10
	REMOVE_FAILED, // 11
	INVALID_CHAIN_NAME, // 12
	INVALID_TABLE, // 13
	INVALID_TARGET, // 14
	ACCESS_DENIED = 100 
} api_result;

typedef enum sailfish_iptables_rule_operation {
	ADD = 0,
	REMOVE,
	FLUSH,
	UNDEFINED
} rule_operation;

typedef enum sailfish_iptables_dbus_rule_args {
	ARGS_IP = 0,
	ARGS_IP_PORT,
	ARGS_IP_PORT_RANGE,
	ARGS_IP_SERVICE,
	ARGS_PORT,
	ARGS_PORT_RANGE,
	ARGS_SERVICE,
	ARGS_CLEAR,
	ARGS_CLEAR_CHAINS,
	ARGS_POLICY,
	ARGS_GET_CONTENT,
	ARGS_CHAIN
} rule_args;
 
typedef struct sailfish_iptables_rule_params {
	gchar *table;
	gchar *chain;
	gchar *target;
	gchar *policy;
	gchar *ip_src;
	gchar *ip_dst;
	gboolean ip_negate_src;
	gboolean ip_negate_dst;
	gchar *service_src;
	gchar *service_dst;
	guint16 port_src[2];
	guint16 port_dst[2];
	gchar *protocol;
	rule_operation operation;
	connman_iptables_content *iptables_content;
	rule_args args;
} rule_params;

typedef enum sailfish_iptables_dbus_access {
	// No clearing of iptables, TODO: only own rules can be removed
	SAILFISH_DBUS_ACCESS_MANAGE = 1, 
	// Full access
	SAILFISH_DBUS_ACCESS,
	// Listen only
	SAILFISH_DBUS_ACCESS_LISTEN
} dbus_access;

api_result clear_iptables_rules(rule_params* params, api_data *data);
api_result clear_iptables_chains(rule_params* params, api_data *data);
api_result get_iptables_content(rule_params* params, api_data *data);

api_result add_rule_to_iptables(rule_params *params, api_data *data);

api_result set_policy(rule_params* params, api_data *data);

api_result manage_chain(rule_params* params, api_data *data);

DBusMessage* process_request(DBusMessage *message,
	api_result (*func)(rule_params* params, api_data *data),
	rule_args args, api_data* data);
	

#ifdef __cplusplus
}
#endif

#endif

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */
