/*
 *
 *  Sailfish Connection Manager iptables plugin parameter handling functions.
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
 
#define CONNMAN_API_SUBJECT_TO_CHANGE

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <connman/log.h>
#include <connman/dbus.h>
#include <connman/gdbus.h>

#include "sailfish-iptables-parameters.h"
#include "sailfish-iptables-policy.h"

void dbus_client_free(dbus_client *client)
{
	if(client)
	{
		DBusConnection *conn = connman_dbus_get_connection();
		
		if(client->watch_id && conn)
		{
			g_dbus_remove_watch(conn, client->watch_id);
			dbus_connection_unref(conn);
		}
		
		if(client->peer)
		{
			da_peer_unref(client->peer);
			client->peer = NULL;
		}
	
		g_free(client);
	}
}

void dbus_client_free1(void *data)
{
	dbus_client_free(data);
}

dbus_client* dbus_client_new()
{
	dbus_client *client = g_new0(dbus_client,1);
	
	client->watch_id = 0;
	client->peer = NULL;
	
	return client;
}

void api_data_free(api_data *data)
{
	if(data)
	{
		sailfish_iptables_policy_uninitialize(data);
		g_hash_table_destroy(data->clients);
		data->clients = NULL;
		g_free(data);
	}
}

api_data* api_data_new()
{
	api_data *data = g_new0(api_data,1);
	
	data->clients = g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
		dbus_client_free1);
		
	data->policy = NULL;
	
	sailfish_iptables_policy_initialize(data);
	
	return data;
}

dbus_client* api_data_get_peer(api_data* data, const gchar* peer_name)
{
	if(data && peer_name && *peer_name)
	{
		dbus_client *client = g_hash_table_lookup(data->clients, peer_name);
		return client;
	}
	return NULL;
}

gboolean api_data_add_peer(api_data *data, dbus_client *client)
{
	if(data && client && client->peer && client->peer->name)
	{
		if(!g_hash_table_replace(data->clients, (gpointer)client->peer->name,
				client))
		{
			DBG("%s %s %s",PLUGIN_NAME,"Cannot add client to db, name: ",
				client->peer->name);
			return false;
		}
		return true;
	}	
	return false;
}

gboolean api_data_remove_peer(api_data *data, const gchar *peer_name)
{
	gboolean rval = false;
	if(data && peer_name && *peer_name)
	{
		rval = g_hash_table_remove(data->clients, peer_name);
		
		if(!rval)
			DBG("%s %s %s", PLUGIN_NAME, 
				"Unable to remove client from db, name:",
				peer_name);
	}
	return rval;
}

client_disconnect_data* client_disconnect_data_new(api_data* data,
	dbus_client* client)
{
	if(!data || !client || !client->peer || !client->peer->name)
		return NULL;
		
	client_disconnect_data* disconnect_data = g_new0(client_disconnect_data,1);
	disconnect_data->main_data = data;
	
	if(client->peer)
		disconnect_data->client_name = g_strdup(client->peer->name);
	else
		disconnect_data->client_name = NULL;
	
	return disconnect_data;
}

void client_disconnect_data_free(client_disconnect_data* data)
{
	if(data)
		g_free(data->client_name);
	g_free(data);
	data = NULL;
}

void rule_params_free(rule_params *params)
{
	if(params)
	{
		g_free(params->ip);
		g_free(params->service);
		g_free(params->protocol);
		g_free(params->table);
		g_free(params->policy);
		g_free(params->chain_name);
		
		if(params->iptables_content)
			connman_iptables_free_content(params->iptables_content);
			
		g_free(params);
	}
}

rule_params* rule_params_new(rule_args args)
{
	rule_params *params = g_new0(rule_params,1);
	params->ip = NULL;
	params->ip_negate = false;
	params->service = NULL;
	params->port[0] = params->port[1] = 0;
	params->protocol = NULL;
	params->operation = UNDEFINED;
	params->table = NULL;
	params->policy = NULL;
	params->chain_name = NULL;
	params->iptables_content = NULL;
	params->args = args;
	
	return params;
}

api_result check_parameters(rule_params* params)
{
	if(!params)
		return INVALID;

	switch(params->args)
	{
		case ARGS_IP:
			return params->ip ? OK : INVALID_IP;
		case ARGS_IP_PORT:
			if(!params->ip) return INVALID_IP;
			if(!params->port[0]) return INVALID_PORT;
			if(!params->protocol) return INVALID_PROTOCOL;
			return OK;
		case ARGS_IP_PORT_RANGE:
			if(!params->ip) return INVALID_IP;
			if(!params->port[0]) return INVALID_PORT;
			if(!params->port[1]) return INVALID_PORT;
			if(params->port[1] < params->port[0] &&
				params->port[1] != params->port[0]) return INVALID_PORT_RANGE;
			if(!params->protocol) return INVALID_PROTOCOL;
			return OK;
		case ARGS_IP_SERVICE:
			if(!params->ip) return INVALID_IP;
			if(!params->service) return INVALID_SERVICE;
			if(!params->port[0]) return INVALID_SERVICE;
			if(!params->protocol) return INVALID_PROTOCOL;
			return OK;
		case ARGS_PORT:
			if(!params->port[0]) return INVALID_PORT;
			if(!params->protocol) return INVALID_PROTOCOL;
			return OK;
		case ARGS_PORT_RANGE:
			if(!params->port[0]) return INVALID_PORT;
			if(!params->port[1]) return INVALID_PORT;
			if(params->port[1] < params->port[0] &&
				params->port[1] != params->port[0]) return INVALID_PORT_RANGE;
			if(!params->protocol) return INVALID_PROTOCOL;
			return OK;
		case ARGS_SERVICE:
			if(!params->service) return INVALID_SERVICE;
			if(!params->protocol) return INVALID_PROTOCOL;
			return OK;
		case ARGS_CLEAR:
			return OK;
		case ARGS_POLICY_IN:
		case ARGS_POLICY_OUT:
			return params->policy ? OK : INVALID_POLICY;
		case ARGS_CHAIN:
			if(!params->chain_name) return INVALID_CHAIN_NAME;
			if(!params->table) return INVALID_REQUEST;
			return OK;
		case ARGS_GET_CONTENT:
			return params->table ? OK : INVALID_REQUEST;
		default:
			return INVALID;
	}
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */
