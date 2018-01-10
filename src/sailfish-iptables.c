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


#define CONNMAN_API_SUBJECT_TO_CHANGE

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdlib.h>
#include <dbus/dbus.h>
#include <glib.h>
#include <connman/log.h>

#include "sailfish-iptables.h"
#include "sailfish-iptables-dbus.h"
#include "sailfish-iptables-validate.h"
#include "sailfish-iptables-parameters.h"
#include "sailfish-iptables-utils.h"
#include "sailfish-iptables-policy.h"

#define ERR(fmt,arg...) connman_error(fmt, ## arg)
//#define DBG(fmt,arg...) connman_debug(fmt, ## arg)

api_result clear_iptables_rules(rule_params* params, api_data *data)
{
	api_result rval = INVALID;
	
	if((rval = check_parameters(params)) != OK)
		return rval;
		
	DBG("%s %s %s", PLUGIN_NAME, "CLEAR table", params->table);
	
	if(!connman_iptables_clear(params->table))
		rval = OK;
		
	return rval;
}

api_result clear_iptables_chains(rule_params* params, api_data *data)
{
	api_result rval = INVALID;
	
	if((rval = check_parameters(params)) != OK)
		return rval;
		
	DBG("%s %s %s", PLUGIN_NAME, "CLEAR table chains", params->table);
	
	if(api_data_remove_custom_chains(data, params->table))
		rval = OK;

	return rval;
}

api_result get_iptables_content(rule_params* params, api_data *data)
{
	api_result rval = INVALID;
	
	if((rval = check_parameters(params)) != OK)
		return rval;
		
	if((params->iptables_content = connman_iptables_get_content(params->table)))
		rval = OK;
	
	return rval;
}

api_result set_policy(rule_params* params, api_data *data)
{
	gint error = 0;
	api_result rval = INVALID;
	
	if((rval = check_parameters(params)) == OK)
	{
		if(!(error = connman_iptables_change_policy(SAILFISH_IPTABLES_TABLE_NAME,
					params->chain_name, params->policy)))
		{
			if(!(error = connman_iptables_commit(SAILFISH_IPTABLES_TABLE_NAME)))
			{
				rval = OK;
				
				DBG("%s %s %s %s", PLUGIN_NAME, "set_policy(): changed policy", 
					params->chain_name, params->policy);
			}
		}
		else
			rval = INVALID_POLICY;
	}

	return rval;
}

api_result add_rule_to_iptables(rule_params *params, api_data *data, guint16 op)
{	
	api_result rval = INVALID;
	gint error = 0;
	GString *rule = NULL;
	gchar* str_rule = NULL;
	const gchar* ipt_operation = NULL;
	gchar ip_direction = 's';
	
	if(!params || ((rval = check_parameters(params)) != OK))
		return rval;

	if(op & OPERATION_OUT) // TODO get this from params
	{
		ipt_operation = IPTABLES_CHAIN_OUTPUT;
		ip_direction = 'd';
	}
	else if (op & OPERATION_IN) // TODO get this from params
	{
		ipt_operation = IPTABLES_CHAIN_INPUT;
		ip_direction = 's';
	}
	else
		return INVALID;
		
	rule = g_string_new("");
	
	// Generate rule
	if(params->args == ARGS_IP)
	{	
		if(params->ip)
			g_string_append_printf(rule,"-%c%s%s",
				ip_direction, params->ip_negate ? " ! " : " ", params->ip);
		else
			rval = INVALID_IP;
	}
	else if(params->args == ARGS_IP_PORT)
	{
		if(params->protocol)
			g_string_append_printf(rule,"-%c%s%s -p %s -m %s --dport %u",
				ip_direction, params->ip_negate ? " ! " : " ",
				params->ip, params->protocol, params->protocol, params->port[0]);
		else
			rval = INVALID_PROTOCOL;
	}
	else if(params->args == ARGS_IP_PORT_RANGE)
	{
		if(params->protocol)
			g_string_append_printf(rule,"-%c%s%s -p %s -m %s --dport %u:%u",
				ip_direction, params->ip_negate ? " ! " : " ",
				params->ip, params->protocol, params->protocol,
				params->port[0], params->port[1]);
		else
			rval = INVALID_PROTOCOL;
	}
	else if(params->args == ARGS_IP_SERVICE)
	{
		if(params->protocol)
			g_string_append_printf(rule,"-%c%s%s -p %s -m %s --dport %d",
				ip_direction, params->ip_negate ? " ! " : " ",
				params->ip, params->protocol, params->protocol,
				params->port[0]);
		else
			rval = INVALID_SERVICE;
	}
	else if(params->args == ARGS_PORT)
	{
		if(params->protocol)
			g_string_append_printf(rule,"-p %s -m %s --dport %u", 
				params->protocol, params->protocol, params->port[0]);
		else
			rval = INVALID_PROTOCOL;
	}
	else if(params->args == ARGS_PORT_RANGE)
	{
		if(params->protocol)
			g_string_append_printf(rule,"-p %s -m %s --dport %u:%u",
				params->protocol, params->protocol, 
				params->port[0], params->port[1]);
		else
			rval = INVALID_PROTOCOL;
	}
	else if(params->args == ARGS_SERVICE)
	{
		if(params->protocol)
			g_string_append_printf(rule,"-p %s -m %s --dport %d",
				params->protocol, params->protocol, params->port[0]);
		else
			rval = INVALID_SERVICE;
	}
	
	// Add target to rule
	if(op & OPERATION_ACCEPT)
		g_string_append(rule,IPTABLES_RULE_ACCEPT);
	else if(op & OPERATION_DENY)
		g_string_append(rule,IPTABLES_RULE_DROP);
	else
		rval = INVALID_REQUEST;
		
	if(rval != OK)
		goto param_error;

	str_rule = g_string_free(rule,FALSE);
	
	if(str_rule && params->operation != UNDEFINED)
	{
		if(params->operation == ADD)
		{	
			if(!(error = connman_iptables_append(SAILFISH_IPTABLES_TABLE_NAME,
				ipt_operation, str_rule)))
				DBG("%s %s %s %s", PLUGIN_NAME, "connman_iptables_append",
					ipt_operation, str_rule);
			else
				ERR("%s %s %s %s  %d", PLUGIN_NAME,
					"connman_iptables_append failure", ipt_operation, str_rule,
					error);
		}
		else if(params->operation == REMOVE)
		{
			if(!(error = connman_iptables_delete(SAILFISH_IPTABLES_TABLE_NAME, 
				ipt_operation, str_rule)))
				DBG("%s %s %s %s", PLUGIN_NAME,
					"connman_iptables_delete success", ipt_operation, str_rule);
			else
				ERR("%s %s %s %s %d", PLUGIN_NAME,
					"connman_iptables_delete failure", ipt_operation, str_rule,
					error);
		}
	
		if(!error)
		{
			if(!(error = connman_iptables_commit(SAILFISH_IPTABLES_TABLE_NAME)))
				DBG("%s %s %d", PLUGIN_NAME, "connman_iptables_commit", error);
			else
			{
				ERR("%s %s %d", PLUGIN_NAME, "connman_iptables_commit failed:",
					error);
				
				// If commit had errors, try to remove added rule
				if(params->operation == ADD)
				{
					if(!connman_iptables_delete(SAILFISH_IPTABLES_TABLE_NAME, 
						ipt_operation, str_rule))
						DBG("%s %s %s", PLUGIN_NAME, 
							"connman_iptables_delete reverted", str_rule);
					else
						ERR("%s %s %s", PLUGIN_NAME, 
							"Cannot revert rule, restart connman. Rule:",
							str_rule);
				}
				
				rval = INVALID;
			}
		}
		else
		{
			if(params->operation == REMOVE)
				rval = RULE_DOES_NOT_EXIST;
			else
				rval = INVALID_REQUEST;
		}
	}
	
	g_free(str_rule);
	
	return params->operation == UNDEFINED ? INVALID_REQUEST : rval;

param_error:
	g_string_free(rule,true);
	DBG("%s %s %s %d", PLUGIN_NAME, "add_rule_to_iptables()", 
		"invalid parameters given, rule is not added, error code", rval);
	return rval;
}

api_result allow_incoming(rule_params* params, api_data *data)
{
	return add_rule_to_iptables(params, data, OPERATION_IN | OPERATION_ACCEPT);
}

api_result allow_outgoing(rule_params* params, api_data *data)
{
	return add_rule_to_iptables(params, data, OPERATION_OUT | OPERATION_ACCEPT);
}

api_result deny_incoming(rule_params* params, api_data *data)
{
	return add_rule_to_iptables(params, data, OPERATION_IN | OPERATION_DENY);
}

api_result deny_outgoing(rule_params* params, api_data *data)
{
	return add_rule_to_iptables(params, data, OPERATION_OUT | OPERATION_DENY);
}

api_result manage_chain(rule_params* params, api_data *data)
{
	gint error = 0;
	switch(params->operation)
	{
		case ADD:
			DBG("%s Adding chain %s to table %s", PLUGIN_NAME,
				params->chain_name, params->table);
			error = connman_iptables_new_chain(params->table, 
				params->chain_name);
			break;
		case REMOVE:
			DBG("%s Removing chain %s from table %s", PLUGIN_NAME,
				params->chain_name, params->table);
			error = connman_iptables_delete_chain(params->table,
				params->chain_name);
			break;
		case FLUSH:
			DBG("%s Flushing chain %s from table %s", PLUGIN_NAME,
				params->chain_name, params->table);
			error = connman_iptables_flush_chain(params->table,
				params->chain_name);
			break;
		default:
			return INVALID_REQUEST;
	}
	
	switch(error)
	{
		// Try to commit
		case 0:
			if(!(error = connman_iptables_commit(params->table)))
			{
				switch(params->operation)
				{
					case ADD:
						api_data_add_custom_chain(data, params->table, 
							params->chain_name);
						break;
					case REMOVE:
						api_data_delete_custom_chain(data, params->table, 
							params->chain_name);
						break;
					default:
						break;
				}
				return OK;
			}
			// Commit failed, try to remove chain
			else
				if(!connman_iptables_delete_chain(params->table,
					params->chain_name))
					ERR("%s %s %s", PLUGIN_NAME,
						"manage_chain() commit error",
						"chain could not be removed, please restart connman.");
			break;
		case -1:
			return INVALID_REQUEST;
		default:
			break;
	}
	
	ERR("%s %s %d %s %d", PLUGIN_NAME, "manage_chain() failed with operation",
		(gint)params->operation, "Error code: ", error);
	return INVALID_CHAIN_NAME;
}

DBusMessage* process_request(DBusMessage *message,
	api_result (*func)(rule_params* params, api_data *data),
	rule_args args, api_data *data)
{
	api_result result = INVALID;
	rule_params *params = NULL;
	
	if(!sailfish_iptables_policy_check_args(message, data, args))
		result = ACCESS_DENIED;
	else if((params = sailfish_iptables_dbus_get_parameters_from_msg(message,
		args)))
	{	
		if((result = func(params, data)) == OK)
		{
			DBusMessage *signal = sailfish_iptables_dbus_signal_from_rule_params(params);
			if(signal)
				sailfish_iptables_dbus_send_signal(signal, data);
		}
		else
			ERR("%s %s %s %d", PLUGIN_NAME, 
				"process_request():", "request was not successful",
				result);
	}

	return sailfish_iptables_dbus_reply_result(message, result, params);
}

void setup_custom_chains_from_output(api_data *data)
{
	GList *iter = NULL;

	connman_iptables_content* content = connman_iptables_get_content(
		SAILFISH_IPTABLES_TABLE_NAME);
		
	if(!content)
		return;
		
	for(iter = g_list_first(content->chains); iter ; iter = iter->next)
	{
		gchar *chain = (gchar*)iter->data;
		
		if(g_str_has_prefix(chain, SAILFISH_IPTABLES_CHAIN_PREFIX))
		{
			DBG("setup_custom_chains_from_output() adding %s", chain);
			gchar **tokens = g_strsplit(chain," ", 2);
			if(api_data_add_custom_chain(data, SAILFISH_IPTABLES_TABLE_NAME, tokens[0]))
				DBG("setup_custom_chains_from_output() added %s", tokens[0]);
			g_strfreev(tokens);
		}
	}
	
	connman_iptables_free_content(content);
}

static int sailfish_iptables_init(void)
{
	DBG("%s %s", PLUGIN_NAME, "initialize");
	
	api_data *data = api_data_new();
		
	int err = connman_iptables_restore(SAILFISH_IPTABLES_TABLE_NAME, NULL);
	
	if(err != 0)
		DBG("%s %s %s", PLUGIN_NAME, "Cannot load default firewall",
			connman_iptables_default_save_path(IPV4));
	else
		setup_custom_chains_from_output(data);
		
	err = sailfish_iptables_dbus_register(data);
	
	if(err != 0)
		DBG("%s %s", PLUGIN_NAME, "Cannot register to D-Bus");
	
	return 0;
}

static void sailfish_iptables_exit(void)
{
	DBG("%s %s", PLUGIN_NAME, "EXIT IPTABLES API");
	
	int err = connman_iptables_save(SAILFISH_IPTABLES_TABLE_NAME, NULL);
	
	if(err != 0)
		DBG("%s %s %s", PLUGIN_NAME, "Cannot save firewall to",
			connman_iptables_default_save_path(IPV4));
			
	err = connman_iptables_clear(SAILFISH_IPTABLES_TABLE_NAME);
	
	if(err != 0)
		DBG("%s %s %s", PLUGIN_NAME, "Cannot clear firewall table",
			SAILFISH_IPTABLES_TABLE_NAME);
	
	sailfish_iptables_dbus_unregister();
}

CONNMAN_PLUGIN_DEFINE(sailfish_ipt_api, PLUGIN_NAME, CONNMAN_VERSION,
	CONNMAN_PLUGIN_PRIORITY_DEFAULT, sailfish_iptables_init,
	sailfish_iptables_exit)

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */
