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
		if(!(error = connman_iptables_change_policy(
					SAILFISH_IPTABLES_TABLE_NAME, params->chain,
					params->policy)))
		{
			if(!(error = connman_iptables_commit(SAILFISH_IPTABLES_TABLE_NAME)))
			{
				rval = OK;
				
				DBG("%s %s %s %s", PLUGIN_NAME, "set_policy(): changed policy", 
					params->chain, params->policy);
			}
		}
		else
			rval = INVALID_POLICY;
	}

	return rval;
}

api_result add_rule_to_iptables(rule_params *params, api_data *data)
{	
	api_result rval = INVALID;
	gint error = 0;
	GString *rule = NULL;
	gchar* str_rule = NULL;
	const gchar* ipt_operation = NULL;
	
	if((rval = check_parameters(params)) != OK)
		return rval;

	ipt_operation = params->chain;
		
	rule = g_string_new("");
	
	// Generate rule
	
	switch(params->args)
	{
		case ARGS_PORT:
		case ARGS_SERVICE:
		case ARGS_PORT_RANGE:
			g_string_append_printf(rule,"-p %s -m %s",
				params->protocol, params->protocol);
					
			if(params->port_src[0])
			{
				if(params->port_src[1]) // Range specified
					g_string_append_printf(rule," --sport %u:%u",
						params->port_src[0], params->port_src[1]);
				else
					g_string_append_printf(rule," --sport %u",
						params->port_src[0]);
			}
			
			if(params->port_dst[0])
			{
				if(params->port_dst[1]) // Range specified
					g_string_append_printf(rule," --dport %u:%u",
					params->port_dst[0], params->port_dst[1]);
				else
					g_string_append_printf(rule," --dport %u",
						params->port_dst[0]);
			}

			break;
		case ARGS_IP:
		case ARGS_IP_PORT:
		case ARGS_IP_SERVICE:
		case ARGS_IP_PORT_RANGE:
			if(params->ip_src)
				g_string_append_printf(rule,"-s%s%s", 
					params->ip_negate_src ? " ! " : " ", params->ip_src);
			
			if(params->ip_dst)
				g_string_append_printf(rule," -d%s%s",
					params->ip_negate_dst ? " ! " : " ", params->ip_dst);
			
			if(params->args == ARGS_IP) // Has no more parameters
				break;
			
			g_string_append_printf(rule," -p %s -m %s",
				params->protocol, params->protocol);
			
			if(params->port_src[0])
			{
				if(params->port_src[1]) // Range specified
					g_string_append_printf(rule," --sport %u:%u",
						params->port_src[0], params->port_src[1]);
				else
					g_string_append_printf(rule," --sport %u",
						params->port_src[0]);
			}
			
			if(params->port_dst[0])
			{
				if(params->port_dst[1]) // Range specified
					g_string_append_printf(rule," --dport %u:%u",
					params->port_dst[0], params->port_dst[1]);
				else
					g_string_append_printf(rule," --dport %u",
						params->port_dst[0]);
			}

			break;
		default:
			rval = INVALID_REQUEST;
			break;
	}
	
	g_string_append_printf(rule," -j %s", params->target);
		
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

api_result manage_chain(rule_params* params, api_data *data)
{
	gint error = 0;
	switch(params->operation)
	{
		case ADD:
			DBG("%s Adding chain %s to table %s", PLUGIN_NAME,
				params->chain, params->table);
			error = connman_iptables_new_chain(params->table, 
				params->chain);
			break;
		case REMOVE:
			DBG("%s Flushing chain %s from table %s (pre-removal)",
				PLUGIN_NAME, params->chain, params->table);
			error = connman_iptables_flush_chain(params->table,
				params->chain);
				
			if(error)
			{
				ERR("%s Flushing chain %s in table %s failed (pre-removal) %s",
					PLUGIN_NAME, params->chain, params->table,
					"chain cannot be deleted.");
				return INVALID; // TODO add iptables error.
			}
			
			DBG("%s Removing chain %s from table %s", PLUGIN_NAME,
				params->chain, params->table);
			error = connman_iptables_delete_chain(params->table,
				params->chain);
			break;
		case FLUSH:
			DBG("%s Flushing chain %s from table %s", PLUGIN_NAME,
				params->chain, params->table);
			error = connman_iptables_flush_chain(params->table,
				params->chain);
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
							params->chain);
						break;
					case REMOVE:
						api_data_delete_custom_chain(data, params->table, 
							params->chain);
						break;
					default:
						break;
				}
				return OK;
			}
			// Commit failed, try to remove chain
			else
				if(!connman_iptables_delete_chain(params->table,
					params->chain))
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
	DBusMessage *signal = NULL;
	
	if(!sailfish_iptables_policy_check_args(message, data, args))
		result = ACCESS_DENIED;
	else if((params = sailfish_iptables_dbus_get_parameters_from_msg(message,
		args)))
	{	
		if((result = func(params, data)) == OK)
		{
			signal = sailfish_iptables_dbus_signal_from_rule_params(params);
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
			gchar **tokens = g_strsplit(chain," ", 2);
			DBG("setup_custom_chains_from_output() adding %s", tokens[0]);
			if(api_data_add_custom_chain(data, SAILFISH_IPTABLES_TABLE_NAME,
				tokens[0]))
				DBG("setup_custom_chains_from_output() added %s", tokens[0]);
			g_strfreev(tokens);
		}
	}
	
	connman_iptables_free_content(content);
}

static int sailfish_iptables_init(void)
{
	DBG("%s %s", PLUGIN_NAME, "initialize");
	
	int err = 0;
	api_data *data = api_data_new();
		
	setup_custom_chains_from_output(data);
		
	err = sailfish_iptables_dbus_register(data);
	
	if(err != 0)
		DBG("%s %s", PLUGIN_NAME, "Cannot register to D-Bus");
	
	return 0;
}

static void sailfish_iptables_exit(void)
{
	DBG("%s %s", PLUGIN_NAME, "EXIT IPTABLES API");
	
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
