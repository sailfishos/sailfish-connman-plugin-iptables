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

#include "sailfish-iptables.h"
#include "sailfish-iptables-dbus.h"
#include "sailfish-iptables-validate.h"
#include "sailfish-iptables-parameters.h"
#include "sailfish-iptables-utils.h"
#include "sailfish-iptables-policy.h"

#define ERR(fmt,arg...) connman_error(fmt, ## arg)
#define DBG(fmt,arg...) connman_debug(fmt, ## arg)


api_result clear_firewall(rule_params* params)
{
	if(!params)
		return INVALID;
		
	const char* table_name = (params->table ?
		params->table : 
		SAILFISH_IPTABLES_TABLE_NAME);
		
	DBG("%s %s %s", PLUGIN_NAME, "CLEAR table", table_name);
	if(!connman_iptables_clear(table_name)) return OK;
	return INVALID_REQUEST;
}

api_result set_policy(rule_params* params)
{
	gint ret = 0;
	api_result rval = INVALID;
	const gchar* ipt_operation = NULL;
	
	if(params && (rval = check_parameters(params)) == OK)
	{
		switch(params->args)
		{
			case ARGS_POLICY_OUT:
				ipt_operation = IPTABLES_CHAIN_OUTPUT;
				break;
			case ARGS_POLICY_IN:
				ipt_operation = IPTABLES_CHAIN_INPUT;
				break;
			default:
				return rval;
		}

		if(!(ret = connman_iptables_change_policy(SAILFISH_IPTABLES_TABLE_NAME,
					ipt_operation, params->policy)))
		{
			if(!(ret = connman_iptables_commit(SAILFISH_IPTABLES_TABLE_NAME)))
			{
				rval = OK;
				
				DBG("%s %s %s", "set_policy(): changed policy", 
					ipt_operation, params->policy);
			}
		}
		else
			rval = INVALID_POLICY;
	}

	return rval;
}

api_result add_rule_to_iptables(rule_params *params, guint16 op)
{	
	api_result rval = INVALID;
	gint error = 0;
	GString *rule = NULL;
	gchar* str_rule = NULL;
	const gchar* ipt_operation = NULL;
	gchar ip_direction = 's';
	
	if(!params || ((rval = check_parameters(params)) != OK))
		return rval;

	if(op & OPERATION_OUT)
	{
		ipt_operation = IPTABLES_CHAIN_OUTPUT;
		ip_direction = 'd';
	}
	else if (op & OPERATION_IN)
	{
		ipt_operation = IPTABLES_CHAIN_INPUT;
		ip_direction = 's';
	}
	else
		return INVALID;
		
	rule = g_string_new("");
	
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
		{
			DBG("NO PROTOCOL DEFINED RULE IS NOT ADDED");
			rval = INVALID_SERVICE;
		}
	}
	else if(params->args == ARGS_IP_PORT_RANGE)
	{
		if(params->protocol)
			g_string_append_printf(rule,"-%c%s%s -p %s -m %s --dport %u:%u",
				ip_direction, params->ip_negate ? " ! " : " ",
				params->ip, params->protocol, params->protocol,
				params->port[0], params->port[1]);
		else
		{
			DBG("NO PROTOCOL DEFINED RULE IS NOT ADDED");
			rval = INVALID_PORT;
		}
	}
	else if(params->args == ARGS_IP_SERVICE)
	{
		if(params->protocol)
			g_string_append_printf(rule,"-%c%s%s -p %s -m %s --dport %d",
				ip_direction, params->ip_negate ? " ! " : " ",
				params->ip, params->protocol, params->protocol,
				params->port[0]);
		else
		{
			DBG("NO PROTOCOL DEFINED RULE IS NOT ADDED");
			rval = INVALID_SERVICE;
		}
	}
	else if(params->args == ARGS_PORT)
	{
		if(params->protocol)
			g_string_append_printf(rule,"-p %s -m %s --dport %u", 
				params->protocol, params->protocol, params->port[0]);
		else
		{
			DBG("NO PROTOCOL DEFINED RULE IS NOT ADDED");
			rval = INVALID_SERVICE;
		}
	}
	else if(params->args == ARGS_PORT_RANGE)
	{
		if(params->protocol)
			g_string_append_printf(rule,"-p %s -m %s --dport %u:%u",
				params->protocol, params->protocol, 
				params->port[0], params->port[1]);
		else
		{
			DBG("NO PROTOCOL DEFINED RULE IS NOT ADDED");
			rval = INVALID_SERVICE;
		}
	}
	else if(params->args == ARGS_SERVICE)
	{
		if(params->protocol)
			g_string_append_printf(rule,"-p %s -m %s --dport %d",
				params->protocol, params->protocol, params->port[0]);
		else
		{
			DBG("NO PROTOCOL DEFINED RULE IS NOT ADDED");
			rval = INVALID_SERVICE;
		}
	}
	
	if(op & OPERATION_ACCEPT)
		g_string_append(rule,IPTABLES_RULE_ACCEPT);
	else if(op & OPERATION_DENY)
		g_string_append(rule,IPTABLES_RULE_DROP);
	else
		rval = INVALID_REQUEST;

	str_rule = g_string_free(rule,FALSE);

	if(rval == OK && str_rule && params->operation != UNDEFINED)
	{
		if(params->operation == ADD)
		{	
			if(!(error = connman_iptables_append(SAILFISH_IPTABLES_TABLE_NAME,
				ipt_operation, str_rule)))
				DBG("%s %s %s %s", PLUGIN_NAME, "connman_iptables_append",
					ipt_operation, str_rule);
			else
				DBG("%s %s %s %s  %d", PLUGIN_NAME,
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
				DBG("%s %s %s %s %d", PLUGIN_NAME,
					"connman_iptables_delete failure", ipt_operation, str_rule,
					error);
		}
	
		if(!error)
		{
			if(!(error = connman_iptables_commit(SAILFISH_IPTABLES_TABLE_NAME)))
				DBG("%s %s %d", PLUGIN_NAME, "connman_iptables_commit", error);
			else
			{
				DBG("%s %s %d", PLUGIN_NAME,
					"connman_iptables_commit failed:", error);
					
				if(params->operation == ADD)
				{
					if(connman_iptables_delete(SAILFISH_IPTABLES_TABLE_NAME, 
						ipt_operation, str_rule))
						ERR("Cannot revert rule (%s) - clear/restart connman",
							str_rule);
					else
						DBG("connman_iptables_delete reverted %s", str_rule);
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
}

api_result allow_incoming(rule_params* params)
{
	return add_rule_to_iptables(params, OPERATION_IN | OPERATION_ACCEPT);
}

api_result allow_outgoing(rule_params* params)
{
	return add_rule_to_iptables(params, OPERATION_OUT | OPERATION_ACCEPT);
}

api_result deny_incoming(rule_params* params)
{
	return add_rule_to_iptables(params,OPERATION_IN | OPERATION_DENY);
}

api_result deny_outgoing(rule_params* params)
{
	return add_rule_to_iptables(params,OPERATION_OUT | OPERATION_DENY);
}

DBusMessage* process_request(DBusMessage *message,
	api_result (*func)(rule_params* params), rule_args args, api_data *data)
{
	api_result result = INVALID;
	rule_params *params = NULL;
	
	if(!sailfish_iptables_policy_check_args(message, data, args))
		result = ACCESS_DENIED;
	else if((params = sailfish_iptables_dbus_get_parameters_from_msg(message,
		args)))
	{	
		if((result = func(params)) == OK)
		{
			DBusMessage *signal = sailfish_iptables_dbus_signal_from_rule_params(params);
			if(signal)
				sailfish_iptables_dbus_send_signal(signal, data);
		}
		else
			ERR("%s %s %d",
				"process_request():", "request was not successful",
				result);
	}
	
	rule_params_free(params);

	return sailfish_iptables_dbus_reply_result(message, result);
}

static int sailfish_iptables_init(void)
{
	DBG("%s %s", PLUGIN_NAME, "initialize");
	
	int err = sailfish_iptables_dbus_register();
	
	if(err != 0)
		DBG("%s %s", PLUGIN_NAME, "Cannot register to D-Bus");
		
	err = connman_iptables_restore(SAILFISH_IPTABLES_TABLE_NAME, NULL);
	
	if(err != 0)
		DBG("%s %s %s", PLUGIN_NAME, "Cannot load default firewall",
			connman_iptables_default_save_path(IPV4));
	
	return 0;
}

static void sailfish_iptables_exit(void)
{
	DBG("%s %s", PLUGIN_NAME, "EXIT IPTABLES API");
	
	sailfish_iptables_dbus_unregister();
	
	int err = connman_iptables_save(SAILFISH_IPTABLES_TABLE_NAME, NULL);
	
	if(err != 0)
		DBG("%s %s %s", PLUGIN_NAME, "Cannot save firewall to",
			connman_iptables_default_save_path(IPV4));
			
	err = connman_iptables_clear(SAILFISH_IPTABLES_TABLE_NAME);
	
	if(err != 0)
		DBG("%s %s %s", PLUGIN_NAME, "Cannot clear firewall table",
			SAILFISH_IPTABLES_TABLE_NAME);
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
