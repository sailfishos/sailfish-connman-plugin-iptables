/*
 *
 *  Connection Manager Sailfish iptables API plugin
 *
 *  Copyright (C) 2017 Jolla Ltd.
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


#define CONNMAN_API_SUBJECT_TO_CHANGE
#define PLUGIN_NAME "SAILFISH_IPTABLES"


#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdlib.h>

#include "sailfish-iptables.h"

#define ERR(fmt,arg...) connman_error(fmt, ## arg)
#define DBG(fmt,arg...) connman_debug(fmt, ## arg)

const gchar const * OP_STR[] = {"Add", "Remove", "Undefined"};
const gchar * const RESULT_STR[] = {
	"Ok",
	"Invalid IP",
	"Invalid port",
	"Invalid port range",
	"Invalid service name",
	"Invalid protocol",
	"Invalid policy",
	"Invalid file path",
	"Cannot process rule",
	"Cannot perform operation",
};

static gboolean negated_ip_address(const gchar* ip)
{
	return ip && ip[0] == '!';
}

gchar* get_protocol_for_service(const gchar *service)
{
	if(service && strlen(service))
	{
		struct servent *s = getservbyname(service, NULL);
		if(s)
			return g_strdup(s->s_proto);
	}
	return NULL;
}

gchar* get_protocol_for_port(guint16 port)
{
	if(port)
	{
		struct servent *s = getservbyport(htons(port), NULL);
		if(s)
			return g_strdup(s->s_proto);	
	}
	return NULL;
}

static gboolean validate_address(gint type, const gchar* address)
{
	struct addrinfo hints;
	struct addrinfo *result = NULL;
	
	memset(&hints, 0, sizeof(struct addrinfo));
	
	hints.ai_family = (type == IPV6 ? AF_INET6 : AF_INET);
	hints.ai_flags = AI_NUMERICHOST;
	
	// Success
	if(!getaddrinfo(address,NULL,&hints,&result))
	{
		if(result)
			freeaddrinfo(result);
		return true;
	}
	return false;
}

static guint32 mask_to_cidr(gint type, const gchar* mask_address)
{
	gint index = 0, b = 0;
	guint32 mask = 0, bits = 0;
	gint i = (type == IPV6 ? IPV6_MASK_MAX : IPV4_MASK_MAX);	
	
	gchar **ip_tokens = NULL;
	
	if(!mask_address)
		return G_MAXUINT32;
	
	ip_tokens = g_strsplit(mask_address,IP_DELIM,4);
	
	// Mask was given as cidr
	if(g_strv_length(ip_tokens) == 1)
	{
		mask = ((guint32)g_ascii_strtoull(ip_tokens[0],NULL,10));
	}
	// Dot notation
	else if(g_strv_length(ip_tokens) == 4)
	{
		for(index = 0; index < 4 && ip_tokens[index]; index++)
		{
			b = 24 - 8 * index; // 24,16,8,0
			mask += ((guint32)g_ascii_strtoull(ip_tokens[index],NULL,10)) << b;
		}
	}
	
	g_strfreev(ip_tokens);
	
	// Return protocol mask max (32/128)
	if (mask == G_MAXUINT32)
		return i;

	// Between 0 and protocol mask max, return given mask
	else if(mask <= i)
		return mask;

	// Value between protocol max and 2^32, calculate cidr mask
	else
	{
		// Create cidr notation (bitmask for nw mask)
		bits = G_MAXUINT32 - 1;
		while(--i >= 0 && mask != bits)
			bits <<= 1;

		return i;
	}
}

gchar* format_ip(gint type, const gchar* ip)
{	
	gchar *formatted_ip = NULL;
	gchar **ip_and_mask = NULL;
	gint mask_max = 0;
	
	if(!ip)
		return NULL;
		
	mask_max = (type == IPV6 ? IPV6_MASK_MAX : IPV4_MASK_MAX);
		
	ip_and_mask = g_strsplit(ip,IP_MASK_DELIM,2);

	if(ip_and_mask && g_strv_length(ip_and_mask) == 2)
	{
		guint32 mask = mask_to_cidr(type, ip_and_mask[1]);
	
		/* 	TODO: when a IP (not network) is given with a bitmask iptables
			command changes the IP address to network, thus this cannot be
			removed using the API as such rule does not exist in iptables -
			the new one with network does.
		*/
		
		// Proper mask, between 0 and 32/128
		if(mask && mask < mask_max)
			formatted_ip = g_strdup_printf("%s/%u",
				ip_and_mask[0], mask);

		/* 	Iptables command removes /32 (or /128 IPv6) from the end, we do the
			same, also for 0, TODO: if 0 given iptables sets 0.0.0.0/0 (any)
		*/
		else if((mask && mask == mask_max) || !mask)
			formatted_ip = g_strdup_printf("%s", ip_and_mask[0]);
		// TODO: this may not be reached
		else
			formatted_ip = g_strdup_printf("%s/%s",
				ip_and_mask[0], ip_and_mask[1]);
	}
	// No mask separator found
	else
		formatted_ip = g_strdup(ip);
		
	DBG("Formatted IP: %s",formatted_ip);

	g_strfreev(ip_and_mask);
	
	return formatted_ip;
	
}

static gboolean validate_ip_mask(gint type, const gchar* mask)
{
	if(type == IPV4 && mask)
	{
		// Dot notation mask
		if(strchr(mask,'.'))
			return validate_address(type, mask);
		else
		{
			guint32 int_mask = g_ascii_strtoull(mask,NULL,10);
			
			// 0, acceptable
			if(!int_mask || 
				(int_mask & (~int_mask >> 1)) ||
				int_mask == G_MAXUINT32)
				return true;
		}
	}
	
	return false;
}

static gboolean validate_ip_address(gint type, const gchar* ip)
{
	gboolean rval = false;
	
	if(ip && strlen(ip))
	{
		const gchar *address = NULL;
		gchar **ip_and_mask = NULL;
		
		// Allow negation
		if(negated_ip_address(ip))
			address = &(ip[1]);
		else
			address = ip;
			
		// Check for mask
		ip_and_mask = g_strsplit(address,IP_MASK_DELIM,2);
		
		// Both IP and mask are defined
		if(ip_and_mask && g_strv_length(ip_and_mask) == 2)
		 	rval = validate_address(type,ip_and_mask[0]) &&
		 			validate_ip_mask(type, ip_and_mask[1]);
		else
			rval = address && validate_address(type, address);
		
		if(ip_and_mask)
			g_strfreev(ip_and_mask);
	}
	return rval;
}

static guint16 validate_service_name(const gchar *service)
{
	if(service && strlen(service))
	{	
		struct servent *s = getservbyname(service, NULL);
		if(s)
			return ntohs(s->s_port);	
	}
	return 0;
}

gboolean validate_protocol(const gchar *protocol)
{
	if(protocol && strlen(protocol))
	{
		struct protoent *p = getprotobyname(protocol);
		if(p)
			return true;
	}
	return false;
}

static gboolean validate_port(guint16 port)
{
	return port && port < 0xFFFF;
}

static rule_operation validate_operation(const gchar *operation)
{
	rule_operation op = UNDEFINED;
	gchar *operation_uppercase = NULL;
	
	if(operation && strlen(operation))
	{
		operation_uppercase = g_utf8_strup(operation,-1);

		if(!g_strcmp0(operation_uppercase,"ADD"))
			op = ADD;

		if(!g_strcmp0(operation_uppercase,"REMOVE"))
			op = REMOVE;

		g_free(operation_uppercase);
	}
	
	return op;
}

static gboolean validate_path(const gchar *path)
{
	if(path && strlen(path))
	{
		// Do proper validation in connman, or add our own validation rules here
		return true;
	}
	return false;
}

static gboolean validate_policy(const gchar* policy)
{
	if(policy && strlen(policy))
	{
		if(!g_strcmp0(policy,IPTABLES_ACCEPT) ||
			!g_strcmp0(policy,IPTABLES_DROP))
			return true;
	}
	return false;
}

gchar** get_port_range_tokens(const gchar* port_str)
{
	if(port_str && strlen(port_str))
		return g_strsplit(port_str,PORT_RANGE_DELIM,2);
	return NULL;
}

gchar *port_to_str(rule_params *params)
{
	gchar* port_str = NULL;
	
	if(params)
	{
		if(params->args == ARGS_PORT_RANGE || 
			params->args == ARGS_IP_PORT_RANGE)
			port_str = g_strdup_printf("%u:%u",params->port[0],params->port[1]);
		else
			port_str = g_strdup_printf("%u",params->port[0]);
	}
	return port_str;
}

const char* api_result_message(api_result result)
{
	if(result >= OK && result <= INVALID)
		return RESULT_STR[result];
		
	return "";
}

void rule_params_free(rule_params *params)
{
	if(params)
	{
		if(params->ip)
			g_free(params->ip);
		if(params->service)
			g_free(params->service);
		if(params->protocol)
			g_free(params->protocol);
		if(params->path)
			g_free(params->path);
		if(params->table)
			g_free(params->table);
		if(params->policy)
			g_free(params->policy);
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
	params->path = NULL;
	params->table = NULL;
	params->policy = NULL;
	params->args = args;
	
	return params;
}

api_result check_parameters(rule_params* params)
{
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
			if(params->port[1] < params->port[0]) return INVALID_PORT_RANGE;
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
			if(params->port[1] < params->port[0]) return INVALID_PORT_RANGE;
			if(!params->protocol) return INVALID_PROTOCOL;
			return OK;
		case ARGS_SERVICE:
			if(!params->service) return INVALID_SERVICE;
			if(!params->protocol) return INVALID_PROTOCOL;
			return OK;
		case ARGS_SAVE:
		case ARGS_LOAD:
			return params->path ? OK : INVALID_FILE_PATH;
		case ARGS_CLEAR:
			return OK;
		case ARGS_POLICY_IN:
		case ARGS_POLICY_OUT:
			return params->policy ? OK : INVALID_POLICY;
		default:
			return INVALID;
	}
}

DBusMessage* __signal_from_rule_params(rule_params* params)
{
	DBusMessage* signal = NULL;
	gchar *port_str = port_to_str(params);

	switch(params->args)
	{
		case ARGS_IP:
			signal = sailfish_iptables_dbus_signal(
				SAILFISH_IPTABLES_SIGNAL_RULE,
				DBUS_TYPE_STRING,	params->ip,
				DBUS_TYPE_STRING,	"",
				DBUS_TYPE_STRING,	OP_STR[params->operation],
				DBUS_TYPE_INVALID);
			break;
		case ARGS_IP_PORT:
		case ARGS_IP_PORT_RANGE:
		case ARGS_IP_SERVICE:
			signal = sailfish_iptables_dbus_signal(
				SAILFISH_IPTABLES_SIGNAL_RULE,
				DBUS_TYPE_STRING,	params->ip,
				DBUS_TYPE_STRING,	port_str,
				DBUS_TYPE_STRING,	OP_STR[params->operation],
				DBUS_TYPE_INVALID);
			break;
		case ARGS_PORT:
		case ARGS_PORT_RANGE:
		case ARGS_SERVICE:
			signal = sailfish_iptables_dbus_signal(
				SAILFISH_IPTABLES_SIGNAL_RULE,
				DBUS_TYPE_STRING,	"",
				DBUS_TYPE_STRING,	port_str,
				DBUS_TYPE_STRING,	OP_STR[params->operation],
				DBUS_TYPE_INVALID);
			break;
		case ARGS_SAVE:
			signal = sailfish_iptables_dbus_signal(
				SAILFISH_IPTABLES_SIGNAL_SAVE,
				DBUS_TYPE_INVALID);
			break;
		case ARGS_LOAD:
			signal = sailfish_iptables_dbus_signal(
				SAILFISH_IPTABLES_SIGNAL_LOAD,
				DBUS_TYPE_INVALID);
		case ARGS_CLEAR:
			signal = sailfish_iptables_dbus_signal(
				SAILFISH_IPTABLES_SIGNAL_CLEAR,
				DBUS_TYPE_INVALID);
			break;
		case ARGS_POLICY_IN:
			signal = sailfish_iptables_dbus_signal(
				SAILFISH_IPTABLES_SIGNAL_POLICY,
				DBUS_TYPE_STRING,	IPTABLES_CHAIN_INPUT,
				DBUS_TYPE_STRING,	params->policy,
				DBUS_TYPE_INVALID);
			break;
		case ARGS_POLICY_OUT:
			signal = sailfish_iptables_dbus_signal(
				SAILFISH_IPTABLES_SIGNAL_POLICY,
				DBUS_TYPE_STRING,	IPTABLES_CHAIN_OUTPUT,
				DBUS_TYPE_STRING,	params->policy,
				DBUS_TYPE_INVALID);
			break;
	}
	g_free(port_str);
	return signal;
}

rule_params* __get_parameters_from_message(DBusMessage* message, rule_args args)
{
	rule_params *params = rule_params_new(args);
	DBusError* error = NULL;
	
	gchar *ip = NULL, *service = NULL, *protocol = NULL, *port_str = NULL;
	gchar *path = NULL, *table = NULL, *policy = NULL, *operation = NULL;
	guint16 port[2] = {0};
	rule_operation op = UNDEFINED;
	gint index = 0;
	
	gboolean rval = false;
	
	switch(params->args)
	{
		case ARGS_IP:
			rval = dbus_message_get_args(message, error,
						DBUS_TYPE_STRING, &ip,
						DBUS_TYPE_STRING, &operation,
						DBUS_TYPE_INVALID);
			break;
		case ARGS_IP_PORT:
			rval = dbus_message_get_args(message, error,
						DBUS_TYPE_STRING, &ip,
						DBUS_TYPE_UINT16, &port,
						DBUS_TYPE_STRING, &protocol,
						DBUS_TYPE_STRING, &operation,
						DBUS_TYPE_INVALID);
			break;
		case ARGS_IP_PORT_RANGE:
			rval = dbus_message_get_args(message, error,
						DBUS_TYPE_STRING, &ip,
						DBUS_TYPE_STRING, &port_str,
						DBUS_TYPE_STRING, &protocol,
						DBUS_TYPE_STRING, &operation,
						DBUS_TYPE_INVALID);
			break;
		case ARGS_IP_SERVICE:
			rval = dbus_message_get_args(message, error,
						DBUS_TYPE_STRING, &ip,
						DBUS_TYPE_STRING, &service,
						DBUS_TYPE_STRING, &protocol,
						DBUS_TYPE_STRING, &operation,
						DBUS_TYPE_INVALID);
			break;
		case ARGS_PORT:
			rval = dbus_message_get_args(message, error,
						DBUS_TYPE_UINT16, &port,
						DBUS_TYPE_STRING, &protocol,			
						DBUS_TYPE_STRING, &operation,
						DBUS_TYPE_INVALID);
			break;
		case ARGS_PORT_RANGE:
			rval = dbus_message_get_args(message, error,
						DBUS_TYPE_STRING, &port_str,
						DBUS_TYPE_STRING, &protocol,
						DBUS_TYPE_STRING, &operation,
						DBUS_TYPE_INVALID);
			break;
		case ARGS_SERVICE:
			rval = dbus_message_get_args(message, error,
						DBUS_TYPE_STRING, &service,
						DBUS_TYPE_STRING, &protocol,
						DBUS_TYPE_STRING, &operation,
						DBUS_TYPE_INVALID);
			break;
		case ARGS_SAVE:
		case ARGS_LOAD:
			rval = dbus_message_get_args(message, error,
						DBUS_TYPE_STRING, &path,
						DBUS_TYPE_INVALID);
			break;
		case ARGS_CLEAR:
			break;
		case ARGS_POLICY_IN:
		case ARGS_POLICY_OUT:
			rval = dbus_message_get_args(message, error,
						DBUS_TYPE_STRING, &policy,
						DBUS_TYPE_INVALID);
			
			break;
	}
	
	if(error)
	{
		DBG("Error, %s %s",
			!rval ? "Could not get args from dbus message" : "", error->message);
		rule_params_free(params);
		return NULL;
	}
	
	if(ip && g_utf8_validate(ip,-1,NULL) && validate_ip_address(IPV4,ip))
	{
		if(negated_ip_address(ip))
		{
			params->ip = format_ip(IPV4,&(ip[1]));
			params->ip_negate = true;
		}
		else
			params->ip = format_ip(IPV4,ip);
	}
	
	// Protocol defined
	if(protocol && g_utf8_validate(protocol, -1, NULL))
	{
		gchar* protocol_lowercase = g_utf8_strdown(protocol, -1);

		if(validate_protocol(protocol_lowercase))
			params->protocol = protocol_lowercase;
	}
	
	// Service defined
	if(service && g_utf8_validate(service,-1,NULL))
	{
		gchar* service_lowercase = g_utf8_strdown(service,-1);
		
		// Check if the service with given name can be found, port and
		// protocol can be retrieved then also
		if((params->port[0] = validate_service_name(service_lowercase)))
		{
			params->service	= service_lowercase;
			
			if(!params->protocol)
				params->protocol = get_protocol_for_service(params->service);
		}
	}
	
	// Port in string format
	if(port_str && strlen(port_str))
	{
		gchar **tokens = get_port_range_tokens(port_str);
		
		if(tokens)
		{
			for(index = 0; tokens[index] && index < 2; index++)
				port[index] = (guint16)g_ascii_strtoull(tokens[index],NULL,10);
		
			// No second port was found, treat as ARGS_PORT/ARGS_IP_PORT
			if(!port[1])
			{
				if(params->args == ARGS_IP_PORT_RANGE)
					params->args = ARGS_IP_PORT;
				else if(params->args == ARGS_PORT_RANGE)
					params->args = ARGS_PORT;
			}
		}
		
		g_strfreev(tokens);
	}
	
	// Check both ports
	for(index = 0; index < 2 ; index++)
	{
		if(port[index] && validate_port(port[index]))
		{
			params->port[index] = port[index];

			if(!params->protocol)
				params->protocol = get_protocol_for_port(params->port[index]);
		}
	}
	
	// Operation defined
	if(operation && strlen(operation))
	{
		if((op = validate_operation(operation)) != UNDEFINED)
			params->operation = op;
	}
	// No operation defined, defaults to ADD
	else
		params->operation = ADD;
	
	//
	if(path && g_utf8_validate(path,-1,NULL) && validate_path(path))
		params->path = g_strdup(path);
	
	if(table && strlen(table) && g_utf8_validate(table,-1,NULL))
		params->table = g_utf8_strdown(table,-1);
	
	if(policy && g_utf8_validate(policy,-1,NULL))
	{
		gchar *policy_uppercase = g_utf8_strup(policy,-1);
		if(validate_policy(policy_uppercase))
			params->policy = policy_uppercase;
	}
		
	return params;
}

static api_result __save_firewall(rule_params* params)
{
	DBG("%s %s %s", PLUGIN_NAME, "SAVE", (params->path ? params->path : "null"));
	
	if(!connman_iptables_save(params->path)) return OK;
	return INVALID_FILE_PATH;
}

static api_result __load_firewall(rule_params* params)
{	
	DBG("%s %s %s", PLUGIN_NAME, "LOAD", (params->path ? params->path : "null"));
	if(!connman_iptables_restore(params->path)) return OK;
	return INVALID_FILE_PATH;
}

static api_result __clear_firewall(rule_params* params)
{
	DBG("%s %s %s", PLUGIN_NAME, "CLEAR",
		params->table ? params->table : SAILFISH_IPTABLES_TABLE_NAME);
	if(!connman_iptables_clear(params->table)) return OK;
	return INVALID_REQUEST;
}

static api_result __set_policy(rule_params* params)
{
	gint ret = 0;
	api_result rval = OK;
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
				return INVALID;
		}

		if(!(ret = connman_iptables_change_policy(
			SAILFISH_IPTABLES_TABLE_NAME,
			ipt_operation,
			params->policy)))
		{
			if(!(ret = connman_iptables_commit(SAILFISH_IPTABLES_TABLE_NAME)))
			{
				rval = OK;
				
				DBG("%s %s %s", "__set_policy(): changed policy", 
					ipt_operation, params->policy);
			}	
			rval = OK;
		}
		else
			rval = INVALID_POLICY;
	}

	return rval;
}

static api_result __add_rule_to_iptables(rule_params *params, guint16 op)
{	
	api_result rval = INVALID;
	gint result = 0;
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
			g_string_append_printf(rule,"-%c%s%s -p %s --dport %u",
				ip_direction, params->ip_negate ? " ! " : " ",
				params->ip, params->protocol, params->port[0]);
		else
		{
			DBG("NO PROTOCOL DEFINED RULE IS NOT ADDED");
			rval = INVALID_SERVICE;
		}
	}
	else if(params->args == ARGS_IP_PORT_RANGE)
	{
		if(params->protocol)
			g_string_append_printf(rule,"-%c%s%s -p %s --dport %u:%u",
				ip_direction, params->ip_negate ? " ! " : " ",
				params->ip, params->protocol,
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
			g_string_append_printf(rule,"-%c%s%s -p %s --dport %d",
				ip_direction, params->ip_negate ? " ! " : " ",
				params->ip, params->protocol, 
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
			g_string_append_printf(rule,"-p %s --dport %u", 
				params->protocol, params->port[0]);
		else
		{
			DBG("NO PROTOCOL DEFINED RULE IS NOT ADDED");
			rval = INVALID_SERVICE;
		}
	}
	else if(params->args == ARGS_PORT_RANGE)
	{
		if(params->protocol)
			g_string_append_printf(rule,"-p %s --dport %u:%u",
				params->protocol, params->port[0], params->port[1]);
		else
		{
			DBG("NO PROTOCOL DEFINED RULE IS NOT ADDED");
			rval = INVALID_SERVICE;
		}
	}
	else if(params->args == ARGS_SERVICE)
	{
		if(params->protocol)
			g_string_append_printf(rule,"-p %s --dport %d",
				params->protocol, params->port[0]);
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
		rval = INVALID;

	str_rule = g_string_free(rule,FALSE);

	if(rval == OK && str_rule && params->operation != UNDEFINED)
	{
		if(params->operation == ADD)
		{	
			if(!(result = connman_iptables_append(SAILFISH_IPTABLES_TABLE_NAME,
				ipt_operation, str_rule)))
				DBG("%s %s %s %s", PLUGIN_NAME, "connman_iptables_append",
					ipt_operation, str_rule);
			else
				DBG("%s %s %s %s  %d", PLUGIN_NAME,
					"connman_iptables_append failure", ipt_operation, str_rule,
					result);
		}
		else if(params->operation == REMOVE)
		{
			if(!(result = connman_iptables_delete(SAILFISH_IPTABLES_TABLE_NAME, 
				ipt_operation, str_rule)))
				DBG("%s %s %s %s", PLUGIN_NAME,
					"connman_iptables_delete success", ipt_operation, str_rule);
			else
				DBG("%s %s %s %s %d", PLUGIN_NAME,
					"connman_iptables_delete failure", ipt_operation, str_rule,
					result);
		}
	
		if(!result)
		{
			if(!(result = connman_iptables_commit(SAILFISH_IPTABLES_TABLE_NAME)))
				DBG("%s %s %d", PLUGIN_NAME, "connman_iptables_commit", result);
			else
			{
				DBG("%s %s %d", PLUGIN_NAME,
					"connman_iptables_commit failed:", result);
					
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

static api_result __allow_incoming(rule_params* params)
{
	return __add_rule_to_iptables(params, OPERATION_IN |OPERATION_ACCEPT);
}

static api_result __allow_outgoing(rule_params* params)
{
	return __add_rule_to_iptables(params, OPERATION_OUT | OPERATION_ACCEPT);
}

static api_result __deny_incoming(rule_params* params)
{
	return __add_rule_to_iptables(params,OPERATION_IN | OPERATION_DENY);
}

static api_result __deny_outgoing(rule_params* params)
{
	return __add_rule_to_iptables(params,OPERATION_OUT | OPERATION_DENY);
}

DBusMessage* __process_request(DBusMessage *message,
	api_result (*func)(rule_params* params), rule_args args)
{
	api_result result = INVALID;
	rule_params *params = NULL;
	
	if((params =  __get_parameters_from_message(message,args)))
	{	
		if((result = func(params)) == OK)
		{
			DBusMessage *signal = __signal_from_rule_params(params);
			if(signal)
				sailfish_iptables_dbus_send_signal(signal);
		}
		else
			ERR("%s %s %d",
				"__process_request():", "request was not successful",
				result);
	}
	
	rule_params_free(params);
	
	DBusMessage* reply = sailfish_iptables_dbus_method_return(message,
			DBUS_TYPE_UINT16,	(guint16)result,
			DBUS_TYPE_STRING, 	api_result_message(result),
			DBUS_TYPE_INVALID);

	if(!reply)
		reply = g_dbus_create_error(message,DBUS_ERROR_NO_MEMORY,
			"failed to add parameters to reply.");

	return reply;
}


DBusMessage* sailfish_iptables_save_firewall(DBusConnection *connection,
			DBusMessage *message, void *user_data)
{
	return __process_request(message, &__save_firewall, ARGS_SAVE);
}
					
DBusMessage* sailfish_iptables_load_firewall(DBusConnection *connection,
			DBusMessage *message, void *user_data)
{
	return __process_request(message, &__load_firewall, ARGS_LOAD);
}

DBusMessage* sailfish_iptables_clear_firewall(DBusConnection *connection,
			DBusMessage *message, void *user_data)
{
	return __process_request(message, &__clear_firewall, ARGS_CLEAR);
}

DBusMessage* sailfish_iptables_version(DBusConnection *connection,
			DBusMessage *message, void *user_data)
{	
	DBusMessage* reply = sailfish_iptables_dbus_method_return(message,
		DBUS_TYPE_INT32,	(gint)SAILFISH_IPTABLES_INTERFACE_VERSION, 
		DBUS_TYPE_INVALID);
	
	if(!reply)
		reply = g_dbus_create_error(message,DBUS_ERROR_NO_MEMORY,
			"failed to add parameters to reply.");
	return reply;
}

DBusMessage* sailfish_iptables_change_input_policy(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return __process_request(message, &__set_policy, ARGS_POLICY_IN);
}

DBusMessage* sailfish_iptables_change_output_policy(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return __process_request(message, &__set_policy, ARGS_POLICY_OUT);
}

// ALLOW INCOMING
DBusMessage* sailfish_iptables_allow_incoming_ip(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return __process_request(message,&__allow_incoming, ARGS_IP);
}

DBusMessage* sailfish_iptables_allow_incoming_ip_port(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return __process_request(message,&__allow_incoming, ARGS_IP_PORT);
}

DBusMessage* sailfish_iptables_allow_incoming_ip_port_range(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return __process_request(message,&__allow_incoming, ARGS_IP_PORT_RANGE);
}

DBusMessage* sailfish_iptables_allow_incoming_port(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return __process_request(message,&__allow_incoming, ARGS_PORT);
}

DBusMessage* sailfish_iptables_allow_incoming_port_range(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return __process_request(message,&__allow_incoming, ARGS_PORT_RANGE);
}

DBusMessage* sailfish_iptables_allow_incoming_ip_service(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return __process_request(message,&__allow_incoming, ARGS_IP_SERVICE);
}

DBusMessage* sailfish_iptables_allow_incoming_service(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return __process_request(message,&__allow_incoming, ARGS_SERVICE);
}

// ALLOW OUTGOING
DBusMessage* sailfish_iptables_allow_outgoing_ip(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return __process_request(message,&__allow_outgoing, ARGS_IP);
}

DBusMessage* sailfish_iptables_allow_outgoing_ip_port(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return __process_request(message,&__allow_outgoing, ARGS_IP_PORT);
}

DBusMessage* sailfish_iptables_allow_outgoing_ip_port_range(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return __process_request(message,&__allow_outgoing, ARGS_IP_PORT_RANGE);
}

DBusMessage* sailfish_iptables_allow_outgoing_port(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return __process_request(message,&__allow_outgoing, ARGS_PORT);
}

DBusMessage* sailfish_iptables_allow_outgoing_port_range(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return __process_request(message,&__allow_outgoing, ARGS_PORT_RANGE);
}

DBusMessage* sailfish_iptables_allow_outgoing_ip_service(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return __process_request(message,&__allow_outgoing, ARGS_IP_SERVICE);
}

DBusMessage* sailfish_iptables_allow_outgoing_service(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return __process_request(message,&__allow_outgoing, ARGS_SERVICE);
}

// DENY INCOMING			
DBusMessage* sailfish_iptables_deny_incoming_ip(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return __process_request(message,&__deny_incoming, ARGS_IP);
}

DBusMessage* sailfish_iptables_deny_incoming_ip_port(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return __process_request(message,&__deny_incoming, ARGS_IP_PORT);
}

DBusMessage* sailfish_iptables_deny_incoming_ip_port_range(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return __process_request(message,&__deny_incoming, ARGS_IP_PORT_RANGE);
}

DBusMessage* sailfish_iptables_deny_incoming_port(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return __process_request(message,&__deny_incoming, ARGS_PORT);
}

DBusMessage* sailfish_iptables_deny_incoming_port_range(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return __process_request(message,&__deny_incoming, ARGS_PORT_RANGE);
}

DBusMessage* sailfish_iptables_deny_incoming_ip_service(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return __process_request(message,&__deny_incoming, ARGS_IP_SERVICE);
}

DBusMessage* sailfish_iptables_deny_incoming_service(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return __process_request(message,&__deny_incoming, ARGS_SERVICE);
}


// DENY OUTGOING
DBusMessage* sailfish_iptables_deny_outgoing_ip(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return __process_request(message,&__deny_outgoing, ARGS_IP);
}

DBusMessage* sailfish_iptables_deny_outgoing_ip_port(
			DBusConnection *connection, DBusMessage *message, void *user_data)
{
	return __process_request(message,&__deny_outgoing, ARGS_IP_PORT);
}

DBusMessage* sailfish_iptables_deny_outgoing_ip_port_range(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return __process_request(message,&__deny_outgoing, ARGS_IP_PORT_RANGE);
}

DBusMessage* sailfish_iptables_deny_outgoing_port(
			DBusConnection *connection, DBusMessage *message, void *user_data)
{
	return __process_request(message,&__deny_outgoing, ARGS_PORT);
}

DBusMessage* sailfish_iptables_deny_outgoing_port_range(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return __process_request(message,&__deny_outgoing, ARGS_PORT_RANGE);
}

DBusMessage* sailfish_iptables_deny_outgoing_ip_service(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return __process_request(message,&__deny_outgoing, ARGS_IP_SERVICE);
}

DBusMessage* sailfish_iptables_deny_outgoing_service(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return __process_request(message,&__deny_outgoing, ARGS_SERVICE);
}


static int sailfish_iptables_init(void)
{
	DBG("%s %s", PLUGIN_NAME, "INITIALIZE IPTABLES API");
	
	int err = sailfish_iptables_dbus_register();
	
	if(err < 0)
		DBG("%s %s", PLUGIN_NAME, "CANNOT REGISTER TO DBUS");
	else
		DBG("%s %s", PLUGIN_NAME, "REGISTER TO DBUS SUCCESS!");
	
	return 0;
}

static void sailfish_iptables_exit(void)
{
	DBG("%s %s", PLUGIN_NAME, "EXIT IPTABLES API");
	
	sailfish_iptables_dbus_unregister();
}

CONNMAN_PLUGIN_DEFINE(sailfish_ipt_api, "Sailfish iptables API", CONNMAN_VERSION,
	CONNMAN_PLUGIN_PRIORITY_DEFAULT, sailfish_iptables_init,
	sailfish_iptables_exit)

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */
