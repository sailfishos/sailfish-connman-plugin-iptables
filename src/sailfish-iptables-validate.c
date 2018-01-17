/*
 *
 *  Sailfish Connection Manager iptables plugin validation functions.
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
#include <errno.h>

#include "sailfish-iptables-validate.h"
#include "sailfish-iptables-utils.h"

gboolean negated_ip_address(const gchar* ip)
{
	return ip && ip[0] == '!';
}

gboolean check_ip_address_length(gint type, const gchar* address)
{
	return strlen(address) > (type == IPV4 ? IPV4_ADDR_MIN : IPV6_ADDR_MIN);
}

gboolean check_ip_address_format(gint type, const gchar* address)
{
	gchar** tokens = NULL;
	gboolean rval = true;
	gint length = 0, i = 0;
	
	if(!address && !*address)
		return false;
		
	tokens = g_strsplit_set(address, (type == IPV6 ? IPV6_DELIM : IPV4_DELIM), -1);
	length = g_strv_length(tokens);
		
	if(type == IPV6)
	{	
		// IPv6 can be just "::"
		if(!tokens || length < 1 || length > IPV6_TOKENS)
			rval = false;
	}
	// IPv4 as default
	else
	{
		if(tokens && length == IPV4_TOKENS)
		{
			// Check for leading zeroes
			for(i = 0; i < length; i++)
			{
				if(strlen(tokens[i]) > 1 && tokens[i][0] == '0')
				{
					rval = false;
					goto out;
				}
			}
		}
		else
			rval = false;
	}
out:
	g_strfreev(tokens);

	return rval;
}

gboolean validate_address(gint type, const gchar* address)
{
	struct addrinfo hints;
	struct addrinfo *result = NULL;
	
	// Address must be at least 1.1.1.1, or IPv4 mapped (::ffff:0.0.0.0)
	if(address && *address && 
		check_ip_address_length(type, address) &&
		check_ip_address_format(type, address))
	{		
		memset(&hints, 0, sizeof(struct addrinfo));

		hints.ai_family = (type == IPV6 ? AF_INET6 : AF_INET);
		hints.ai_flags = AI_NUMERICHOST;

		// Success
		if(!getaddrinfo(address,NULL,&hints,&result))
		{
			if(result)
			{
				freeaddrinfo(result);
				return true;
			}
		}
	}
	return false;
}

gboolean validate_ip_mask(gint type, const gchar* mask)
{
	guint32 int_mask = 0;
	
	if(type == IPV4 && mask && *mask)
	{
		// Dot notation mask
		if(strchr(mask,'.'))
			int_mask = mask_to_cidr(type, mask);
		else
			int_mask = g_ascii_strtoull(mask,NULL,10);

		if((!int_mask || // 0, acceptable
			(int_mask & (~int_mask >> 1))) && // Proper mask
			int_mask != G_MAXUINT32)
			return true;
	}
	
	return false;
}

gboolean validate_ip_address(gint type, const gchar* ip)
{
	gboolean rval = false;
	
	if(ip && *ip)
	{
		const gchar *address = NULL;
		gchar **ip_and_mask = NULL;
		
		// Allow negation
		if(negated_ip_address(ip))
			address = &ip[1];
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
		
		g_strfreev(ip_and_mask);
	}
	return rval;
}

guint16 validate_service_name(const gchar *service)
{
	if(service && *service)
	{	
		struct servent *s = getservbyname(service, NULL);
		if(s)
			return ntohs(s->s_port);	
	}
	return 0;
}

gboolean validate_protocol(const gchar *protocol)
{
	if(protocol && *protocol)
	{
		struct protoent *p = getprotobyname(protocol);
		if(p)
			return true;
	}
	return false;
}

gchar* validate_protocol_int(gint protocol)
{
	gchar *proto_str = NULL;
	
	/* TODO add support for other protocols too via getprotobynumber(). */
	switch(protocol)
	{
		case IPPROTO_TCP:
			return g_strdup("tcp");
		case IPPROTO_UDP:
			return g_strdup("udp");
		default:
			return NULL;
	}
	
	/*if(protocol && protocol != G_MAXUINT32)
	{
		struct protoent *p = getprotobynumber(protocol);
		
		if(p)
			proto_str = g_utf8_strdown(p->p_name, -1);
	}
	else if(protocol == G_MAXUINT32)
		proto_str = g_strdup("all");*/
	
	return proto_str;
}

gboolean validate_port(guint16 port)
{
	return port && port <= 0xFFFF;
}

rule_operation validate_operation(guint16 operation)
{
	switch(operation)
	{
		case ADD:
			return ADD;
		case REMOVE:
			return REMOVE;
		case FLUSH:
			return FLUSH;
		default:
			return UNDEFINED;
	}
}

gchar *validate_chain(const gchar *table, const gchar *chain)
{
	gint i = 0;
	gchar *custom_chain = NULL;
	
	if(!table || !(*table) || !chain || !(*chain))
		return NULL;
	
	const gchar const * DEFAULT_CHAINS[] = {
		"INPUT",
		"OUTPUT",
		"FORWARD",
		NULL
	};
	
	for(i = 0; DEFAULT_CHAINS[i]; i++)
	{
		if(!g_ascii_strcasecmp(chain,DEFAULT_CHAINS[i]))
			return g_utf8_strup(chain, -1); // return a copy
	}
	
	// Prefix chain
	custom_chain = g_strdup_printf("%s%s", SAILFISH_IPTABLES_CHAIN_PREFIX, chain);
	
	// Find chain with prefixed target name, table can be NULL and results in
	// -EINVAL but check_parameters() will return INVALID_TABLE in such case
	switch(connman_iptables_find_chain(table, custom_chain))
	{
		case 0:
			return custom_chain; // Return formatted chain that is prefixed
		// TODO add DBG to these
		case -1:
		case -EINVAL:
		default:
			break;
	}
	
	g_free(custom_chain);
	
	return NULL;
}

gchar* validate_target(const gchar *table, const gchar *target)
{
	gint i = 0;
	gchar *chain = NULL;
	
	if(!table || !(*table) || !target || !(*target))
		return NULL;
	
	// Add sailfish builtin targets here
	const gchar const * ALLOWED_TARGETS[] = {
		"ACCEPT",
		"DROP",
		"QUEUE",
		"RETURN",
		"REJECT",
		NULL
	};
	
	const gchar const * DENIED_TARGETS[] = {
		"INPUT",
		"OUTPUT",
		"FORWARD",
		NULL
	};
	
	// One of the builtin targets
	for(i = 0; ALLOWED_TARGETS[i]; i++)
	{
		if(!g_ascii_strcasecmp(target, ALLOWED_TARGETS[i]))
			return g_utf8_strup(target, -1); // Return a copy
	}
	
	// If one of the bultin chains
	for(i = 0; DENIED_TARGETS[i]; i++)
	{
		if(!g_ascii_strcasecmp(target, ALLOWED_TARGETS[i]))
			return NULL; // Return null, this is invalid target
	}
	
	// Prefix chain
	chain = g_strdup_printf("%s%s",	SAILFISH_IPTABLES_CHAIN_PREFIX, target);
	
	// Find chain with prefixed target name, table can be NULL and results in
	// -EINVAL but check_parameters() will return INVALID_TABLE in such case
	switch(connman_iptables_find_chain(table, chain))
	{
		case 0:
			return chain; // Return formatted chain that is prefixed
		// TODO add DBG to these
		case -1:
		case -EINVAL:
		default:
			break;
	}
	
	g_free(chain);
	
	return NULL;
}

gboolean validate_policy(const gchar* policy)
{
	if(policy && *policy)
	{
		if(!g_strcmp0(policy,IPTABLES_ACCEPT) ||
			!g_strcmp0(policy,IPTABLES_DROP))
			return true;
	}
	return false;
}

gchar* validate_policy_int(guint16 policy_int)
{
	switch(policy_int)
	{
		case IPTABLES_ACCEPT_INT:
			return g_strdup(IPTABLES_ACCEPT);
		case IPTABLES_DROP_INT:
			return g_strdup(IPTABLES_DROP);
		default:
			return NULL;
	}
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */
