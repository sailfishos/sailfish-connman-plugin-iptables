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

#include "sailfish-iptables-parameters.h"
#include "sailfish-iptables-validate.h"
#include "sailfish-iptables-utils.h"
#include "sailfish-iptables-dbus.h"

void rule_params_free(rule_params *params)
{
	if(params)
	{
		g_free(params->ip);
		g_free(params->service);
		g_free(params->protocol);
		g_free(params->path);
		g_free(params->table);
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

