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

#ifndef _SAILFISH_IPTABLES_H_
#define _SAILFISH_IPTABLES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "sailfish-iptables-dbus.h"

#define SAILFISH_IPTABLES_INTERFACE_VERSION		1
#define SAILFISH_IPTABLES_TABLE_NAME			"filter"
#define IPTABLES_CHAIN_INPUT					"INPUT"
#define IPTABLES_CHAIN_OUTPUT					"OUTPUT"
#define IPTABLES_ACCEPT							"ACCEPT"
#define IPTABLES_DROP							"DROP"
#define IPTABLES_RULE_ACCEPT					" -j "IPTABLES_ACCEPT
#define IPTABLES_RULE_DROP						" -j "IPTABLES_DROP

#define	OPERATION_IN 							0x0001
#define	OPERATION_OUT 							0x0002
#define	OPERATION_ACCEPT 						0x0004
#define	OPERATION_DENY 							0x0008

#define IP_MASK_DELIM							"/"
#define PORT_RANGE_DELIM						":"
#define IP_DELIM								"."

#define IPV4									4
#define IPV6									6
#define IPV4_MASK_MAX							32
#define IPV6_MASK_MAX							128

typedef enum sailfish_iptables_result {
	OK = 0,
	INVALID_IP,
	INVALID_PORT,
	INVALID_PORT_RANGE,
	INVALID_SERVICE,
	INVALID_PROTOCOL,
	INVALID_POLICY,
	INVALID_FILE_PATH,
	RULE_DOES_NOT_EXIST,
	INVALID_REQUEST,
	INVALID
} api_result;

typedef enum sailfish_iptables_rule_operation {
	ADD = 0,
	REMOVE,
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
	ARGS_SAVE,
	ARGS_LOAD,
	ARGS_CLEAR,
	ARGS_POLICY_IN,
	ARGS_POLICY_OUT
} rule_args;
 
typedef struct sailfish_iptables_rule_params {
	gchar *ip;
	gboolean ip_negate;
	gchar *service;
	guint16 port[2];
	gchar *protocol;
	rule_operation operation;
	gchar *path;
	gchar *table;
	gchar *policy;
	rule_args args;
} rule_params;

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
