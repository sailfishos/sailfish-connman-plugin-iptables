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

#define SAILFISH_IPTABLES_ALLOW_IN_IP			"AllowIncomingIp"
#define SAILFISH_IPTABLES_ALLOW_IN_IP_PORT		"AllowIncomingIpWithPort"
#define SAILFISH_IPTABLES_ALLOW_IN_IP_PORT_RANGE	"AllowIncomingIpWithPortRange"
#define SAILFISH_IPTABLES_ALLOW_IN_PORT			"AllowIncomingPort"
#define SAILFISH_IPTABLES_ALLOW_IN_PORT_RANGE		"AllowIncomingPortRange"
#define SAILFISH_IPTABLES_ALLOW_IN_IP_SERVICE		"AllowIncomingIpWithService"
#define SAILFISH_IPTABLES_ALLOW_IN_SERVICE		"AllowIncomingService"

#define SAILFISH_IPTABLES_ALLOW_OUT_IP			"AllowOutgoingIp"
#define SAILFISH_IPTABLES_ALLOW_OUT_IP_PORT		"AllowOutgoingIpWithPort"
#define SAILFISH_IPTABLES_ALLOW_OUT_IP_PORT_RANGE	"AllowOutgoingIpWithPortRange"
#define SAILFISH_IPTABLES_ALLOW_OUT_PORT		"AllowOutgoingPort"
#define SAILFISH_IPTABLES_ALLOW_OUT_PORT_RANGE		"AllowOutgoingPortRange"
#define SAILFISH_IPTABLES_ALLOW_OUT_IP_SERVICE		"AllowOutgoingIpWithService"
#define SAILFISH_IPTABLES_ALLOW_OUT_SERVICE		"AllowOutgoingService"

#define SAILFISH_IPTABLES_DENY_IN_IP			"DenyIncomingIp"
#define SAILFISH_IPTABLES_DENY_IN_IP_PORT		"DenyIncomingIpWithPort"
#define SAILFISH_IPTABLES_DENY_IN_IP_PORT_RANGE		"DenyIncomingIpWithPortRange"
#define SAILFISH_IPTABLES_DENY_IN_PORT			"DenyIncomingPort"
#define SAILFISH_IPTABLES_DENY_IN_PORT_RANGE		"DenyIncomingPortRange"
#define SAILFISH_IPTABLES_DENY_IN_IP_SERVICE		"DenyIncomingIpWithService"
#define SAILFISH_IPTABLES_DENY_IN_SERVICE		"DenyIncomingService"

#define SAILFISH_IPTABLES_DENY_OUT_IP			"DenyOutgoingIp"
#define SAILFISH_IPTABLES_DENY_OUT_IP_PORT		"DenyOutgoingIpWithPort"
#define SAILFISH_IPTABLES_DENY_OUT_IP_PORT_RANGE	"DenyOutgoingIpWithPortRange"
#define SAILFISH_IPTABLES_DENY_OUT_PORT			"DenyOutgoingPort"
#define SAILFISH_IPTABLES_DENY_OUT_PORT_RANGE		"DenyOutgoingPortRange"
#define SAILFISH_IPTABLES_DENY_OUT_IP_SERVICE		"DenyOutgoingIpWithService"
#define SAILFISH_IPTABLES_DENY_OUT_SERVICE		"DenyOutgoingService"

#define SAILFISH_IPTABLES_CHANGE_IN_POLICY		"ChangeInputPolicy"
#define SAILFISH_IPTABLES_CHANGE_OUT_POLICY		"ChangeOutputPolicy"

#define SAILFISH_IPTABLES_CLEAR_IPTABLES_TABLE		"ClearIptablesTable"
#define SAILFISH_IPTABLES_CLEAR_IPTABLES_CHAINS		"ClearIptablesChains"

#define SAILFISH_IPTABLES_REGISTER_CLIENT		"Register"
#define SAILFISH_IPTABLES_UNREGISTER_CLIENT		"Unregister"

#define SAILFISH_IPTABLES_MANAGE_CHAIN			"ManageChain"

#define SAILFISH_IPTABLES_GET_IPTABLES_CONTENT	"GetIptablesContent"

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
	12 = "Invalid chain name given. Chain name is reserved (add) or does not exist (remove)."
	13 = "Access denied",
*/

#define SAILFISH_IPTABLES_RESULT_TYPE			{"result", "q"}
#define SAILFISH_IPTABLES_RESULT_STRING			{"string", "s"}
#define SAILFISH_IPTABLES_RESULT_VERSION		{"version", "i"}
#define SAILFISH_IPTABLES_RESULT_CHAINS			{"chains", "as"}
#define SAILFISH_IPTABLES_RESULT_RULES			{"rules", "as"}


#define SAILFISH_IPTABLES_INPUT_ABSOLUTE_PATH		{"absolute_path","s"}
#define SAILFISH_IPTABLES_INPUT_IP			{"ip","s"}
#define SAILFISH_IPTABLES_INPUT_PORT			{"port","q"}
#define SAILFISH_IPTABLES_INPUT_PORT_STR		{"port","s"}
#define SAILFISH_IPTABLES_INPUT_SERVICE			{"service","s"}
#define SAILFISH_IPTABLES_INPUT_PROTOCOL		{"protocol","s"}
#define SAILFISH_IPTABLES_INPUT_OPERATION		{"operation","s"}
#define SAILFISH_IPTABLES_INPUT_POLICY			{"policy", "s"}
#define SAILFISH_IPTABLES_INPUT_TABLE			{"table", "s"}
#define SAILFISH_IPTABLES_INPUT_CHAIN			{"chain", "s"}

#define SAILFISH_IPTABLES_SIGNAL_POLICY_CHAIN		{"chain", "s"}
#define SAILFISH_IPTABLES_SIGNAL_POLICY_TYPE		SAILFISH_IPTABLES_INPUT_POLICY

const gchar const * OP_STR[] = {"Add", "Remove", "Undefined", NULL};
const gchar * EMPTY_STR = "";

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
			NULL)
		},
		{ GDBUS_SIGNAL(
			SAILFISH_IPTABLES_SIGNAL_POLICY,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_SIGNAL_POLICY_CHAIN, 
				SAILFISH_IPTABLES_SIGNAL_POLICY_TYPE))
		},
		{ GDBUS_SIGNAL(
			SAILFISH_IPTABLES_SIGNAL_CHAIN,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_SIGNAL_POLICY_CHAIN, 
				SAILFISH_IPTABLES_INPUT_OPERATION))
		},
		{ GDBUS_SIGNAL(
			SAILFISH_IPTABLES_SIGNAL_RULE,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_IP,
				SAILFISH_IPTABLES_INPUT_PORT_STR,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION
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
		{ GDBUS_METHOD(SAILFISH_IPTABLES_CHANGE_IN_POLICY, 
			GDBUS_ARGS(SAILFISH_IPTABLES_INPUT_POLICY),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_change_input_policy)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_MANAGE_CHAIN, 
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_CHAIN,
				SAILFISH_IPTABLES_INPUT_OPERATION),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_manage_chain)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_CHANGE_OUT_POLICY, 
			GDBUS_ARGS(SAILFISH_IPTABLES_INPUT_POLICY),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_change_output_policy)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_ALLOW_IN_IP,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_IP,
				SAILFISH_IPTABLES_INPUT_OPERATION),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_allow_incoming_ip)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_ALLOW_IN_IP_PORT,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_IP,
				SAILFISH_IPTABLES_INPUT_PORT,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION
			),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_allow_incoming_ip_port)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_ALLOW_IN_IP_PORT_RANGE,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_IP,
				SAILFISH_IPTABLES_INPUT_PORT_STR,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION
			),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_allow_incoming_ip_port_range)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_ALLOW_IN_PORT,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_PORT,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION
			),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_allow_incoming_port)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_ALLOW_IN_PORT_RANGE,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_PORT_STR,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION
			),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_allow_incoming_port_range)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_ALLOW_IN_IP_SERVICE,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_IP,
				SAILFISH_IPTABLES_INPUT_SERVICE,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION
			),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_allow_incoming_ip_service)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_ALLOW_IN_SERVICE,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_SERVICE,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_allow_incoming_service)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_ALLOW_OUT_IP,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_IP,
				SAILFISH_IPTABLES_INPUT_OPERATION),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_allow_outgoing_ip)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_ALLOW_OUT_IP_PORT,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_IP,
				SAILFISH_IPTABLES_INPUT_PORT,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION
			),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_allow_outgoing_ip_port)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_ALLOW_OUT_IP_PORT_RANGE,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_IP,
				SAILFISH_IPTABLES_INPUT_PORT_STR,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION
			),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_allow_outgoing_ip_port_range)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_ALLOW_OUT_PORT,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_PORT,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION
			),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_allow_outgoing_port)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_ALLOW_OUT_PORT_RANGE,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_PORT_STR,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION
			),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_allow_outgoing_port_range)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_ALLOW_OUT_IP_SERVICE,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_IP,
				SAILFISH_IPTABLES_INPUT_SERVICE,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION
			),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_allow_outgoing_ip_service)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_ALLOW_OUT_SERVICE,
			GDBUS_ARGS(
			SAILFISH_IPTABLES_INPUT_SERVICE,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_allow_outgoing_service)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_DENY_IN_IP,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_IP,
				SAILFISH_IPTABLES_INPUT_OPERATION),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_deny_incoming_ip)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_DENY_IN_IP_PORT,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_IP,
				SAILFISH_IPTABLES_INPUT_PORT,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION
			),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_deny_incoming_ip_port)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_DENY_IN_IP_PORT_RANGE,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_IP,
				SAILFISH_IPTABLES_INPUT_PORT_STR,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION
			),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_deny_incoming_ip_port_range)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_DENY_IN_PORT,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_PORT,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION
			),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_deny_incoming_port)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_DENY_IN_PORT_RANGE,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_PORT_STR,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION
			),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_deny_incoming_port_range)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_DENY_IN_IP_SERVICE,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_IP,
				SAILFISH_IPTABLES_INPUT_SERVICE,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION
			),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_deny_incoming_ip_service)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_DENY_IN_SERVICE,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_SERVICE,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_deny_incoming_service)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_DENY_OUT_IP,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_IP,
				SAILFISH_IPTABLES_INPUT_OPERATION),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_deny_outgoing_ip)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_DENY_OUT_IP_PORT,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_IP,
				SAILFISH_IPTABLES_INPUT_PORT,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION
			),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_deny_outgoing_ip_port)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_DENY_OUT_IP_PORT_RANGE,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_IP,
				SAILFISH_IPTABLES_INPUT_PORT_STR,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION
			),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_deny_outgoing_ip_port_range)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_DENY_OUT_PORT,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_PORT,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION
			),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_deny_outgoing_port)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_DENY_OUT_PORT_RANGE,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_PORT_STR,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION
			),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_deny_outgoing_port_range)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_DENY_OUT_IP_SERVICE,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_IP,
				SAILFISH_IPTABLES_INPUT_SERVICE,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION
			),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_deny_outgoing_ip_service)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_DENY_OUT_SERVICE,
			GDBUS_ARGS(
				SAILFISH_IPTABLES_INPUT_SERVICE,
				SAILFISH_IPTABLES_INPUT_PROTOCOL,
				SAILFISH_IPTABLES_INPUT_OPERATION),
			GDBUS_ARGS(
				SAILFISH_IPTABLES_RESULT_TYPE,
				SAILFISH_IPTABLES_RESULT_STRING
			),
			sailfish_iptables_deny_outgoing_service)
		},
		{ GDBUS_METHOD(SAILFISH_IPTABLES_GET_VERSION, 
			NULL,
			GDBUS_ARGS(SAILFISH_IPTABLES_RESULT_VERSION),
			sailfish_iptables_version)
		},
		{ }
	};
	
/* New method sailfish_iptables_rule:
	IP: str / uint32
	Mask: uint8 (0-128)
	Port start: uint16
	Port end: uint16
	Protocol: uint8 (IPPROTO_TCP/UDP/SCTP))
	Operation: uint8 0/1 (add-default,remove)
	Direction: uint8 0/1 (INPUT/OUTPUT)
	Target:	uint8 0/1/2/3/4 (ACCEPT,DROP,QUEUE,RETURN,REJECT) - custom target?
	
*/

/* New method sailfish_iptables_new_custom_rule:
	IP: str / uint32
	Mask: uint8 (0-128)
	Port start: uint16
	Port end: uint16
	Protocol: uint8 (IPPROTO_TCP/UDP/SCTP))
	Operation: uint8 0/1 (add-default,remove)
	Direction: uint8 0/1 (INPUT/OUTPUT)
	Target:	str (custom chain name)
	
*/


static void dbus_client_destroy(void *user_data)
{
	if(user_data)
	{
		client_disconnect_data *data = (client_disconnect_data*)user_data;
	
		api_data_remove_peer(data->main_data, data->client_name);
	
		client_disconnect_data_free(data);
	}
}

static void dbus_client_disconnected(DBusConnection *connection, void *user_data)
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
	return process_request(message, &clear_iptables_rules, ARGS_CLEAR, user_data);
}

DBusMessage* sailfish_iptables_clear_iptables_chains(DBusConnection *connection,
			DBusMessage *message, void *user_data)
{
	return process_request(message, &clear_iptables_chains, ARGS_CLEAR, user_data);
}

DBusMessage* sailfish_iptables_get_iptables_content(DBusConnection *connection,
			DBusMessage *message, void *user_data)
{
	return process_request(message, &get_iptables_content, ARGS_GET_CONTENT, user_data);
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

DBusMessage* sailfish_iptables_change_input_policy(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return process_request(message, &set_policy, ARGS_POLICY_IN, user_data);
}

DBusMessage* sailfish_iptables_change_output_policy(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return process_request(message, &set_policy, ARGS_POLICY_OUT, user_data);
}

// ALLOW INCOMING
DBusMessage* sailfish_iptables_allow_incoming_ip(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return process_request(message, &allow_incoming, ARGS_IP, user_data);
}

DBusMessage* sailfish_iptables_allow_incoming_ip_port(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return process_request(message,&allow_incoming, ARGS_IP_PORT, user_data);
}

DBusMessage* sailfish_iptables_allow_incoming_ip_port_range(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return process_request(message,&allow_incoming, ARGS_IP_PORT_RANGE, user_data);
}

DBusMessage* sailfish_iptables_allow_incoming_port(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return process_request(message,&allow_incoming, ARGS_PORT, user_data);
}

DBusMessage* sailfish_iptables_allow_incoming_port_range(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return process_request(message,&allow_incoming, ARGS_PORT_RANGE, user_data);
}

DBusMessage* sailfish_iptables_allow_incoming_ip_service(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return process_request(message,&allow_incoming, ARGS_IP_SERVICE, user_data);
}

DBusMessage* sailfish_iptables_allow_incoming_service(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return process_request(message,&allow_incoming, ARGS_SERVICE, user_data);
}

// ALLOW OUTGOING
DBusMessage* sailfish_iptables_allow_outgoing_ip(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return process_request(message,&allow_outgoing, ARGS_IP, user_data);
}

DBusMessage* sailfish_iptables_allow_outgoing_ip_port(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return process_request(message,&allow_outgoing, ARGS_IP_PORT, user_data);
}

DBusMessage* sailfish_iptables_allow_outgoing_ip_port_range(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return process_request(message,&allow_outgoing, ARGS_IP_PORT_RANGE, user_data);
}

DBusMessage* sailfish_iptables_allow_outgoing_port(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return process_request(message,&allow_outgoing, ARGS_PORT, user_data);
}

DBusMessage* sailfish_iptables_allow_outgoing_port_range(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return process_request(message,&allow_outgoing, ARGS_PORT_RANGE, user_data);
}

DBusMessage* sailfish_iptables_allow_outgoing_ip_service(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return process_request(message,&allow_outgoing, ARGS_IP_SERVICE, user_data);
}

DBusMessage* sailfish_iptables_allow_outgoing_service(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return process_request(message,&allow_outgoing, ARGS_SERVICE, user_data);
}

// DENY INCOMING
DBusMessage* sailfish_iptables_deny_incoming_ip(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return process_request(message,&deny_incoming, ARGS_IP, user_data);
}

DBusMessage* sailfish_iptables_deny_incoming_ip_port(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return process_request(message,&deny_incoming, ARGS_IP_PORT, user_data);
}

DBusMessage* sailfish_iptables_deny_incoming_ip_port_range(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return process_request(message,&deny_incoming, ARGS_IP_PORT_RANGE, user_data);
}

DBusMessage* sailfish_iptables_deny_incoming_port(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return process_request(message,&deny_incoming, ARGS_PORT, user_data);
}

DBusMessage* sailfish_iptables_deny_incoming_port_range(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return process_request(message,&deny_incoming, ARGS_PORT_RANGE, user_data);
}

DBusMessage* sailfish_iptables_deny_incoming_ip_service(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return process_request(message,&deny_incoming, ARGS_IP_SERVICE, user_data);
}

DBusMessage* sailfish_iptables_deny_incoming_service(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return process_request(message,&deny_incoming, ARGS_SERVICE, user_data);
}


// DENY OUTGOING
DBusMessage* sailfish_iptables_deny_outgoing_ip(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return process_request(message,&deny_outgoing, ARGS_IP, user_data);
}

DBusMessage* sailfish_iptables_deny_outgoing_ip_port(
			DBusConnection *connection, DBusMessage *message, void *user_data)
{
	return process_request(message,&deny_outgoing, ARGS_IP_PORT, user_data);
}

DBusMessage* sailfish_iptables_deny_outgoing_ip_port_range(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return process_request(message,&deny_outgoing, ARGS_IP_PORT_RANGE, user_data);
}

DBusMessage* sailfish_iptables_deny_outgoing_port(
			DBusConnection *connection, DBusMessage *message, void *user_data)
{
	return process_request(message,&deny_outgoing, ARGS_PORT, user_data);
}

DBusMessage* sailfish_iptables_deny_outgoing_port_range(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return process_request(message,&deny_outgoing, ARGS_PORT_RANGE, user_data);
}

DBusMessage* sailfish_iptables_deny_outgoing_ip_service(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return process_request(message,&deny_outgoing, ARGS_IP_SERVICE, user_data);
}

DBusMessage* sailfish_iptables_deny_outgoing_service(
			DBusConnection *connection,	DBusMessage *message, void *user_data)
{
	return process_request(message,&deny_outgoing, ARGS_SERVICE, user_data);
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
	const gchar* msg = api_result_message(result);
	DBusMessage* reply = NULL;

	if(!params || !params->iptables_content)
		reply = g_dbus_create_reply(message,
			DBUS_TYPE_UINT16,	&res,
			DBUS_TYPE_STRING, 	&msg,
			DBUS_TYPE_INVALID);
	
	else if(params->iptables_content)
	{
		DBusMessageIter iter, array;
		GList *list_iter = NULL;
		
		reply = dbus_message_new_method_return(message);
			
		dbus_message_iter_init_append(reply, &iter);
		
		dbus_message_iter_append_basic(&iter, DBUS_TYPE_UINT16, &res);
		dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &msg);
		
		// Chains
		dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_TYPE_STRING_AS_STRING, &array);
			
		for(list_iter = params->iptables_content->chains ; list_iter ; list_iter = list_iter->next)
		{
			gchar* content = (gchar*)list_iter->data;
			dbus_message_iter_append_basic(&array, DBUS_TYPE_STRING, &content);
		}
		
		dbus_message_iter_close_container(&iter, &array);
		
		// Rules
		dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_TYPE_STRING_AS_STRING, &array);
			
		for(list_iter = params->iptables_content->rules ; list_iter ; list_iter = list_iter->next)
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
	gchar *port_str = port_to_str(params);
	const gchar *empty = EMPTY_STR;
	const gchar *op = OP_STR[params->operation];
	const gchar *chain = NULL;

	switch(params->args)
	{
		case ARGS_IP:
			signal = sailfish_iptables_dbus_signal(
				SAILFISH_IPTABLES_SIGNAL_RULE,
				DBUS_TYPE_STRING,	&(params->ip),
				DBUS_TYPE_STRING,	&empty,
				DBUS_TYPE_STRING,	&op,
				DBUS_TYPE_INVALID);
			break;
		case ARGS_IP_PORT:
		case ARGS_IP_PORT_RANGE:
		case ARGS_IP_SERVICE:
			signal = sailfish_iptables_dbus_signal(
				SAILFISH_IPTABLES_SIGNAL_RULE,
				DBUS_TYPE_STRING,	&(params->ip),
				DBUS_TYPE_STRING,	&port_str,
				DBUS_TYPE_STRING,	&op,
				DBUS_TYPE_INVALID);
			break;
		case ARGS_PORT:
		case ARGS_PORT_RANGE:
		case ARGS_SERVICE:
			signal = sailfish_iptables_dbus_signal(
				SAILFISH_IPTABLES_SIGNAL_RULE,
				DBUS_TYPE_STRING,	&empty,
				DBUS_TYPE_STRING,	&port_str,
				DBUS_TYPE_STRING,	&op,
				DBUS_TYPE_INVALID);
			break;
		case ARGS_CLEAR:
			signal = sailfish_iptables_dbus_signal(
				SAILFISH_IPTABLES_SIGNAL_CLEAR,
				DBUS_TYPE_INVALID);
			break;
		case ARGS_POLICY_IN:
			chain = IPTABLES_CHAIN_INPUT;
			signal = sailfish_iptables_dbus_signal(
				SAILFISH_IPTABLES_SIGNAL_POLICY,
				DBUS_TYPE_STRING,	&chain,
				DBUS_TYPE_STRING,	&(params->policy),
				DBUS_TYPE_INVALID);
			break;
		case ARGS_POLICY_OUT:
			chain = IPTABLES_CHAIN_OUTPUT;
			signal = sailfish_iptables_dbus_signal(
				SAILFISH_IPTABLES_SIGNAL_POLICY,
				DBUS_TYPE_STRING,	&chain,
				DBUS_TYPE_STRING,	&(params->policy),
				DBUS_TYPE_INVALID);
			break;
		case ARGS_CHAIN:
			signal = sailfish_iptables_dbus_signal(
				SAILFISH_IPTABLES_SIGNAL_CHAIN,
				DBUS_TYPE_STRING,	&(params->chain_name),
				DBUS_TYPE_STRING,	&op,
				DBUS_TYPE_INVALID);
		default:
			break;
	}
	g_free(port_str);
	return signal;
}

rule_params* sailfish_iptables_dbus_get_parameters_from_msg(DBusMessage* message, rule_args args)
{
	rule_params *params = rule_params_new(args);
	DBusError* error = NULL;
	
	gchar *ip = NULL, *service = NULL, *protocol = NULL, *port_str = NULL;
	gchar *table = NULL, *policy = NULL, *operation = NULL, *chain_name = NULL;
	dbus_uint16_t port[2] = {0};
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
		case ARGS_CLEAR:
			// TODO enable this when other than "filter" table is supported
			/*rval = dbus_message_get_args(message, error,
						DBUS_TYPE_STRING, &table,
						DBUS_TYPE_INVALID);*/
			break;
		case ARGS_POLICY_IN:
		case ARGS_POLICY_OUT:
			rval = dbus_message_get_args(message, error,
						DBUS_TYPE_STRING, &policy,
						DBUS_TYPE_INVALID);
			
			break;
		case ARGS_CHAIN:
			rval = dbus_message_get_args(message, error,
						DBUS_TYPE_STRING, &chain_name,
						DBUS_TYPE_STRING, &operation,
						DBUS_TYPE_INVALID);
			break;
		case ARGS_GET_CONTENT:
			// TODO enable this when other than "filter" table is supported
			/*rval = dbus_message_get_args(message, error,
						DBUS_TYPE_STRING, &table,
						DBUS_TYPE_INVALID);*/
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
	if(port_str && *port_str)
	{
		gchar **tokens = get_port_range_tokens(port_str);
		
		if(tokens)
		{
			for(index = 0; index < 2 && tokens[index] ; index++)
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
	if(operation && *operation)
	{
		if((op = validate_operation(operation)) != UNDEFINED)
			params->operation = op;
	}
	// No operation defined, defaults to ADD
	else
		params->operation = ADD;
	
	// For now always default to "filter" table (SAILFISH_IPTABLES_TABLE_NAME)
	if(table && *table && g_utf8_validate(table,-1,NULL))
		params->table = g_strdup(SAILFISH_IPTABLES_TABLE_NAME);//g_utf8_strdown(table,-1);
	else
		params->table = g_strdup(SAILFISH_IPTABLES_TABLE_NAME);
	
	if(policy && g_utf8_validate(policy,-1,NULL))
	{
		gchar *policy_uppercase = g_utf8_strup(policy,-1);
		if(validate_policy(policy_uppercase))
			params->policy = policy_uppercase;
	}
	
	if(chain_name && *chain_name && g_utf8_validate(chain_name,-1, NULL))
		params->chain_name = g_strdup_printf("%s%s", 
			SAILFISH_IPTABLES_CHAIN_PREFIX, chain_name);
		
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
