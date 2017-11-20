#ifndef __SAILFISH_IPTABLES_H_
#define __SAILFISH_IPTABLES_H_

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
