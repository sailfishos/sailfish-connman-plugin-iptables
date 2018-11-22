#include <stdio.h>
#include <errno.h>
#include <glib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include "../src/sailfish-iptables-validate.h"
#include "../src/sailfish-iptables-parameters.h"
#include "../src/sailfish-iptables-utils.h"
#include "../src/sailfish-iptables-policy.h"

#define CONNMAN_API_SUBJECT_TO_CHANGE

// To be able to build the tests without connman
DBusConnection* connman_dbus_get_connection() { return NULL; }
void connman_log(const char *fmt, ...) { return; }
void connman_error(const char *fmt, ...) { return; }
gboolean g_dbus_remove_watch(DBusConnection *connection, guint id) { return TRUE; }
int connman_iptables_delete_chain(const char *table_name, const char *chain) { return 0; }
int connman_iptables_commit(const char *table_name) { return 0; }
const char *connman_storage_dir(void) { return "/tmp"; }
int connman_iptables_find_chain(const char *table_name, const char *chain)
{
	return g_ascii_strcasecmp(chain,"sfos_CUSTOM1");
}
int connman_iptables_flush_chain(const char *table_name, const char *chain) {return 0;}

GList *api_data_get_custom_chain_table(api_data *data, const gchar* table_name);
custom_chain_item* custom_chain_item_new(const gchar* table);
void custom_chain_item_free(custom_chain_item *item);
gboolean custom_chain_item_add_to_chains(custom_chain_item* item,
	const gchar* chain);
gboolean custom_chain_item_remove_from_chains(custom_chain_item *item,
	const gchar* chain);
gchar* sailfish_iptables_load_policy(const gchar* policyfile);

// From connman sailfish_iptables_extension.c
void connman_iptables_free_content(connman_iptables_content *content)
{
	if(!content)
		return;
		
	g_list_free(content->chains);
	g_list_free(content->rules);
	g_free(content->table);
	g_free(content);
}

void da_peer_unref(DAPeer* peer)
{
	if(peer)
	{
		if(peer->name)
			g_free((gchar*)peer->name);
		g_free(peer);
	}
}

int da_system_uid(const char* user)
{
	if (!g_strcmp0(user, "sailfish-mdm") || !g_strcmp0(user,"nemo"))
		return 1;
	else
		return -1;
}

int da_system_gid(const char* group)
{
	if (!g_strcmp0(group, "privileged"))
		return 1;
	else
		return -1;
}

static void test_iptables_plugin_policy_check_user()
{
	gint i = 0;
	api_data* data = api_data_new();
	DAPeer* peer = g_new0(DAPeer, 1);
	
	g_assert(data);
	
	static const gid_t groups[] = {
		39, 100, 993, 996, 997, 999, 1000, 1002, 1003, 1004,
		1005, 1006, 1024, 100000
	};
	
	DACred cred = {
		100000, 100000,
		groups, G_N_ELEMENTS(groups),
		0,
		DBUSACCESS_CRED_CAPS | DBUSACCESS_CRED_GROUPS
	};
	
	peer->cred = cred;
	
	gchar *peer_name = g_strdup(":1.1234");
	peer->name = g_strdup(peer_name);
	
	g_assert(!sailfish_iptables_policy_check_peer(data, peer, SAILFISH_DBUS_ACCESS_MANAGE));
	g_assert(!sailfish_iptables_policy_check_peer(data, peer, SAILFISH_DBUS_ACCESS));
	g_assert(!sailfish_iptables_policy_check_peer(data, peer, SAILFISH_DBUS_ACCESS_LISTEN));
	
	g_assert(!sailfish_iptables_policy_check_peer(data, peer, 0));
	g_assert(!sailfish_iptables_policy_check_peer(data, peer, 100));
	
	DBusMessage* msg = dbus_message_new_method_call("net.connman",
		"/org/sailfishos/connman/mdm/iptables",
		"org.sailfishos.connman.mdm.iptables",
		"GetVersion");
		
	dbus_message_set_sender(msg, peer_name);
	
	dbus_client* client = dbus_client_new();
	g_assert(client);
	
	client->peer = peer;
	g_assert(api_data_add_peer(data, client));
	
	for(i = 0; i <= ARGS_CHAIN ; i++)
		g_assert(!sailfish_iptables_policy_check_args(msg, data, i));
	
	g_assert(!sailfish_iptables_policy_check_args(msg, data, ARGS_CHAIN+1));
	
	g_assert(api_data_remove_peer(data, peer_name));
	
	dbus_message_unref(msg);
	api_data_free(data);
	g_free(peer_name);
}

static void test_iptables_plugin_policy_check_root()
{
	gint i = 0;
	api_data* data = api_data_new();
	DAPeer* peer = g_new0(DAPeer,1);
	
	g_assert(data);
	
	DACred cred = {
		0, 0,
		NULL, 0,
		G_GUINT64_CONSTANT(0xfffffff008003420),
		DBUSACCESS_CRED_CAPS | DBUSACCESS_CRED_GROUPS
	};
	
	peer->cred = cred;
	
	gchar *peer_name = g_strdup(":1.1234");
	peer->name = g_strdup(peer_name);
		
	g_assert(sailfish_iptables_policy_check_peer(data, peer, SAILFISH_DBUS_ACCESS_MANAGE));
	g_assert(sailfish_iptables_policy_check_peer(data, peer, SAILFISH_DBUS_ACCESS));
	g_assert(sailfish_iptables_policy_check_peer(data, peer, SAILFISH_DBUS_ACCESS_LISTEN));
	
	g_assert(!sailfish_iptables_policy_check_peer(data, peer, 0));
	g_assert(!sailfish_iptables_policy_check_peer(data, peer, SAILFISH_DBUS_ACCESS_LISTEN+1));
	
	DBusMessage* msg = dbus_message_new_method_call("net.connman",
		"/org/sailfishos/connman/mdm/iptables",
		"org.sailfishos.connman.mdm.iptables",
		"GetVersion");
		
	dbus_message_set_sender(msg, peer_name);
	
	dbus_client* client = dbus_client_new();
	g_assert(client);
	
	client->peer = peer;
	g_assert(api_data_add_peer(data, client));
	
	for(i = 0; i <= ARGS_CHAIN ; i++)
		g_assert(sailfish_iptables_policy_check_args(msg, data, i));
	
	g_assert(!sailfish_iptables_policy_check_args(msg, data, ARGS_CHAIN+1));
	
	g_assert(api_data_remove_peer(data, peer_name));
	
	dbus_message_unref(msg);
	api_data_free(data);
	g_free(peer_name);
}

static void test_iptables_plugin_policy_check_basic()
{
	gint i = 0;
	api_data* data = api_data_new();
	
	g_assert(data);
	
	for(i = 0; i <= SAILFISH_DBUS_ACCESS_LISTEN ; i++)
		g_assert(!sailfish_iptables_policy_check_peer(NULL, NULL,i));
	
	for(i = 0; i <= SAILFISH_DBUS_ACCESS_LISTEN ; i++)
		g_assert(!sailfish_iptables_policy_check_peer(data, NULL,i));
	
	g_assert(!sailfish_iptables_policy_get_peer(NULL, NULL));
	g_assert(!sailfish_iptables_policy_check(NULL, NULL, SAILFISH_DBUS_ACCESS_MANAGE));
	g_assert(!sailfish_iptables_policy_check_args(NULL, NULL, ARGS_CLEAR));
	
	DBusMessage* msg = dbus_message_new_method_call("net.connman",
		"/org/sailfishos/connman/mdm/iptables",
		"org.sailfishos.connman.mdm.iptables",
		"GetVersion");
		
	dbus_message_set_sender(msg,":1.1234");
	
	g_assert(!sailfish_iptables_policy_get_peer(msg, data));
	g_assert(!sailfish_iptables_policy_check(msg, data, SAILFISH_DBUS_ACCESS_MANAGE));
	
	dbus_message_unref(msg);
	api_data_free(data);
}

#define DEFAULT_POLICY1 "1;* = deny;" \
    "(user(sailfish-mdm)|group(privileged)) & manage() = allow;" \
    "group(privileged) & listen() = allow;" \
    "group(privileged) & full() = deny;"

static void test_iptables_plugin_policy_load()
{
	gchar *policy = NULL;
	
	policy = sailfish_iptables_load_policy(NULL);
	g_assert(policy);
	g_assert(!g_ascii_strcasecmp(policy, DEFAULT_POLICY1));
	g_free(policy);
	
	policy = sailfish_iptables_load_policy("");
	g_assert(policy);
	g_assert(!g_ascii_strcasecmp(policy, DEFAULT_POLICY1));
	g_free(policy);
	
	policy = sailfish_iptables_load_policy("policy.conf");
	g_assert(policy);
	g_assert(!g_ascii_strcasecmp(policy, DEFAULT_POLICY1));
	g_free(policy);
	
	policy = sailfish_iptables_load_policy("policy");
	g_assert(policy);
	g_assert(!g_ascii_strcasecmp(policy, DEFAULT_POLICY1));
	g_free(policy);
	
	policy = sailfish_iptables_load_policy("policy.sh");
	g_assert(policy);
	g_assert(!g_ascii_strcasecmp(policy, DEFAULT_POLICY1));
	g_free(policy);
	
	policy = sailfish_iptables_load_policy("../../policy.conf");
	g_assert(policy);
	g_assert(!g_ascii_strcasecmp(policy, DEFAULT_POLICY1));
	g_free(policy);
	
	policy = sailfish_iptables_load_policy("iptables_policy.conf");
	g_assert(policy);
	g_assert(!g_ascii_strcasecmp(policy, DEFAULT_POLICY1));
	g_free(policy);
}

static void test_iptables_plugin_utils_protocol_for_service()
{
	gchar* protocol = get_protocol_for_service("ssh");
	g_assert(g_ascii_strcasecmp(protocol,"tcp") == 0);
	g_free(protocol);

	g_assert(!get_protocol_for_service("nothing"));
}

static void test_iptables_plugin_utils_protocol_for_port()
{
	gchar* protocol = get_protocol_for_port(22);
	g_assert(g_ascii_strcasecmp(protocol,"tcp") == 0);
	g_free(protocol);
	
	g_assert(!get_protocol_for_port(0));
}

static void test_iptables_plugin_utils_mask_to_cidr()
{
	struct in_addr addr;
	memset(&addr,0,sizeof(struct in_addr));
	gint i = 0;
	
	g_assert(inet_aton("255.255.255.255", &addr));
	
	// Check all valid masks
	for(i = 32 ; i >= 0 ; i--)
	{
		g_assert(mask_to_cidr(IPV4,inet_ntoa(addr)) == i);
		
		// Reduce one up bit from mask, 255.255.255.254, 255.255.255.252 etc.
		in_addr_t addr_int = ntohl(addr.s_addr);
		addr_int <<= 1;
		addr.s_addr = htonl(addr_int);
	}

	// Addresses provide error, max32bit unsigned
	g_assert(mask_to_cidr(IPV4,"192.168.10.0") == G_MAXUINT32);
	g_assert(mask_to_cidr(IPV4,"192.168.0.200") == G_MAXUINT32);
	g_assert(mask_to_cidr(IPV4,"255.255.252.10") == G_MAXUINT32);
	g_assert(mask_to_cidr(IPV4,"255.255.200.10") == G_MAXUINT32);
	g_assert(mask_to_cidr(IPV4,"8.8.8.8") == G_MAXUINT32);
	g_assert(mask_to_cidr(IPV4,NULL) == G_MAXUINT32);
}

static gchar *combine_ip_mask(const gchar* address, guint32 mask)
{
	gchar *result = NULL;
	if(address && *address)
		result = g_strdup_printf("%s/%u",address,mask);
		
	return result;
}

static void test_iptables_plugin_utils_format_ip()
{
	gchar* ip = NULL;
	
	ip = format_ip(IPV4,"192.168.10.1");
	g_assert(g_ascii_strcasecmp(ip,"192.168.10.1") == 0);
	g_free(ip);
	
	// Mask is removed if mask is 32 or 0 in cidr format
	ip = format_ip(IPV4,"192.168.10.1/32");
	g_assert(g_ascii_strcasecmp(ip,"192.168.10.1") == 0);
	g_free(ip);
	
	ip = format_ip(IPV4,"192.168.10.1/0");
	g_assert(g_ascii_strcasecmp(ip,"192.168.10.1") == 0);
	g_free(ip);
	
	ip = format_ip(IPV4,"192.168.10.1/0.0.0.0");
	g_assert(g_ascii_strcasecmp(ip,"192.168.10.1") == 0);
	g_free(ip);
	
	ip = format_ip(IPV4,"192.168.10.1/255.255.255.255");
	g_assert(g_ascii_strcasecmp(ip,"192.168.10.1") == 0);
	g_free(ip);
	
	// Check all dot notation masks with ip
	struct in_addr addr;
	memset(&addr,0,sizeof(struct in_addr));
	gint i = 0;
	
	g_assert(inet_aton("255.255.255.254", &addr));
	
	// Check all valid masks (excluding 32 and 0)
	for(i = 31 ; i > 0 ; i--)
	{
		// Create dot notation format
		gchar *ip_input = g_strjoin("/", "192.168.10.0", inet_ntoa(addr), NULL);
		// Create ip dot notation / cidr
		gchar *ip_check = combine_ip_mask("192.168.10.0",i);
		
		// Check both in dot notation
		ip = format_ip(IPV4,ip_input);
		g_assert(g_ascii_strcasecmp(ip,ip_check) == 0);
		g_free(ip);
		
		// Check dot notation ip / cidr
		ip = format_ip(IPV4,ip_check);
		g_assert(g_ascii_strcasecmp(ip,ip_check) == 0);
		g_free(ip);
		
		g_free(ip_input);
		g_free(ip_check);
		
		// Reduce one up bit from mask, 255.255.255.254, 255.255.255.252 etc.
		in_addr_t addr_int = ntohl(addr.s_addr);
		addr_int <<= 1;
		addr.s_addr = htonl(addr_int);
	}
	
	g_assert(!format_ip(IPV4, ""));
	g_assert(!format_ip(IPV4, NULL));
}

static void full_parameter_prepare(rule_params *params)
{
	g_assert(params);
		
	g_assert(check_parameters(params) == INVALID_TABLE);
	
	params->table = g_strdup("table");
	g_assert(check_parameters(params) == INVALID_CHAIN_NAME);
	
	params->chain = g_strdup("chain");
	g_assert(check_parameters(params) == INVALID_TARGET);
	
	params->target = g_strdup("ACCEPT");
}

static void test_iptables_plugin_parameters_ip_full()
{
	/* IP only : ARGS_IP */
	rule_params *params = rule_params_new(ARGS_IP);

	full_parameter_prepare(params);
	
	g_assert(check_parameters(params) == INVALID_IP);
	
	params->ip_src = g_strdup("192.168.10.1");
	g_assert(check_parameters(params) == OK);
	
	params->ip_dst = g_strdup("192.168.10.1");
	g_assert(check_parameters(params) == OK);
	
	g_free(params->ip_src);
	params->ip_src = NULL;
	g_assert(check_parameters(params) == OK);
	
	g_free(params->ip_dst);
	params->ip_dst = NULL;
	g_assert(check_parameters(params) == INVALID_IP);
	
	rule_params_free(params);
}

static void test_iptables_plugin_parameters_port_full()
{
	/* Port only : ARGS_PORT */
	rule_params *params = rule_params_new(ARGS_PORT);
	guint16 i = 0;
	
	full_parameter_prepare(params);
	
	// Both unset, fail
	g_assert(check_parameters(params) == INVALID_PORT);
	
	// Either set, pass to next check (proto)
	params->port_dst[0] = 80;
	g_assert(check_parameters(params) == INVALID_PROTOCOL);
	
	// Both set, pass to next check (proto)
	params->port_src[0] = 8080;
	g_assert(check_parameters(params) == INVALID_PROTOCOL);
	
	// Src set, pass to next check (proto)
	params->port_dst[0] = 0;
	g_assert(check_parameters(params) == INVALID_PROTOCOL);
	
	params->protocol = g_strdup("tcp");
	g_assert(check_parameters(params) == INVALID_REQUEST);
	
	for(i = 0; i < 4 ; i++)
	{
		params->operation = i;
		if(i < 2)
			g_assert(check_parameters(params) == OK);
		else
			g_assert(check_parameters(params) == INVALID_REQUEST);
	}
	
	params->operation = 0; // add
	
	params->port_dst[0] = params->port_src[0] = 0; // Reset
	
	// Both unset, fail
	g_assert(check_parameters(params) == INVALID_PORT);
	
	params->port_dst[1] = params->port_src[1] = 443;
	
	// range ports have no effect
	g_assert(check_parameters(params) == INVALID_PORT);
	
	//dst set, pass
	params->port_dst[0] = 80;
	g_assert(check_parameters(params) == OK);
	
	// Both set, pass 
	params->port_src[0] = 8080;
	g_assert(check_parameters(params) == OK);
	
	// Src set, pass 
	params->port_dst[0] = 0;
	g_assert(check_parameters(params) == OK);
	
	rule_params_free(params);
}

static void test_iptables_plugin_parameters_ip_and_port_full()
{
	/* Port and ip  : ARGS_IP_PORT */
	rule_params *params = rule_params_new(ARGS_IP_PORT);
	guint16 i = 0;
	
	full_parameter_prepare(params);
	
	g_assert(check_parameters(params) == INVALID_IP);
	
	params->ip_src = g_strdup("192.168.10.1");
	g_assert(check_parameters(params) == INVALID_PORT);
	
	params->ip_dst = g_strdup("192.168.10.1");
	g_assert(check_parameters(params) == INVALID_PORT);
	
	g_free(params->ip_src);
	params->ip_src = NULL;
	g_assert(check_parameters(params) == INVALID_PORT);
	
	g_free(params->ip_dst);
	params->ip_dst = NULL;
	g_assert(check_parameters(params) == INVALID_IP);
	
	params->ip_src = g_strdup("192.168.10.1");
	g_assert(check_parameters(params) == INVALID_PORT);
	
	// Either set, pass to next check (proto)
	params->port_dst[0] = 80;
	g_assert(check_parameters(params) == INVALID_PROTOCOL);
	
	// Both set, pass to next check (proto)
	params->port_src[0] = 8080;
	g_assert(check_parameters(params) == INVALID_PROTOCOL);
	
	// Src set, pass to next check (proto)
	params->port_dst[0] = 0;
	g_assert(check_parameters(params) == INVALID_PROTOCOL);
	
	params->protocol = g_strdup("tcp");
	g_assert(check_parameters(params) == INVALID_REQUEST);
	
	for(i = 0; i < 4 ; i++)
	{
		params->operation = i;
		if(i < 2)
			g_assert(check_parameters(params) == OK);
		else
			g_assert(check_parameters(params) == INVALID_REQUEST);
	}
	
	params->operation = 0; // add
	
	// Reset
	params->port_dst[0] = params->port_src[0] = 0; 
	g_free(params->ip_src);
	params->ip_src = NULL;	
	g_free(params->ip_dst);
	params->ip_dst = NULL;
	
	params->ip_src = g_strdup("192.168.10.1");
	params->port_dst[1] = params->port_src[1] = 443;
	
	// range ports have no effect
	g_assert(check_parameters(params) == INVALID_PORT);
	
	//dst set, pass
	params->port_dst[0] = 80;
	g_assert(check_parameters(params) == OK);
	
	// Both set, pass 
	params->port_src[0] = 8080;
	g_assert(check_parameters(params) == OK);
	
	// Src set, pass 
	params->port_dst[0] = 0;
	g_assert(check_parameters(params) == OK);
	
	// Reset
	g_free(params->ip_src);
	params->ip_src = NULL;
	params->port_dst[0] = params->port_src[0] = 0; 
	
	params->ip_dst = g_strdup("192.168.10.1");
	params->port_dst[1] = params->port_src[1] = 443;
	
	// range ports have no effect
	g_assert(check_parameters(params) == INVALID_PORT);
	
	//dst set, pass
	params->port_dst[0] = 80;
	g_assert(check_parameters(params) == OK);
	
	// Both set, pass 
	params->port_src[0] = 8080;
	g_assert(check_parameters(params) == OK);
	
	// Src set, pass 
	params->port_dst[0] = 0;
	g_assert(check_parameters(params) == OK);
	
	rule_params_free(params);
}

static void reset_params_ips(rule_params *params)
{
	g_assert(params);
		
	g_free(params->ip_src);
	params->ip_src = NULL;
	g_free(params->ip_dst);
	params->ip_dst = NULL;
}

static void reset_params_ports(rule_params *params)
{
	params->port_dst[0] = params->port_src[0] = params->port_dst[1] = params->port_src[1] = 0;
}

static void ip_port_and_range_full_positive(rule_params *params)
{
	guint16 i = 0;
	g_assert(params);
	
	reset_params_ports(params);
	
	params->operation = 0;

/* src ports */
	params->port_src[0] = params->port_src[1] = 8080;
	g_assert(check_parameters(params) == OK);
	
	params->port_src[0] = 8081;
	g_assert(check_parameters(params) == INVALID_PORT_RANGE);
	
	params->port_src[0] = 80;
	g_assert(check_parameters(params) == OK);
	
	for(i = 0; i < 4 ; i++)
	{
		params->operation = i;
		if(i < 2)
			g_assert(check_parameters(params) == OK);
		else
			g_assert(check_parameters(params) == INVALID_REQUEST);
	}
	
	reset_params_ports(params);
	
	params->operation = 0; // add

/* dst ports */
	params->port_dst[0] = params->port_dst[1] = 8080;
	g_assert(check_parameters(params) == OK);
	
	params->port_dst[0] = 8081;
	g_assert(check_parameters(params) == INVALID_PORT_RANGE);
	
	params->port_dst[0] = 80;
	g_assert(check_parameters(params) == OK);
		
	for(i = 0; i < 4 ; i++)
	{
		params->operation = i;
		if(i < 2)
			g_assert(check_parameters(params) == OK);
		else
			g_assert(check_parameters(params) == INVALID_REQUEST);
	}
	
	reset_params_ports(params);
	
	params->operation = 0;
	
/* all ports */
	params->port_dst[0] = params->port_dst[1] = 8080;
	params->port_src[0] = params->port_src[1] = 8082;
	g_assert(check_parameters(params) == OK);
	
	params->port_dst[0] = 8081;
	g_assert(check_parameters(params) == INVALID_PORT_RANGE);
	
	params->port_dst[0] = 80; // ok
	params->port_src[0] = 8083; // not ok
	g_assert(check_parameters(params) == INVALID_PORT_RANGE);
	
	params->port_src[0] = 8080;
	g_assert(check_parameters(params) == OK);
	
	for(i = 0; i < 4 ; i++)
	{
		params->operation = i;
		if(i < 2)
			g_assert(check_parameters(params) == OK);
		else
			g_assert(check_parameters(params) == INVALID_REQUEST);
	}
}

static void ip_port_and_range_full_negative(rule_params *params)
{
	g_assert(params);
	
	reset_params_ports(params);
	
	params->operation = 0;

/* src ports */
	params->port_src[0] = 8080;
	g_assert(check_parameters(params) == INVALID_PORT);
	
	params->port_src[0] = 0;
	params->port_src[1] = 8080;
	g_assert(check_parameters(params) == INVALID_PORT);
	
	params->port_src[0] = 8081;
	params->port_src[1] = 8080;
	g_assert(check_parameters(params) == INVALID_PORT_RANGE);
	
	params->port_src[0] = 8080;
	params->port_src[1] = 8080;
	g_assert(check_parameters(params) == OK);
	
	reset_params_ports(params);

/* dst ports */
	params->port_dst[0] = 8080;
	g_assert(check_parameters(params) == INVALID_PORT);
	
	params->port_dst[0] = 0;
	params->port_dst[1] = 8080;
	g_assert(check_parameters(params) == INVALID_PORT);
	
	params->port_dst[0] = 8081;
	params->port_dst[1] = 8080;
	g_assert(check_parameters(params) == INVALID_PORT_RANGE);
	
	params->port_dst[0] = 8080;
	params->port_dst[1] = 8080;
	g_assert(check_parameters(params) == OK);
	
	reset_params_ports(params);
	
/* all ports */

	// src 0 + dst 0
	params->port_dst[0] = 8080;
	params->port_src[0] = 8082;
	g_assert(check_parameters(params) == INVALID_PORT);
	
	// src 0 + dst 1
	params->port_dst[0] = 0;
	params->port_dst[1] = 8080;
	g_assert(check_parameters(params) == INVALID_PORT);
	
	// src 1 + dst 0
	params->port_src[0] = 0;
	params->port_src[1] = 8083;
	params->port_dst[0] = 0;
	g_assert(check_parameters(params) == INVALID_PORT);
	
	// src 1 + dst 1
	reset_params_ports(params);
	params->port_src[1] = 8083;
	params->port_dst[1] = 8080;
	g_assert(check_parameters(params) == INVALID_PORT);
	
	reset_params_ports(params);
	
// Ranges
	params->port_dst[0] = 8080;
	params->port_src[0] = 8082;
	g_assert(check_parameters(params) == INVALID_PORT);
	
	params->port_dst[1] = 90;
	params->port_src[1] = 90;
	g_assert(check_parameters(params) == INVALID_PORT_RANGE);
	
	params->port_dst[1] = 8081;
	g_assert(check_parameters(params) == INVALID_PORT_RANGE);
	
	params->port_src[1] = 8083;
	g_assert(check_parameters(params) == OK);

}

static void test_iptables_plugin_parameters_ip_and_port_range_full()
{
	/* Port and ip  : ARGS_IP_PORT */
	rule_params *params = rule_params_new(ARGS_IP_PORT_RANGE);
	
	full_parameter_prepare(params);
	
	g_assert(check_parameters(params) == INVALID_IP);
	
	params->protocol = g_strdup("tcp");
	
/* src ip */
	params->ip_src = g_strdup("192.168.10.1");
	g_assert(check_parameters(params) == INVALID_PORT);
	
	ip_port_and_range_full_positive(params);
	
	reset_params_ips(params);
	reset_params_ports(params);
	
/* dst ip */	

	params->ip_dst = g_strdup("192.168.10.1");
	g_assert(check_parameters(params) == INVALID_PORT);
	
	ip_port_and_range_full_positive(params);
	
	reset_params_ports(params);
	
/* both */
	params->ip_src = g_strdup("192.168.10.1");
	g_assert(check_parameters(params) == INVALID_PORT);
	
	ip_port_and_range_full_positive(params);
	
	reset_params_ips(params);
	reset_params_ports(params);

/* Negative src */
	params->ip_src = g_strdup("192.168.10.1");
	g_assert(check_parameters(params) == INVALID_PORT);
	
	ip_port_and_range_full_negative(params);
	
	reset_params_ips(params);
	reset_params_ports(params);

/* Negative dst */
	params->ip_dst = g_strdup("192.168.10.1");
	g_assert(check_parameters(params) == INVALID_PORT);
	
	ip_port_and_range_full_negative(params);
	
	reset_params_ports(params);
	
/* Negative both*/
	params->ip_src = g_strdup("192.168.10.2");
	g_assert(check_parameters(params) == INVALID_PORT);
	
	ip_port_and_range_full_negative(params);
	
	rule_params_free(params);
}

static void test_iptables_plugin_parameters_port_range_full()
{
	/* Port and ip  : ARGS_PORT_RANGE */
	rule_params *params = rule_params_new(ARGS_PORT_RANGE);
	
	full_parameter_prepare(params);
	
	g_assert(check_parameters(params) == INVALID_PORT);
	
	params->protocol = g_strdup("tcp");
	
	ip_port_and_range_full_positive(params);
	
	reset_params_ports(params);
	
	ip_port_and_range_full_negative(params);

	rule_params_free(params);
}

static void test_iptables_plugin_parameters_service_full()
{
	/* service  : ARGS_SERVICE */
	rule_params *params = rule_params_new(ARGS_SERVICE);
	guint16 i = 0;
	
	g_assert(params);
	
	full_parameter_prepare(params);

	g_assert(check_parameters(params) == INVALID_SERVICE);
	
	params->service_src = g_strdup("http");
	g_assert(check_parameters(params) == INVALID_SERVICE);
	
	params->protocol = g_strdup("tcp");
	g_assert(check_parameters(params) == INVALID_REQUEST);
	
	for(i = 2; i < 4 ; i++)
	{
		params->operation = i;
		g_assert(check_parameters(params) == INVALID_REQUEST);
	}

	for(i = 0; i < 2 ; i++)
	{
		params->operation = i;
		g_assert(check_parameters(params) == OK);
	}
		
	rule_params_free(params);
}

static void test_iptables_plugin_parameters_check_icmp_full()
{
	rule_params *params = rule_params_new(ARGS_ICMP);
	
	g_assert(params);
	
	full_parameter_prepare(params);
	g_assert(check_parameters(params) == INVALID_ICMP);
	
	params->icmp[0] = params->icmp[1] = 0;
	g_assert(check_parameters(params) == INVALID_REQUEST);
	
	params->operation = ADD;
	g_assert(check_parameters(params) == OK);
	
	params->icmp[0] = 8;
	params->icmp[1] = 15;
	g_assert(check_parameters(params) == OK);
	
	params->icmp[0] = params->icmp[1] = G_MAXUINT16;
	g_assert(check_parameters(params) == INVALID_ICMP);
	
	params->icmp[0] = 160;
	g_assert(check_parameters(params) == INVALID_ICMP);
	
	params->icmp[0] = 0xffff;
	params->icmp[1] = 1;
	g_assert(check_parameters(params) == INVALID_ICMP);
	
	params->args = ARGS_IP_ICMP;
	g_assert(check_parameters(params) == INVALID_IP);
	
	params->ip_src = g_strdup("192.168.10.1");
	g_assert(check_parameters(params));
	
	params->ip_dst = g_strdup("192.168.10.1");
	g_assert(check_parameters(params) == INVALID_ICMP);
	
	params->icmp[0] = 8;
	params->icmp[1] = 15;
	g_assert(check_parameters(params) == OK);
	
	params->icmp[0] = params->icmp[1] = G_MAXUINT16;
	g_free(params->ip_src);
	params->ip_src = NULL;
	g_assert(check_parameters(params) == INVALID_ICMP);
	
	params->icmp[0] = params->icmp[1] = 0;
	g_assert(check_parameters(params) == OK);

	rule_params_free(params);
}

static void test_iptables_plugin_parameters_chain()
{
	/* service  : ARGS_SERVICE */
	rule_params *params = rule_params_new(ARGS_CHAIN);
	guint16 i = 0;
	
	g_assert(params);

	g_assert(check_parameters(params) == INVALID_CHAIN_NAME);
	
	params->chain = g_strdup("chain1");
	g_assert(check_parameters(params) == INVALID_REQUEST);
	
	params->table = g_strdup("table");
	g_assert(check_parameters(params) == INVALID_REQUEST);
	
	for(i = 3; i < 5 ; i++)
	{
		params->operation = i;
		g_assert(check_parameters(params) == INVALID_REQUEST);
	}

	for(i = 0; i < 2 ; i++)
	{
		params->operation = i;
		g_assert(check_parameters(params) == OK);
	}
	
	params->operation = 0;
	
	
	rule_params_free(params);
}

static void test_iptables_plugin_parameters_check_operation()
{
	rule_params *params = rule_params_new(ARGS_CHAIN);
	guint16 i = 0;
	
	g_assert(params);
	g_assert(!check_operation(NULL));
	
	// ADD, REMOVE and FLUSH ok for ARGS_CHAIN
	for(i = 0; i < 3 ; i++)
	{
		params->operation = i;
		g_assert(check_operation(params));
	}
	
	for(i = 3; i < 5 ; i++)
	{
		params->operation = i;
		g_assert(!check_operation(params));
	}
	
	params->args = ARGS_IP;
	
	// ADD, REMOVE and FLUSH ok for rest that require operation
	for(i = 0; i < 2 ; i++)
	{
		params->operation = i;
		g_assert(check_operation(params));
	}
	
	for(i = 2; i < 5 ; i++)
	{
		params->operation = i;
		g_assert(!check_operation(params));
	}
	
	rule_params_free(params);
}

static void test_iptables_plugin_parameters_check_ips()
{
	gint i = 0;
	rule_params *params = rule_params_new(ARGS_IP);
	
	g_assert(params);
	
	for(i = ARGS_IP ; i <= ARGS_IP_SERVICE ; i++)
	{
		params->args = i;
		
		// src NULL, dst NULL = false
		g_assert(!check_ips(params));
		
		// src NULL, dst data = true
		params->ip_dst = g_strdup("1.2.3.4");
		g_assert(check_ips(params));
		
		// src data, dst data = true
		params->ip_src = g_strdup("1.2.3.4");
		g_assert(check_ips(params));
		
		g_free(params->ip_dst);
		params->ip_dst = NULL;
		
		// src data, dst NULL, true
		g_assert(check_ips(params));
		
		g_free(params->ip_src);
		params->ip_src = NULL;
	}
	
	rule_params_free(params);
}

static void test_iptables_plugin_parameters_check_ports()
{
	rule_params *params = rule_params_new(ARGS_IP_PORT);
	
	gint i = 0;
	
	gint basic_full[] = {
		ARGS_IP_PORT,
		ARGS_IP_SERVICE,
		ARGS_PORT,
		ARGS_SERVICE,
		0
	};
	
	gint src_and_dest_range[] = {
		ARGS_IP_PORT_RANGE,
		ARGS_PORT_RANGE,
		0
	};
	
	g_assert(params);
	
	g_assert(!check_ports(params));
	
/*--------------BASIC FULL--------------*/
	// Should fail
	for(i = 0; basic_full[i] ; i++)
	{
		params->args = basic_full[i];
		g_assert(!check_ports(params));
	}
	
	// Only one set - ok  as either should be set
	params->port_dst[0] = 80;
	
	for(i = 0; basic_full[i] ; i++)
	{
		params->args = basic_full[i];
		g_assert(check_ports(params));
	}
	
	// Both set, ok
	params->port_src[0] = 8080;
	
	for(i = 0; basic_full[i] ; i++)
	{
		params->args = basic_full[i];
		g_assert(check_ports(params));
	}
	
	// Only one set, ok
	params->port_dst[0] = 0;
	
	for(i = 0; basic_full[i] ; i++)
	{
		params->args = basic_full[i];
		g_assert(check_ports(params));
	}
	
	// Reset	
	params->port_dst[0] = params->port_dst[1] = params->port_src[0] = params->port_src[1] = 0;

/*--------------FULL RANGE------------------*/
	for(i = 0; src_and_dest_range[i] ; i++)
	{
		params->args = src_and_dest_range[i];
		g_assert(!check_ports(params));
	}
	
	// Either dst or src set should be ok (or both)
	params->port_dst[0] = 80;
	
	for(i = 0; src_and_dest_range[i] ; i++)
	{
		params->args = src_and_dest_range[i];
		g_assert(!check_ports(params));
	}
	
	// Fail as dst and src [0] are only set
	params->port_src[0] = 8080;
	
	for(i = 0; src_and_dest_range[i] ; i++)
	{
		params->args = src_and_dest_range[i];
		g_assert(!check_ports(params));
	}
	
	// Ok, at least dst set
	params->port_dst[1] = 443;
	
	for(i = 0; src_and_dest_range[i] ; i++)
	{
		params->args = src_and_dest_range[i];
		g_assert(check_ports(params));
	}
	
	// Ok all set
	params->port_src[1] = 8088;
	
	for(i = 0; src_and_dest_range[i] ; i++)
	{
		params->args = src_and_dest_range[i];
		g_assert(check_ports(params));
	}
	
	// Succeeds, as src has both
	params->port_dst[0] = 0;
	
	for(i = 0; src_and_dest_range[i] ; i++)
	{
		params->args = src_and_dest_range[i];
		g_assert(check_ports(params));
	}
	
	// fails
	params->port_src[0] = 0;
	
	for(i = 0; src_and_dest_range[i] ; i++)
	{
		params->args = src_and_dest_range[i];
		g_assert(!check_ports(params));
	}
	
	// fails
	params->port_dst[1] = 0;
	
	for(i = 0; src_and_dest_range[i] ; i++)
	{
		params->args = src_and_dest_range[i];
		g_assert(!check_ports(params));
	}
	
	rule_params_free(params);
}

static void test_iptables_plugin_parameters_check_service()
{
	rule_params *params = rule_params_new(ARGS_SERVICE);
	
	g_assert(params);
	
	gint full[] = { ARGS_SERVICE, ARGS_IP_SERVICE, 0 };
	gint i = 0;

	for(i = 0; full[i]; i++)
	{
		params->args = full[i];
		
		g_assert(!check_service(params));
	
		params->service_dst = g_strdup("http");
		g_assert(check_service(params));
	
		params->service_src = g_strdup("ssh");
		g_assert(check_service(params));
	
		g_free(params->service_dst);
		params->service_dst = NULL;
		g_assert(check_service(params));
	
		g_free(params->service_src);
		params->service_src = NULL;
		g_assert(!check_service(params));
	
		g_free(params->service_dst);
		g_free(params->service_src);
		params->service_dst = params->service_src = NULL;
	}
	
	rule_params_free(params);
}

static void test_iptables_plugin_parameters_check_chain_restricted()
{
	rule_params *params = rule_params_new(ARGS_POLICY);
	
	g_assert(params);
	
	gint i = 0;
	const gchar const * DEFAULT_CHAINS[] = {
		"INPUT",
		"OUTPUT",
		"FORWARD",
		NULL
	};
	
	g_assert(!check_chain_restricted(NULL));
	g_assert(!check_chain_restricted(params));
	
	for(i = 0; DEFAULT_CHAINS[i]; i++)
	{
		params->chain = g_strdup(DEFAULT_CHAINS[i]);
		
		g_assert(check_chain_restricted(params));
		
		g_free(params->chain);
	}
	
	params->chain = g_strdup("CUSTOM1");
	g_assert(!check_chain_restricted(params));
	
	rule_params_free(params);
}

static void test_iptables_plugin_parameters_check_port_range()
{
	rule_params *params = rule_params_new(ARGS_PORT_RANGE);
	
	g_assert(params);
	
	params->port_src[0] = 22;
	g_assert(!check_port_range(params));
	
	params->port_src[1] = 21;
	g_assert(!check_port_range(params));

	params->port_src[1] = 22;
	g_assert(check_port_range(params));	
	
	params->port_src[1] = 23;
	g_assert(check_port_range(params));
	
	rule_params_free(params);
}

static void test_iptables_plugin_parameters_check_icmp()
{
	rule_params *params = rule_params_new(ARGS_ICMP);
	
	g_assert(params);
	
	g_assert(!check_icmp(params));
	
	params->icmp[0] = params->icmp[1] = 0;
	
	g_assert(check_icmp(params));
	
	params->icmp[0] = 8;
	params->icmp[1] = 15;
	
	g_assert(check_icmp(params));
	
	params->icmp[0] = 161;
	
	g_assert(check_icmp(params));

	params->icmp[1] = G_MAXUINT16;

	g_assert(!check_icmp(params));
	
	params->icmp[0] = G_MAXUINT16;
	params->icmp[1] = 1;
	g_assert(!check_icmp(params));

	rule_params_free(params);
}

static void test_iptables_plugin_parameters_dbus_client()
{
	dbus_client* client = dbus_client_new();
	
	g_assert(client);
	g_assert(!client->peer);
	g_assert(!client->watch_id);
	
	dbus_client_free(client);
	
	client = dbus_client_new();
	
	dbus_client_free1(client);	
}

static void test_iptables_plugin_parameters_api_data()
{
	gint i = 0, max = 5;
	const gchar const * NAMES[] = {"name1", "name2", "name3", "name4", "name5", 
		NULL};
	api_data *data = api_data_new();
	
	g_assert(data);
	g_assert(data->clients);
	g_assert(data->policy);
	g_assert(!data->custom_chains);
	
	dbus_client* tmp = dbus_client_new();
	DAPeer* peer_tmp = g_new0(DAPeer,1);

	g_assert(!api_data_add_peer(NULL,NULL));
	g_assert(!api_data_add_peer(data,NULL));
	g_assert(!api_data_add_peer(data, tmp));

	tmp->peer = peer_tmp;
	g_assert(!api_data_add_peer(data, tmp));

	dbus_client_free(tmp);
	
	g_assert(!api_data_get_peer(NULL,NULL));
	g_assert(!api_data_get_peer(data,NULL));
	g_assert(!api_data_get_peer(data,""));
	g_assert(!api_data_get_peer(data,NAMES[0]));
	
	g_assert(!api_data_remove_peer(NULL,NULL));
	g_assert(!api_data_remove_peer(data,NULL));
	g_assert(!api_data_remove_peer(data,""));
	g_assert(!api_data_remove_peer(data,NAMES[0]));
	
	for(i = 0; i < max; i++)
	{
		dbus_client* client = dbus_client_new();
		
		DAPeer* peer = g_new0(DAPeer,1);
		peer->name = g_strdup(NAMES[i]);

		DACred cred = {
			0, 0,
			NULL, 0,
			G_GUINT64_CONSTANT(0xfffffff008003420),
			DBUSACCESS_CRED_CAPS | DBUSACCESS_CRED_GROUPS
		};
	
		peer->cred = cred;
		peer->bus = DA_BUS_SYSTEM;
		
		client->peer = peer;
	
		g_assert(api_data_add_peer(data,client));
		g_assert(g_hash_table_size(data->clients) == i+1);
		g_assert(api_data_get_peer(data,NAMES[i]));
	}
	
	g_assert(api_data_remove_peer(data,NAMES[0]));
	g_assert(g_hash_table_size(data->clients) == max-1);
	
	api_data_free(data);
}

static void test_iptables_plugin_parameters_custom_chains()
{
	custom_chain_item *item = NULL;
	gint i = 0;
	const gchar const * chains[] = {"chain1", "chain2", "chain3", NULL};
	
	g_assert(!custom_chain_item_new(NULL));
	item = custom_chain_item_new("test");
	g_assert(item);
	g_assert(!g_ascii_strcasecmp(item->table,"test"));
	g_assert(!item->chains);
	
	g_assert(!custom_chain_item_add_to_chains(NULL, NULL));
	g_assert(!custom_chain_item_add_to_chains(item, NULL));
	g_assert(!custom_chain_item_add_to_chains(NULL, "chain"));
	
	for(i = 0; chains[i] ; i++)
		g_assert(custom_chain_item_add_to_chains(item,chains[i]));
	
	g_assert(g_list_length(item->chains) == i);
	
	g_assert(!custom_chain_item_remove_from_chains(item,NULL));
	g_assert(!custom_chain_item_remove_from_chains(item,""));
	g_assert(!custom_chain_item_remove_from_chains(item,"chain"));
	
	g_assert(custom_chain_item_remove_from_chains(item,chains[2]));
	g_assert(g_list_length(item->chains) == i - 1);
	
	g_assert(custom_chain_item_remove_from_chains(item,chains[0]));
	g_assert(!custom_chain_item_remove_from_chains(item,chains[0]));
	
	g_assert(custom_chain_item_remove_from_chains(item,chains[1]));
	
	g_assert(!g_list_length(item->chains));
	
	custom_chain_item_free(item);

}

static void test_iptables_plugin_parameters_api_data_chains()
{
	gint i = 0;
	const gchar const * NAMES[] = {"chain1", "chain2", "chain3", "chain4", NULL};
	GList *chains = NULL;
	custom_chain_item *item = NULL;
	
	api_data *data = api_data_new();
	
	g_assert(!data->custom_chains);
	
	g_assert(!api_data_get_custom_chain_table(NULL, NULL));
	g_assert(!api_data_get_custom_chain_table(data, NULL));
	g_assert(!api_data_get_custom_chain_table(NULL, "filter"));
	g_assert(!api_data_get_custom_chain_table(data, "filter"));
	
	g_assert(!api_data_remove_custom_chains(NULL, NULL));
	g_assert(!api_data_remove_custom_chains(data, NULL));
	g_assert(!api_data_remove_custom_chains(NULL, "filter"));
	
	// List null, nothing done = true
	g_assert(api_data_remove_custom_chains(data, "filter"));
	
	g_assert(!api_data_add_custom_chain(NULL, NULL, NULL));
	g_assert(!api_data_add_custom_chain(data, NULL, NULL));
	g_assert(!api_data_add_custom_chain(data, "filter", NULL));
	g_assert(!api_data_add_custom_chain(NULL, "filter", "chain"));
	g_assert(!api_data_add_custom_chain(NULL, NULL, "chain"));
	
	for(i = 0 ; NAMES[i] ; i++)
		g_assert(api_data_add_custom_chain(data, "filter", NAMES[i]));
	
	chains = api_data_get_custom_chain_table(data, "filter");
	g_assert(chains);
	item = (custom_chain_item*)chains->data;
	g_assert(g_list_length(item->chains) == i);
	
	// Try to remove nonexisting
	g_assert(!api_data_delete_custom_chain(data,"filter","test2"));
	
	chains = api_data_get_custom_chain_table(data, "filter");
	g_assert(chains);
	item = (custom_chain_item*)chains->data;
	g_assert(g_list_length(item->chains) == i);
	
	// Remove existing
	g_assert(api_data_delete_custom_chain(data,"filter", NAMES[0]));
	
	chains = api_data_get_custom_chain_table(data, "filter");
	g_assert(chains);
	item = (custom_chain_item*)chains->data;
	g_assert(g_list_length(item->chains) == i-1);
	
	g_assert(!api_data_remove_custom_chains(data,"filter1"));
	g_assert(api_data_remove_custom_chains(data,"filter"));
	
	api_data_free(data);
}

static void test_iptables_plugin_parameters_disconnect_data()
{	
	api_data* a_data = api_data_new();
	dbus_client* client = dbus_client_new();
	client_disconnect_data *cd_data = NULL;
	
	g_assert(!client_disconnect_data_new(NULL,NULL));
	g_assert(!client_disconnect_data_new(a_data, NULL));
	g_assert(!client_disconnect_data_new(a_data, client));
	
	DAPeer* peer = g_new0(DAPeer,1);
	gchar *peer_name = g_strdup("peer");
	peer->name = peer_name;
		
	client->peer = peer;
	
	cd_data = client_disconnect_data_new(a_data, client);
	g_assert(cd_data);
	g_assert(cd_data->main_data);
	g_assert(cd_data->client_name);
	client_disconnect_data_free(cd_data);
	
	g_free(peer_name);
	g_free(peer);
	client->peer = NULL;
	
	dbus_client_free(client);
	api_data_free(a_data);
}


static void test_iptables_plugin_negated_ip_address()
{
	g_assert(negated_ip_address("!192.168.10.1"));
	
	g_assert(!negated_ip_address("192.168.10.1"));
	g_assert(!negated_ip_address(NULL));

}

static void test_iptables_plugin_validate_address()
{
	g_assert(validate_address(IPV4,"192.168.0.1"));
	g_assert(validate_address(IPV4,"10.0.0.1"));
	g_assert(validate_address(IPV4,"8.8.8.8"));
	g_assert(validate_address(IPV4,"0.0.0.0"));
	
	// IPv6
	g_assert(validate_address(IPV6,"fe80::200:5aee:feaa:20a2"));
	g_assert(validate_address(IPV6,"2001:db8:3333:4444:5555:6666:7777:8888"));
	g_assert(validate_address(IPV6,"2001:db8:3333:4444:CCCC:DDDD:EEEE:FFFF"));
	g_assert(validate_address(IPV6,"::"));
	g_assert(validate_address(IPV6,"fdf8:f53b:82e4::"));
	g_assert(validate_address(IPV6,"2001:db8::"));
	g_assert(validate_address(IPV6,"::1234:5678"));
	g_assert(validate_address(IPV6,"2001:db8::1234:5678"));
	g_assert(validate_address(IPV6,"2001:0db8:0001:0000:0000:0ab9:C0A8:0102"));
	
	g_assert(validate_address(IPV6,"::FFFF:8.8.8.8"));
	g_assert(validate_address(IPV6,"2001:db8:3333:4444:5555:6666:1.2.3.4"));
	g_assert(validate_address(IPV6,"::11.22.33.44"));
	g_assert(validate_address(IPV6,"2001:db8::123.123.123.123"));
	g_assert(validate_address(IPV6,"::1234:5678:91.123.4.56"));
	g_assert(validate_address(IPV6,"::1234:5678:1.2.3.4"));
	g_assert(validate_address(IPV6,"2001:db8::1234:5678:5.6.7.8"));
	
	
	g_assert(!validate_address(IPV4,""));
	g_assert(!validate_address(IPV4,NULL));
	
	g_assert(!validate_ip_address(IPV4,"256.256.256.256"));

	g_assert(!validate_address(IPV4,"192.168.1"));
	g_assert(!validate_address(IPV4,"192.168"));
	g_assert(!validate_address(IPV4,"192"));
	
	g_assert(!validate_address(IPV4,"192.168.1."));
	g_assert(!validate_address(IPV4,"192.168.."));
	g_assert(!validate_address(IPV4,"192..."));
	
	g_assert(!validate_address(IPV4,"jolla.com"));
	
	g_assert(!validate_address(IPV4,"015.014.013.012"));
}

static void test_iptables_plugin_validate_mask()
{
	struct in_addr addr;
	memset(&addr,0,sizeof(struct in_addr));
	gint mask = 0;
	
	g_assert(inet_aton("255.255.255.255", &addr));
	
	// Check all valid masks
	for(mask = 32 ; mask >= 0 ; mask--)
	{
		g_assert(validate_ip_mask(IPV4,inet_ntoa(addr)));
		
		gchar *mask_str = g_strdup_printf("%d",mask);
		g_assert(validate_ip_mask(IPV4, mask_str));
		g_free(mask_str);
		
		// Reduce one up bit from mask, 255.255.255.254, 255.255.255.252 etc.
		in_addr_t addr_int = ntohl(addr.s_addr);
		addr_int <<= 1;
		addr.s_addr = htonl(addr_int);
	}
	
	g_assert(validate_ip_mask(IPV4, "0.0.0.0"));
	
	g_assert(!validate_ip_mask(IPV4, "255.255.123.1"));
	g_assert(!validate_ip_mask(IPV4, "192.168.10.0"));
	g_assert(!validate_ip_mask(IPV4, "10.10.10.10"));
	g_assert(!validate_ip_mask(IPV4, "8.8.8.8"));
	
	g_assert(!validate_ip_mask(IPV4,""));
	g_assert(!validate_ip_mask(IPV4,NULL));
}

static void test_iptables_plugin_validate_ip_address()
{
	g_assert(validate_ip_address(IPV4,"8.8.8.8"));
	g_assert(validate_ip_address(IPV4,"192.168.10.1"));
	g_assert(validate_ip_address(IPV4,"192.168.1.0"));
	
	g_assert(validate_ip_address(IPV4,"!10.10.10.10"));
	
	g_assert(validate_ip_address(IPV4,"192.168.1.0/255.255.255.0"));
	g_assert(validate_ip_address(IPV4,"192.168.1.0/24"));
	
	g_assert(validate_ip_address(IPV4,"!192.168.1.0/255.255.255.0"));
	g_assert(validate_ip_address(IPV4,"!192.168.1.0/24"));
	
	g_assert(!validate_ip_address(IPV4,""));
	g_assert(!validate_ip_address(IPV4,NULL));
}

static void test_iptables_plugin_validate_service_name()
{
	g_assert(validate_service_name("ssh"));
	
	g_assert(!validate_service_name("tcp"));
	g_assert(!validate_service_name(""));
	g_assert(!validate_service_name(NULL));
}

static void test_iptables_plugin_validate_protocol()
{
	g_assert(validate_protocol("tcp"));
	g_assert(validate_protocol("udp"));
	g_assert(validate_protocol("sctp"));
	g_assert(validate_protocol("icmp"));
	g_assert(validate_protocol("TCP"));
	
	g_assert(!validate_protocol("ssh"));
	g_assert(!validate_protocol(""));
	g_assert(!validate_protocol(NULL));
}

static void test_iptables_plugin_validate_port()
{
	g_assert(validate_port(1));
	g_assert(validate_port(22));
	g_assert(validate_port(8080));
	g_assert(validate_port(0xFFFF));
	g_assert(validate_port(0xDEAD));
	g_assert(validate_port(0xBEEF));
	
	g_assert(!validate_port(0));
}

static void test_iptables_plugin_validate_operation()
{
	g_assert(validate_operation(0) == ADD);
	
	g_assert(validate_operation(1) == REMOVE);
	
	g_assert(validate_operation(2) == FLUSH);
	
	g_assert(validate_operation(3) == UNDEFINED);
	
	g_assert(validate_operation(42) == UNDEFINED);
	
	g_assert(validate_operation(-1) == UNDEFINED);
}

static void test_iptables_plugin_validate_chain()
{
	gint i = 0;
	const gchar *table = "filter";
	const gchar const * CHAINS[] = {"INPUT", "OUTPUT", "FORWARD", "CUSTOM1", NULL};
	gchar *chain = NULL;
	
	g_assert(!validate_chain(NULL,NULL));
	g_assert(!validate_chain(NULL,""));
	g_assert(!validate_chain("",NULL));
	g_assert(!validate_chain("",""));
	
	g_assert(!validate_chain(table,NULL));
	g_assert(!validate_chain(table,""));

	for(i = 0; CHAINS[i]; i++)
	{
		chain = validate_chain(table, CHAINS[i]);
		g_assert(chain);
		
		if(i == 3)
			g_assert(!g_ascii_strcasecmp(chain, "sfos_CUSTOM1"));
		else
			g_assert(!g_ascii_strcasecmp(chain, CHAINS[i]));
			
		g_free(chain);
	}
	
	g_assert(!validate_chain(table,"CUSTOM2"));
}

static void test_iptables_plugin_validate_target()
{
	gint i = 0;
	const gchar const * PASS[] = {"ACCEPT", "DROP", "QUEUE", "RETURN", "REJECT", "CUSTOM1", NULL};
	const gchar const * FAIL[] = {"INPUT", "OUTPUT", "FORWARD", "CUSTOM2", NULL};
	const gchar *table = "filter";
	gchar *target = NULL;
	
	g_assert(!validate_target(NULL,NULL));
	g_assert(!validate_target(NULL,""));
	g_assert(!validate_target("",NULL));
	g_assert(!validate_target("",""));
	
	g_assert(!validate_target(table,NULL));
	g_assert(!validate_target(table,""));
	
	for(i = 0; PASS[i] ; i++)
	{
		target = validate_target(table,PASS[i]);
		g_assert(target);
		
		if(i == 5)
			g_assert(!g_ascii_strcasecmp(target, "sfos_CUSTOM1"));
		else
			g_assert(!g_ascii_strcasecmp(target, PASS[i]));
		
		g_free(target);
	}
	
	for(i = 0; FAIL[i] ; i++)
		g_assert(!validate_target(table,FAIL[i]));
}

static void test_iptables_plugin_validate_policy()
{

	g_assert(validate_policy("ACCEPT"));
	g_assert(validate_policy("DROP"));
	
	g_assert(!validate_policy("accept"));
	g_assert(!validate_policy("drop"));
	g_assert(!validate_policy("Accept"));
	g_assert(!validate_policy("Drop"));

	g_assert(!validate_policy(""));
	g_assert(!validate_policy(NULL));
	g_assert(!validate_policy("REJECT"));
	g_assert(!validate_policy("QUEUE"));
}

static void test_iptables_plugin_validate_icmp()
{
	guint16 icmp[2] = {0};
	int type = IPV4;
	
	g_assert(validate_icmp(type, icmp));
	
	icmp[0] = 8;
	icmp[1] = 10;
	
	g_assert(validate_icmp(type, icmp));
	
	icmp[0] = 44;
	
	g_assert(!validate_icmp(type, icmp));
	
	icmp[0] = 8;
	icmp[1] = 16;
	
	g_assert(!validate_icmp(type, icmp));
	
	icmp[0] = 44;
	icmp[1] = 16;
	
	g_assert(!validate_icmp(type, icmp));
	
	type = IPV6;
	icmp[0] = icmp[1] = 0;
	
	g_assert(validate_icmp(type, icmp));
	
	icmp[0] = 8;
	icmp[1] = 10;
	
	g_assert(validate_icmp(type, icmp));
	
	icmp[0] = 161;
	icmp[1] = 255;
	
	g_assert(validate_icmp(type, icmp));
	
	icmp[0] = 163;
	
	g_assert(!validate_icmp(type, icmp));
	
	icmp[0] = 161;
	icmp[1] = 256;
	
	g_assert(!validate_icmp(type, icmp));
	
	icmp[0] = 200;
	icmp[1] = 257;
	
	g_assert(!validate_icmp(type, icmp));
}

#define PREFIX				"/sailfish_connman_plugin_iptables_"
#define PREFIX_VALIDATE			PREFIX"validate/"
#define PREFIX_PARAMETERS		PREFIX"parameters/"
#define PREFIX_UTILS			PREFIX"utils/"
#define PREFIX_DBUS			PREFIX"dbus/"
#define PREFIX_POLICY		PREFIX"policycheck/"


int main(int argc, char *argv[])
{	
	g_test_init(&argc, &argv, NULL);
	
	g_test_add_func(PREFIX_VALIDATE "policy", test_iptables_plugin_validate_policy);
	g_test_add_func(PREFIX_VALIDATE "port", test_iptables_plugin_validate_port);
	g_test_add_func(PREFIX_VALIDATE "operation", test_iptables_plugin_validate_operation);
	g_test_add_func(PREFIX_VALIDATE "protocol", test_iptables_plugin_validate_protocol);
	g_test_add_func(PREFIX_VALIDATE "service_name", test_iptables_plugin_validate_service_name);
	g_test_add_func(PREFIX_VALIDATE "ip_address", test_iptables_plugin_validate_ip_address);
	g_test_add_func(PREFIX_VALIDATE "address", test_iptables_plugin_validate_address);
	g_test_add_func(PREFIX_VALIDATE "mask", test_iptables_plugin_validate_mask);
	g_test_add_func(PREFIX_VALIDATE "negated_ip_address", test_iptables_plugin_negated_ip_address);
	g_test_add_func(PREFIX_VALIDATE "chain", test_iptables_plugin_validate_chain);
	g_test_add_func(PREFIX_VALIDATE "target", test_iptables_plugin_validate_target);
	g_test_add_func(PREFIX_VALIDATE "icmp", test_iptables_plugin_validate_icmp);
	
	g_test_add_func(PREFIX_PARAMETERS "check_operation", test_iptables_plugin_parameters_check_operation);
	g_test_add_func(PREFIX_PARAMETERS "check_ips", test_iptables_plugin_parameters_check_ips);
	g_test_add_func(PREFIX_PARAMETERS "check_ports", test_iptables_plugin_parameters_check_ports);
	g_test_add_func(PREFIX_PARAMETERS "check_port_range", test_iptables_plugin_parameters_check_port_range);
	g_test_add_func(PREFIX_PARAMETERS "check_service", test_iptables_plugin_parameters_check_service);
	g_test_add_func(PREFIX_PARAMETERS "check_chain_restricted", test_iptables_plugin_parameters_check_chain_restricted);
	g_test_add_func(PREFIX_PARAMETERS "check_icmp", test_iptables_plugin_parameters_check_icmp);
	g_test_add_func(PREFIX_PARAMETERS "ip_full", test_iptables_plugin_parameters_ip_full);
	g_test_add_func(PREFIX_PARAMETERS "port_full", test_iptables_plugin_parameters_port_full);
	g_test_add_func(PREFIX_PARAMETERS "ip_and_port_full", test_iptables_plugin_parameters_ip_and_port_full);
	g_test_add_func(PREFIX_PARAMETERS "ip_and_port_range_full", test_iptables_plugin_parameters_ip_and_port_range_full);
	g_test_add_func(PREFIX_PARAMETERS "port_range_full", test_iptables_plugin_parameters_port_range_full);
	g_test_add_func(PREFIX_PARAMETERS "service_full", test_iptables_plugin_parameters_service_full);
	g_test_add_func(PREFIX_PARAMETERS "icmp_full", test_iptables_plugin_parameters_check_icmp_full);
	g_test_add_func(PREFIX_PARAMETERS "chains", test_iptables_plugin_parameters_chain);
	g_test_add_func(PREFIX_PARAMETERS "dbus_client", test_iptables_plugin_parameters_dbus_client);
	g_test_add_func(PREFIX_PARAMETERS "api_data", test_iptables_plugin_parameters_api_data);
	g_test_add_func(PREFIX_PARAMETERS "api_data_chains", test_iptables_plugin_parameters_api_data_chains);
	g_test_add_func(PREFIX_PARAMETERS "custom_chain", test_iptables_plugin_parameters_custom_chains);
	g_test_add_func(PREFIX_PARAMETERS "disconnect_data", test_iptables_plugin_parameters_disconnect_data);
	
	g_test_add_func(PREFIX_UTILS "protocol_for_service", test_iptables_plugin_utils_protocol_for_service);
	g_test_add_func(PREFIX_UTILS "protocol_for_port", test_iptables_plugin_utils_protocol_for_port);
	g_test_add_func(PREFIX_UTILS "mask_to_cidr", test_iptables_plugin_utils_mask_to_cidr);
	g_test_add_func(PREFIX_UTILS "format_ip", test_iptables_plugin_utils_format_ip);
	
	g_test_add_func(PREFIX_POLICY "basic", test_iptables_plugin_policy_check_basic);
	g_test_add_func(PREFIX_POLICY "root", test_iptables_plugin_policy_check_root);
	g_test_add_func(PREFIX_POLICY "user", test_iptables_plugin_policy_check_user);
	g_test_add_func(PREFIX_POLICY "load", test_iptables_plugin_policy_load);

	return g_test_run();
}
