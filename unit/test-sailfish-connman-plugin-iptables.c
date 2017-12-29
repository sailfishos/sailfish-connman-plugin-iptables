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
gboolean g_dbus_remove_watch(DBusConnection *connection, guint id) { return TRUE; }

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
	g_assert(!sailfish_iptables_policy_check_peer(data, peer, SAILFISH_DBUS_ACCESS_FULL));
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
	g_assert(sailfish_iptables_policy_check_peer(data, peer, SAILFISH_DBUS_ACCESS_FULL));
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

static void test_iptables_plugin_utils_api_result_message()
{
	g_assert(g_ascii_strcasecmp(api_result_message(OK),"Ok") == 0);
	g_assert(g_ascii_strcasecmp(api_result_message(INVALID_IP),"Invalid IP") == 0);
	g_assert(g_ascii_strcasecmp(api_result_message(INVALID_PORT),"Invalid port") == 0);
	g_assert(g_ascii_strcasecmp(api_result_message(INVALID_PORT_RANGE),"Invalid port range") == 0);
	g_assert(g_ascii_strcasecmp(api_result_message(INVALID_SERVICE),"Invalid service name") == 0);
	g_assert(g_ascii_strcasecmp(api_result_message(INVALID_PROTOCOL),"Invalid protocol") == 0);
	g_assert(g_ascii_strcasecmp(api_result_message(INVALID_POLICY),"Invalid policy") == 0);
	g_assert(g_ascii_strcasecmp(api_result_message(RULE_DOES_NOT_EXIST),"Rule does not exist") == 0);
	g_assert(g_ascii_strcasecmp(api_result_message(INVALID_REQUEST),"Cannot process request") == 0);
	g_assert(g_ascii_strcasecmp(api_result_message(INVALID),"Cannot perform operation") == 0);
	g_assert(g_ascii_strcasecmp(api_result_message(UNAUTHORIZED),"Unauthorized, please try again") == 0);
	g_assert(g_ascii_strcasecmp(api_result_message(REMOVE_FAILED),"Unregister failed") == 0);
	g_assert(g_ascii_strcasecmp(api_result_message(ACCESS_DENIED),"Access denied") == 0);
	g_assert(g_ascii_strcasecmp(api_result_message(999),"") == 0);
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

static void test_iptables_plugin_utils_get_port_range_tokens()
{
	gchar** tokens = NULL;
	
	tokens = get_port_range_tokens("1000:2000");
	g_assert(tokens && g_strv_length(tokens) == 2);
	g_assert(g_ascii_strcasecmp(tokens[0],"1000") == 0);
	g_assert(g_ascii_strcasecmp(tokens[1],"2000") == 0);
	g_strfreev(tokens);
	
	tokens = get_port_range_tokens(":");
	g_assert(tokens && g_strv_length(tokens) == 2);
	g_assert(g_ascii_strcasecmp(tokens[0],"") == 0);
	g_assert(g_ascii_strcasecmp(tokens[1],"") == 0);
	g_strfreev(tokens);
	
	g_assert(!get_port_range_tokens(""));
	g_assert(!get_port_range_tokens(NULL));
}

static void test_iptables_plugin_utils_port_to_str()
{
	gchar* port = NULL;
	
	rule_params *params = rule_params_new(ARGS_PORT_RANGE);
	params->port[0] = 22;
	params->port[1] = 80;
	
	port = port_to_str(params);
	
	g_assert(g_ascii_strcasecmp(port,"22:80") == 0);
	g_free(port);
	
	params->args = ARGS_IP_PORT_RANGE;
	port = port_to_str(params);
	g_assert(g_ascii_strcasecmp(port,"22:80") == 0);
	g_free(port);
	
	params->args = ARGS_IP_PORT;
	port = port_to_str(params);
	g_assert(g_ascii_strcasecmp(port,"22") == 0);
	g_free(port);
	
	params->args = ARGS_IP;
	g_assert(!port_to_str(params));
	
	rule_params_free(params);
	
	g_assert(!port_to_str(NULL));
}


static void test_iptables_plugin_parameters_ip()
{
	/* IP only : ARGS_IP */
	rule_params *params = rule_params_new(ARGS_IP);

	g_assert(params);
	g_assert(check_parameters(params) == INVALID_IP);
	
	params->ip = g_strdup("192.168.10.1");
	g_assert(check_parameters(params) == OK);
	
	rule_params_free(params);
}

static void test_iptables_plugin_parameters_port()
{
	/* Port only : ARGS_PORT */
	rule_params *params = rule_params_new(ARGS_PORT);
	
	g_assert(params);
	g_assert(check_parameters(params) == INVALID_PORT);
	
	params->port[0] = 80;
	g_assert(check_parameters(params) == INVALID_PROTOCOL);
	
	params->protocol = g_strdup("tcp");
	g_assert(check_parameters(params) == OK);
	
	rule_params_free(params);
}

static void test_iptables_plugin_parameters_ip_and_port()
{
	/* Port and ip  : ARGS_IP_PORT */
	rule_params *params = rule_params_new(ARGS_IP_PORT);
	
	g_assert(params);
	g_assert(check_parameters(params) == INVALID_IP);
	
	params->ip = g_strdup("192.168.10.1");
	g_assert(check_parameters(params) == INVALID_PORT);
	
	params->port[0] = 80;
	g_assert(check_parameters(params) == INVALID_PROTOCOL);
	
	params->protocol = g_strdup("tcp");
	g_assert(check_parameters(params) == OK);
	
	rule_params_free(params);
}

static void test_iptables_plugin_parameters_ip_and_port_range()
{
	/* Port and ip  : ARGS_IP_PORT */
	rule_params *params = rule_params_new(ARGS_IP_PORT_RANGE);
	
	g_assert(params);
	g_assert(check_parameters(params) == INVALID_IP);
	
	params->ip = g_strdup("192.168.10.1");
	g_assert(check_parameters(params) == INVALID_PORT);
	
	params->port[0] = 80;
	g_assert(check_parameters(params) == INVALID_PORT);
	
	params->port[1] = 22;
	g_assert(check_parameters(params) == INVALID_PORT_RANGE);
	
	params->port[1] = 8080;
	g_assert(check_parameters(params) == INVALID_PROTOCOL);
	
	params->protocol = g_strdup("tcp");
	g_assert(check_parameters(params) == OK);
	
	rule_params_free(params);
}

static void test_iptables_plugin_parameters_port_range()
{
	/* Port range  : ARGS_PORT_RANGE */
	rule_params *params = rule_params_new(ARGS_PORT_RANGE);
	
	g_assert(params);

	g_assert(check_parameters(params) == INVALID_PORT);
	
	params->port[0] = 80;
	g_assert(check_parameters(params) == INVALID_PORT);
	
	params->port[1] = 80;
	g_assert(check_parameters(params) == INVALID_PROTOCOL);
	
	params->port[1] = 22;
	g_assert(check_parameters(params) == INVALID_PORT_RANGE);
	
	params->port[1] = 8080;
	g_assert(check_parameters(params) == INVALID_PROTOCOL);
	
	params->protocol = g_strdup("tcp");
	g_assert(check_parameters(params) == OK);
	
	rule_params_free(params);
}

static void test_iptables_plugin_parameters_service()
{
	/* service  : ARGS_SERVICE */
	rule_params *params = rule_params_new(ARGS_SERVICE);
	
	g_assert(params);

	g_assert(check_parameters(params) == INVALID_SERVICE);
	
	params->service = g_strdup("http");
	g_assert(check_parameters(params) == INVALID_PROTOCOL);
	
	params->protocol = g_strdup("tcp");
	g_assert(check_parameters(params) == OK);
	
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
	const gchar const * NAMES[] = {"name1", "name2", "name3", "name4", "name5"};
	api_data *data = api_data_new();
	
	g_assert(data);
	g_assert(data->clients);
	g_assert(data->policy);
	
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
	g_assert(validate_operation("ADD") == ADD);
	g_assert(validate_operation("Add") == ADD);
	g_assert(validate_operation("add") == ADD);
	g_assert(validate_operation("add ") == ADD);
	g_assert(validate_operation(" AdD") == ADD);
	g_assert(validate_operation(" ADD ") == ADD);
	
	g_assert(validate_operation("REMOVE") == REMOVE);
	g_assert(validate_operation("Remove") == REMOVE);
	g_assert(validate_operation("remove") == REMOVE);
	g_assert(validate_operation(" Remove") == REMOVE);
	g_assert(validate_operation("remove ") == REMOVE);
	g_assert(validate_operation(" REMOVE ") == REMOVE);
	
	g_assert(validate_operation("Removed") == UNDEFINED);
	
	g_assert(validate_operation("A D D") == UNDEFINED);
	g_assert(validate_operation(NULL) == UNDEFINED);
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
	
	g_test_add_func(PREFIX_PARAMETERS "ip", test_iptables_plugin_parameters_ip);
	g_test_add_func(PREFIX_PARAMETERS "port", test_iptables_plugin_parameters_port);
	g_test_add_func(PREFIX_PARAMETERS "ip_and_port", test_iptables_plugin_parameters_ip_and_port);
	g_test_add_func(PREFIX_PARAMETERS "ip_and_port_range", test_iptables_plugin_parameters_ip_and_port_range);
	g_test_add_func(PREFIX_PARAMETERS "port_range", test_iptables_plugin_parameters_port_range);
	g_test_add_func(PREFIX_PARAMETERS "service", test_iptables_plugin_parameters_service);
	g_test_add_func(PREFIX_PARAMETERS "dbus_client", test_iptables_plugin_parameters_dbus_client);
	g_test_add_func(PREFIX_PARAMETERS "api_data", test_iptables_plugin_parameters_api_data);
	g_test_add_func(PREFIX_PARAMETERS "disconnect_data", test_iptables_plugin_parameters_disconnect_data);
	
	g_test_add_func(PREFIX_UTILS "api_result_message", test_iptables_plugin_utils_api_result_message);
	g_test_add_func(PREFIX_UTILS "protocol_for_service", test_iptables_plugin_utils_protocol_for_service);
	g_test_add_func(PREFIX_UTILS "protocol_for_port", test_iptables_plugin_utils_protocol_for_port);
	g_test_add_func(PREFIX_UTILS "mask_to_cidr", test_iptables_plugin_utils_mask_to_cidr);
	g_test_add_func(PREFIX_UTILS "format_ip", test_iptables_plugin_utils_format_ip);
	g_test_add_func(PREFIX_UTILS "get_port_range_tokens", test_iptables_plugin_utils_get_port_range_tokens);
	g_test_add_func(PREFIX_UTILS "port_to_str", test_iptables_plugin_utils_port_to_str);
	
	g_test_add_func(PREFIX_POLICY "basic", test_iptables_plugin_policy_check_basic);
	g_test_add_func(PREFIX_POLICY "root", test_iptables_plugin_policy_check_root);
	g_test_add_func(PREFIX_POLICY "user", test_iptables_plugin_policy_check_user);

	return g_test_run();
}
