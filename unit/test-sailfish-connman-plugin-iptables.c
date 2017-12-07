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

#define CONNMAN_API_SUBJECT_TO_CHANGE

static void test_iptables_plugin_utils_api_result_message()
{
	g_assert(g_ascii_strcasecmp(api_result_message(OK),"Ok") == 0);
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
	
	g_assert(validate_operation("REMOVE") == REMOVE);
	g_assert(validate_operation("Remove") == REMOVE);
	g_assert(validate_operation("remove") == REMOVE);
	
	g_assert(validate_operation("Removed") == UNDEFINED);
	g_assert(validate_operation(" Remove") == UNDEFINED);
	g_assert(validate_operation("A D D") == UNDEFINED);
	g_assert(validate_operation(NULL) == UNDEFINED);
}

static void test_iptables_plugin_validate_path()
{
	g_assert(validate_path("/path/to/file"));
	
	g_assert(!validate_path(""));
	g_assert(!validate_path(NULL));
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

int main(int argc, char *argv[])
{	
	g_test_init(&argc, &argv, NULL);
	
	g_test_add_func(PREFIX_VALIDATE "policy", test_iptables_plugin_validate_policy);
	g_test_add_func(PREFIX_VALIDATE "port", test_iptables_plugin_validate_port);
	g_test_add_func(PREFIX_VALIDATE "path", test_iptables_plugin_validate_path);
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
	
	g_test_add_func(PREFIX_UTILS "api_result_message", test_iptables_plugin_utils_api_result_message);
	g_test_add_func(PREFIX_UTILS "protocol_for_service", test_iptables_plugin_utils_protocol_for_service);
	g_test_add_func(PREFIX_UTILS "protocol_for_port", test_iptables_plugin_utils_protocol_for_port);
	g_test_add_func(PREFIX_UTILS "mask_to_cidr", test_iptables_plugin_utils_mask_to_cidr);
	g_test_add_func(PREFIX_UTILS "format_ip", test_iptables_plugin_utils_format_ip);
	g_test_add_func(PREFIX_UTILS "get_port_range_tokens", test_iptables_plugin_utils_get_port_range_tokens);
	g_test_add_func(PREFIX_UTILS "port_to_str", test_iptables_plugin_utils_port_to_str);

	return g_test_run();
}
