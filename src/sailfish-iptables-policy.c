/*
 *
 *  Sailfish Connection Manager iptables plugin policy check functions.
 *
 *  BSD 3-Clause License
 *
 *  Copyright (c) 2017-2018, Jolla Ltd.
 *  Contact: Jussi Laakkonen <jussi.laakkonen@jolla.com>
 *  All rights reserved.

 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *  Redistributions of source code must retain the above copyright notice, this
 *  list of conditions and the following disclaimer.
 *
 *  Redistributions in binary form must reproduce the above copyright notice,
 *  this list of conditions and the following disclaimer in the documentation
 *  and/or other materials provided with the distribution.
 *
 *  Neither the name of the copyright holder nor the names of its
 *  contributors may be used to endorse or promote products derived from
 *  this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 *  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 *  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 *  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 *  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#define CONNMAN_API_SUBJECT_TO_CHANGE

#define POLICY_PATH 				"/etc/connman"
#define POLICY_SUFFIX				".conf"
#define DEFAULT_POLICY_FILE 		"iptables_policy.conf"

#define SAILFISH_IPTABLES_DBUS_ACCESS_POLICY DA_POLICY_VERSION ";* = deny;" \
    "(user(sailfish-mdm)|group(privileged)) & manage() = allow;" \
    "group(privileged) & listen() = allow;" \
    "group(privileged) & full() = deny;" // maybe not needed

#include <stdbool.h>
#include <limits.h>
#include <stdlib.h>

#include <dbusaccess/dbusaccess_peer.h>
#include <dbusaccess/dbusaccess_policy.h>
#include <connman/log.h>

#include "sailfish-iptables-policy.h"
#include "sailfish-iptables-parameters.h"
#include "sailfish-iptables.h"

#define ERR(fmt,arg...) connman_error(fmt, ## arg)

static const DA_ACTION sailfish_iptables_dbus_access_policy_actions[] = {
	{ "manage", SAILFISH_DBUS_ACCESS_MANAGE, 0 },
	{ "full", SAILFISH_DBUS_ACCESS, 0 },
	{ "listen", SAILFISH_DBUS_ACCESS_LISTEN, 0 },
	{}
};

gchar* sailfish_iptables_load_policy(const gchar* policyfile)
{
	gchar *file = NULL, *file_real = NULL, *contents = NULL;
	gsize length = 0;
	GError *error = NULL;

	// Use default file if not defined
	if(!policyfile || !(*policyfile))
		file = g_strdup_printf("%s/%s", POLICY_PATH,
				DEFAULT_POLICY_FILE);
	else
		file = g_strdup_printf("%s/%s", POLICY_PATH, policyfile);

	file_real = realpath(file, NULL);

	// If file does not exist, directs outside storage dir, contents is not
	// available or contents is empty use the default policy
	if(!file_real || !g_str_has_prefix(file_real, POLICY_PATH) ||
		!g_str_has_suffix(file_real, POLICY_SUFFIX) ||
		!g_file_get_contents(file_real, &contents, &length, &error) ||
		!(*contents)) {
		DBG("%s %s policy file unavailable, using default policy",
			PLUGIN_NAME, "sailfish_iptables_load_policy()");
		contents = g_strdup(SAILFISH_IPTABLES_DBUS_ACCESS_POLICY);
	}

	DBG("%s %s Loaded policy from %s", PLUGIN_NAME,
		"sailfish_iptables_load_policy()", file_real ?
			file_real : "default:");

	g_free(file);
	g_free(file_real);

	return contents;
}

gboolean sailfish_iptables_policy_check_peer(api_data* data, DAPeer *peer,
	dbus_access policy)
{
	if(peer && data) {
		switch(policy) {
		case SAILFISH_DBUS_ACCESS:
		case SAILFISH_DBUS_ACCESS_MANAGE:
		case SAILFISH_DBUS_ACCESS_LISTEN:
			return da_policy_check(data->policy,
					&peer->cred, policy, NULL,
					DA_ACCESS_DENY);
		default:
			return false;
		}
	}
	return false;
}

DAPeer* sailfish_iptables_policy_get_peer(DBusMessage *message, api_data *data)
{
	if(message && data) {
		const gchar* sender = dbus_message_get_sender(message);
		dbus_client* client = api_data_get_peer(data, sender);

		return client && client->peer ? client->peer :
			da_peer_get(data->da_bus, sender);
	}
	return NULL;
}

gboolean sailfish_iptables_policy_check(DBusMessage *message, api_data* data,
	dbus_access policy)
{
	DAPeer *peer = sailfish_iptables_policy_get_peer(message, data);

	return sailfish_iptables_policy_check_peer(data, peer, policy);
}

gboolean sailfish_iptables_policy_check_args(DBusMessage *message,
	api_data* data, rule_args args)
{
	switch(args) {
	case ARGS_CLEAR:
		return sailfish_iptables_policy_check(message, data,
			SAILFISH_DBUS_ACCESS);
	case ARGS_IP:
	case ARGS_IP_PORT:
	case ARGS_IP_PORT_RANGE:
	case ARGS_IP_SERVICE:
	case ARGS_IP_ICMP:
	case ARGS_PORT:
	case ARGS_PORT_RANGE:
	case ARGS_SERVICE:
	case ARGS_POLICY:
	case ARGS_CHAIN:
	case ARGS_GET_CONTENT:
	case ARGS_CLEAR_CHAINS:
	case ARGS_ICMP:
		return sailfish_iptables_policy_check(message, data,
			SAILFISH_DBUS_ACCESS_MANAGE);
	default:
		return false;
	}
}

void sailfish_iptables_policy_initialize(api_data* data)
{
	if(data) {
		// Load from default path
		gchar* dbus_policy = sailfish_iptables_load_policy(
						DEFAULT_POLICY_FILE);

		data->da_bus = DA_BUS_SYSTEM;
		data->policy = da_policy_new_full(dbus_policy,
			sailfish_iptables_dbus_access_policy_actions);

		if(!data->policy)
			ERR("%s %s %s/%s", PLUGIN_NAME,
				"sailfish_iptables_policy_initialize() "
				"failed to load D-Bus policy, plugin access "
				"is restricted. Check policy file at",
				POLICY_PATH, DEFAULT_POLICY_FILE);

		g_free(dbus_policy);
	}
}

void sailfish_iptables_policy_uninitialize(api_data* data)
{
	if(data && data->policy) {
		da_policy_unref(data->policy);
		data->policy = NULL;
	}
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */
