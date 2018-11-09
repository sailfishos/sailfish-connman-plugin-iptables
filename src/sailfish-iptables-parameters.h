/*
 *
 *  Sailfish Connection Manager iptables plugin parameter handling.
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

#ifndef _SAILFISH_IPTABLES_PARAMETERS_H_
#define _SAILFISH_IPTABLES_PARAMETERS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <glib.h>
#include <dbus/dbus.h>

#include <dbusaccess/dbusaccess_peer.h>

#include "sailfish-iptables.h"

void dbus_client_free(dbus_client *client);
void dbus_client_free1(void *data);
dbus_client* dbus_client_new();

void api_data_free(api_data *data);
api_data* api_data_new();

dbus_client* api_data_get_peer(api_data *data, const gchar *peer_name);
gboolean api_data_add_peer(api_data *data, dbus_client *client);
gboolean api_data_remove_peer(api_data *data, const gchar *peer_name);

gboolean api_data_remove_custom_chains(api_data *data, const gchar* table_name);
gboolean api_data_add_custom_chain(api_data *data, const gchar *table_name, 
	const gchar* chain);
gboolean api_data_delete_custom_chain(api_data *data, const gchar *table_name,
	const gchar* chain);

client_disconnect_data* client_disconnect_data_new(api_data* data,
	dbus_client* client);
void client_disconnect_data_free(client_disconnect_data* data);

void rule_params_free(rule_params *params);
rule_params* rule_params_new(rule_args args);

gboolean check_operation(rule_params *params);
gboolean check_ips(rule_params *params);
gboolean check_ports(rule_params *params);
gboolean check_service(rule_params *params);
gboolean check_port_range(rule_params *params);
gboolean check_icmp(rule_params *params);
api_result check_parameters(rule_params* params);
gboolean check_chain_restricted(rule_params *params);

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
