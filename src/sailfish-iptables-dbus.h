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
#define CONNMAN_API_SUBJECT_TO_CHANGE

#ifndef _SAILFISH_IPTABLES_DBUS_H_
#define _SAILFISH_IPTABLES_DBUS_H_

#include <stdbool.h>
#include <string.h>
#include <dbus/dbus.h>
#include <glib.h>

#include <connman/log.h>
#include <connman/plugin.h>
#include <connman/dbus.h>
#include <connman/iptables_ext.h>
#include <connman/gdbus.h>

#include "sailfish-iptables.h"
#include "sailfish-iptables-parameters.h"

#define SAILFISH_IPTABLES_DBUS_INTERFACE	"org.sailfishos.connman.mdm.iptables"
#define SAILFISH_IPTABLES_DBUS_PATH		"/org/sailfishos/connman/mdm/iptables"

// SIGNALS 

#define SAILFISH_IPTABLES_SIGNAL_INIT		"Initialize"
#define SAILFISH_IPTABLES_SIGNAL_STOP		"Shutdown"
#define SAILFISH_IPTABLES_SIGNAL_CLEAR		"IptablesTableCleared"
#define SAILFISH_IPTABLES_SIGNAL_CLEAR_CHAINS	"IptablesChainsCleared"
#define SAILFISH_IPTABLES_SIGNAL_POLICY		"PolicyChanged"
#define SAILFISH_IPTABLES_SIGNAL_RULE_ADD		"RuleAdded"
#define SAILFISH_IPTABLES_SIGNAL_RULE_REM		"RuleRemoved"
#define SAILFISH_IPTABLES_SIGNAL_CHAIN		"ChainChanged"

gint sailfish_iptables_dbus_register(api_data* data);

gint sailfish_iptables_dbus_unregister();

DBusMessage* sailfish_iptables_dbus_signal(const gchar* signal,
	gint first_arg_type, ...);
	
DBusMessage* sailfish_iptables_dbus_reply_result(DBusMessage *message,
	api_result result, rule_params* params);

void sailfish_iptables_dbus_send_signal(DBusMessage *signal, api_data *data);

DBusMessage* sailfish_iptables_dbus_signal_from_rule_params(rule_params* params);

rule_params* sailfish_iptables_dbus_get_parameters_from_msg(DBusMessage* message, rule_args args);


#endif /* __SAILFISH_IPTABLES_DBUS_H_ */

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */
