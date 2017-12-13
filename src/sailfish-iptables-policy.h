/*
 *
 *  Sailfish Connection Manager iptables plugin policy check functions.
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

#ifndef _SAILFISH_IPTABLES_POLICY_H_
#define _SAILFISH_IPTABLES_POLICY_H_

#include <dbus/dbus.h>
#include <glib.h>

#include "sailfish-iptables.h"

#ifdef __cplusplus
extern "C" {
#endif

gboolean sailfish_iptables_policy_check_peer(api_data* data, DAPeer *peer, 
	dbus_access policy);

gboolean sailfish_iptables_policy_check(DBusMessage *message, api_data* data, 
	dbus_access policy);
	
gboolean sailfish_iptables_policy_check_args(DBusMessage *message,
	api_data* data, rule_args args);

DAPeer* sailfish_iptables_policy_get_peer(DBusMessage *message, api_data *data);

void sailfish_iptables_policy_initialize(api_data* data);
void sailfish_iptables_policy_uninitialize(api_data* data);

#ifdef __cplusplus
}
#endif

#endif /* __SAILFISH_IPTABLES_POLICY_H_ */

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */
