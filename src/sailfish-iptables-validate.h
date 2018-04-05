/*
 *
 *  Sailfish Connection Manager iptables plugin validation functions.
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

#ifndef _SAILFISH_IPTABLES_VALIDATE_H_
#define _SAILFISH_IPTABLES_VALIDATE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <glib.h>

#include "sailfish-iptables.h"

gboolean negated_ip_address(const gchar* ip);

gboolean validate_address(gint type, const gchar* address);
gboolean validate_ip_mask(gint type, const gchar* mask);
gboolean validate_ip_address(gint type, const gchar* ip);
guint16 validate_service_name(const gchar *service);
gboolean validate_protocol(const gchar *protocol);
gchar* validate_protocol_int(gint protocol);
gboolean validate_port(guint16 port);
rule_operation validate_operation(guint16 operation);
gchar* validate_chain(const gchar *table, const gchar *chain);
gchar* validate_target(const gchar* table, const gchar *target);
gboolean validate_path(const gchar *path);
gboolean validate_policy(const gchar* policy);
gchar* validate_policy_int(guint16 policy_int);

#ifdef __cplusplus
}
#endif

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */

#endif
