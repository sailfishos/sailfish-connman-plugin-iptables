/*
 *
 *  Sailfish Connection Manager iptables plugin utility functions.
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
 
#define CONNMAN_API_SUBJECT_TO_CHANGE

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "sailfish-iptables-utils.h"

gchar* get_protocol_for_service(const gchar *service)
{
	if(service && *service) {
		struct servent *s = getservbyname(service, NULL);
		if(s)
			return g_strdup(s->s_proto);
	}
	return NULL;
}

gchar* get_protocol_for_port(guint16 port)
{
	if(port) {
		struct servent *s = getservbyport(htons(port), NULL);
		if(s)
			return g_strdup(s->s_proto);
	}
	return NULL;
}

guint32 mask_to_cidr(gint type, const gchar* mask_address)
{
	gint index = 0, b = 0;
	guint32 mask = 0, bits = 0;
	gint i = (type == IPV6 ? IPV6_MASK_MAX : IPV4_MASK_MAX);

	gchar **ip_tokens = NULL;

	if(!mask_address)
		return G_MAXUINT32;

	ip_tokens = g_strsplit(mask_address,IPV4_DELIM,IPV4_TOKENS);

	if(ip_tokens) {
		// Mask was given as cidr
		if(g_strv_length(ip_tokens) == 1) {
			mask = ((guint32)g_ascii_strtoull(ip_tokens[0], NULL,
				10));
		}
		// Dot notation
		else if(g_strv_length(ip_tokens) == 4) {
			for(index = 0; index < 4 && ip_tokens[index]; index++)
			{
				b = 24 - 8 * index; // 24,16,8,0
				mask += ((guint32)g_ascii_strtoull(
					ip_tokens[index], NULL, 10)) << b;
			}
		}
	}

	g_strfreev(ip_tokens);

	// Return protocol mask max (32/128)
	if (mask == G_MAXUINT32)
		return i;

	// Between 0 and protocol mask max, return given mask
	else if(mask <= i)
		return mask;

	// Value between protocol max and 2^32, calculate cidr mask
	bits = G_MAXUINT32 - 1;

	// Create cidr notation (bitmask for nw mask) by decrementing 
	while(--i >= 0 && mask != bits)
		bits <<= 1;

	return i;
}

gchar* format_ip(gint type, const gchar* ip)
{
	gchar *formatted_ip = NULL;
	gchar **ip_and_mask = NULL;
	gint mask_max = 0;

	if(!ip || !*ip)
		return NULL;

	mask_max = (type == IPV6 ? IPV6_MASK_MAX : IPV4_MASK_MAX);

	ip_and_mask = g_strsplit(ip,IP_MASK_DELIM,2);

	if(ip_and_mask && g_strv_length(ip_and_mask) == 2) {
		guint32 mask = mask_to_cidr(type, ip_and_mask[1]);

		/*
		 * TODO: when a IP (not network) is given with a bitmask
		 * iptables command changes the IP address to network, thus
		 * this cannot be removed using the API as such rule does not
		 * exist in iptables the new one with network does.
		*/

		// Proper mask, between 0 and 32/128
		if(mask && mask < mask_max)
			formatted_ip = g_strdup_printf("%s/%u",
				ip_and_mask[0], mask);

		/*
		 * Iptables command removes /32 (or /128 IPv6) from the end, we
		 * do the same, also for 0, TODO: if 0 given iptables sets
		 * 0.0.0.0/0 (any)
		*/
		else if((mask && mask == mask_max) || !mask)
			formatted_ip = g_strdup_printf("%s", ip_and_mask[0]);
		// TODO: this may not be reached
		else
			formatted_ip = g_strdup_printf("%s/%s",
				ip_and_mask[0], ip_and_mask[1]);
	}
	// No mask separator found
	else
		formatted_ip = g_strdup(ip);

	g_strfreev(ip_and_mask);

	return formatted_ip;

}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */
