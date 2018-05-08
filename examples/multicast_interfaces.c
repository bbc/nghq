/*
 * nghq
 *
 * Copyright (c) 2018 British Broadcasting Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <net/if.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <netdb.h>

#include "multicast_interfaces.h"

static int
_match_sockaddr(const struct sockaddr *addr1, socklen_t addr1len,
                const struct sockaddr *addr2, socklen_t addr2len)
{
    if (addr1 == addr2)
        return 1;
    if (addr1len != addr2len)
        return 0;
    if (addr1->sa_family != addr2->sa_family)
        return 0;
    switch (addr1->sa_family) {
    case AF_INET: {
            const struct sockaddr_in *sin1 = (const struct sockaddr_in*)addr1;
            const struct sockaddr_in *sin2 = (const struct sockaddr_in*)addr2;
            if (sin1->sin_port != sin2->sin_port)
                return 0;
            if (sin1->sin_addr.s_addr != sin2->sin_addr.s_addr)
                return 0;
        }
        break;
    case AF_INET6: {
            const struct sockaddr_in6 *sin1 = (const struct sockaddr_in6*)addr1;
            const struct sockaddr_in6 *sin2 = (const struct sockaddr_in6*)addr2;
            if (sin1->sin6_port != sin2->sin6_port)
                return 0;
            if (!IN6_ARE_ADDR_EQUAL(&sin1->sin6_addr, &sin2->sin6_addr))
                return 0;
        }
        break;
    default:
        return 0;
    }
    return 1;
}

static mcast_ifc_list*
_find_idx_and_addr_in_list (mcast_ifc_list** listp, unsigned int idx,
                            const struct sockaddr *addr, socklen_t addrlen)
{
    mcast_ifc_list *node = NULL;
    for (node = *listp; node && node->ifc_idx < idx; node = node->ifc_next);
    while (node && node->ifc_idx == idx &&
           !_match_sockaddr(addr, addrlen, node->ifc_addr, node->ifc_addrlen))
        node = node->ifc_next;
    if (node && node->ifc_idx == idx)
        return node;
    return NULL;
}

static void
_insert_in_list (mcast_ifc_list** listp, char *name, unsigned int idx,
                 const struct sockaddr *addr, socklen_t addrlen)
{
    mcast_ifc_list *node = NULL;
    mcast_ifc_list **insert_at = listp;

    while (*insert_at) {
        if ((*insert_at)->ifc_idx > idx)
            break;
        insert_at = &((*insert_at)->ifc_next);
    }

    node = (mcast_ifc_list*) malloc (sizeof(mcast_ifc_list));
    node->ifc_next = *insert_at;
    node->ifc_name = strdup (name);
    node->ifc_idx = idx;
    node->ifc_addr = (struct sockaddr*) malloc (addrlen);
    memcpy(node->ifc_addr, addr, addrlen);
    node->ifc_addrlen = addrlen;
    *insert_at = node;
}

static void
_add_interface (mcast_ifc_list** listp, char *name, unsigned int idx,
                const struct sockaddr *addr)
{
    socklen_t addrlen = 0;
    switch (addr->sa_family) {
    case AF_INET: addrlen = sizeof(struct sockaddr_in); break;
    case AF_INET6: addrlen = sizeof(struct sockaddr_in6); break;
    default:
        return;
    }
    mcast_ifc_list *node =
            _find_idx_and_addr_in_list(listp, idx, addr, addrlen);
    if (!node)
        _insert_in_list(listp, name, idx, addr, addrlen);
}

mcast_ifc_list*
get_multicast_interfaces ()
{
    mcast_ifc_list* root = NULL;
    struct ifaddrs *ifa = NULL;

    if (getifaddrs (&ifa) == 0) {
        for (struct ifaddrs *ifa_it = ifa; ifa_it; ifa_it = ifa_it->ifa_next) {
            if (ifa_it->ifa_flags & IFF_MULTICAST && ifa_it->ifa_addr) {
                _add_interface (&root, ifa_it->ifa_name,
                                if_nametoindex (ifa_it->ifa_name),
                                ifa_it->ifa_addr);
            }
        }
        freeifaddrs(ifa);
    }

    return root;
}

void
free_multicast_interfaces(mcast_ifc_list* list)
{
    while (list) {
        mcast_ifc_list* to_del = list;
        list = list->ifc_next;
        if (to_del->ifc_name)
            free(to_del->ifc_name);
        if (to_del->ifc_addr)
            free(to_del->ifc_addr);
        free(to_del);
    }
}

// vim:ts=8:sts=4:sw=4:expandtab:
