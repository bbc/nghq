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

#ifndef _MULTICAST_INTERFACES_H_
#define _MULTICAST_INTERFACES_H_

typedef struct mcast_ifc_list_st {
    struct mcast_ifc_list_st* ifc_next;
    char*                     ifc_name;
    unsigned int              ifc_idx;
    struct sockaddr*          ifc_addr;
    socklen_t                 ifc_addrlen;
} mcast_ifc_list;

extern mcast_ifc_list* get_multicast_interfaces();
extern void free_multicast_interfaces(mcast_ifc_list*);

#endif /* _MULTICAST_INTERFACES_H_ */

// vim:ts=8:sts=4:sw=4:expandtab:
