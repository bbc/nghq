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

#ifndef LIB_MULTICAST_H_
#define LIB_MULTICAST_H_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "nghq_internal.h"

#define FAKE_CLIENT_INITIAL_DCID_LEN 16
static const uint8_t fake_client_initial_dcid[] = {
  0x6d, 0x63, 0x61, 0x73, /* "mcast-quic-recv\0" */
  0x74, 0x2d, 0x71, 0x75,
  0x69, 0x63, 0x2d, 0x72,
  0x65, 0x63, 0x76, 0x00,
};

#define FAKE_SERVER_HANDSHAKE_SCID_LEN 16
static const uint8_t fake_server_handshake_scid[] = {
  0x6d, 0x63, 0x61, 0x73, /* "mcast-quic-serv\0" */
  0x74, 0x2d, 0x71, 0x75,
  0x69, 0x63, 0x2d, 0x73,
  0x65, 0x72, 0x76, 0x00,
};

size_t get_fake_client_initial_packet (uint8_t* sid, size_t sid_len,
                                       uint32_t init_pkt_num,
                                       nghq_transport_parameters *t_params,
                                       uint8_t **pkt);

size_t get_fake_server_initial_packet (uint8_t* sid, size_t sid_len,
                                       uint32_t pkt_num,
                                       nghq_transport_parameters *t_params,
                                       uint8_t **pkt);

size_t get_fake_server_handshake_packet (uint8_t* sid, size_t sid_len,
                                         uint32_t pkt_num,
                                         nghq_transport_parameters *t_params,
                                         uint8_t **pkt);

size_t get_fake_client_stream_0_packet (uint32_t pkt_num, uint8_t **pkt);

static const uint8_t quic_mcast_magic[] = {
    0x71, 0x75, 0x69, 0x63, 0x2d, 0x6d, 0x63, 0x61, /* quic-mcast magic */
    0x73, 0x74, 0x20, 0x6d, 0x61, 0x67, 0x69, 0x63, 0x00
};

#define LENGTH_QUIC_MCAST_MAGIC 17

#define INITIAL_MCAST_PACKET_NUMBER 0x01234567

#endif /* LIB_MULTICAST_H_ */
