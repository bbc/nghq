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
#include <arpa/inet.h>

#include "multicast.h"
#include "util.h"

/* +-+-+-+-+-+-+-+-+
 * |1|1| 0 |R R|P P|
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         Version (32)                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | DCID Len (8)  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |               Destination Connection ID (0..160)            ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | SCID Len (8)  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                 Source Connection ID (0..160)               ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         Token Length (i)                    ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                            Token (*)                        ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                           Length (i)                        ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Packet Number (8/16/24/32)               ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                          Payload (*)                        ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

static const uint8_t fake_client_initial_packet_fixed_dcid[] = {
    0x6d, 0x63, 0x61, 0x73, /* "mcast-quic-recv\0" */
    0x74, 0x2d, 0x71, 0x75,
    0x69, 0x63, 0x2d, 0x72,
    0x65, 0x63, 0x76, 0x00,
};

#define MIN_LENGTH_INITIAL_PAYLOAD 1200

static const uint8_t fake_server_handshake_packet_fixed_scid[] = {
    0x10,                   /* Source Connection ID Length = 16 */
    0x6d, 0x63, 0x61, 0x73, /* "mcast-quic-serv\0" */
    0x74, 0x2d, 0x71, 0x75,
    0x69, 0x63, 0x2d, 0x73,
    0x65, 0x72, 0x76, 0x00,
};

static const uint8_t fake_client_stream_0_payload[] = {
    0x0a, 0x00, 0x10, /* Stream with length field,  Stream ID 0, Length 16 */
    0x71, 0x75, 0x69, 0x63, 0x2d, 0x6d, 0x63, 0x61, /* quic-mcast magic */
    0x73, 0x74, 0x20, 0x6d, 0x61, 0x67, 0x69, 0x63
};

#define LENGTH_CLIENT_STREAM_0_PAYLOAD sizeof(fake_client_stream_0_payload)

#define INCLUDE_HEADER 0x1
#define IGNORE_ZERO_VALUE 0x2

size_t _bytes_required (int64_t param, int flags) {
  size_t rv = 0;
  if ((param < 0) || ((param == 0) && (flags & IGNORE_ZERO_VALUE))) {
    return 0;
  } else if (param <= 255) {
    rv = 1;
  } else if (param <= 65535) {
    rv = 2;
  } else if (param <= 16777215) {
    rv = 3;
  } else if (param <= 4294967295) {
    rv = 4;
  } else if (param <= 1099511627775) {
    rv = 5;
  } else if (param <= 281474976710655) {
    rv = 6;
  } else if (param <= 72057594037928935) {
    rv = 7;
  } else {
    rv = 8;
  }
  if (flags & INCLUDE_HEADER) {
    rv += 4;
  }
  return rv;
}

size_t _transport_param_int_bytes_required (int64_t t_param) {
  if (t_param <= 0) return 0;
  return _make_varlen_int(NULL, t_param) + 4;
}

size_t _transport_params_bytes_required (nghq_transport_parameters *t_params,
                                         bool server) {
  size_t rv = _transport_param_int_bytes_required (t_params->idle_timeout);
  rv += _transport_param_int_bytes_required (t_params->max_packet_size);
  rv += _transport_param_int_bytes_required (t_params->initial_max_data);
  if (server && t_params->stateless_reset_token.used) {
      rv += 4 + NGHQ_STATELESS_RESET_LENGTH;
  }
  rv += _transport_param_int_bytes_required (
      t_params->initial_max_stream_data_bidi_local);
  rv += _transport_param_int_bytes_required (
      t_params->initial_max_stream_data_bidi_remote);
  rv += _transport_param_int_bytes_required (
      t_params->initial_max_stream_data_uni);
  rv += _transport_param_int_bytes_required (
      t_params->initial_max_streams_bidi);
  rv += _transport_param_int_bytes_required (t_params->initial_max_streams_uni);
  rv += _transport_param_int_bytes_required (
      t_params->active_connection_id_limit);
  return rv;
}

/*
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Parameter Type (16)       |            Length (16)        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                      Parameter Value (i)                    ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
size_t _write_transport_parameter_int(uint16_t param_type, int64_t param,
                                      uint8_t* buf) {
  if (param <= 0) { return 0; }
  put_uint16_in_buf (buf, param_type);
  /* Because the spec is deliberately difficult and mandates a varint here
   * instead of just using the TLS field length...
   */
  size_t bytes_req = _make_varlen_int(buf + 4, param);
  put_uint16_in_buf (buf + 2, (uint16_t) bytes_req);
  return 4 + bytes_req;
}

/*
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |    Parameters Length (16)     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Parameter Type (16)       |            Length (16)        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                      Parameter Value (i)                    ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
size_t _write_transport_params (nghq_transport_parameters *t_params,
                                uint8_t *buf, bool server) {
  size_t rv = 2;
  put_uint16_in_buf(buf, (uint16_t) _transport_params_bytes_required(t_params,
                                                                     server));
  rv += _write_transport_parameter_int (
      TRANSPORT_PARAM_IDLE_TIMEOUT, t_params->idle_timeout, buf + rv);
  if (server && t_params->stateless_reset_token.used) {
    put_uint16_in_buf (buf + rv, TRANSPORT_PARAM_STATELESS_RESET);
    put_uint16_in_buf (buf + rv + 2, NGHQ_STATELESS_RESET_LENGTH);
    memcpy(buf + 4, t_params->stateless_reset_token.token,
           NGHQ_STATELESS_RESET_LENGTH);
    rv += 4 + NGHQ_STATELESS_RESET_LENGTH;
  }
  rv += _write_transport_parameter_int (
      TRANSPORT_PARAM_MAX_PACKET_SIZE, t_params->max_packet_size,
      buf + rv);
  rv += _write_transport_parameter_int (
      TRANSPORT_PARAM_INITIAL_MAX_DATA, t_params->initial_max_data,
      buf + rv);
  rv += _write_transport_parameter_int (
      TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
      t_params->initial_max_stream_data_bidi_local, buf + rv);
  rv += _write_transport_parameter_int (
      TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
      t_params->initial_max_stream_data_bidi_remote, buf + rv);
  rv += _write_transport_parameter_int (
      TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_UNI,
      t_params->initial_max_stream_data_uni, buf + rv);
  rv += _write_transport_parameter_int (
      TRANSPORT_PARAM_INITIAL_MAX_STREAMS_BIDI,
      t_params->initial_max_streams_bidi, buf + rv);
  rv += _write_transport_parameter_int (
      TRANSPORT_PARAM_INITIAL_MAX_STREAMS_UNI,
      t_params->initial_max_streams_uni, buf + rv);
  rv += _write_transport_parameter_int (
      TRANSPORT_PARAM_ACTIVE_CONNECTION_ID_LIMIT,
      t_params->active_connection_id_limit, buf + rv);
  return rv;
}

/* +-+-+-+-+-+-+-+-+
 * |1|1| 0 |R R|P P|
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         Version (32)                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | DCID Len (8)  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |               Destination Connection ID (0..160)            ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | SCID Len (8)  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                 Source Connection ID (0..160)               ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         Token Length (i)                    ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                            Token (*)                        ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                           Length (i)                        ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Packet Number (8/16/24/32)               ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Payload (Transport Parameters in CRYPTO frame)      ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
size_t get_fake_client_initial_packet (uint8_t* sid, size_t sid_len,
                                       uint32_t init_pkt_num,
                                       nghq_transport_parameters *t_params,
                                       uint8_t **pkt) {
  /* Calculate the length of the initial packet */
  size_t packet_len, offset, payload_len = 0, t_param_len = 0;
  size_t header_len = 6; /* initial byte + version + sid len field */
  header_len += 18; /* Fixed DCID of "mcast-quic-serv\0" + empty token len*/
  header_len += sid_len;
  header_len += _bytes_required ((int64_t) init_pkt_num, 0);
  /*
   * Still need to add the length field, but this is dependent on calculating
   * the transport parameters length...
   */

  /* Allowed client parameters:
   *  * idle_timeout
   *  * max_packet_size
   *  * initial_max_data
   *  * initial_max_stream_data_bidi_local
   *  * initial_max_stream_data_bidi_remote
   *  * initial_max_stream_data_uni
   *  * initial_max_streams_bidi
   *  * initial_max_streams_uni
   *  * ack_delay_exponent                    <-- Ignored
   *  * max_ack_delay                         <-- Ignored
   *  * disable_active_migration              <-- Ignored?
   *  * active_connection_id_limit            <-- MUST be zero for mcast
   */
  t_param_len = _transport_params_bytes_required (t_params, false);
  /*
   * 4 bytes for CRYPTO frame type (0x06) and offset field (0) and the transport
   * parameter structure length (2 bytes).
   */
  payload_len = t_param_len + 4 + _make_varlen_int(NULL, (uint64_t) t_param_len);

  if (payload_len < MIN_LENGTH_INITIAL_PAYLOAD) {
    payload_len = MIN_LENGTH_INITIAL_PAYLOAD;
  }
  header_len += _make_varlen_int(NULL, (uint64_t) payload_len +
                                 _bytes_required ((int64_t) init_pkt_num, 0));
  packet_len = header_len + payload_len;
  uint8_t *buf = (uint8_t *) malloc (packet_len);
  if (buf == NULL) {
    return 0;
  }
  memset(buf, 0, packet_len);

  buf[0] = 0xC0 + (uint8_t)(_bytes_required ((int64_t) init_pkt_num, 0) - 1);
  buf[1] = 0xff; buf[2] = 0x00; buf[3] = 0x00; buf[4] = 0x16; /* draft-22 */
  offset = 5;
  buf[offset++] = (uint8_t) sizeof(fake_client_initial_packet_fixed_dcid);
  memcpy(buf + offset, fake_client_initial_packet_fixed_dcid,
         sizeof(fake_client_initial_packet_fixed_dcid));
  offset += sizeof(fake_client_initial_packet_fixed_dcid);
  buf[offset++] = (uint8_t) sid_len;
  memcpy(buf + offset, sid, sid_len);
  offset += sid_len;
  buf[offset++] = 0; /* Empty token length */
  offset += _make_varlen_int(buf + offset, (uint64_t) payload_len +
                             _bytes_required ((int64_t) init_pkt_num, 0));
  offset += put_packet_number (init_pkt_num, buf + offset, packet_len - offset);

  offset += _make_varlen_int (buf + offset, 0x06ULL);
  buf[offset++] = 0; /* Offset... */
  offset += _make_varlen_int (buf + offset, t_param_len + 2);
  offset += _write_transport_params (t_params, buf + offset, false);

  *pkt = buf;
  return packet_len;
}

/*
 * +-+-+-+-+-+-+-+-+
 * |1|1| 0 |R R|P P|  INITIAL
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         Version (32)                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | DCID Len (8)  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |               Destination Connection ID (0..160)            ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | SCID Len (8)  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                 Source Connection ID (0..160)               ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         Token Length (i)                    ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                            Token (*)                        ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                           Length (i)                        ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Packet Number (8/16/24/32)               ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Payload (ACK client initial, 20 bytes of PADDING for ngtcp2)...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
size_t get_fake_server_initial_packet (uint8_t* sid, size_t sid_len,
                                       uint32_t pkt_num,
                                       nghq_transport_parameters *t_params,
                                       uint8_t **pkt) {
  size_t packet_len, offset, payload_len = 0;
    size_t header_len = 6; /* initial byte + version + sid len field */
    header_len += 18; /* Fixed SCID of "mcast-quic-serv\0" + empty token len*/
    header_len += sid_len;
    header_len += _bytes_required ((int64_t) pkt_num, 0);

    /* ACK the client initial
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                      Frame Type: ACK (0x02)                 ...
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                     Largest Acknowledged (0)                ...
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                          ACK Delay (0)                      ...
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                       ACK Range Count (0)                   ...
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                       First ACK Range (0)                   ...
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *    = 5 bytes
     */
    payload_len += 5;

    /* 20 byte PADDING payload */
    payload_len = 20;

    header_len += _make_varlen_int(NULL, (uint64_t) payload_len +
                                   _bytes_required ((int64_t) pkt_num, 0));
    packet_len = header_len + payload_len;
    uint8_t *buf = (uint8_t *) malloc (packet_len);
    if (buf == NULL) {
      return 0;
    }
    memset(buf, 0, packet_len);

    buf[0] = 0xC0 + (uint8_t)(_bytes_required ((int64_t) pkt_num, 0) - 1);
    buf[1] = 0xff; buf[2] = 0x00; buf[3] = 0x00; buf[4] = 0x16; /* draft-22 */
    offset = 5;
    buf[offset++] = (uint8_t) sid_len;
    memcpy(buf + offset, sid, sid_len);
    offset += sid_len;
    memcpy(buf + offset, fake_server_handshake_packet_fixed_scid,
             sizeof(fake_server_handshake_packet_fixed_scid));
    offset += sizeof(fake_server_handshake_packet_fixed_scid);
    buf[offset++] = 0; /* Empty token length */
    offset += _make_varlen_int(buf + offset, (uint64_t) payload_len +
                               _bytes_required ((int64_t) pkt_num, 0));
    offset += put_packet_number(pkt_num, buf + offset, packet_len - offset);

    buf[offset++] = 0x02;
    memset (buf + offset, 0, 24);

    *pkt = buf;
    return packet_len;
}

/*
 * +-+-+-+-+-+-+-+-+
 * |1|1| 2 |R R|P P|  HANDSHAKE
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         Version (32)                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | DCID Len (8)  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |               Destination Connection ID (0..160)            ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | SCID Len (8)  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                 Source Connection ID (0..160)               ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                           Length (i)                        ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Packet Number (8/16/24/32)               ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Payload (Transport Parameters in CRYPTO frame)      ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
size_t get_fake_server_handshake_packet (uint8_t* sid, size_t sid_len,
                                             uint32_t pkt_num,
                                             nghq_transport_parameters *t_params,
                                             uint8_t **pkt) {
  /* TODO: Might have to add a server initial packet to this ... */
  size_t packet_len, offset, payload_len = 0, t_param_len, header_len = 6; /* initial byte + version + dcid len field */
  header_len += sid_len;
  header_len += 17; /* Fixed SCID of "mcast-quic-serv\0"*/
  header_len += _bytes_required ((int64_t) pkt_num, 0);

  /* Allowed client parameters:
   *  * original_connection_id                <-- Ignored?
   *  * idle_timeout
   *  * stateless_reset_token                 <-- Ignored?
   *  * max_packet_size
   *  * initial_max_data
   *  * initial_max_stream_data_bidi_local
   *  * initial_max_stream_data_bidi_remote
   *  * initial_max_stream_data_uni
   *  * initial_max_streams_bidi
   *  * initial_max_streams_uni
   *  * ack_delay_exponent                    <-- Ignored
   *  * max_ack_delay                         <-- Ignored
   *  * disable_active_migration              <-- Ignored?
   *  * preferred_address                     <-- Ignored
   *  * active_connection_id_limit            <-- MUST be zero for mcast
   */
  t_param_len = _transport_params_bytes_required (t_params, true);
  /*
   * 4 bytes for CRYPTO frame type (0x06), offset and the transport parameter
   * structure length (2 bytes).
   */
  payload_len = t_param_len + 4 + _make_varlen_int(NULL, (uint64_t) t_param_len);

  packet_len = payload_len + header_len;
  packet_len += _make_varlen_int(NULL, (uint64_t) payload_len);
  //packet_len += 20; /* PADDING for INITIAL */
  uint8_t *buf = (uint8_t *) malloc (packet_len);
  if (buf == NULL) {
    return 0;
  }

  offset = 0;
  buf[offset] = 0xE0 + (uint8_t)(_bytes_required ((int64_t) pkt_num, 0) - 1);
  buf[offset+1] = 0xff; buf[offset+2] = 0x00; buf[offset+3] = 0x00;
  buf[offset+4] = 0x16; /* draft-22 */
  offset += 5;
  buf[offset++] = (uint8_t) sid_len;
  memcpy(buf + offset, sid, sid_len);
  offset += sid_len;
  memcpy(buf + offset, fake_server_handshake_packet_fixed_scid, 17);
  offset += 17;
  offset += _make_varlen_int(buf + offset, (uint64_t) payload_len +
                             _bytes_required ((int64_t) pkt_num, 0));
  offset += put_packet_number (pkt_num, buf + offset, packet_len - offset);

  offset += _make_varlen_int (buf + offset, 0x06ULL);
  buf[offset++] = 0; /* Offset... */
  offset += _make_varlen_int (buf + offset, t_param_len + 2);
  offset += _write_transport_params (t_params, buf + offset, false);

  *pkt = buf;
  return packet_len;
}

/*
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+
 * |1|1| 2 |R R|P P|  HANDSHAKE
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         Version (32)                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | DCID Len (8)  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |               Destination Connection ID (0..160)            ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | SCID Len (8)  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                 Source Connection ID (0..160)               ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                           Length (i)                        ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Packet Number (8/16/24/32)               ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |Payload (ACK srvr handshake, 20 bytes of PADDING for ngtcp2) ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |0|1|S|R|R|K|P P|
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                Destination Connection ID (0..160)           ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                   Packet Number (8/16/24/32)                ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                   Stream frame (0x08 - 0x0f)                ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         Stream ID (0)                       ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         [Offset (0)]                        ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         [Length (16)]                       ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                Stream Data ("quic-mcast magic")             ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
size_t get_fake_client_stream_0_packet (uint8_t* sid, size_t sid_len,
                                        uint32_t pkt_num, uint8_t **pkt) {
  size_t offset = 0, short_pkt_offset = 0;
  size_t dcid_len = sizeof(fake_server_handshake_scid);
  size_t handshake_ack_len = 1 + 4 + 1 + dcid_len + 1 + sid_len +
      _bytes_required ((int64_t) 26, false) +
      _bytes_required ((int64_t) 0, false) + 25;
  size_t short_packet_len = 1 + dcid_len + 1 + LENGTH_CLIENT_STREAM_0_PAYLOAD;

  uint8_t *buf = (uint8_t *) malloc (handshake_ack_len + short_packet_len);
  if (buf == NULL) {
    return 0;
  }

  buf[offset] = 0xE0 + (uint8_t)(_bytes_required ((int64_t) pkt_num, 0) - 1);
  buf[offset+1] = 0xff; buf[offset+2] = 0x00; buf[offset+3] = 0x00;
  buf[offset+4] = 0x16; /* draft-22 */
  offset += 5;
  buf[offset++] = dcid_len;
  memcpy(buf + offset, fake_server_handshake_scid, dcid_len);
  offset += dcid_len;
  buf[offset++] = sid_len;
  memcpy(buf + offset, sid, sid_len);
  offset += sid_len;
  buf[offset++] = 26; /* Length = 26 (25 plus 1 byte for pktnum) */
  buf[offset++] = 0; /* Packet Number = 0 */
  buf[offset++] = 0x02; /* ACK frame */
  /*
   * 24 bytes:
   *  ACK Largest Acknowledged: 0 (Only 1 Handshake packet to fake ACK)
   *  ACK Delay: 0
   *  ACK Range Count: 0
   *  First ACK Range: 0
   * And then the 20 bytes of padding to keep ngtcp2 happy
   */
  memset(buf + offset, 0, 24);
  offset += 24;
  short_pkt_offset = offset;

  memcpy(buf + short_pkt_offset + 1, fake_server_handshake_scid, dcid_len);
  short_pkt_offset += dcid_len + 1;
  size_t pktnumlen = put_packet_number(pkt_num, buf + short_pkt_offset,
                       handshake_ack_len + short_packet_len - short_pkt_offset);
  /* First byte of the short packet, now we now how long the packet number is */
  buf[offset] = 0x40 + ((uint8_t) pktnumlen - 1);
  short_pkt_offset += pktnumlen;
  memcpy(buf + short_pkt_offset, fake_client_stream_0_payload,
         LENGTH_CLIENT_STREAM_0_PAYLOAD);

  *pkt = buf;

  return handshake_ack_len + short_packet_len;
}
