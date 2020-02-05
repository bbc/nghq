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

#ifndef LIB_NGHQ_INTERNAL_H_
#define LIB_NGHQ_INTERNAL_H_

#include <stdint.h>

#include "nghq/nghq.h"

#include "frame_types.h"

/* forward declarations for unreferenced pointer types */
struct nghq_map_ctx;
typedef struct nghq_map_ctx nghq_map_ctx;

struct nghq_hdr_compression_ctx;
typedef struct nghq_hdr_compression_ctx nghq_hdr_compression_ctx;

struct nghq_io_buf;
typedef struct nghq_io_buf nghq_io_buf;

typedef enum nghq_stream_state {
  STATE_OPEN,
  STATE_HDRS,
  STATE_BODY,
  STATE_TRAILERS,
  STATE_DONE
} nghq_stream_state;

#define CLIENT_REQUEST_STREAM(x) ((x % 4) == 0)
#define SERVER_PUSH_STREAM(x) ((x % 4) == 3)

#define STREAM_FLAG_STARTED UINT8_C(0x01)
#define STREAM_FLAG_TRAILERS_PROMISED UINT8_C(0x02)

typedef struct nghq_gap {
  uint64_t begin;
  uint64_t end;
  struct nghq_gap *next;
} nghq_gap;

typedef struct nghq_stream_frame {
  nghq_frame_type           frame_type;
  nghq_gap*                 gaps;

  // Single buffer to cover whole frame. Buffer memory (data->buf) only present
  // when frame_type != NGHQ_FRAME_TYPE_DATA.
  nghq_io_buf*              data;

  // Value to subtract from stream offset to get the body data offset for the
  // first byte of this data frame (frame_type == NGHQ_FRAME_TYPE_DATA).
  size_t                    data_offset_adjust;

  // Stream offset of first byte after the frame header
  // (frame_type == NGHQ_FRAME_TYPE_DATA).
  size_t                    end_header_offset;

  struct nghq_stream_frame* next;
} nghq_stream_frame;

typedef struct {
  uint64_t      push_id;
  int64_t       stream_id;
  nghq_io_buf*  send_buf;
  nghq_io_buf*  recv_buf;
  size_t        buf_idx;
  uint64_t      tx_offset;  /*Offset where all data before is acked by remote peer*/
  size_t        data_frames_total; /* total size of BODY data seen so far */
  void *        user_data;
  uint8_t       priority;
  nghq_stream_state recv_state;
  nghq_stream_state send_state;
  nghq_error    status;
  uint8_t       flags;
  size_t        next_recv_offset;
  nghq_stream_frame* active_frames;
} nghq_stream;

#define STREAM_STARTED(x) (x & STREAM_FLAG_STARTED)
#define STREAM_TRAILERS_PROMISED(x) (x & STREAM_FLAG_TRAILERS_PROMISED)

typedef struct tls13_varlen_vector {
  size_t size;
  uint8_t *value;
} tls13_varlen_vector;

#define TRANSPORT_PARAM_ORIGINAL_CONNECTION_ID 0x0000
#define TRANSPORT_PARAM_IDLE_TIMEOUT 0x0001
#define TRANSPORT_PARAM_STATELESS_RESET 0x0002
#define TRANSPORT_PARAM_MAX_PACKET_SIZE 0x0003
#define TRANSPORT_PARAM_INITIAL_MAX_DATA 0x0004
#define TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL 0x0005
#define TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE 0x0006
#define TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_UNI 0x0007
#define TRANSPORT_PARAM_INITIAL_MAX_STREAMS_BIDI 0x0008
#define TRANSPORT_PARAM_INITIAL_MAX_STREAMS_UNI 0x0009
#define TRANSPORT_PARAM_ACK_DELAY_EXPONENT 0x000a
#define TRANSPORT_PARAM_MAX_ACK_DELAY 0x000b
#define TRANSPORT_PARAM_DISABLE_MIGRATION 0x000c
#define TRANSPORT_PARAM_PREFERRED_ADDRESS 0x000d
#define TRANSPORT_PARAM_ACTIVE_CONNECTION_ID_LIMIT 0x000e

#define NGHQ_STATELESS_RESET_LENGTH 16

#define NGHQ_INIT_REQUEST_STREAM_ID 0

typedef struct nghq_transport_parameters {
  tls13_varlen_vector original_connection_id;
  int64_t idle_timeout;
  struct {
    bool used;
    uint8_t token[NGHQ_STATELESS_RESET_LENGTH];
  } stateless_reset_token;
  int64_t max_packet_size;
  int64_t initial_max_data;
  int64_t initial_max_stream_data_bidi_local;
  int64_t initial_max_stream_data_bidi_remote;
  int64_t initial_max_stream_data_uni;
  int64_t initial_max_streams_bidi;
  int64_t initial_max_streams_uni;
  int64_t ack_delay_exponent;
  int64_t max_ack_delay;
  bool disable_active_migration;
  struct {
    uint8_t ipv4Address[4];
    uint16_t ipv4Port;
    uint8_t ipv6Address[16];
    uint16_t ipv6Port;
    tls13_varlen_vector connectionId;
    uint8_t statelessResetToken[16];
  } preferred_address;
  int64_t active_connection_id_limit;
} nghq_transport_parameters;

typedef enum {
  NGHQ_STREAM_CLIENT_BIDI = 0,
  NGHQ_STREAM_SERVER_BIDI = 1,
  NGHQ_STREAM_CLIENT_UNI = 2,
  NGHQ_STREAM_SERVER_UNI = 3,
} nghq_stream_type;

typedef struct timeval nghq_ts;

struct nghq_session {
  uint8_t*        session_id;
  size_t          session_id_len;

  /* The next stream ID to open for each stream type */
  uint64_t        next_stream_id[4];

  /* The maximum allowed stream IDs for client requests and server pushes */
  uint64_t        max_open_requests;
  uint64_t        max_open_client_uni;
  uint64_t        max_open_server_uni;

  uint64_t        next_push_promise;
  uint64_t        max_push_promise;

  /* Mode */
  enum {
    NGHQ_ROLE_CLIENT,
    NGHQ_ROLE_SERVER,
    NGHQ_ROLE_MAX
  } role;

  nghq_mode       mode;
  int             handshake_complete;

  nghq_ts         last_recv_ts;

  uint64_t        tx_pkt_num;
  uint64_t        rx_pkt_num;

  uint8_t         remote_pktnum;
  uint64_t        last_remote_pkt_num;

  /* Application-specific stuff */
  nghq_callbacks  callbacks;
  nghq_settings   settings;
  nghq_transport_settings transport_settings;
  nghq_transport_parameters t_params;

  /* Currently running transfers */
  nghq_map_ctx *  transfers;
  nghq_map_ctx *  promises;

  nghq_hdr_compression_ctx *hdr_ctx;

  void *          session_user_data;

  nghq_io_buf*  send_buf;
  nghq_io_buf*  recv_buf;
};

int nghq_recv_stream_data (nghq_session* session, nghq_stream* stream,
                           const uint8_t* data, size_t datalen, size_t off,
                           uint8_t end_of_stream);

int nghq_deliver_headers (nghq_session* session, uint8_t flags,
                          nghq_header **hdrs, size_t num_hdrs,
                          void *request_user_data);

int nghq_queue_send_frame (nghq_session* session, uint64_t stream_id,
                           uint8_t* buf, size_t buflen);

int nghq_write_send_buffer (nghq_session* session);

int nghq_stream_cancel (nghq_session* session, nghq_stream *stream, int error);

int nghq_stream_ended (nghq_session* session, nghq_stream *stream);

int nghq_stream_close (nghq_session* session, nghq_stream *stream,
                       uint16_t app_error_code);

int nghq_change_max_stream_id (nghq_session* session, uint64_t max_stream_id);

nghq_stream *nghq_stream_new (uint64_t stream_id);
nghq_stream *nghq_req_stream_new(nghq_session* session);

nghq_stream *nghq_open_stream (nghq_session* session, nghq_stream_type type);

void nghq_update_timeout (nghq_session *session);

#define NGHQ_FRAME_OVERHEADS (1 + 4)

#define NGHQ_INVALID_STREAM_ID UINT64_C(0x7FFFFFFFFFFFFFFF)
#define NGHQ_NO_PUSH UINT64_C(0x7FFFFFFFFFFFFFFF)
#define NGHQ_MULTICAST_MAX_UNI_STREAM_ID UINT64_C(0x3FFFFFFFFFFFFFFF)
#define NGHQ_MULTICAST_MAX_PUSH_ID UINT64_C(0x3FFFFFFFFFFFFFFF)

#define NGHQ_PUSH_PROMISE_STREAM 0
#define NGHQ_CONTROL_CLIENT 2
#define NGHQ_CONTROL_SERVER 3

#define QUIC_ERR_STOPPING UINT16_C(0x0000)
#define QUIC_ERR_HTTP_NO_ERROR UINT16_C(0x0001)
#define QUIC_ERR_HTTP_PUSH_REFUSED UINT16_C(0x0002)
#define QUIC_ERR_HTTP_INTERNAL_ERROR UINT16_C(0x0003)
#define QUIC_ERR_HTTP_PUSH_ALREADY_IN_CACHE UINT16_C(0x0004)
#define QUIC_ERR_HTTP_REQUEST_CANCELLED UINT16_C(0x0005)
#define QUIC_ERR_HTTP_HPACK_DECOMPRESSION_FAILED UINT16_C(0x0006)
#define QUIC_ERR_HTTP_CONNECT_ERROR UINT16_C(0x0007)
#define QUIC_ERR_HTTP_EXCESSIVE_LOAD UINT16_C(0x0008)
#define QUIC_ERR_HTTP_VERSION_FALLBACK UINT16_C(0x0009)
#define QUIC_ERR_HTTP_WRONG_STREAM UINT16_C(0x000A)
#define QUIC_ERR_HTTP_PUSH_LIMIT_EXCEEDED UINT16_C(0x000B)
#define QUIC_ERR_HTTP_DUPLICATE_PUSH UINT16_C(0x000C)
#define QUIC_ERR_MALFORMED_FRAME(x) (x & 0100)
#define QUIC_ERR_MALFORMED_DATA_FRAME UINT16_C(0x0100)
#define QUIC_ERR_MALFORMED_HEADERS_FRAME UINT16_C(0x0101)
#define QUIC_ERR_MALFORMED_PRIORITY_FRAME UINT16_C(0x0102)
#define QUIC_ERR_MALFORMED_CANCEL_PUSH_FRAME UINT16_C(0x0103)
#define QUIC_ERR_MALFORMED_SETTINGS_FRAME UINT16_C(0x0104)
#define QUIC_ERR_MALFORMED_PUSH_PROMISE_FRAME UINT16_C(0x0105)
#define QUIC_ERR_MALFORMED_GOAWAY_FRAME UINT16_C(0x0107)
#define QUIC_ERR_MALFORMED_MAX_PUSH_ID UINT16_C(0x010D)

#endif /* LIB_NGHQ_INTERNAL_H_ */
