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

#include "nghq/nghq.h"

#include <ngtcp2/ngtcp2.h>

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

#define STREAM_FLAG_STARTED 0x01
#define STREAM_FLAG_TRAILERS_PROMISED 0x02

typedef struct {
  uint64_t      push_id;
  uint64_t      stream_id;
  nghq_io_buf*  send_buf;
  nghq_io_buf*  recv_buf;
  size_t        buf_idx;
  uint64_t      tx_offset;  /*Offset where all data before is acked by remote peer*/
  size_t        headers_off; /* Size of HEADERS blocks before BODY */
  size_t        body_off; /* Combined size of BODY headers on stream so far */
  void *        user_data;
  uint8_t       priority;
  nghq_stream_state recv_state;
  nghq_stream_state send_state;
  nghq_error    status;
  uint8_t       flags;
} nghq_stream;

#define STREAM_STARTED(x) (x & STREAM_FLAG_STARTED)
#define STREAM_TRAILERS_PROMISED(x) (x & STREAM_FLAG_TRAILERS_PROMISED)

struct nghq_session {
  /* ngtcp2 tracking */
  ngtcp2_conn*    ngtcp2_session;

  uint64_t        connection_id;

  /* The highest seen stream IDs for both client requests and server pushes */
  uint64_t        highest_bidi_stream_id;
  uint64_t        highest_uni_stream_id;

  /* The maximum allowed stream IDs for client requests and server pushes */
  uint64_t        max_open_requests;
  uint64_t        max_open_server_pushes;

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

  /* Application-specific stuff */
  nghq_callbacks  callbacks;
  nghq_settings   settings;
  nghq_transport_settings transport_settings;

  /* Currently running transfers */
  nghq_map_ctx *  transfers;
  nghq_map_ctx *  promises;

  nghq_hdr_compression_ctx *hdr_ctx;

  void *          session_user_data;

  nghq_io_buf*  send_buf;
  nghq_io_buf*  recv_buf;
};

int nghq_recv_stream_data (nghq_session* session, nghq_stream* stream,
                           const uint8_t* data, size_t datalen, size_t off);

int nghq_queue_send_frame (nghq_session* session, uint64_t stream_id,
                           uint8_t* buf, size_t buflen);

int nghq_write_send_buffer (nghq_session* session);

int nghq_stream_ended (nghq_session* session, nghq_stream *stream);

int nghq_stream_close (nghq_session* session, nghq_stream *stream,
                       uint16_t app_error_code);

int nghq_change_max_stream_id (nghq_session* session, uint64_t max_stream_id);

int nghq_mcast_swallow (nghq_session* session, const ngtcp2_pkt_hd *hd,
                        const ngtcp2_frame *fr);

nghq_stream *nghq_stream_new (uint64_t stream_id);
nghq_stream *nghq_req_stream_new(nghq_session* session);

#define NGHQ_NO_PUSH 0x7FFFFFFFFFFFFFFF
#define NGHQ_MULTICAST_MAX_UNI_STREAM_ID 0x3FFFFFFFFFFFFFFF
#define NGHQ_MULTICAST_MAX_PUSH_ID 0x3FFFFFFFFFFFFFFF

#define NGHQ_CONTROL_QUIC 0
#define NGHQ_CONTROL_CLIENT 2
#define NGHQ_CONTROL_SERVER 3

#define QUIC_ERR_STOPPING 0x0000
#define QUIC_ERR_HTTP_NO_ERROR 0x0001
#define QUIC_ERR_HTTP_PUSH_REFUSED 0x0002
#define QUIC_ERR_HTTP_INTERNAL_ERROR 0x0003
#define QUIC_ERR_HTTP_PUSH_ALREADY_IN_CACHE 0x0004
#define QUIC_ERR_HTTP_REQUEST_CANCELLED 0x0005
#define QUIC_ERR_HTTP_HPACK_DECOMPRESSION_FAILED 0x0006
#define QUIC_ERR_HTTP_CONNECT_ERROR 0x0007
#define QUIC_ERR_HTTP_EXCESSIVE_LOAD 0x0008
#define QUIC_ERR_HTTP_VERSION_FALLBACK 0x0009
#define QUIC_ERR_HTTP_WRONG_STREAM 0x000A
#define QUIC_ERR_HTTP_PUSH_LIMIT_EXCEEDED 0x000B
#define QUIC_ERR_HTTP_DUPLICATE_PUSH 0x000C
#define QUIC_ERR_MALFORMED_FRAME(x) (x & 0100)
#define QUIC_ERR_MALFORMED_DATA_FRAME 0x0100
#define QUIC_ERR_MALFORMED_HEADERS_FRAME 0x0101
#define QUIC_ERR_MALFORMED_PRIORITY_FRAME 0x0102
#define QUIC_ERR_MALFORMED_CANCEL_PUSH_FRAME 0x0103
#define QUIC_ERR_MALFORMED_SETTINGS_FRAME 0x0104
#define QUIC_ERR_MALFORMED_PUSH_PROMISE_FRAME 0x0105
#define QUIC_ERR_MALFORMED_GOAWAY_FRAME 0x0107
#define QUIC_ERR_MALFORMED_MAX_PUSH_ID 0x010D

#endif /* LIB_NGHQ_INTERNAL_H_ */
