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

#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <errno.h>
#include <stdbool.h>

#include "nghq/nghq.h"
#include "nghq_internal.h"
#include "frame_parser.h"
#include "frame_creator.h"
#include "header_compression.h"
#include "map.h"
#include "util.h"
#include "tcp2_callbacks.h"
#include "multicast.h"
#include "io_buf.h"
#include "lang.h"

#include "debug.h"

#define MIN(a,b) ((a<b)?(a):(b))

/* minimum byte overhead for a stream frame packet                      *
 * (quic pkt header + quic stream frame header + http/quic data header) */
#define MIN_STREAM_PACKET_OVERHEAD 27

static void _conn_ack_timeout (nghq_session *session, void *timer_id,
                               void *nghq_data)
{
  session->conn_ack_timer = NULL;
  nghq_io_buf *new_pkt = (nghq_io_buf *) malloc (sizeof(nghq_io_buf));
  new_pkt->buf = (uint8_t *) malloc(
                                 session->transport_settings.max_packet_size);
  new_pkt->buf_len = session->transport_settings.max_packet_size;

  new_pkt->buf_len = ngtcp2_conn_write_pkt (session->ngtcp2_session,
		                            new_pkt->buf, new_pkt->buf_len,
					    get_timestamp_now());

  nghq_io_buf_push (&session->send_buf, new_pkt);
  nghq_write_send_buffer (session);
}

static void _conn_loss_timeout (nghq_session *session, void *timer_id,
		                void *nghq_data)
{
  session->conn_loss_timer = NULL;
  ngtcp2_conn_on_loss_detection_alarm (session->ngtcp2_session,
                                       get_timestamp_now());
}

static void _adjust_timer(nghq_session *session, ngtcp2_tstamp trigger_time, ngtcp2_tstamp *tstamp, void **timer, nghq_timer_event cb, void *data)
{
  if (trigger_time != *tstamp) {
    if (trigger_time == UINT64_MAX) {
      // cancel expiry timer
      if (*timer) {
        session->callbacks.cancel_timer_callback (session,
                                                  session->session_user_data,
                                                  *timer);
        *timer = NULL;
      }
    } else {
      ngtcp2_tstamp now = get_timestamp_now ();
      if (trigger_time <= now) {
        // time has passed, do now and cancel any existing timer
        cb (session, *timer, data);
        if (*timer) {
          session->callbacks.cancel_timer_callback (session, session->session_user_data, *timer);
          *timer = NULL;
          *tstamp = UINT64_MAX;
        }
      } else {
        double from_now = ((double)(trigger_time - now))/1e9;
        if (*timer) {
          // timer already exists, update
          session->callbacks.reset_timer_callback (session, session->session_user_data, *timer, from_now);
        } else {
          // create new exiry timer
          *timer = session->callbacks.set_timer_callback (session, from_now, session->session_user_data, cb, data);
        }
      }
    }
    *tstamp = trigger_time;
  }
}

static void _update_timers(nghq_session *session)
{
  ngtcp2_tstamp ts;

  if (!session->callbacks.set_timer_callback) return;

  ts = ngtcp2_conn_loss_detection_expiry (session->ngtcp2_session);
  _adjust_timer(session, ts, &session->conn_loss_tstamp,
                &session->conn_loss_timer, _conn_loss_timeout, NULL);

  ts = ngtcp2_conn_ack_delay_expiry (session->ngtcp2_session);
  _adjust_timer(session, ts, &session->conn_ack_tstamp,
                &session->conn_ack_timer, _conn_ack_timeout, NULL);
}

nghq_stream * nghq_stream_init() {
  nghq_stream *stream = (nghq_stream *) calloc (1, sizeof(nghq_stream));
  if (stream == NULL) {
    return NULL;
  }
  stream->push_id = NGHQ_STREAM_ID_MAP_NOT_FOUND;
  stream->stream_id = NGHQ_STREAM_ID_MAP_NOT_FOUND;
  stream->user_data = (void *) &stream->stream_id; /*Guaranteed to be unique!*/
  stream->recv_state = STATE_OPEN;
  stream->send_state = STATE_OPEN;
  stream->status = NGHQ_OK;
  stream->flags = STREAM_FLAG_STARTED;
  return stream;
}

static nghq_session * _nghq_session_new_common(const nghq_callbacks *callbacks,
                                      const nghq_settings *settings,
                                      const nghq_transport_settings *transport,
                                      void *session_user_data) {
  nghq_session *session = (nghq_session *) malloc (sizeof(nghq_session));

  if (session == NULL) {
    ERROR("Couldn't create session object!\n");
    return NULL;
  }

  session->connection_id = transport->init_conn_id;
  session->mode = transport->mode;
  session->handshake_complete = 0;
  session->max_open_requests = transport->max_open_requests;
  session->max_open_server_pushes = transport->max_open_server_pushes;
  session->highest_bidi_stream_id = 0;
  session->highest_uni_stream_id = 0;
  session->next_push_promise = 0;
  session->max_push_promise = 0;


  memcpy(&session->callbacks, callbacks, sizeof(nghq_callbacks));
  memcpy(&session->settings, settings, sizeof(nghq_settings));
  memcpy(&session->transport_settings, transport,
         sizeof(nghq_transport_settings));

  session->transfers = nghq_stream_id_map_init();
  nghq_stream *stream0 = nghq_stream_init();
  stream0->stream_id = 0;
  nghq_stream_id_map_add (session->transfers, 0, stream0);
  session->promises = nghq_stream_id_map_init();
  session->session_user_data = session_user_data;

  nghq_init_hdr_compression_ctx(&session->hdr_ctx);

  session->send_buf = NULL;
  session->recv_buf = NULL;

  session->remote_pktnum = 2;
  session->last_remote_pkt_num = 0;

  session->conn_loss_tstamp = UINT64_MAX;
  session->conn_loss_timer = NULL;
  session->conn_ack_tstamp = UINT64_MAX;
  session->conn_ack_timer = NULL;

  return session;
}

static int _nghq_start_session(nghq_session *session,
                               const nghq_transport_settings *t) {
  if (session->mode == NGHQ_MODE_MULTICAST) {
    DEBUG("Starting a new multicast session\n");
    /* Just set defaults and return */
    session->highest_bidi_stream_id = 4;
    session->highest_uni_stream_id = NGHQ_MULTICAST_MAX_UNI_STREAM_ID;
    session->max_push_promise = NGHQ_MULTICAST_MAX_UNI_STREAM_ID;
    return NGHQ_OK;
  }
  DEBUG("Starting a new unicast session\n");
  session->highest_bidi_stream_id = NGHQ_MULTICAST_MAX_UNI_STREAM_ID;
  session->highest_uni_stream_id = NGHQ_MULTICAST_MAX_UNI_STREAM_ID;
  session->max_push_promise = 0;

  return NGHQ_OK;
}

nghq_session * nghq_session_client_new (const nghq_callbacks *callbacks,
                                        const nghq_settings *settings,
                                        const nghq_transport_settings *transport,
                                        void *session_user_data) {
  nghq_session *session = _nghq_session_new_common (callbacks, settings, transport,
                                               session_user_data);
  int result;

  if (session != NULL) {
    session->role = NGHQ_ROLE_CLIENT;
  }

  if (_nghq_start_session(session, transport) != NGHQ_OK) {
    free (session);
    return NULL;
  }

  ngtcp2_conn_callbacks tcp2_callbacks = {
    .send_client_initial = nghq_transport_send_client_initial,
    .send_client_handshake = nghq_transport_send_client_handshake,
    .recv_client_initial = NULL,
    .send_server_handshake = NULL,
    .recv_stream0_data = nghq_transport_recv_stream0_data,
    .handshake_completed = nghq_transport_handshake_completed,
    .recv_version_negotiation = nghq_transport_recv_version_negotiation,
    .hs_encrypt = nghq_transport_encrypt, /*TODO: Do we need to replace these */
    .hs_decrypt = nghq_transport_decrypt, /* with handshake-specific          */
                                          /* encrypt/decrypt funcs?           */
    .encrypt = nghq_transport_encrypt,
    .decrypt = nghq_transport_decrypt,
    .recv_stream_data = nghq_transport_recv_stream_data,
    .acked_stream_data_offset = nghq_transport_acked_stream_data_offset,
    .stream_close = nghq_transport_stream_close,
    .recv_stateless_reset = nghq_transport_recv_stateless_reset,
    .recv_server_stateless_retry = nghq_transport_recv_server_stateless_retry,
    .extend_max_stream_id = nghq_transport_extend_max_stream_id,
  };

  srand(time(NULL));
  uint64_t init_conn_id = rand64();

  ngtcp2_settings tcp2_settings;
  tcp2_settings.initial_ts = get_timestamp_now();
  tcp2_settings.log_printf = nghq_transport_debug;
  tcp2_settings.max_stream_data = (transport->max_stream_data)?
                                      (transport->max_stream_data):(256 * 1024);
  tcp2_settings.max_data = (transport->max_data)?(transport->max_data):
                               (1 * 1024 * 1024);
  tcp2_settings.max_stream_id_bidi = session->highest_bidi_stream_id;
  tcp2_settings.max_stream_id_uni = session->highest_uni_stream_id;
  tcp2_settings.idle_timeout = transport->idle_timeout;
  tcp2_settings.omit_connection_id = 0;
  tcp2_settings.max_packet_size = NGTCP2_MAX_PKT_SIZE;
  tcp2_settings.ack_delay_exponent = NGTCP2_DEFAULT_ACK_DELAY_EXPONENT;
  tcp2_settings.flags = NGTCP2_SETTINGS_FLAG_UNORDERED_DATA;

  result = ngtcp2_conn_client_new(&session->ngtcp2_session, init_conn_id,
                                  NGTCP2_PROTO_VER_D9, &tcp2_callbacks,
                                  &tcp2_settings, (void *) session);
  if (result != 0) {
    ERROR("ngtcp2_conn_client_new failed with error %d", result);
    goto nghq_client_fail_session;
  }

  DEBUG("Created new client ngtcp2_conn: %p\n", (void *) session->ngtcp2_session);

  if (session->mode == NGHQ_MODE_MULTICAST) {
    uint8_t *buf = malloc(64);
    nghq_io_buf_new(&session->send_buf, buf, 64, 0, 0);
    uint8_t *init_buf = malloc(session->transport_settings.max_packet_size);
    ngtcp2_conn_set_handshake_tx_keys(session->ngtcp2_session,
                                      quic_mcast_magic, LENGTH_QUIC_MCAST_MAGIC,
                                      quic_mcast_magic, LENGTH_QUIC_MCAST_MAGIC);
    ngtcp2_conn_set_handshake_rx_keys(session->ngtcp2_session,
                                      quic_mcast_magic, LENGTH_QUIC_MCAST_MAGIC,
                                      quic_mcast_magic, LENGTH_QUIC_MCAST_MAGIC);

    result = ngtcp2_conn_handshake(session->ngtcp2_session, init_buf,
                                   session->transport_settings.max_packet_size,
                                   NULL, 0, get_timestamp_now());

    if (result < 0) {
      ERROR("Failed to fake writing the client initial packet: %d %s\n",
            result, ngtcp2_strerror(result));
      free (init_buf);
      goto nghq_client_fail_conn;
    }

    /* Fake handshake for multicast */
    uint8_t *fake_server_handshake;
    size_t len_server_hs = get_fake_server_handshake_packet (
        session->connection_id, 1, tcp2_settings.max_stream_data,
        tcp2_settings.max_data, &fake_server_handshake);
    result = ngtcp2_conn_handshake (session->ngtcp2_session, init_buf,
                                    session->transport_settings.max_packet_size,
                                    fake_server_handshake, len_server_hs,
                                    get_timestamp_now());
    free (fake_server_handshake);
    free (init_buf);

    if (result < 0) {
      ERROR("Failed to submit fake server handshake to client instance: %s\n",
            ngtcp2_strerror(result));
      goto nghq_client_fail_conn;
    }

    ngtcp2_conn_handshake_completed(session->ngtcp2_session);

    result = ngtcp2_conn_update_tx_keys(session->ngtcp2_session,
                                        quic_mcast_magic,
                                        LENGTH_QUIC_MCAST_MAGIC,
                                        quic_mcast_magic,
                                        LENGTH_QUIC_MCAST_MAGIC);
    if (result != 0) {
      ERROR("ngtcp2_conn_update_tx_keys: %s\n", ngtcp2_strerror((int) result));
    }

    result = ngtcp2_conn_update_rx_keys(session->ngtcp2_session,
                                        quic_mcast_magic,
                                        LENGTH_QUIC_MCAST_MAGIC,
                                        quic_mcast_magic,
                                        LENGTH_QUIC_MCAST_MAGIC);
    if (result != 0) {
      ERROR("ngtcp2_conn_update_rx_keys: %s\n", ngtcp2_strerror((int) result));
    }
  }

  session->connection_id =
      ngtcp2_conn_negotiated_conn_id(session->ngtcp2_session);

  DEBUG("Negotiated connection ID: %lu\n", session->connection_id);

  return session;

nghq_client_fail_conn:
  ngtcp2_conn_del(session->ngtcp2_session);
nghq_client_fail_session:
  free(session);

  return NULL;
}

nghq_session * nghq_session_server_new (const nghq_callbacks *callbacks,
                                        const nghq_settings *settings,
                                        const nghq_transport_settings *transport,
                                        void *session_user_data) {
  nghq_session *session = _nghq_session_new_common (callbacks, settings,
                                                    transport,
                                                    session_user_data);
  int result;
  uint64_t control_stream;

  if (session != NULL) {
    session->role = NGHQ_ROLE_SERVER;
  }

  if (_nghq_start_session(session, transport) != NGHQ_OK) {
    free (session);
    return NULL;
  }

  ngtcp2_conn_callbacks tcp2_callbacks = {
    NULL,
    NULL,
    nghq_transport_recv_client_initial,
    nghq_transport_send_server_handshake,
    nghq_transport_recv_stream0_data,
    nghq_transport_handshake_completed,
    nghq_transport_recv_version_negotiation,
    nghq_transport_encrypt,   /* TODO: Do we need to replace these with    */
    nghq_transport_decrypt,   /* handshake-specific encrypt/decrypt funcs? */
    nghq_transport_encrypt,
    nghq_transport_decrypt,
    nghq_transport_recv_stream_data,
    nghq_transport_acked_stream_data_offset,
    nghq_transport_stream_close,
    nghq_transport_recv_stateless_reset,
    nghq_transport_recv_server_stateless_retry,
    nghq_transport_extend_max_stream_id,
  };

  ngtcp2_settings tcp2_settings;
  tcp2_settings.initial_ts = get_timestamp_now();
  tcp2_settings.log_printf = nghq_transport_debug;
  tcp2_settings.max_stream_data = (transport->max_stream_data)?
                                      (transport->max_stream_data):(256 * 1024);
  tcp2_settings.max_data = (transport->max_data)?(transport->max_data):
                               (1 * 1024 * 1024);
  tcp2_settings.max_stream_id_bidi = session->highest_bidi_stream_id;
  tcp2_settings.max_stream_id_uni = session->highest_uni_stream_id;
  tcp2_settings.idle_timeout = transport->idle_timeout;
  tcp2_settings.omit_connection_id = 0;
  tcp2_settings.max_packet_size = NGTCP2_MAX_PKT_SIZE;
  tcp2_settings.ack_delay_exponent = NGTCP2_DEFAULT_ACK_DELAY_EXPONENT;
  tcp2_settings.flags = NGTCP2_SETTINGS_FLAG_UNORDERED_DATA;

  uint64_t conn_id = session->connection_id;

  result = ngtcp2_conn_server_new(&session->ngtcp2_session, conn_id,
                                  NGTCP2_PROTO_VER_D9, &tcp2_callbacks,
                                  &tcp2_settings, (void *) session);
  if (result != 0) {
    ERROR("ngtcp2_conn_server_new failed with error %d", result);
    goto nghq_srv_fail_session;
  }

  if (session->mode == NGHQ_MODE_MULTICAST) {
    ngtcp2_pkt_hd hd;
    ngtcp2_transport_params params;
    uint8_t *in_buf, *out_buf;
    size_t len_client_init;
    ssize_t encoded_params_size = 128;

    len_client_init = get_fake_client_initial_packet (session->connection_id,
                                       0, tcp2_settings.max_stream_data,
                                       MIN(UINT32_MAX, tcp2_settings.max_data),
                                       &in_buf);
    result = ngtcp2_accept(&hd, in_buf, len_client_init);
    if (result < 0) {
      ERROR("The fake client initial packet was not accepted by ngtcp2: %s\n",
            ngtcp2_strerror(result));
      goto nghq_srv_fail_conn;
    }
    session->connection_id = hd.conn_id;

    out_buf = (uint8_t *) malloc(128);
    if (out_buf == NULL) {
      ERROR("Failed to allocate buffer for the encoded transport parameters\n");
      goto nghq_srv_fail_conn;
    }

    nghq_stream *stream0 = nghq_stream_id_map_find (session->transfers, 0);
    nghq_io_buf_new(&stream0->send_buf, out_buf, encoded_params_size, 0, 0);
    static uint8_t out_buf2[128];
    ngtcp2_conn_set_handshake_tx_keys(session->ngtcp2_session,
                                      quic_mcast_magic, LENGTH_QUIC_MCAST_MAGIC,
                                      quic_mcast_magic, LENGTH_QUIC_MCAST_MAGIC);
    ngtcp2_conn_set_handshake_rx_keys(session->ngtcp2_session,
                                      quic_mcast_magic, LENGTH_QUIC_MCAST_MAGIC,
                                      quic_mcast_magic, LENGTH_QUIC_MCAST_MAGIC);
    result = ngtcp2_conn_handshake(session->ngtcp2_session, out_buf2,
                                   sizeof(out_buf2), in_buf, len_client_init,
                                   get_timestamp_now());

    free (in_buf);
    if (result < 0) {
      ERROR("ngtcp2_conn_handshake encountered an error: %s\n",
            ngtcp2_strerror(result));
      goto nghq_srv_fail_conn;
    }

    ngtcp2_conn_get_local_transport_params(session->ngtcp2_session, &params,
                             NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS);
    params.v.ee.len = 1;
    params.v.ee.supported_versions[0] = NGTCP2_PROTO_VER_D9;
    params.initial_max_stream_data = tcp2_settings.max_stream_data;
    params.initial_max_data = tcp2_settings.max_data;
    params.initial_max_stream_id_bidi = 4;
    params.initial_max_stream_id_uni = 0x3FFFFFFF;

    encoded_params_size = ngtcp2_encode_transport_params(out_buf, 128,
                            NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS,
                            &params);
    if (encoded_params_size < 0) {
      ERROR("ngtcp2_encode_transport_params: %s\n",
            ngtcp2_strerror((int) encoded_params_size));
      free (out_buf);
      goto nghq_srv_fail_conn;
    }

    while (result > 0) {
      result = ngtcp2_conn_handshake (session->ngtcp2_session, out_buf,
                                      encoded_params_size, NULL, 0,
                                      get_timestamp_now());
      if (ngtcp2_conn_get_handshake_completed(session->ngtcp2_session)) {
        break;
      }
    }
    if (result < 0) {
      ERROR("ngtcp2_conn_handshake encountered an error: %s\n",
            ngtcp2_strerror(result));
      goto nghq_srv_fail_conn;
    }

    result = ngtcp2_conn_write_pkt(session->ngtcp2_session,
                                   stream0->send_buf->buf,
                                   stream0->send_buf->buf_len,
                                   get_timestamp_now());
    if (result < 0) {
      ERROR("ngtcp2_conn_write_pkt Couldn't write handshake: %s\n",
            ngtcp2_strerror(result));
      goto nghq_srv_fail_conn;
    }

    result = ngtcp2_conn_update_early_keys(session->ngtcp2_session,
                                           quic_mcast_magic,
                                           LENGTH_QUIC_MCAST_MAGIC,
                                           quic_mcast_magic,
                                           LENGTH_QUIC_MCAST_MAGIC);
    if (result != 0) {
      ERROR("ngtcp2_conn_update_early_keys: %s\n",
            ngtcp2_strerror((int) result));
    }

    result = ngtcp2_conn_update_tx_keys(session->ngtcp2_session,
                                        quic_mcast_magic,
                                        LENGTH_QUIC_MCAST_MAGIC,
                                        quic_mcast_magic,
                                        LENGTH_QUIC_MCAST_MAGIC);
    if (result != 0) {
      ERROR("ngtcp2_conn_update_tx_keys: %s\n", ngtcp2_strerror((int) result));
    }

    ngtcp2_conn_set_aead_overhead(session->ngtcp2_session, 0);

    result = ngtcp2_conn_update_rx_keys(session->ngtcp2_session,
                                        quic_mcast_magic,
                                        LENGTH_QUIC_MCAST_MAGIC,
                                        quic_mcast_magic,
                                        LENGTH_QUIC_MCAST_MAGIC);
    if (result != 0) {
      ERROR("ngtcp2_conn_update_rx_keys: %s\n", ngtcp2_strerror((int) result));
    }

    uint8_t *strm4pkt;
    size_t len_strm4_pkt = get_fake_client_stream_4_packet (
                                            session->connection_id, 2,
                                            tcp2_settings.max_data, &strm4pkt);
    result = ngtcp2_conn_recv(session->ngtcp2_session, strm4pkt, len_strm4_pkt,
                              get_timestamp_now());

    nghq_io_buf_pop(&stream0->send_buf);

    free (strm4pkt);
    if (result < 0) {
      ERROR("Failed to read stream 4 packet: %s\n",
            ngtcp2_strerror((int) result));
    }
  }

  /* Open a server control channel */
  nghq_stream* control = nghq_stream_new(NGHQ_CONTROL_SERVER);
  result = ngtcp2_conn_open_uni_stream(session->ngtcp2_session, &control_stream,
                                   (void *) control);
  if (control_stream != NGHQ_CONTROL_SERVER) {
    /* This must never happen, the server control MUST be on 3! */
    ERROR("Couldn't open server control stream 3: %s\n",
          ngtcp2_strerror(result));
    goto nghq_srv_fail_conn;
  }
  nghq_stream_id_map_add(session->transfers, control->stream_id, control);

  /* TODO: Send a SETTINGS frame */

  DEBUG("Created new server ngtcp2_conn: %p\n",
        (void *) session->ngtcp2_session);

  return session;

nghq_srv_fail_conn:
  ngtcp2_conn_del(session->ngtcp2_session);
nghq_srv_fail_session:
  free(session);

  return NULL;
}

int nghq_session_close (nghq_session *session, nghq_error reason) {
  nghq_stream *it;
  if (session == NULL) {
    return NGHQ_SESSION_CLOSED;
  }

  /* Close any running streams - iterate from first stream after 4 */
  it = nghq_stream_id_map_find(session->transfers, 4);
  for (it = nghq_stream_id_map_iterator(session->transfers, it); it;
       it = nghq_stream_id_map_iterator(session->transfers, it)) {
    nghq_stream_close(session, it, QUIC_ERR_HTTP_REQUEST_CANCELLED);
  }
  if (session->mode == NGHQ_MODE_MULTICAST) {
    nghq_stream* stream4 = nghq_stream_id_map_find (session->transfers, 4);
    if (stream4 != NULL) {
      if (session->role == NGHQ_ROLE_SERVER) {
        /* https://tools.ietf.org/html/draft-pardue-quic-http-mcast-02#section-5.5 */
#define MAKE_HEADER(key, field, value) \
        static const char key##_field[] = field; \
        static const char key##_value[] = value; \
        static const nghq_header key = {(uint8_t *) key##_field, sizeof(key##_field)-1, (uint8_t *) key##_value, sizeof(key##_value)-1};
        MAKE_HEADER(req_method, ":method", "GET");
        MAKE_HEADER(req_scheme, ":scheme", "http");
        MAKE_HEADER(req_path, ":path", "goaway");
        MAKE_HEADER(req_connection, "connection", "close");
        static const nghq_header *req[] = {
            &req_method, &req_scheme, &req_path, &req_connection
        };
        MAKE_HEADER(resp_status, ":status", "200");
        MAKE_HEADER(resp_connection, "connection", "close");
        static const nghq_header *resp[] = {
            &resp_status, &resp_connection
        };
#undef MAKE_HEADER
        nghq_submit_push_promise(session, stream4->user_data, req,
                                 sizeof(req)/sizeof(req[0]),
                                 (void *) stream4);
        nghq_feed_headers (session, resp, sizeof(resp)/sizeof(resp[0]), 1,
                           (void *) stream4);
      } else {
        /* multicast client also needs to close stream 4 */
        nghq_stream_close(session, stream4, QUIC_ERR_HTTP_REQUEST_CANCELLED);
      }
    }
  } else if (session->mode == NGHQ_MODE_UNICAST) {
    uint8_t* closebuf;
    ssize_t rv;
    closebuf = (uint8_t *) malloc (session->transport_settings.max_packet_size);
    rv = ngtcp2_conn_write_connection_close (session->ngtcp2_session, closebuf,
           session->transport_settings.max_packet_size, 0, get_timestamp_now());
    if (rv < 0) {
      switch (rv) {
        case NGTCP2_ERR_NOMEM:
          return NGHQ_OUT_OF_MEMORY;
        case NGTCP2_ERR_NOBUF:
        case NGTCP2_ERR_CALLBACK_FAILURE:
          return NGHQ_INTERNAL_ERROR;
        case NGTCP2_ERR_INVALID_STATE:
          return NGHQ_SESSION_CLOSED;
        case NGTCP2_ERR_PKT_NUM_EXHAUSTED:
          return NGHQ_TRANSPORT_PROTOCOL;
        default:
          return NGHQ_ERROR;
      }
    }
    nghq_io_buf_new(&session->send_buf, closebuf, rv, 1, 0);
  }

  return NGHQ_OK;
}

static void _clean_up_streams (nghq_session *session, nghq_map_ctx *strm_ctx) {
  if (strm_ctx != NULL) {
    nghq_stream *stream = nghq_stream_id_map_iterator(strm_ctx, NULL);
    while (stream != NULL) {
      uint64_t stream_id = stream->stream_id;
      nghq_stream_ended(session, stream);
      stream = nghq_stream_id_map_remove (strm_ctx, stream_id);
    }
    nghq_stream_id_map_destroy (strm_ctx);
  }
}

int nghq_session_free (nghq_session *session) {
  _clean_up_streams (session, session->transfers);
  _clean_up_streams (session, session->promises);
  nghq_free_hdr_compression_ctx (session->hdr_ctx);
  nghq_io_buf_clear (&session->send_buf);
  nghq_io_buf_clear (&session->recv_buf);
  ngtcp2_conn_del (session->ngtcp2_session);
  free (session);
  return NGHQ_OK;
}

#define BUFFER_READ_SIZE 4096

int nghq_session_recv (nghq_session *session) {
  int recv = 1;
  int rv = NGHQ_NO_MORE_DATA;

  while (recv) {
    uint8_t* buf;
    size_t buflen;

    buf = (uint8_t *) malloc (BUFFER_READ_SIZE);
    if (buf == NULL) {
      recv = 0;
      rv = NGHQ_OUT_OF_MEMORY;
      break;
    }

    buflen = BUFFER_READ_SIZE;

    ssize_t socket_rv = session->callbacks.recv_callback(session, buf, buflen,
                                                   session->session_user_data);
    if (socket_rv < 0) {
      free (buf);
      /* errors */
      if (socket_rv == NGHQ_EOF) {
        return NGHQ_SESSION_CLOSED;
      }
      return NGHQ_ERROR;
    } else if (socket_rv == 0) {
      free (buf);
      /* no more data to read */
      recv = 0;
    } else {
      nghq_io_buf_new(&session->recv_buf, buf, (size_t) socket_rv, 0, 0);
    }
  }

  while (session->recv_buf != NULL) {
    rv = ngtcp2_conn_recv(session->ngtcp2_session, session->recv_buf->buf,
                           session->recv_buf->buf_len, get_timestamp_now());

    free (session->recv_buf->buf);
    nghq_io_buf *pop = session->recv_buf;
    session->recv_buf = session->recv_buf->next_buf;
    free (pop);

    if (rv != 0) {
      ERROR("ngtcp2_conn_recv returned error %s\n", ngtcp2_strerror(rv));
      if (rv == NGTCP2_ERR_TLS_DECRYPT) {
        return NGHQ_CRYPTO_ERROR;
      }
      return NGHQ_ERROR;
    }

    _update_timers(session);

    rv = NGHQ_OK;

    if (ngtcp2_conn_in_draining_period(session->ngtcp2_session)) {
      return NGHQ_SESSION_CLOSED;
    }
  }

  return rv;
}

/* TODO: Make this more scalable? Copied from client.cc in ngtcp2 examples */
#define MAX_BYTES_IN_FLIGHT 1460 * 10

int nghq_session_send (nghq_session *session) {
  int rv = NGHQ_NO_MORE_DATA;
  if (ngtcp2_conn_bytes_in_flight(session->ngtcp2_session) >=
      MAX_BYTES_IN_FLIGHT) {
    if (rv == NGHQ_NO_MORE_DATA) {
      DEBUG("Too many bytes in flight, session blocked\n");
      return NGHQ_SESSION_BLOCKED;
    }
  }
  rv = nghq_write_send_buffer (session);

  /*
   * Go through all the streams and grab any packets that need sending
   *
   * TODO: This won't work particularly well when there's a lot of streams
   * running at once - it'll always send data from the lower streams even if
   * there's a lot of data waiting on higher number streams - change the list
   * of frames waiting to be sent into an all-streams structure?
   */
  nghq_stream *it = nghq_stream_id_map_find(session->transfers, 0);
  while ((rv != NGHQ_ERROR) && (rv != NGHQ_EOF)) {
    if (ngtcp2_conn_bytes_in_flight(session->ngtcp2_session) >=
        MAX_BYTES_IN_FLIGHT) {
      if (rv == NGHQ_NO_MORE_DATA) {
        return NGHQ_SESSION_BLOCKED;
      }
      break;
    }

    while (it->send_buf == NULL) {
      it = nghq_stream_id_map_iterator(session->transfers, it);
      if (it == NULL) {
        DEBUG("No more data to be sent on any streams\n");
        return rv;
      }
    }

    DEBUG("Got data to send for stream %lu\n", it->stream_id);

    size_t sent = 0;

    nghq_io_buf *new_pkt = (nghq_io_buf *) malloc (sizeof(nghq_io_buf));
    new_pkt->buf = (uint8_t *) malloc(
        session->transport_settings.max_packet_size);
    new_pkt->buf_len = session->transport_settings.max_packet_size;

    uint8_t last_data = (uint8_t) it->send_buf->complete;
    uint8_t *buffer = it->send_buf->send_pos;
    uint8_t free_buffer = 0;
    size_t buf_len = it->send_buf->remaining;
    nghq_io_buf *next_buf = it->send_buf->next_buf;
    while (buf_len < (session->transport_settings.max_packet_size -
                      MIN_STREAM_PACKET_OVERHEAD) &&
           next_buf) {
      /* pack data with next stream buffer(s) */
      if (free_buffer) {
        buffer = realloc(buffer, buf_len + next_buf->remaining);
      } else {
        buffer = (uint8_t*) malloc (buf_len + next_buf->remaining);
        memcpy (buffer, it->send_buf->send_pos, it->send_buf->remaining);
      }
      memcpy (buffer + buf_len, next_buf->send_pos, next_buf->remaining);
      buf_len += next_buf->remaining;
      last_data |= (uint8_t) next_buf->complete;
      free_buffer = 1;
      next_buf = next_buf->next_buf;
    }

    ssize_t pkt_len = ngtcp2_conn_write_stream(session->ngtcp2_session,
                                               new_pkt->buf, new_pkt->buf_len,
                                               &sent, it->stream_id,
                                               last_data, buffer, buf_len,
                                               get_timestamp_now());

    if (free_buffer) free(buffer);

    if (pkt_len < 0) {
      switch (pkt_len) {
        case NGTCP2_ERR_EARLY_DATA_REJECTED:
        case NGTCP2_ERR_STREAM_DATA_BLOCKED:
        case NGTCP2_ERR_STREAM_SHUT_WR:
        case NGTCP2_ERR_STREAM_NOT_FOUND:
          free(new_pkt->buf);
          free(new_pkt);
          return 0;
      }
      ERROR("ngtcp2_conn_write_stream failed: %s\n", ngtcp2_strerror((int) pkt_len));
      rv = NGHQ_TRANSPORT_ERROR;
      break;
    } else if (pkt_len > 0) {
      /* delete any whole buffers sent */
      while (it->send_buf && sent >= it->send_buf->remaining) {
        DEBUG("Sent buffer of size %lu on stream %lu\n",
              it->send_buf->buf_len, it->stream_id);
        sent -= it->send_buf->remaining;
        nghq_io_buf_pop(&it->send_buf);
      }
      if (sent > 0) {
        if (!it->send_buf) {
          ERROR("Somehow sent more than was available in the buffer!");
          free(new_pkt->buf);
          free(new_pkt);
          return NGHQ_INTERNAL_ERROR;
        }
        it->send_buf->send_pos += sent;
        it->send_buf->remaining -= sent;
        DEBUG("%lu bytes remaining of buffer to send on stream %lu\n",
              it->send_buf->remaining, it->stream_id);
        it->send_buf->complete = last_data;
        last_data = 0;
      }
    } else {
      free(new_pkt->buf);
      free(new_pkt);
      return NGHQ_SESSION_BLOCKED;
    }

    new_pkt->buf_len = pkt_len;
    new_pkt->complete = last_data;

    nghq_io_buf_push(&session->send_buf, new_pkt);

    _update_timers(session);

    rv = nghq_write_send_buffer (session);

    if (last_data) {
      nghq_stream* to_del;
      DEBUG("Ending stream %lu\n", it->stream_id);
      if (session->callbacks.on_request_close_callback != NULL) {
        session->callbacks.on_request_close_callback(session, it->status,
                                                     it->user_data);
      }
      it->send_state = STATE_DONE;
      //to_del = it;
      //it = nghq_stream_id_map_remove (session->transfers, it->stream_id);
      //nghq_stream_ended(session, to_del);
      if (it == NULL) {
        break;
      }
    }
  }

  return rv;
}

static int _transport_params_initial_size = 128;

ssize_t nghq_get_transport_params (nghq_session *session, uint8_t **buf) {
  ngtcp2_transport_params params;
  ngtcp2_transport_params_type param_type;
  ssize_t actual_size;

  if (session == NULL) {
    return NGHQ_SESSION_CLOSED;
  }

  if (session->role == NGHQ_ROLE_CLIENT) {
    param_type = NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO;
  } else if (session->role == NGHQ_ROLE_SERVER) {
    param_type = NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS;
  }

  ngtcp2_conn_get_local_transport_params(session->ngtcp2_session, &params,
                                         param_type);

  if (session->mode == NGHQ_MODE_MULTICAST) {
    params.initial_max_stream_id_uni = 0x3fffffff;
    params.initial_max_stream_id_bidi = 4;
  }

  *buf = (uint8_t *) malloc (_transport_params_initial_size);
  if (*buf == NULL) {
    return NGHQ_OUT_OF_MEMORY;
  }

  actual_size = ngtcp2_encode_transport_params(*buf,
                                               _transport_params_initial_size,
                                               param_type, &params);

  while (actual_size == NGTCP2_ERR_NOBUF) {
    if (_transport_params_initial_size == 512) {
      free (*buf);
      return NGHQ_INTERNAL_ERROR;
    }
    _transport_params_initial_size *= 2;
    *buf = (uint8_t *) realloc (*buf, _transport_params_initial_size);
    if (*buf == NULL) {
      return NGHQ_OUT_OF_MEMORY;
    }
    actual_size = ngtcp2_encode_transport_params(*buf,
                                                 _transport_params_initial_size,
                                                 param_type, &params);
  }

  *buf = (uint8_t *) realloc (*buf, actual_size);

  return actual_size;
}

int nghq_feed_transport_params (nghq_session *session, const uint8_t *buf,
                                size_t buflen) {
  int rv = NGTCP2_ERR_FATAL;
  ngtcp2_transport_params params;
  ngtcp2_transport_params_type param_type;

  if (session == NULL) {
    return NGHQ_SESSION_CLOSED;
  }

  if (session->role == NGHQ_ROLE_SERVER) {
    param_type = NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO;
  } else if (session->role == NGHQ_ROLE_CLIENT) {
    param_type = NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS;
  }

  rv = ngtcp2_decode_transport_params(&params, param_type, buf, buflen);

  if (rv != 0) {
    ERROR("ngtcp2_decode_transport_params failed: %s\n", ngtcp2_strerror(rv));
    return NGHQ_TRANSPORT_PROTOCOL;
  }

  DEBUG("Multicast transport parameters from \"remote\" set as:\n"
        "\tversion: %x\n\tinitial_max_stream_data: %u\n"
        "\tinitial_max_data: %u\n\tinitial_max_stream_id_bidi: %u\n"
        "\tinitial_max_stream_id_uni: %u\n\tidle_timeout: %u\n"
        "\tomit_connection_id: %u\n\tmax_packet_size: %u\n"
        "\tack_delay_exponent: %u\n",
        (session->role==NGHQ_ROLE_SERVER)?(params.v.ch.initial_version):(params.v.ee.negotiated_version),
        params.initial_max_stream_data, params.initial_max_data,
        params.initial_max_stream_id_bidi, params.initial_max_stream_id_uni,
        params.idle_timeout, params.omit_connection_id,
        params.max_packet_size, params.ack_delay_exponent);

  if (session->mode == NGHQ_MODE_MULTICAST) {
    params.initial_max_stream_id_bidi = 0xfffffffc;
  }
  rv = ngtcp2_conn_set_remote_transport_params(session->ngtcp2_session,
                                               param_type, &params);
  if (rv != 0) {
    ERROR("ngtcp2_conn_set_remote_transport_params failed: %s\n",
          ngtcp2_strerror(rv));
    switch (rv) {
      case NGTCP2_ERR_PROTO:
        return NGHQ_TRANSPORT_PROTOCOL;
      case NGTCP2_ERR_INVALID_ARGUMENT:
        return NGHQ_INTERNAL_ERROR;
      case NGTCP2_ERR_VERSION_NEGOTIATION:
        return NGHQ_TRANSPORT_VERSION;
    }
  }

  return NGHQ_OK;
}

int nghq_submit_request (nghq_session *session, const nghq_header **hdrs,
                         size_t num_hdrs, const uint8_t *req_body, size_t len,
                         int final, void *request_user_data) {
  int rv;
  nghq_stream *new_stream;

  if (session == NULL) {
    return NGHQ_ERROR;
  }

  if (session->role != NGHQ_ROLE_CLIENT) {
    return NGHQ_CLIENT_ONLY;
  }

  if (session->mode == NGHQ_MODE_MULTICAST) {
    /* For multicast just make stream 4 use the request_user_data passed in */
    new_stream = nghq_stream_id_map_find (session->transfers, 4);
    if (new_stream) new_stream->user_data = request_user_data;
    return NGHQ_OK;
  }

  if (session->max_open_requests <=
      nghq_stream_id_map_num_requests(session->transfers)) {
    return NGHQ_TOO_MANY_REQUESTS;
  }

  new_stream = nghq_req_stream_new(session);
  if (new_stream == NULL) {
    return NGHQ_OUT_OF_MEMORY;
  }
  new_stream->user_data = request_user_data;

  rv = nghq_feed_headers (session, hdrs, num_hdrs, 0,
                          request_user_data);
  if (rv != NGHQ_OK) {
    nghq_stream_id_map_remove (session->transfers, new_stream->stream_id);
    nghq_stream_ended (session, new_stream);
    return rv;
  }

  if (len > 0) {
    return (int)nghq_feed_payload_data(session, req_body, len, 0,
                                       request_user_data);
  }

  if (final) {
    nghq_stream_id_map_remove (session->transfers, new_stream->stream_id);
    nghq_stream_ended (session, new_stream);
  }

  return rv;
}

int nghq_submit_push_promise (nghq_session *session,
                              void * init_request_user_data,
                              const nghq_header **hdrs, size_t num_hdrs,
                              void *promised_request_user_data) {
  int rv;
  uint64_t init_request_stream_id;

  if (session == NULL) {
    return NGHQ_ERROR;
  }

  if (session->role != NGHQ_ROLE_SERVER) {
    return NGHQ_SERVER_ONLY;
  }

  if (session->next_push_promise >= session->max_push_promise) {
    return NGHQ_PUSH_LIMIT_REACHED;
  }

  /*
   * Push promises must be associated with a stream ID - in multicast mode we
   * fake this as Stream 4.
   */
  if (session->mode == NGHQ_MODE_MULTICAST) {
    init_request_stream_id = 4;
  } else {
    init_request_stream_id =
        nghq_stream_id_map_search(session->transfers, init_request_user_data);
    if (init_request_stream_id == NGHQ_STREAM_ID_MAP_NOT_FOUND) {
      return NGHQ_ERROR;
    }
  }

  uint8_t* push_promise_buf = NULL;
  size_t push_promise_len = 0;

  DEBUG("Creating new push promise %lu with %lu headers\n",
        session->next_push_promise, num_hdrs);

  rv = create_push_promise_frame(session->hdr_ctx, session->next_push_promise,
                                 hdrs, num_hdrs, &push_promise_buf,
                                 &push_promise_len);

  DEBUG("Push promise frame length: %lx\n", push_promise_len);

  if (rv < 0) {
    goto push_promise_frame_err;
  }

  nghq_stream *promised_stream = nghq_stream_init();
  if (promised_stream == NULL) {
    ERROR("Couldn't allocate new stream");
    rv = NGHQ_OUT_OF_MEMORY;
    goto push_promise_frame_err;
  }

  promised_stream->push_id = session->next_push_promise++;
  promised_stream->user_data = promised_request_user_data;

  nghq_stream_id_map_add (session->promises, promised_stream->push_id,
                          promised_stream);

  nghq_stream *init_stream = nghq_stream_id_map_find(session->transfers,
                                                     init_request_stream_id);
  rv = nghq_io_buf_new(&init_stream->send_buf, push_promise_buf,
                       push_promise_len, 0, 0);
  if (rv < 0) {
    ERROR("Couldn't add push promise buffer to send buffer\n");
    goto push_promise_io_err;
  }

  return NGHQ_OK;

push_promise_io_err:
  nghq_stream_id_map_remove(session->promises, promised_stream->push_id);
  nghq_stream_ended(session, promised_stream);
push_promise_frame_err:
  free (push_promise_buf);

  return rv;
}

int nghq_set_request_user_data(nghq_session *session, void * current_user_data,
                               void * new_user_data) {
  nghq_stream *stream = nghq_stream_id_map_stream_search(session->transfers,
                                                         current_user_data);
  if (stream == NULL) {
    stream = nghq_stream_id_map_stream_search(session->promises,
                                              current_user_data);
    if (stream == NULL) {
      return NGHQ_BAD_USER_DATA;
    }
    DEBUG("Setting request user data for push promise %lu\n", stream->push_id);
  } else {
    DEBUG("Setting request user data for request %lu\n", stream->stream_id);
  }

  stream->user_data = new_user_data;
  return NGHQ_OK;
}

int nghq_set_session_user_data(nghq_session *session, void * current_user_data,
                               void * new_user_data) {
  if (current_user_data != session->session_user_data) {
    return NGHQ_BAD_USER_DATA;
  }
  session->session_user_data = new_user_data;
  return NGHQ_OK;
}

int nghq_feed_headers (nghq_session *session, const nghq_header **hdrs,
                       size_t num_hdrs, int final, void *request_user_data) {
  uint8_t* buf;
  size_t buf_len;
  nghq_stream* stream;
  uint64_t stream_id;
  int rv;

  if (session == NULL) {
    return NGHQ_ERROR;
  }

  stream_id = nghq_stream_id_map_search(session->transfers, request_user_data);

  if (stream_id == NGHQ_STREAM_ID_MAP_NOT_FOUND) {
    uint64_t push_id = nghq_stream_id_map_search(session->promises,
                                                 request_user_data);
    if (push_id == NGHQ_STREAM_ID_MAP_NOT_FOUND) {
      /* Bad user data */
      return NGHQ_ERROR;
    }
    DEBUG("Feeding %lu headers for push promise %lu\n", num_hdrs, push_id);
    /* Start of a server push, so open a new unidirectional stream */
    if (session->max_open_server_pushes <=
        nghq_stream_id_map_num_pushes(session->transfers)) {
      return NGHQ_TOO_MANY_REQUESTS;
    }

    stream = nghq_stream_id_map_find(session->promises, push_id);

    ngtcp2_conn_open_uni_stream(session->ngtcp2_session, &stream_id,
                                (void *) stream);

    stream->stream_id = stream_id;
    stream->send_state = STATE_HDRS;

    DEBUG("Push promise %lu will be sent on stream ID %lu\n", push_id,
          stream_id);

    rv = create_headers_frame (session->hdr_ctx, (int64_t) push_id, hdrs,
                               num_hdrs, &buf, &buf_len);
    if (rv < 0) {
      return rv;
    } else {
      rv = NGHQ_OK;
    }

    nghq_stream_id_map_add(session->transfers, stream_id, stream);
    nghq_stream_id_map_remove(session->promises, push_id);
  } else {
    DEBUG("Feeding %lu headers on stream ID %lu\n", num_hdrs, stream_id);
    stream = nghq_stream_id_map_find(session->transfers, stream_id);
    switch (stream->send_state) {
      case STATE_OPEN:
        stream->send_state = STATE_HDRS;
        break;
      case STATE_HDRS:
        break;
      case STATE_BODY:
        if (STREAM_TRAILERS_PROMISED(stream->flags)) {
          stream->send_state = STATE_TRAILERS;
        } else {
          return NGHQ_TRAILERS_NOT_PROMISED;
        }
        break;
      case STATE_TRAILERS:
        break;
      default:
        ERROR("Tried to send headers for stream %lu when it is closed!\n",
              stream->stream_id);
        return NGHQ_REQUEST_CLOSED;
    }
    rv = create_headers_frame (session->hdr_ctx, -1, hdrs, num_hdrs, &buf,
                               &buf_len);

    if (rv < 0) {
      return rv;
    } else {
      rv = NGHQ_OK;
    }
  }

  nghq_io_buf_new(&stream->send_buf, buf, buf_len, final, 0);

  return rv;
}

ssize_t nghq_feed_payload_data(nghq_session *session, const uint8_t *buf,
                               size_t len, int final, void *request_user_data) {
  nghq_io_buf* frame;
  uint64_t stream_id;
  nghq_stream* stream;
  ssize_t rv;

  if (session == NULL) {
    return NGHQ_ERROR;
  }

  stream_id = nghq_stream_id_map_search(session->transfers, request_user_data);

  DEBUG("Feeding %s%lu bytes of payload data for stream ID %lu\n", (final?"final ":""), len, stream_id);

  if (stream_id == NGHQ_STREAM_ID_MAP_NOT_FOUND) {
    return NGHQ_ERROR;
  }

  stream = nghq_stream_id_map_find(session->transfers, stream_id);

  if (stream->send_state > STATE_BODY) {
    return NGHQ_REQUEST_CLOSED;
  }
  stream->send_state = STATE_BODY;

  frame = (nghq_io_buf *) calloc (1, sizeof(nghq_io_buf));

  rv = create_data_frame (buf, len, &frame->buf, &frame->buf_len);
  frame->complete = (final)?(1):(0);
  frame->send_pos = frame->buf;
  frame->remaining = frame->buf_len;

  nghq_io_buf_push(&stream->send_buf, frame);

  return rv;
}

int nghq_end_request (nghq_session *session, nghq_error result,
                      void *request_user_data) {
  nghq_stream* stream = nghq_stream_id_map_stream_search (session->transfers,
                                                          request_user_data);
  if (stream == NULL) {
    uint8_t* buf;
    size_t buflen;
    int rv;
    stream = nghq_stream_id_map_stream_search (session->promises,
                                               request_user_data);
    if (stream == NULL) {
      return NGHQ_REQUEST_CLOSED;
    }
    /* Send a CANCEL_PUSH frame! */
    rv = create_cancel_push_frame (stream->push_id, &buf, &buflen);
    if (rv != NGHQ_OK) {
      return rv;
    }

    if (session->role == NGHQ_ROLE_CLIENT) {
      return nghq_queue_send_frame(session, NGHQ_CONTROL_CLIENT, buf, buflen);
    } else { /* NGHQ_ROLE_SERVER */
      return nghq_queue_send_frame(session, NGHQ_CONTROL_SERVER, buf, buflen);
    }
  }
  return nghq_stream_cancel(session, stream, 0);
}

uint64_t nghq_get_max_client_requests (nghq_session *session) {
  return session->max_open_requests;
}

int nghq_set_max_client_requests (nghq_session *session, uint64_t max_requests){
  return NGHQ_OK;
}

uint64_t nghq_get_max_pushed (nghq_session *session) {
  return session->max_open_server_pushes;
}

int nghq_set_max_pushed(nghq_session *session, uint64_t max_pushed) {
  return NGHQ_OK;
}

uint64_t nghq_get_max_promises (nghq_session *session) {
  return session->max_push_promise - session->next_push_promise;
}

int nghq_set_max_promises (nghq_session* session, uint64_t max_push) {
  uint8_t* buf;
  size_t buflen;
  int rv;

  if (session->role != NGHQ_ROLE_CLIENT) {
    return NGHQ_CLIENT_ONLY;
  }
  if ((session->next_push_promise + max_push) < session->max_push_promise) {
    return NGHQ_INVALID_PUSH_LIMIT;
  }

  session->max_push_promise = session->next_push_promise + max_push;

  rv = create_max_push_id_frame (session->max_push_promise, &buf, &buflen);
  if (rv != NGHQ_OK) {
    return rv;
  }

  rv = nghq_queue_send_frame(session, NGHQ_CONTROL_CLIENT, buf, buflen);

  return rv;
}

/*
 * Private
 */

static int _trim_and_append (nghq_io_buf *buf, const uint8_t *data,
                             size_t datalen) {
  if (buf->send_pos == buf->buf) {
    /* no data processed, just append the new data */
    errno = 0;
    buf->buf = realloc (buf->buf, buf->buf_len + datalen);
    if (errno == ENOMEM) {
      return 0;
    }
    memcpy (buf->buf + buf->buf_len, data, datalen);
    buf->buf_len += datalen;
    buf->remaining = buf->buf_len;
    buf->send_pos = buf->buf;
  } else {
    /* some data already processed, so we can forget it */
    /* copy what's left and append new data */
    uint8_t *new_buf = malloc (buf->remaining + datalen);
    if (new_buf == NULL) {
      return 0;
    }
    memcpy (new_buf, buf->send_pos, buf->remaining);
    memcpy (new_buf + buf->remaining, data, datalen);
    free (buf->buf);
    buf->buf = new_buf;
    buf->send_pos = buf->buf;
    buf->offset += buf->buf_len - buf->remaining;
    buf->remaining += datalen;
    buf->buf_len = buf->remaining;
  }
  return 1;
}

static int _nghq_insert_recv_stream_data (nghq_stream* stream,
                                          const uint8_t* data, size_t datalen,
                                          size_t off, uint8_t eos) {
  uint8_t *buf;
  nghq_io_buf **pbuf = &stream->recv_buf;

  /* find pointer to buffer adjacent or after this data */
  while (*pbuf && (*pbuf)->offset + (*pbuf)->buf_len < off) {
    pbuf = &((*pbuf)->next_buf);
  }

  if (*pbuf == NULL || (*pbuf)->offset > off) {
    nghq_io_buf *next = *pbuf;
    *pbuf = NULL;
    /* insert new buffer */
    buf = malloc (datalen);
    if (buf == NULL) {
      return NGHQ_OUT_OF_MEMORY;
    }
    nghq_io_buf_new(pbuf, buf, datalen, eos, off);
    (*pbuf)->next_buf = next;
    memcpy (buf, data, datalen);
  } else {
    /* new data adjacent or overlapping this buffer */
    size_t end_overlap = ((*pbuf)->offset + (*pbuf)->buf_len) - off;
    if (end_overlap >= datalen) {
      /* total overlap, ignore buffer */
      return NGHQ_OK;
    }
    data += end_overlap;
    datalen -= end_overlap;
    if (!_trim_and_append((*pbuf), data, datalen)) {
      return NGHQ_OUT_OF_MEMORY;
    }
    /* mark buffer as containing the end of the stream if eos set */
    (*pbuf)->complete |= eos;
  }

  /* merge buffer with next if overlapping or adjacent */
  nghq_io_buf **next = &((*pbuf)->next_buf);
  if (*next != NULL && (*next)->offset <= (*pbuf)->offset + (*pbuf)->buf_len) {
    size_t overlap = (*pbuf)->offset + (*pbuf)->buf_len - (*next)->offset;
    if (!_trim_and_append((*pbuf), (*next)->buf + overlap, (*next)->buf_len - overlap)) {
      return NGHQ_OUT_OF_MEMORY;
    }
    (*pbuf)->complete |= (*next)->complete;
    nghq_io_buf_pop (next);
  }

  return NGHQ_OK;
}

int _nghq_stream_headers_frame (nghq_session* session, nghq_stream* stream,
                                nghq_stream_frame *frame) {
  nghq_header** hdrs = NULL;
  size_t num_hdrs;
  size_t to_process;
  switch (stream->recv_state) {
    case STATE_OPEN:
      stream->recv_state = STATE_HDRS;
      break;
    case STATE_HDRS:
      break;
    case STATE_BODY:
      stream->recv_state = STATE_TRAILERS;
    case STATE_TRAILERS:
      break;
    default:
      ERROR("Received HEADERS for stream %lu, but receive state is done!\n",
            stream->stream_id);
      return NGHQ_REQUEST_CLOSED;
  }
  to_process = parse_headers_frame (session->hdr_ctx, frame->data, &hdrs,
                                    &num_hdrs);

  if (hdrs != NULL) {
    int rv;
    uint8_t flags = 0;

    if (STREAM_STARTED(stream->flags)) {
      if (session->callbacks.on_begin_headers_callback) {
        rv = session->callbacks.on_begin_headers_callback(session,
                                                  session->session_user_data,
                                                  stream->user_data);
        if (rv != NGHQ_OK) {
          return rv;
        }
      }
    }

    if (stream->recv_state > STATE_HDRS) {
      flags += NGHQ_HEADERS_FLAGS_TRAILERS;
    }

    rv = nghq_deliver_headers (session, flags, hdrs, num_hdrs,
                               stream->user_data);
    if (rv != 0) {
      return rv;
    }
  }

  return NGHQ_OK;
}

static int _nghq_stream_priority_frame (nghq_session* session,
                                        nghq_stream* stream,
                                        nghq_stream_frame *frame) {
  uint8_t flags;
  uint64_t request_id;
  uint64_t dependency_id;
  uint8_t weight;

  if ((stream->stream_id != NGHQ_CONTROL_CLIENT) &&
      (stream->stream_id != NGHQ_CONTROL_SERVER)) {
    return NGHQ_HTTP_WRONG_STREAM;
  } else if ((stream->stream_id == NGHQ_CONTROL_CLIENT) &&
             (session->role == NGHQ_ROLE_CLIENT)) {
    return NGHQ_HTTP_WRONG_STREAM;
  } else if ((stream->stream_id == NGHQ_CONTROL_SERVER) &&
             (session->role == NGHQ_ROLE_SERVER)) {
    return NGHQ_HTTP_WRONG_STREAM;
  }

  parse_priority_frame (frame->data, &flags, &request_id, &dependency_id,
                              &weight);

  DEBUG("TODO: Process priority frames\n");

  return NGHQ_OK;
}

static int _nghq_stream_cancel_push_frame (nghq_session* session,
                                           nghq_stream* stream,
                                           nghq_stream_frame *frame) {
  uint64_t push_id;

  parse_cancel_push_frame (frame->data, &push_id);

  nghq_stream_id_map_remove(session->promises, push_id);

  return NGHQ_OK;
}

static int _nghq_stream_settings_frame (nghq_session* session,
                                        nghq_stream* stream,
                                        nghq_stream_frame *frame) {
  nghq_settings *new_settings;

  parse_settings_frame (frame->data, &new_settings);

  /* err... TODO? */
  if (new_settings != NULL) free (new_settings);

  return NGHQ_OK;
}

static bool _hdr_field_is_value(nghq_header** hdrs, size_t num_hdrs,
                                       const char *field, const char *value)
{
  size_t field_len = strlen(field);
  size_t value_len = strlen(value);
  for (size_t i = 0; i < num_hdrs; i++) {
    if (hdrs[i]->name_len == field_len &&
        hdrs[i]->value_len == value_len &&
        memcmp(hdrs[i]->name, field, field_len) == 0 &&
        memcmp(hdrs[i]->value, value, value_len) == 0) {
      return true;
    }
  }
  return false;
}

static void _free_headers(nghq_header **hdrs, size_t num_hdrs)
{
  int i;
  for (i = 0; i < num_hdrs; i++) {
    free (hdrs[i]->name);
    free (hdrs[i]->value);
    free (hdrs[i]);
  }
  free (hdrs);
}

static int _nghq_stream_push_promise_frame (nghq_session* session,
                                            nghq_stream* stream,
                                            nghq_stream_frame *frame) {
  nghq_header** hdrs = NULL;
  size_t num_hdrs;
  size_t to_process;
  uint64_t push_id;

  if (stream->recv_state == STATE_DONE) {
    return NGHQ_REQUEST_CLOSED;
  }

  to_process = parse_push_promise_frame (session->hdr_ctx,
                                         frame->data, &push_id,
                                         &hdrs, &num_hdrs);

  if (push_id > session->max_push_promise) {
    return NGHQ_HTTP_MALFORMED_FRAME;
  }

  if (hdrs != NULL) {
    if (session->role == NGHQ_ROLE_CLIENT &&
        session->mode == NGHQ_MODE_MULTICAST &&
        _hdr_field_is_value(hdrs, num_hdrs, ":path", "goaway") &&
        _hdr_field_is_value(hdrs, num_hdrs, "connection", "close")) {
      /* multicast goaway detected - close the session */
      nghq_session_close(session, NGHQ_OK);
      /* flush subsequent packets from receive queue */
      nghq_io_buf_clear(&session->recv_buf->next_buf);
      _free_headers(hdrs, num_hdrs);
      return NGHQ_OK;
    }
  }

  nghq_stream* new_promised_stream = nghq_stream_init();
  new_promised_stream->push_id = push_id;
  new_promised_stream->user_data = &new_promised_stream->push_id;
  nghq_stream_id_map_add(session->promises, push_id, new_promised_stream);

  if (hdrs != NULL) {
    int rv;

    if (session->callbacks.on_begin_promise_callback) {
      rv = session->callbacks.on_begin_promise_callback(session,
                            session->session_user_data, stream->user_data,
                            new_promised_stream->user_data);
      if (rv != NGHQ_OK) {
        _free_headers(hdrs, num_hdrs);
        return rv;
      }
    } else {
      _free_headers(hdrs, num_hdrs);
      return NGHQ_NOT_INTERESTED;
    }
    new_promised_stream->recv_state = STATE_HDRS;

    rv = nghq_deliver_headers (session, 0, hdrs, num_hdrs,
                               new_promised_stream->user_data);
    if (rv != NGHQ_OK) {
      return rv;
    }
  }

  return NGHQ_OK;
}

static int _nghq_stream_goaway_frame (nghq_session* session,
                                      nghq_stream* stream,
                                      nghq_stream_frame *frame) {
  uint64_t last_stream_id;

  parse_goaway_frame (frame->data, &last_stream_id);

  return NGHQ_OK;
}

static int _nghq_stream_max_push_id_frame (nghq_session* session,
                                           nghq_stream* stream,
                                           nghq_stream_frame *frame) {
  uint64_t max_push_id;

  parse_max_push_id_frame (frame->data, &max_push_id);

  /* TODO: If this is invalid, send an error to remote peer */
  if (session->role != NGHQ_ROLE_SERVER) {
    return NGHQ_HTTP_MALFORMED_FRAME;
  }

  if (session->max_push_promise > max_push_id) {
    return NGHQ_HTTP_MALFORMED_FRAME;
  }

  session->max_push_promise = max_push_id;

  return NGHQ_OK;
}

static int _nghq_stream_recv_data_at (nghq_stream* stream, size_t offset,
                                      nghq_io_buf *outbuf) {
  nghq_io_buf **pb = &stream->recv_buf;
  while (*pb) {
    if ((*pb)->offset <= offset && (*pb)->offset + (*pb)->buf_len > offset) {
      outbuf->buf = (*pb)->buf + (offset - (*pb)->offset);
      outbuf->buf_len = (*pb)->buf_len - (offset - (*pb)->offset);
      outbuf->send_pos = outbuf->buf;
      outbuf->remaining = outbuf->buf_len;
      outbuf->offset = offset;
      outbuf->complete = (*pb)->complete;
      return 1;
    }
    pb = &(*pb)->next_buf;
  }
  return 0;
}

static void _nghq_stream_recv_pop_data (nghq_stream* stream, size_t offset,
                                        size_t len) {
  nghq_io_buf **pb = &stream->recv_buf;
  while (*pb) {
    if ((*pb)->offset <= offset && (*pb)->offset + (*pb)->buf_len > offset) {
      if ((*pb)->send_pos = (*pb)->buf + (offset - (*pb)->offset)) {
        (*pb)->send_pos += len;
        (*pb)->remaining -= len;
      } else if ((*pb)->send_pos + (*pb)->remaining ==
                 (*pb)->buf + (offset - (*pb)->offset) + len) {
        (*pb)->remaining -= len;
      } else {
        // area to remove is in the middle of the buffer, split it
        size_t first_len = (offset - (*pb)->offset);
        size_t second_len = (((*pb)->send_pos - (*pb)->buf) + (*pb)->remaining)
                                - ((offset - (*pb)->offset) + len);
        if (first_len < second_len) {
          // make first part the new buffer as it's smaller
          nghq_io_buf *tmp = NULL;
          nghq_io_buf_new (&tmp, (*pb)->send_pos, first_len, 0,
                           (*pb)->offset + ((*pb)->send_pos - (*pb)->buf));
          (*pb)->send_pos = (*pb)->buf + (offset - (*pb)->offset) + len;
          (*pb)->remaining = second_len;
          tmp->next_buf = *pb;
          *pb = tmp;
        } else {
          nghq_io_buf *tmp = NULL;
          nghq_io_buf_new (&tmp, (*pb)->buf + (offset - (*pb)->offset) + len,
                           second_len, (*pb)->complete, offset + len);
          (*pb)->remaining = first_len;
          tmp->next_buf = (*pb)->next_buf;
          (*pb)->next_buf = tmp;
        }
      }
      if ((*pb)->remaining == 0) {
        nghq_io_buf_pop(pb);
      }
      break;
    }
    pb = &(*pb)->next_buf;
  }

  if (*pb && (*pb)->remaining == 0) {
    nghq_io_buf_pop (pb);
  }
}

static int _nghq_stream_frame_add (nghq_stream* stream,
                                   nghq_frame_type frame_type,
                                   size_t frame_size, size_t offset,
                                   nghq_io_buf *data) {
  nghq_stream_frame **pf;
  nghq_stream_frame *f =
                    (nghq_stream_frame*) calloc (1, sizeof(nghq_stream_frame));
  uint8_t *buf = NULL;
  int complete = 0;
  f->frame_type = frame_type;
  if (frame_type != NGHQ_FRAME_TYPE_DATA) {
    buf = (uint8_t*) malloc (frame_size);
    if (!buf) return NGHQ_OUT_OF_MEMORY;
  } else {
    uint8_t *bodydata = NULL;
    size_t datalen = 0;
    ssize_t to_process = parse_data_frame (data, &bodydata, &datalen);
    size_t hdr_len = frame_size - datalen;
    f->end_header_offset = offset + hdr_len;
    f->data_offset_adjust = f->end_header_offset - stream->data_frames_total;
    stream->data_frames_total += datalen;
  }
  if (data->complete && frame_size == data->buf_len) complete=1;
  nghq_io_buf_new (&f->data, buf, frame_size, complete, offset);
  f->gaps = (nghq_gap*) calloc (1, sizeof(nghq_gap));
  if (!f->gaps) {
    nghq_io_buf_clear (&f->data);
    return NGHQ_OUT_OF_MEMORY;
  }
  f->gaps->end = frame_size;

  // Append frame to active stream frames
  for (pf = &stream->active_frames; *pf; pf = &(*pf)->next);
  *pf = f;

  return NGHQ_OK;
}

static void _remove_gap (nghq_gap **list, size_t begin, size_t end) {
  nghq_gap **pg = list;
  while (*pg && (*pg)->end <= begin) pg = &(*pg)->next;
  if (*pg && ((*pg)->begin < end || (*pg)->end > begin)) {
    // split/truncate/delete entry
    if ((*pg)->begin < begin && (*pg)->end > end) {
      // split
      nghq_gap *new_gap = (nghq_gap*) malloc (sizeof(nghq_gap));
      new_gap->begin = end;
      new_gap->end = (*pg)->end;
      (*pg)->end = begin;
      new_gap->next = (*pg)->next;
      (*pg)->next = new_gap;
    } else {
      // truncate/delete
      if ((*pg)->begin >= begin) {
        (*pg)->begin = end;
      }
      if ((*pg)->end <= end) {
        (*pg)->end = begin;
      }
      if ((*pg)->end <= (*pg)->begin) {
        nghq_gap *to_del = *pg;
        *pg = (*pg)->next;
        free (to_del);
      }
    }
  }
}

static size_t _frame_add_data(nghq_stream_frame *frame, nghq_io_buf *data) {
  size_t copy_offset = (data->offset - frame->data->offset);
  size_t copy_len = data->buf_len;
  int complete = data->complete;

  if (copy_len > frame->data->buf_len - copy_offset) {
    copy_len = frame->data->buf_len - copy_offset;
    /* not including the last bytes of data, so this is not complete */
    complete = 0;
  }

  if (frame->data->buf) {
    // Only copy data if frame has a buffer to put it in
    memcpy (frame->data->buf + copy_offset, data->buf, copy_len);
  }

  frame->data->complete |= complete;

  _remove_gap(&frame->gaps, copy_offset, copy_offset + copy_len);

  return copy_len;
}

static int _frame_contains_stream_range (nghq_stream_frame *frame, size_t offset, size_t datalen, size_t *frame_data_offset) {
  size_t end_offset = offset + datalen;
  if (frame->data->offset < end_offset &&
      frame->data->offset + frame->data->buf_len > offset) {
    // frame overlaps data, find first offset within frame
    if (offset > frame->data->offset) {
      *frame_data_offset = offset;
    } else {
      *frame_data_offset = frame->data->offset;
    }
    return 1;
  }
  return 0;
}

static void _frame_free (nghq_stream_frame *frame) {
  for (nghq_gap **pg = &frame->gaps; *pg;) {
    nghq_gap *to_del = *pg;
    *pg = (*pg)->next;
    free (to_del);
  }

  nghq_io_buf_clear (&frame->data);

  free (frame);
}

int nghq_recv_stream_data (nghq_session* session, nghq_stream* stream,
                           const uint8_t* data, size_t datalen, size_t off,
                           uint8_t end_of_stream) {
  nghq_io_buf frame_data;
  nghq_frame_type frame_type;

  if (!STREAM_STARTED(stream->flags)) {
    return NGHQ_REQUEST_CLOSED;
  }

  _nghq_insert_recv_stream_data(stream, data, datalen, off, end_of_stream);

  // Add new frames
  while (_nghq_stream_recv_data_at(stream, stream->next_recv_offset,
                                   &frame_data) > 0) {
    if (SERVER_PUSH_STREAM(stream->stream_id) &&
        stream->next_recv_offset == 0) {
      size_t push_off = 0;
      uint64_t push_id = _get_varlen_int(frame_data.buf, &push_off,
                                         frame_data.buf_len);
      if (push_off > frame_data.buf_len) {
        ERROR("Not enough data for push ID in stream %lu\n", stream->stream_id);
        return NGHQ_ERROR;
      }
      stream->next_recv_offset = push_off;
      _nghq_stream_recv_pop_data(stream, 0, push_off);
      continue;
    }

    ssize_t size = parse_frame_header (&frame_data, &frame_type);

    if (size > 0) {
      _nghq_stream_frame_add(stream, frame_type, size, frame_data.offset, &frame_data);
      stream->next_recv_offset += size;
    } else {
      break;
    }
  }

  // Populate the active frames with unused data that fits
  for (nghq_io_buf **pb = &stream->recv_buf; *pb; ) {
    int data_modified = 0;
    int block_frame_processing = 0;
    off = (*pb)->offset + ((*pb)->send_pos - (*pb)->buf);
    if (off > stream->next_recv_offset) break;
    datalen = (*pb)->remaining;
    for (nghq_stream_frame **pf = &stream->active_frames; *pf; ) {
      size_t frame_data_offset = 0;
      if (_frame_contains_stream_range(*pf, off, datalen, &frame_data_offset)) {
        _nghq_stream_recv_data_at(stream, frame_data_offset, &frame_data);
        size_t used = _frame_add_data(*pf, &frame_data);
        if ((*pf)->frame_type == NGHQ_FRAME_TYPE_DATA) {
          uint8_t *data = frame_data.buf;
          size_t data_offset;
          size_t data_used = used;
          size_t hdr_bytes = 0;
          int last_data = (*pf)->data->complete;

          if (stream->recv_state == STATE_OPEN) {
            // headers frame not seen yet, hang onto data for now
            continue;
          }

          if (stream->recv_state == STATE_HDRS) {
            stream->recv_state = STATE_BODY;
          }

          if (frame_data_offset < (*pf)->end_header_offset) {
            // first block of body frame, skip header
            hdr_bytes = (*pf)->end_header_offset - frame_data_offset;
          }
          data_used -= hdr_bytes;
          data += hdr_bytes;
          data_offset = frame_data_offset + hdr_bytes - (*pf)->data_offset_adjust;
          // send data immediately - not stored in DATA frames
          session->callbacks.on_data_recv_callback(session,
                                         last_data?NGHQ_DATA_FLAGS_END_DATA:0,
                                         data, data_used, data_offset,
                                         stream->user_data);
        }
        _nghq_stream_recv_pop_data(stream, frame_data_offset, used);
        data_modified = 1;
      }

      if (((!block_frame_processing) ||
           (*pf)->frame_type == NGHQ_FRAME_TYPE_DATA) &&
          (*pf)->gaps == NULL) {
        nghq_stream_frame *frame = *pf;
        int rv = NGHQ_OK;
        switch (frame->frame_type) {
          case NGHQ_FRAME_TYPE_DATA:
            // Already dealt with data
            break;
          case NGHQ_FRAME_TYPE_HEADERS:
            rv = _nghq_stream_headers_frame (session, stream, frame);
            break;
          case NGHQ_FRAME_TYPE_PRIORITY:
            rv = _nghq_stream_priority_frame (session, stream, frame);
            break;
          case NGHQ_FRAME_TYPE_CANCEL_PUSH:
            rv = _nghq_stream_cancel_push_frame (session, stream, frame);
            break;
          case NGHQ_FRAME_TYPE_SETTINGS:
            rv = _nghq_stream_settings_frame (session, stream, frame);
            break;
          case NGHQ_FRAME_TYPE_PUSH_PROMISE:
            rv = _nghq_stream_push_promise_frame (session, stream, frame);
            break;
          case NGHQ_FRAME_TYPE_GOAWAY:
            rv = _nghq_stream_goaway_frame (session, stream, frame);
            break;
          case NGHQ_FRAME_TYPE_MAX_PUSH_ID:
            rv = _nghq_stream_max_push_id_frame (session, stream, frame);
            break;
          default:
            /* Unknown frame type! */
            ERROR("Unknown frame type 0x%x\n", frame->frame_type);
            rv = NGHQ_INTERNAL_ERROR;
        }
        *pf = frame->next;
        _frame_free (frame);
        if (rv != NGHQ_OK) {
          return rv;
        }
      } else {
        // frame not complete or blocked from processing
        if ((*pf)->frame_type != NGHQ_FRAME_TYPE_DATA) {
          // If this wasn't a data frame, block the processing of later frames
          block_frame_processing = 1;
        }
        pf = &(*pf)->next;
      }
    }
    if (!data_modified) {
      pb = &(*pb)->next_buf;
    }
  }

  return NGHQ_OK;
}

int nghq_deliver_headers (nghq_session* session, uint8_t flags,
                          nghq_header **hdrs, size_t num_hdrs,
                          void *request_user_data) {
  int i, rv = NGHQ_OK;

  for (i = 0; i < num_hdrs; i++) {
    if (rv == NGHQ_OK) {
      rv = session->callbacks.on_headers_callback(session, flags, hdrs[i],
                                                  request_user_data);
    }
    free (hdrs[i]->name);
    free (hdrs[i]->value);
    free (hdrs[i]);
  }
  free (hdrs);

  return rv;
}

int nghq_queue_send_frame (nghq_session* session, uint64_t stream_id,
                           uint8_t* buf, size_t buflen) {
  int rv = NGHQ_INTERNAL_ERROR;
  nghq_stream *stream = nghq_stream_id_map_find(session->transfers, stream_id);
  if (stream != NULL) {
    nghq_io_buf_new (&stream->send_buf, buf, buflen, 0, 0);
    rv = NGHQ_OK;
  }
  return rv;
}

int nghq_write_send_buffer (nghq_session* session) {
  int rv = NGHQ_NO_MORE_DATA;
  while (session->send_buf != NULL) {
    ssize_t written =
        session->callbacks.send_callback (session, session->send_buf->buf,
                                           session->send_buf->buf_len,
                                           session->session_user_data);

    if (written != session->send_buf->buf_len) {
      if (written == 0) {
        rv = NGHQ_SESSION_BLOCKED;
        break;
      } else if (written == NGHQ_EOF) {
        rv = NGHQ_EOF;
        break;
      }
      rv = NGHQ_ERROR;
      break;
    }

    if (session->mode == NGHQ_MODE_MULTICAST && session->handshake_complete) {
        ngtcp2_pkt_hd hdr;
        ssize_t read = ngtcp2_pkt_decode_hd (&hdr, session->send_buf->buf,
                                             session->send_buf->buf_len);
        if (read > 0) {
          nghq_mcast_fake_ack (session, &hdr);
        }
    }

    free (session->send_buf->buf);
    nghq_io_buf *pop = session->send_buf;
    session->send_buf = session->send_buf->next_buf;
    free (pop);

    rv = NGHQ_OK;
  }
  return rv;
}

/*
 * Call this method if you want to stop a stream that is currently running.
 *
 * If error is non-zero, then it's reported to ngtcp2 that it's closing for
 * an internal error, instead of just closing the stream ID.
 */
int nghq_stream_cancel (nghq_session* session, nghq_stream *stream, int error) {
  uint16_t app_error_code = QUIC_ERR_HTTP_NO_ERROR;
  if (error) {
    app_error_code = QUIC_ERR_HTTP_INTERNAL_ERROR;
  }
  return ngtcp2_conn_shutdown_stream (session->ngtcp2_session,
                                      stream->stream_id, app_error_code);
}

/*
 * Call this if a stream has naturally ended to clean up the stream object
 */
int nghq_stream_ended (nghq_session* session, nghq_stream *stream) {
  if (stream == NULL) return NGHQ_OK;

  nghq_io_buf_clear(&stream->send_buf);
  nghq_io_buf_clear(&stream->recv_buf);

  stream->send_state = STATE_DONE;
  stream->recv_state = STATE_DONE;
  stream->flags ^= STREAM_FLAG_STARTED;

  free (stream);

  return NGHQ_OK;
}

int nghq_stream_close (nghq_session* session, nghq_stream *stream,
                       uint16_t app_error_code) {
  int request_closing = 1, rv = 0;
  nghq_error status = NGHQ_OK;

  DEBUG("Stream %lu is closing with code 0x%04X\n", stream->stream_id,
        app_error_code);

  switch (app_error_code) {
    case QUIC_ERR_STOPPING:
      /* TODO: ngtcp2 currently uses 0 to mean closed nicely, not STOPPING */
      break;
    case QUIC_ERR_HTTP_NO_ERROR:
      /* Shutting down normally */
      break;
    case QUIC_ERR_HTTP_PUSH_REFUSED:
      status = NGHQ_HTTP_PUSH_REFUSED;
      break;
    case QUIC_ERR_HTTP_INTERNAL_ERROR:
      /* Deal with this - remote end is probably going away */
      status = NGHQ_INTERNAL_ERROR;
      break;
    case QUIC_ERR_HTTP_PUSH_ALREADY_IN_CACHE:
      /* Deal with this - call nghq_on_request_close_callback with status
       * NGHQ_HTTP_PUSH_ALREADY_IN_CACHE */
      status = NGHQ_PUSH_ALREADY_IN_CACHE;
      break;
    case QUIC_ERR_HTTP_REQUEST_CANCELLED:
      status = NGHQ_NOT_INTERESTED;
      break;
    case QUIC_ERR_HTTP_HPACK_DECOMPRESSION_FAILED:
      status = NGHQ_HDR_COMPRESS_FAILURE;
      break;
    case QUIC_ERR_HTTP_CONNECT_ERROR:
      status = NGHQ_HTTP_CONNECT_ERROR;
      break;
    case QUIC_ERR_HTTP_EXCESSIVE_LOAD:
      /* TODO: Deal with this */
      break;
    case QUIC_ERR_HTTP_VERSION_FALLBACK:
      status = NGHQ_TRANSPORT_VERSION;
      break;
    case QUIC_ERR_HTTP_WRONG_STREAM:
      status = NGHQ_HTTP_WRONG_STREAM;
      break;
    case QUIC_ERR_HTTP_PUSH_LIMIT_EXCEEDED:
      status = NGHQ_PUSH_LIMIT_REACHED;
      break;
    case QUIC_ERR_HTTP_DUPLICATE_PUSH:
      status = NGHQ_HTTP_DUPLICATE_PUSH;
      break;
    case QUIC_ERR_MALFORMED_DATA_FRAME:
    case QUIC_ERR_MALFORMED_HEADERS_FRAME:
    case QUIC_ERR_MALFORMED_PRIORITY_FRAME:
    case QUIC_ERR_MALFORMED_CANCEL_PUSH_FRAME:
    case QUIC_ERR_MALFORMED_SETTINGS_FRAME:
    case QUIC_ERR_MALFORMED_PUSH_PROMISE_FRAME:
    case QUIC_ERR_MALFORMED_GOAWAY_FRAME:
    case QUIC_ERR_MALFORMED_MAX_PUSH_ID:
      status = NGHQ_HTTP_MALFORMED_FRAME;
      break;
    default:
      ERROR("Unknown HTTP/QUIC Error Code 0x%4X\n", app_error_code);
      status = NGHQ_INTERNAL_ERROR;
  }

  if (request_closing) {
    uint64_t stream_id = stream->stream_id;
    session->callbacks.on_request_close_callback (session, status,
                                                  stream->user_data);
    rv = nghq_stream_ended (session, stream);
    nghq_stream_id_map_remove (session->transfers, stream_id);
  }

  return rv;
}

int nghq_change_max_stream_id (nghq_session* session, uint64_t max_stream_id) {
  return NGHQ_OK;
}

static uint64_t _pkt_num_mask(uint64_t pkt_num) {
  if (pkt_num < 0x100) return UINT64_C(0xff);
  if (pkt_num < 0x10000) return UINT64_C(0xffff);
  return UINT64_C(0xffffffff);
}

static uint64_t _calc_pkt_number (nghq_session* session, uint64_t pkt_num) {
  uint64_t rv = pkt_num;
  if (rv < session->last_remote_pkt_num) {
    uint64_t mask = _pkt_num_mask(pkt_num);
    rv |= session->last_remote_pkt_num & ~mask;
    if (rv < session->last_remote_pkt_num) rv += mask + 1;
  }
  session->last_remote_pkt_num = rv;
  return rv;
}

void nghq_mcast_fake_ack (nghq_session* session, const ngtcp2_pkt_hd *hd) {
  /*
   * Generate a fake ACK to feed back into ngtcp2 to keep it happy that
   * everything sent has been successfully received.
   */
  nghq_io_buf *fake = (nghq_io_buf *) malloc (sizeof(nghq_io_buf));
  if (fake == NULL) {
    return;
  }
  uint64_t real_pkt_num = _calc_pkt_number(session, hd->pkt_num);
  /*
   * Short frame header:
   *    * 1 byte type
   *    * 8 bytes connection ID
   *    * 1 bytes packet number (type = 0x1F)
   *
   * Then one more byte for the Frame type in the payload header type
   */
  uint64_t acklen = 11;
  acklen += _make_varlen_int(NULL, real_pkt_num); /* Largest Acknowledged */
  acklen += _make_varlen_int(NULL, 0);            /* ACK Delay */
  acklen += _make_varlen_int(NULL, 0);            /* ACK Block Count */
  acklen += _make_varlen_int(NULL, 0);            /* First ACK Block */

  fake->buf = (uint8_t *) malloc (acklen);
  if (fake->buf == NULL) {
    free (fake);
    return;
  }

  acklen = 11;
  fake->buf[0] = 0x1f; /* 1 byte packet number */
  put_uint64_in_buf(fake->buf + 1, session->connection_id);
  fake->buf[9] = session->remote_pktnum;
  session->remote_pktnum++;
  fake->buf[10] = NGTCP2_FRAME_ACK;
  acklen += _make_varlen_int(fake->buf + acklen, real_pkt_num);
  acklen += _make_varlen_int(fake->buf + acklen, 0);
  acklen += _make_varlen_int(fake->buf + acklen, 0);
  acklen += _make_varlen_int(fake->buf + acklen, 0);

  fake->buf_len = acklen;

  nghq_io_buf_push (&session->recv_buf, fake);
}

/*
 * This function will swallow any packets that were going to be sent
 * automatically by ngtcp2 before actually sending them, in order to stop
 * banned packets from making it out onto the wire in a multicast session.
 */
int nghq_mcast_swallow (nghq_session* session, const ngtcp2_pkt_hd *hd,
                        const ngtcp2_frame *fr) {
  /* All banned as per draft-pardue-quic-http-mcast Appendix C Table 3 */
  if ((hd->type == NGTCP2_FRAME_APPLICATION_CLOSE) ||
      (hd->type == NGTCP2_FRAME_BLOCKED) ||
      (hd->type == NGTCP2_FRAME_CONNECTION_CLOSE) ||
      (hd->type == NGTCP2_FRAME_MAX_DATA) ||
      (hd->type == NGTCP2_FRAME_MAX_STREAM_DATA) ||
      (hd->type == NGTCP2_FRAME_MAX_STREAM_ID) ||
      ((session->role == NGHQ_ROLE_CLIENT) &&
          (hd->type == NGTCP2_FRAME_PING)) ||
      (hd->type == NGTCP2_FRAME_PONG) ||
      ((session->role == NGHQ_ROLE_CLIENT) &&
          (hd->type == NGTCP2_FRAME_RST_STREAM)) ||
      (hd->type == NGTCP2_FRAME_STREAM_BLOCKED) ||
      (hd->type == NGTCP2_FRAME_STREAM_ID_BLOCKED)) {
    DEBUG("Dropping packet not allowed by quic-http-mcast: %d\n", hd->type);
    return -1;
  }
  if (hd->type == NGTCP2_FRAME_STREAM) {
    DEBUG("Faking ACK for stream %lu", fr->stream.stream_id);
    nghq_mcast_fake_ack(session, hd);
  }
  return 0;
}

nghq_stream *nghq_stream_new (uint64_t stream_id) {
  nghq_stream *stream = nghq_stream_init();
  if (stream == NULL) {
    return NULL;
  }
  stream->stream_id = stream_id;
  return stream;
}

nghq_stream *nghq_req_stream_new(nghq_session* session) {
  int result;
  nghq_stream *stream = nghq_stream_init();
  if (stream == NULL) {
    return NULL;
  }

  result = ngtcp2_conn_open_bidi_stream(session->ngtcp2_session,
                                        &stream->stream_id, stream);

  if (result != 0) {
    ERROR("ngtcp2_conn_open_bidi_stream failed with %s\n",
          ngtcp2_strerror(result));
    free (stream);
    return NULL;
  }

  result = nghq_stream_id_map_add (session->transfers, stream->stream_id,
                                   stream);
  if (result != 0) {
    ERROR("Failed to add new stream %lu to map\n", stream->stream_id);
    ngtcp2_conn_shutdown_stream(session->ngtcp2_session, stream->stream_id,
                                0x01); /* Internal Error code */
    free (stream);
    return NULL;
  }

  return stream;
}

PACKED_STRUCT(alpn_name)
struct alpn_name {
    uint8_t len;
    uint8_t name[];
};
END_PACKED_STRUCT(alpn_name)

static const struct alpn_name * const _draft9_alpn = (const struct alpn_name*)"\x06hqm-03";
static const struct alpn_name *_draft9_alpns[] = {_draft9_alpn, NULL};

static const struct alpn_name **_get_alpn_protocols()
{
#if NGTCP2_PROTO_VER_MAX == NGTCP2_PROTO_VER_D9
    return _draft9_alpns;
#else
    return NULL;
#endif
}

ssize_t nghq_select_alpn (nghq_session *session, const uint8_t *buf,
                          size_t buflen, const uint8_t **proto)
{
    const struct alpn_name **alpn_protocols = _get_alpn_protocols ();

    if (session == NULL || session->role != NGHQ_ROLE_SERVER)
        return (ssize_t) NGHQ_SERVER_ONLY;
    if (alpn_protocols == NULL) return (ssize_t) NGHQ_HTTP_ALPN_FAILED;

    for (size_t idx = 0; idx < buflen; idx += buf[idx]+1) {
        for (size_t i = 0; alpn_protocols[i] != NULL; i++) {
            if (buf[idx] != alpn_protocols[i]->len) continue;
            if (memcmp (buf+idx+1, alpn_protocols[i]->name,
                        alpn_protocols[i]->len) != 0)
                continue;
            if (proto != NULL) *proto = buf+idx+1;
            return (ssize_t) (alpn_protocols[i]->len);
        }
    }
    return (ssize_t) NGHQ_HTTP_ALPN_FAILED;
}

ssize_t nghq_get_alpn (const uint8_t **alpn)
{
    const struct alpn_name **alpn_protocols = _get_alpn_protocols ();
    static size_t total_len = 0;
    static uint8_t *alpns = NULL;

    if (alpn_protocols == NULL) return (ssize_t) NGHQ_HTTP_ALPN_FAILED;

    if (total_len == 0U || alpns == NULL) {
        total_len = 0U;
        for (size_t i = 0; alpn_protocols[i] != NULL; i++) {
            total_len += alpn_protocols[i]->len + 1;
        }
        alpns = (uint8_t*) realloc (alpns, total_len);
        size_t idx = 0;
        for (size_t i = 0; alpn_protocols[i] != NULL; i++) {
            memcpy (alpns+idx, alpn_protocols[i], alpn_protocols[i]->len + 1);
            idx += alpn_protocols[i]->len + 1;
        }
    }

    if (alpn != NULL) *alpn = alpns;
    return (ssize_t)total_len;
}


// vim:ts=8:sts=2:sw=2:expandtab:
