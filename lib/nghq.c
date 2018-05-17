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

#include "debug.h"

nghq_stream * nghq_stream_init() {
  nghq_stream *stream = (nghq_stream *) malloc (sizeof(nghq_stream));
  if (stream == NULL) {
    return NULL;
  }
  stream->push_id = NGHQ_STREAM_ID_MAP_NOT_FOUND;
  stream->stream_id = NGHQ_STREAM_ID_MAP_NOT_FOUND;
  stream->send_buf = NULL;
  stream->recv_buf = NULL;
  stream->buf_idx = 0;
  stream->tx_offset = 0;
  stream->headers_off = 0;
  stream->body_off = 0;
  stream->user_data = (void *) &stream->stream_id; /*Guaranteed to be unique!*/
  stream->priority = 0;
  stream->recv_state = STATE_OPEN;
  stream->send_state = STATE_OPEN;
  stream->status = NGHQ_OK;
  stream->flags = STREAM_FLAG_STARTED;
  return stream;
}

nghq_session * _nghq_session_new_common(const nghq_callbacks *callbacks,
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
  session->max_open_requests = transport->max_open_requests * 4;
  session->max_open_server_pushes = (transport->max_open_server_pushes * 4) + 3;
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

  return session;
}

int _nghq_start_session(nghq_session *session, const nghq_transport_settings *t) {
  if (session->mode == NGHQ_MODE_MULTICAST) {
    DEBUG("Starting a new multicast session\n");
    /* Just set defaults and return */
    session->highest_bidi_stream_id = 4;
    session->highest_uni_stream_id = NGHQ_MULTICAST_MAX_UNI_STREAM_ID;
    session->max_push_promise = NGHQ_MULTICAST_MAX_UNI_STREAM_ID;
    return NGHQ_OK;
  }
  DEBUG("Starting a new unicast session\n");
  session->highest_bidi_stream_id = t->max_open_requests * 4;
  session->highest_uni_stream_id = (t->max_open_server_pushes * 4) + 3;
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
    nghq_transport_send_client_initial,
    nghq_transport_send_client_handshake,
    NULL,
    NULL,
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

  srand(time(NULL));
  uint64_t init_conn_id = rand64();

  ngtcp2_settings tcp2_settings;
  tcp2_settings.initial_ts = get_timestamp_now();
  tcp2_settings.log_printf = nghq_transport_debug;
  tcp2_settings.max_stream_data = 256 * 1024;
  tcp2_settings.max_data = 1 * 1024 * 1024;
  tcp2_settings.max_stream_id_bidi = session->max_open_requests;
  tcp2_settings.max_stream_id_uni = session->max_open_server_pushes;
  tcp2_settings.idle_timeout = transport->idle_timeout;
  tcp2_settings.omit_connection_id = 0;
  tcp2_settings.max_packet_size = NGTCP2_MAX_PKT_SIZE;
  tcp2_settings.ack_delay_exponent = NGTCP2_DEFAULT_ACK_DELAY_EXPONENT;

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
    nghq_io_buf_new(&session->send_buf, buf, 64, 0);
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
        session->connection_id, 1, &fake_server_handshake);
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
  tcp2_settings.max_stream_data = 256 * 1024;
  tcp2_settings.max_data = 1 * 1024 * 1024;
  tcp2_settings.max_stream_id_bidi = session->max_open_requests;
  tcp2_settings.max_stream_id_uni = session->max_open_server_pushes;
  tcp2_settings.idle_timeout = transport->idle_timeout;
  tcp2_settings.omit_connection_id = 0;
  tcp2_settings.max_packet_size = NGTCP2_MAX_PKT_SIZE;
  tcp2_settings.ack_delay_exponent = NGTCP2_DEFAULT_ACK_DELAY_EXPONENT;

  uint64_t conn_id = 1;

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
                                                      0, &in_buf);
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
    nghq_io_buf_new(&stream0->send_buf, out_buf, encoded_params_size, 0);
    result = 1;
    result = ngtcp2_conn_handshake(session->ngtcp2_session, out_buf, 128,
                                   in_buf, len_client_init,
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
    size_t len_strm4_pkt = get_fake_client_stream_4_packet (session->connection_id,
                                                            2, &strm4pkt);
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

  /* Close any running streams - iterate from first non-0 stream */
  it = nghq_stream_id_map_find(session->transfers, 0);
  it = nghq_stream_id_map_iterator(session->transfers, it);
  if (session->mode == NGHQ_MODE_MULTICAST) {
    if (session->role == NGHQ_ROLE_SERVER) {
      nghq_stream* stream4 = nghq_stream_id_map_find (session->transfers, 4);
      if (stream4 != NULL) {
        /* https://tools.ietf.org/html/draft-pardue-quic-http-mcast-02#section-5.5 */
#define MAKE_HEADER(key, field, value) \
        static const char key##_field[] = field; \
        static const char key##_value[] = value; \
        static const nghq_header key = {(uint8_t *) key##_field, sizeof(key##_field)-1, (uint8_t *) key##_value, sizeof(key##_value)-1};
	MAKE_HEADER(req_method, ":method", "GET");
	MAKE_HEADER(req_path, ":path", "goaway");
	MAKE_HEADER(req_connection, "Connection", "close");
        static const nghq_header *req[] = {
            &req_method, &req_path, &req_connection
        };
	MAKE_HEADER(resp_status, ":status", "200");
	MAKE_HEADER(resp_connection, "Connection", "close");
        static const nghq_header *resp[] = {
            &resp_status, &resp_connection
        };
#undef MAKE_HEADER
        nghq_submit_push_promise(session, stream4->user_data, req,
                                 sizeof(req)/sizeof(req[0]),
                                 (void *) stream4);
        nghq_feed_headers (session, resp, sizeof(resp)/sizeof(resp[0]), 1,
                           (void *) stream4);
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
    nghq_io_buf_new(&session->send_buf, closebuf, rv, 1);
  }

  return NGHQ_OK;
}

void _clean_up_streams (nghq_session *session, nghq_map_ctx *strm_ctx) {
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
      nghq_io_buf_new(&session->recv_buf, buf, (size_t) socket_rv, 0);
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
    ssize_t pkt_len = ngtcp2_conn_write_stream(session->ngtcp2_session,
                                               new_pkt->buf, new_pkt->buf_len,
                                               &sent, it->stream_id,
                                               last_data,
                                               it->send_buf->send_pos,
                                               it->send_buf->remaining,
                                               get_timestamp_now());

    if (sent < 0) {
      switch (sent) {
        case NGTCP2_ERR_EARLY_DATA_REJECTED:
        case NGTCP2_ERR_STREAM_DATA_BLOCKED:
        case NGTCP2_ERR_STREAM_SHUT_WR:
        case NGTCP2_ERR_STREAM_NOT_FOUND:
          return 0;
      }
      ERROR("ngtcp2_conn_write_stream failed: %s\n", ngtcp2_strerror((int) sent));
      rv = NGHQ_TRANSPORT_ERROR;
      break;
    } else if (sent > 0) {
      if (sent == it->send_buf->remaining) {
        DEBUG("Sent buffer of size %lu on stream %lu\n", it->send_buf->buf_len,
              it->stream_id);
        nghq_io_buf_pop(&it->send_buf);
      } else if (sent > it->send_buf->remaining) {
        ERROR("Somehow sent more than was available in the buffer!");
        return NGHQ_INTERNAL_ERROR;
      } else {
        it->send_buf->send_pos += sent;
        it->send_buf->remaining -= sent;
        DEBUG("%lu bytes remaining of buffer to send on stream %lu\n",
              it->send_buf->remaining, it->stream_id);
        /*
         * If the final bit is set but we still have data to send, unset it!
         */
        if (new_pkt->buf[0] & 0x01) {
          DEBUG("Having to unset the final bit in the frame header!\n");
          new_pkt->buf[0] |= 0xFE;
        }
        last_data = 0;
      }
    }

    new_pkt->buf_len = pkt_len;

    nghq_io_buf_push(&session->send_buf, new_pkt);

    rv = nghq_write_send_buffer (session);

    if (last_data) {
      nghq_stream* to_del;
      DEBUG("Ending stream %lu\n", it->stream_id);
      if (session->callbacks.on_request_close_callback != NULL) {
        session->callbacks.on_request_close_callback(session, it->status,
                                                     it->user_data);
      }
      it->send_state = STATE_DONE;
      to_del = it;
      it = nghq_stream_id_map_remove (session->transfers, it->stream_id);
      nghq_stream_ended(session, to_del);
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

  if (session->max_open_requests <=
      nghq_stream_id_map_num_requests(session->transfers)) {
    return NGHQ_TOO_MANY_REQUESTS;
  }

  new_stream = nghq_stream_init();
  if (new_stream == NULL) {
    return NGHQ_OUT_OF_MEMORY;
  }
  new_stream->user_data = request_user_data;

  rv = ngtcp2_conn_open_bidi_stream(session->ngtcp2_session,
                                    &new_stream->stream_id, (void*) new_stream);

  if (rv != 0) {
    if (rv == NGTCP2_ERR_NOMEM) {
      return NGHQ_OUT_OF_MEMORY;
    } else if (rv == NGTCP2_ERR_STREAM_ID_BLOCKED) {
      return NGHQ_TOO_MANY_REQUESTS;
    }
  }

  rv = nghq_feed_headers (session, hdrs, num_hdrs, final, request_user_data);
  if (rv != NGHQ_OK) {
    free (new_stream);
    return rv;
  }
  nghq_stream_id_map_add(session->transfers, new_stream->stream_id, new_stream);
  if (len > 0) {
    return (int)nghq_feed_payload_data(session, req_body, len, final,
                                       request_user_data);
  }

  if (final) {
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

  uint8_t* push_promise_buf;
  size_t push_promise_len;

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
                       push_promise_len, 0);
  if (rv < 0) {
    ERROR("Couldn't add push promise buffer to send buffer\n");
    goto push_promise_io_err;
  }

  return NGHQ_OK;

push_promise_io_err:
  nghq_stream_id_map_remove(session->promises, promised_stream->push_id);
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
    }
  }

  nghq_io_buf_new(&stream->send_buf, buf, buf_len, final);

  if (final) {
    nghq_stream_ended (session, stream);
  }

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

  DEBUG("Feeding %lu bytes of payload data for stream ID %lu\n", len, stream_id);

  if (stream_id == NGHQ_STREAM_ID_MAP_NOT_FOUND) {
    return NGHQ_ERROR;
  }

  stream = nghq_stream_id_map_find(session->transfers, stream_id);

  if (stream->send_state > STATE_BODY) {
    return NGHQ_REQUEST_CLOSED;
  }
  stream->send_state = STATE_BODY;

  frame = (nghq_io_buf *) malloc (sizeof(nghq_io_buf));

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

int nghq_recv_stream_data (nghq_session* session, nghq_stream* stream,
                           const uint8_t* data, size_t datalen, size_t off) {
  if (!STREAM_STARTED(stream->flags)) {
    return NGHQ_REQUEST_CLOSED;
  }

  if (stream->recv_buf == NULL) {
    uint8_t *buf = malloc (datalen);
    if (buf == NULL) {
      return NGHQ_OUT_OF_MEMORY;
    }
    nghq_io_buf_new(&stream->recv_buf, buf, 0, 0);
  } else {
    errno = 0;
    stream->recv_buf->buf = (uint8_t *)
        realloc(stream->recv_buf->buf, stream->recv_buf->buf_len + datalen);
    if (errno == ENOMEM) {
      return NGHQ_OUT_OF_MEMORY;
    }
  }

  memcpy(stream->recv_buf->buf + stream->recv_buf->buf_len, data, datalen);
  stream->recv_buf->buf_len += datalen;

  nghq_frame_type frame_type;
  if (SERVER_PUSH_STREAM(stream->stream_id)) {

  }
  /*
   * Size is the size of the first frame in the queue to be processed for this
   * stream.
   */
  ssize_t size = parse_frames (stream->recv_buf->buf,
                               stream->recv_buf->buf_len, &frame_type);
  ssize_t to_process = 0;

  switch (frame_type) {
    case NGHQ_FRAME_TYPE_DATA: {
      uint8_t* outbuf = NULL;
      size_t outbuflen = 0;
      size_t offset = off - stream->headers_off - stream->body_off;

      switch (stream->recv_state) {
        case STATE_OPEN:
          DEBUG("Warning: DATA frame seen before any HEADERS for stream %lu\n",
                stream->stream_id);
        case STATE_HDRS:
          stream->recv_state = STATE_BODY;
        case STATE_BODY:
          break;
        default:
          ERROR("Received DATA for stream %lu after the end of the body\n",
                stream->stream_id);
          return NGHQ_REQUEST_CLOSED;
      }

      to_process = parse_data_frame (stream->recv_buf->buf,
                                     stream->recv_buf->buf_len, &outbuf,
                                     &outbuflen);

      if (outbuf != NULL) {
        session->callbacks.on_data_recv_callback(session, 0, outbuf,
                                                 outbuflen, offset,
                                                 stream->user_data);
        stream->body_off += (stream->recv_buf->buf_len - outbuflen);
      }
      break;
    }
    case NGHQ_FRAME_TYPE_HEADERS: {
      nghq_header** hdrs = NULL;
      size_t num_hdrs;
      switch (stream->recv_state) {
        case STATE_OPEN:
          session->callbacks.on_begin_headers_callback(session,
                                                       NGHQ_HT_HEADERS,
                                                       session->session_user_data,
                                                       stream->user_data);
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
      to_process = parse_headers_frame (session->hdr_ctx,
                                        stream->recv_buf->buf,
                                        stream->recv_buf->buf_len, &hdrs,
                                        &num_hdrs);

      if (hdrs != NULL) {
        int rv;
        uint8_t flags = 0;

        if (STREAM_STARTED(stream->flags)) {
          rv = session->callbacks.on_begin_headers_callback(session,
                    NGHQ_HT_HEADERS, session->session_user_data,
                    stream->user_data);
          if (rv != NGHQ_OK) {
            return rv;
          }
        }

        if (stream->recv_state >= STATE_HDRS) {
          flags += NGHQ_HEADERS_FLAGS_TRAILERS;
        }

        rv = nghq_deliver_headers (session, flags, hdrs, num_hdrs,
                                   stream->user_data);
        if (rv != 0) {
          return rv;
        }

        stream->headers_off = off;
      }
      break;
    }
    case NGHQ_FRAME_TYPE_PRIORITY: {
      /* TODO */
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

      parse_priority_frame (stream->recv_buf->buf, stream->recv_buf->buf_len,
                            &flags, &request_id, &dependency_id, &weight);

      DEBUG("TODO: Process priority frames\n");

      break;
    }
    case NGHQ_FRAME_TYPE_CANCEL_PUSH: {
      uint64_t push_id;
      parse_cancel_push_frame (stream->recv_buf->buf,
                               stream->recv_buf->buf_len, &push_id);

      nghq_stream_id_map_remove(session->promises, push_id);

      break;
    }
    case NGHQ_FRAME_TYPE_SETTINGS: {
      nghq_settings *new_settings;

      parse_settings_frame (stream->recv_buf->buf, stream->recv_buf->buf_len,
                            &new_settings);

      /* err... TODO? */
      free (new_settings);
      size = 0;
      break;
    }
    case NGHQ_FRAME_TYPE_PUSH_PROMISE: {
      nghq_header** hdrs = NULL;
      size_t num_hdrs;
      uint64_t push_id;

      if (stream->recv_state == STATE_DONE) {
        return NGHQ_REQUEST_CLOSED;
      }

      to_process = parse_push_promise_frame (session->hdr_ctx,
                                             stream->recv_buf->buf,
                                             stream->recv_buf->buf_len,
                                             &push_id, &hdrs, &num_hdrs);

      if (push_id > session->max_push_promise) {
        return NGHQ_HTTP_MALFORMED_FRAME;
      }

      if (to_process < stream->recv_buf->buf_len) {
        nghq_stream* new_promised_stream = nghq_stream_init();
        new_promised_stream->push_id = push_id;
        new_promised_stream->user_data = &new_promised_stream->push_id;
        nghq_stream_id_map_add(session->promises, push_id,
                               new_promised_stream);
        if (hdrs != NULL) {
          int rv;

          rv = session->callbacks.on_begin_headers_callback(session,
                    NGHQ_HT_PUSH_PROMISE, session->session_user_data,
                    new_promised_stream->user_data);
          if (rv != NGHQ_OK) {
            return rv;
          }
          new_promised_stream->recv_state = STATE_HDRS;

          rv = nghq_deliver_headers (session, 0, hdrs, num_hdrs,
                                     new_promised_stream->user_data);
          if (rv != NGHQ_OK) {
            return rv;
          }
        }
      }

      break;
    }
    case NGHQ_FRAME_TYPE_GOAWAY: {
      /* TODO */
      uint64_t last_stream_id;

      parse_goaway_frame (stream->recv_buf->buf, stream->recv_buf->buf_len,
                          &last_stream_id);
      break;
    }
    case NGHQ_FRAME_TYPE_MAX_PUSH_ID: {
      uint64_t max_push_id;

      parse_max_push_id_frame (stream->recv_buf->buf,
                               stream->recv_buf->buf_len, &max_push_id);

      /* TODO: If this is invalid, send an error to remote peer */
      if (session->role != NGHQ_ROLE_SERVER) {
        return NGHQ_HTTP_MALFORMED_FRAME;
      }

      if (session->max_push_promise > max_push_id) {
        return NGHQ_HTTP_MALFORMED_FRAME;
      }

      session->max_push_promise = max_push_id;

      break;
    }
    default:
      /* Unknown frame type! */
      ERROR("Unknown frame type 0x%x\n", frame_type);
      return NGHQ_INTERNAL_ERROR;
  }

  if (to_process == 0) {
    if (size == stream->recv_buf->buf_len) {
      nghq_io_buf_pop (&stream->recv_buf);
    }
    else if (size < stream->recv_buf->buf_len) {
      /* Shorten the buffer in order to pick up the next frame */
      size_t left = stream->recv_buf->buf_len - size;
      uint8_t* tmp = (uint8_t *) malloc (left);
      if (tmp == NULL) {
        return NGHQ_OUT_OF_MEMORY;
      }
      memcpy (tmp, stream->recv_buf->buf + size, left);
      free (stream->recv_buf->buf);
      stream->recv_buf->buf = tmp;
    }
  } else if (to_process < 0) {
    return to_process;
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
    nghq_io_buf_new (&stream->send_buf, buf, buflen, 0);
    rv = NGHQ_OK;
  }
  return rv;
}

int nghq_write_send_buffer (nghq_session* session) {
  int rv = NGHQ_SESSION_BLOCKED;
  while (session->send_buf != NULL) {
    ssize_t written =
        session->callbacks.send_callback (session, session->send_buf->buf,
                                           session->send_buf->buf_len,
                                           session->session_user_data);

    if (written != session->send_buf->buf_len) {
      if (written == 0) {
        break;
      } else if (written == NGHQ_EOF) {
        rv = NGHQ_EOF;
        break;
      }
      rv = NGHQ_ERROR;
      break;
    }

    free (session->send_buf->buf);
    nghq_io_buf *pop = session->send_buf;
    session->send_buf = session->send_buf->next_buf;
    free (pop);
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
  while (stream->send_buf != NULL) {
    nghq_io_buf_pop(&stream->send_buf);
  }

  while (stream->recv_buf != NULL) {
    nghq_io_buf_pop(&stream->recv_buf);
  }

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
    session->callbacks.on_request_close_callback (session, status,
                                                  stream->user_data);
    rv = nghq_stream_ended (session, stream);
  }

  return rv;
}

int nghq_change_max_stream_id (nghq_session* session, uint64_t max_stream_id) {
  return NGHQ_OK;
}

void nghq_mcast_fake_ack (nghq_session* session, const ngtcp2_pkt_hd *hd) {
  /*
   * Generate a fake ACK to feed back into ngtcp2 to keep it happy that
   * everything sent has been successfully received.
   */
  nghq_io_buf *fake = (nghq_io_buf *) malloc (sizeof(nghq_io_buf *));
  if (fake == NULL) {
    return;
  }
  uint64_t acklen = 1;  /* Frame Type is 1 byte at the start (0x0e for ACK) */
  acklen += _make_varlen_int(NULL, hd->pkt_num);  /* Largest Acknowledged */
  acklen += _make_varlen_int(NULL, 0);            /* ACK Delay */
  acklen += _make_varlen_int(NULL, 1);            /* ACK Block Count */
  acklen += _make_varlen_int(NULL, 0);            /* First ACK Block */

  fake->buf = (uint8_t *) malloc (acklen);
  if (fake->buf == NULL) {
    free (fake);
    return;
  }

  acklen = 1;
  fake->buf[0] = NGTCP2_FRAME_ACK;
  acklen += _make_varlen_int(fake->buf + acklen, hd->pkt_num);
  acklen += _make_varlen_int(fake->buf + acklen, 0);
  acklen += _make_varlen_int(fake->buf + acklen, 1);
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

