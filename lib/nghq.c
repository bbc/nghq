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
#include <sys/time.h>

#include "nghq/nghq.h"
#include "nghq_internal.h"
#include "frame_parser.h"
#include "frame_creator.h"
#include "header_compression.h"
#include "map.h"
#include "util.h"
#include "io_buf.h"
#include "lang.h"
#include "quic_transport.h"

#include "debug.h"

#define MIN(a,b) ((a<b)?(a):(b))

/* minimum byte overhead for a stream frame packet                      *
 * (quic pkt header + quic stream frame header + http/quic data header) */
#define MIN_STREAM_PACKET_OVERHEAD 27

static void _check_for_trailers (nghq_stream *stream, const nghq_header **hdrs,
                                 size_t num_hdrs)
{
  static const char trailer_name[] = "trailer";
  size_t i;
  for (i = 0; i < num_hdrs; i++) {
    if (hdrs[i]->name_len == sizeof(trailer_name)-1 &&
        strncasecmp ((const char*)hdrs[i]->name, trailer_name, sizeof(trailer_name)-1) == 0) {
      stream->flags |= STREAM_FLAG_TRAILERS_PROMISED;
    }
  }
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

static void _nghq_stream_timeout (nghq_session *session, void *timer_id,
                                      void *nghq_data)
{
  nghq_stream *stream = (nghq_stream *) nghq_data;
  if (nghq_stream_id_map_find (session->transfers, stream->stream_id) == NULL) {
    NGHQ_LOG_WARN (session, "Received stream timeout for Stream ID %lu that is "
                   "not in our running transfers. Ignoring.\n",
                   stream->stream_id);
    return;
  }
  NGHQ_LOG_DEBUG (session, "Received stream timeout, ending stream %lu with "
                  "outstanding data\n", stream->stream_id);
  nghq_stream_close (session, stream, QUIC_ERR_PACKET_LOSS);
}

static void _nghq_session_timeout (nghq_session *session, void *timer_id,
                                   void *nghq_data)
{
  NGHQ_LOG_DEBUG (session, "Session timeout fired!\n");
  nghq_close_all_streams (session, &session->transfers);
  nghq_close_all_streams (session, &session->promises);
  session->session_timed_out = 1;
}

static nghq_session * _nghq_session_new_common(const nghq_callbacks *callbacks,
                                      const nghq_settings *settings,
                                      const nghq_transport_settings *transport,
                                      void *session_user_data) {
  nghq_session *session = (nghq_session *) calloc (1, sizeof(nghq_session));
  int i;

  if (session == NULL) {
    return NULL;
  }

  if (transport->session_id_len > 20) {
    NGHQ_LOG_ERROR (session, "Session ID size of %u is not allowed\n",
                    transport->session_id_len);
    free (session);
    return NULL;
  }
  session->session_id = (uint8_t *) malloc (transport->session_id_len);
  if (session->session_id == NULL) {
    NGHQ_LOG_ERROR (session, "Couldn't allocate space for a session ID of size "
                    "%u\n", transport->session_id_len);
    free (session);
    return NULL;
  }
  memcpy(session->session_id, transport->session_id, transport->session_id_len);
  session->session_id_len = transport->session_id_len;
  session->mode = transport->mode;
  session->handshake_complete = 0;
  session->max_open_requests = transport->max_open_requests;
  session->max_open_client_uni = 0;
  session->max_open_server_uni = transport->max_open_server_pushes;
  for (i = 0; i < 4; i++) session->next_stream_id[i] = 0;
  session->next_push_promise = 0;
  session->max_push_promise = 0;


  memcpy(&session->callbacks, callbacks, sizeof(nghq_callbacks));
  memcpy(&session->settings, settings, sizeof(nghq_settings));
  memcpy(&session->transport_settings, transport,
         sizeof(nghq_transport_settings));
  session->packet_buf_len =
      transport->max_packet_size - transport->encryption_overhead;

  session->transfers = nghq_stream_id_map_init();
  nghq_open_stream (session, NGHQ_STREAM_CLIENT_BIDI); /* Stream 0 */
  session->promises = nghq_stream_id_map_init();
  session->session_user_data = session_user_data;

  nghq_init_hdr_compression_ctx(&session->hdr_ctx);

  session->send_buf = NULL;
  session->recv_buf = NULL;

  session->tx_pkt_num = 0;
  session->rx_pkt_num = 0;
  session->remote_pktnum = 2;
  session->last_remote_pkt_num = 0;
  session->session_timeout_timer = NULL;
  session->session_timed_out = 0;

  memset (&session->t_params, 0, sizeof(session->t_params));
  session->t_params.idle_timeout = transport->idle_timeout;
  session->t_params.max_packet_size = transport->max_packet_size;
  session->t_params.max_packet_size -= NGHQ_FRAME_OVERHEADS;
  session->t_params.max_packet_size -= session->session_id_len;
  session->t_params.initial_max_data = transport->max_data;
  session->t_params.initial_max_stream_data_bidi_local =
      session->t_params.initial_max_stream_data_bidi_remote =
          session->t_params.initial_max_stream_data_uni =
              transport->max_stream_data;
  session->t_params.initial_max_streams_bidi =
      (int64_t) transport->max_open_requests;
  session->t_params.initial_max_streams_uni =
      (int64_t) transport->max_open_server_pushes;
  session->t_params.ack_delay_exponent = (int64_t) transport->ack_delay_exponent;
  session->t_params.max_ack_delay = 0; //TODO?
  session->t_params.disable_active_migration = true;
  session->t_params.active_connection_id_limit = 0;

  session->log_level = NGHQ_LOG_LEVEL_WARN;
  session->log_cb = NULL;

  gettimeofday(&session->last_recv_ts, NULL);

  return session;
}

static int _nghq_start_session(nghq_session *session,
                               const nghq_transport_settings *t) {
  if (session->mode == NGHQ_MODE_MULTICAST) {
    NGHQ_LOG_DEBUG (session, "Starting a new multicast session\n");
    /* Just set defaults and return */
    session->max_push_promise = NGHQ_MULTICAST_MAX_UNI_STREAM_ID;
    return NGHQ_OK;
  }
  NGHQ_LOG_DEBUG (session, "Starting a new unicast session\n");
  session->max_push_promise = 0;

  return NGHQ_OK;
}

nghq_session * nghq_session_client_new (const nghq_callbacks *callbacks,
                                        const nghq_settings *settings,
                                        const nghq_transport_settings *transport,
                                        void *session_user_data) {
  nghq_session *session = _nghq_session_new_common (callbacks, settings, transport,
                                               session_user_data);
  if (!session) return NULL;

  if (session != NULL) {
    session->role = NGHQ_ROLE_CLIENT;
  }

  if (_nghq_start_session(session, transport) != NGHQ_OK) {
    goto nghq_client_fail_session;
  }

  session->handshake_complete = 1;

  return session;

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
  if (session != NULL) {
    session->role = NGHQ_ROLE_SERVER;
  }

  if (_nghq_start_session(session, transport) != NGHQ_OK) {
    goto nghq_srv_fail_session;
  }

  nghq_open_stream(session, NGHQ_STREAM_SERVER_UNI);
  session->handshake_complete = 1;

  return session;

nghq_srv_fail_session:
  free(session);

  return NULL;
}

int nghq_session_close (nghq_session *session, nghq_error reason) {
  nghq_stream *it = NULL;
  if (session == NULL) {
    return NGHQ_SESSION_CLOSED;
  }

  if (session->mode == NGHQ_MODE_MULTICAST) {
    if (session->role == NGHQ_ROLE_SERVER) {
      nghq_stream* init_req_stream = nghq_stream_id_map_find (
          session->transfers, NGHQ_INIT_REQUEST_STREAM_ID);
      if (init_req_stream != NULL) {
        /* https://tools.ietf.org/html/draft-pardue-quic-http-mcast-05#section-5.5 */
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
        nghq_submit_push_promise(session, init_req_stream->user_data, req,
                                 sizeof(req)/sizeof(req[0]),
                                 (void *) init_req_stream);
        nghq_feed_headers (session, resp, sizeof(resp)/sizeof(resp[0]), 1,
                           (void *) init_req_stream);
      }
    }
  } else {
    /* TODO, should we ever make a unicast version. */
    return NGHQ_NOT_IMPLEMENTED;
  }

  /* Close all running streams */
  for (it = nghq_stream_id_map_iterator(session->transfers, it); it;
       it = nghq_stream_id_map_iterator(session->transfers, it)) {
    nghq_stream_close(session, it, QUIC_ERR_HTTP_REQUEST_CANCELLED);
  }

  return NGHQ_OK;
}

int nghq_session_free (nghq_session *session) {
  nghq_close_all_streams (session, &session->transfers);
  nghq_close_all_streams (session, &session->promises);
  nghq_free_hdr_compression_ctx (session->hdr_ctx);
  nghq_io_buf_clear (&session->send_buf);
  nghq_io_buf_clear (&session->recv_buf);
  if (session->session_id) {
    free (session->session_id);
    session->session_id = NULL;
  }
  free (session);
  return NGHQ_OK;
}

#define BUFFER_READ_SIZE 4096

int nghq_session_recv (nghq_session *session) {
  int recv = 1;
  int rv = NGHQ_NO_MORE_DATA;

  if (nghq_check_timeout(session) == NGHQ_TRANSPORT_TIMEOUT) {
    return NGHQ_TRANSPORT_TIMEOUT;
  }

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
    rv = quic_transport_packet_parse (session, session->recv_buf->buf,
                                      session->recv_buf->buf_len,
                                      get_timestamp_now());
    free (session->recv_buf->buf);
    nghq_io_buf *pop = session->recv_buf;
    session->recv_buf = session->recv_buf->next_buf;
    free (pop);

    if (rv != 0) {
      NGHQ_LOG_ERROR (session, "quic_transport_packet_parse returned %s\n",
                      nghq_strerror(rv));
      return rv;
    }

    rv = NGHQ_OK;
  }

  return rv;
}

int nghq_session_send (nghq_session *session) {
  int rv = NGHQ_NO_MORE_DATA;

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
    size_t packet_len;
    ssize_t res;
    uint64_t pktnum;

    nghq_io_buf *new_pkt = nghq_io_buf_alloc (NULL, session->packet_buf_len, 0,
                                              0);
    if (new_pkt == NULL) {
      return NGHQ_OUT_OF_MEMORY;
    }

    res = quic_transport_write_quic_header (session, new_pkt->buf,
                                            new_pkt->buf_len, &pktnum);
    if (res < NGHQ_OK) return res;
    packet_len = res;

    while (packet_len < new_pkt->buf_len) {
      uint8_t *outbuf = new_pkt->buf + packet_len;
      size_t len_remain = new_pkt->buf_len - packet_len;
      while ((it != NULL) && (it->send_buf == NULL)) {
        it = nghq_stream_id_map_iterator (session->transfers, it);
        while ((it != NULL) && (it->send_state == STATE_DONE) &&
               (it->recv_state == STATE_DONE) && (it->send_buf == NULL) &&
               (it->recv_buf == NULL)) {
          uint64_t stream_id = it->stream_id;
          nghq_stream_ended(session, it);
          it = nghq_stream_id_map_remove (session->transfers, stream_id);
        }
      }

      if (it == NULL) {
        NGHQ_LOG_DEBUG (session, "No more data to be sent on any streams\n");
        break;
      }

      NGHQ_LOG_DEBUG (session, "Got data to send for stream %lu\n",
                      it->stream_id);

      size_t written = 0;
      ssize_t off = quic_transport_write_stream (session, it,
                                                it->send_buf->send_pos,
                                                it->send_buf->remaining,
                                                outbuf, len_remain,
                                                it->send_buf->complete,
                                                &written);

      if (off < NGHQ_OK) {
        if (off != NGHQ_TOO_MUCH_DATA) rv = (int) off;
        break;
      }
      packet_len += off;
      if (written == it->send_buf->remaining) {
        if (it->send_buf->complete) {
          NGHQ_LOG_DEBUG (session, "Ending stream %lu\n", it->stream_id);
          if (session->callbacks.on_request_close_callback != NULL) {
            session->callbacks.on_request_close_callback(session, it->status,
                                                         it->user_data);
          }
          it->send_state = STATE_DONE;
        }
        nghq_io_buf_pop (&it->send_buf);
      } else {
        it->send_buf->send_pos += written;
        it->send_buf->remaining -= written;
      }
    }

    if (packet_len == res) {
      NGHQ_LOG_DEBUG (session, "No packet to be sent\n");
      quic_transport_abandon_packet (session, new_pkt->buf, new_pkt->buf_len,
                                     pktnum);
      free (new_pkt->buf);
      free (new_pkt);
      break;
    }

    new_pkt->buf_len = packet_len;

    nghq_io_buf *enc_pkt = new_pkt;
    if (session->transport_settings.encryption_overhead) {
      size_t enc_pkt_len =
          new_pkt->buf_len + session->transport_settings.encryption_overhead;
      enc_pkt = nghq_io_buf_alloc (NULL, enc_pkt_len, new_pkt->complete, 0);
      if (enc_pkt == NULL) {
        free (new_pkt->buf);
        free (new_pkt);
        return NGHQ_OUT_OF_MEMORY;
      }
    }

    res = quic_transport_encrypt (session, new_pkt->buf, new_pkt->buf_len,
                                  enc_pkt->buf, enc_pkt->buf_len);
    if (res < NGHQ_OK) {
      if (new_pkt != enc_pkt) {
        free (enc_pkt->buf);
        free (enc_pkt);
      }
      free (new_pkt->buf);
      free (new_pkt);
      return res;
    }
    enc_pkt->buf_len = res;

    nghq_io_buf_push(&session->send_buf, enc_pkt);

    if (session->transport_settings.encryption_overhead) {
      free (new_pkt->buf);
      free (new_pkt);
    }
  }

  rv = nghq_write_send_buffer (session);

  return rv;
}

ssize_t nghq_get_transport_params (nghq_session *session, uint8_t **buf) {
  return NGHQ_NOT_IMPLEMENTED;
}

int nghq_feed_transport_params (nghq_session *session, const uint8_t *buf,
                                size_t buflen) {
  return NGHQ_NOT_IMPLEMENTED;
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

  NGHQ_LOG_DEBUG (session, "nghq_submit_push_promise(0x%p, 0x%p, (%lu), 0x%p)\n"
                  , session, init_request_user_data, num_hdrs,
                  promised_request_user_data);

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
   * fake this as Stream 0.
   */
  if (session->mode == NGHQ_MODE_MULTICAST) {
    init_request_stream_id = NGHQ_INIT_REQUEST_STREAM_ID;
  } else {
    init_request_stream_id =
        nghq_stream_id_map_search(session->transfers, init_request_user_data);
    if (init_request_stream_id == NGHQ_STREAM_ID_MAP_NOT_FOUND) {
      return NGHQ_ERROR;
    }
  }

  uint8_t* push_promise_buf = NULL;
  size_t push_promise_len = 0;

  NGHQ_LOG_DEBUG (session, "Creating new push promise %lu with %lu headers\n",
                  session->next_push_promise, num_hdrs);

  rv = create_push_promise_frame(session, session->hdr_ctx,
                                 session->next_push_promise,
                                 hdrs, num_hdrs, &push_promise_buf,
                                 &push_promise_len);

  NGHQ_LOG_DEBUG (session, "Push promise frame length: %lx\n",
                  push_promise_len);

  if (rv < 0) {
    goto push_promise_frame_err;
  }

  nghq_stream *promised_stream = nghq_stream_init();
  if (promised_stream == NULL) {
    NGHQ_LOG_ERROR (session, "Couldn't allocate new stream\n");
    rv = NGHQ_OUT_OF_MEMORY;
    goto push_promise_frame_err;
  }

  promised_stream->push_id = session->next_push_promise++;
  promised_stream->stream_id = NGHQ_INVALID_STREAM_ID;
  promised_stream->user_data = promised_request_user_data;
  promised_stream->recv_state = STATE_DONE;

  nghq_stream_id_map_add (session->promises, promised_stream->push_id,
                          promised_stream);

  nghq_stream *init_stream = nghq_stream_id_map_find(session->transfers,
                                                     init_request_stream_id);
  rv = nghq_io_buf_new(&init_stream->send_buf, push_promise_buf,
                       push_promise_len, 0, 0);
  if (rv < 0) {
    NGHQ_LOG_ERROR (session, "Couldn't add push promise buffer to send buffer\n");
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
    NGHQ_LOG_DEBUG (session, "Setting request user data for push promise %lu\n",
                    stream->push_id);
  } else {
    NGHQ_LOG_DEBUG (session, "Setting request user data for request %lu\n",
                    stream->stream_id);
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
  int64_t stream_id;
  int rv;

  NGHQ_LOG_DEBUG (session, "nghq_feed_headers(0x%p, (%lu), %s, %p)\n", session,
                  num_hdrs, (final)?("final set"):("clear"), request_user_data);

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
    NGHQ_LOG_DEBUG (session, "Feeding %lu headers for push promise %lu\n",
                    num_hdrs, push_id);
    /* Start of a server push, so open a new unidirectional stream */
    int64_t new_stream_id = quic_transport_open_stream(session,
                                                       NGHQ_STREAM_SERVER_UNI);
    if (new_stream_id < NGHQ_OK) {
      NGHQ_LOG_ERROR (session, "Failed to open new stream for push %lu - "
                      "Reason: %ld\n", push_id, new_stream_id);
      return new_stream_id;
    }

    stream = nghq_stream_id_map_find(session->promises, push_id);
    stream->stream_id = new_stream_id;
    stream->send_state = STATE_HDRS;
    stream->user_data = request_user_data;
    _check_for_trailers(stream, hdrs, num_hdrs);

    NGHQ_LOG_INFO (session, "Push promise %lu will be sent on stream ID %lu\n",
                   push_id, new_stream_id);

    rv = create_headers_frame (session, session->hdr_ctx, (int64_t) push_id,
                               hdrs, num_hdrs, &buf, &buf_len);
    if (rv < 0) {
      return rv;
    } else {
      rv = NGHQ_OK;
    }

    nghq_stream_id_map_add(session->transfers, new_stream_id, stream);
    nghq_stream_id_map_remove(session->promises, push_id);
  } else {
    NGHQ_LOG_DEBUG (session, "Feeding %lu headers on stream ID %lu\n", num_hdrs,
                    stream_id);
    stream = nghq_stream_id_map_find(session->transfers, stream_id);
    switch (stream->send_state) {
      case STATE_OPEN:
        _check_for_trailers(stream, hdrs, num_hdrs);
        stream->send_state = STATE_HDRS;
        break;
      case STATE_HDRS:
        _check_for_trailers(stream, hdrs, num_hdrs);
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
        NGHQ_LOG_WARN (session, "Tried to send headers for stream %lu when it "
                       "is closed!\n", stream->stream_id);
        return NGHQ_REQUEST_CLOSED;
    }
    rv = create_headers_frame (session, session->hdr_ctx, -1, hdrs, num_hdrs,
                               &buf, &buf_len);

    if (rv < 0) {
      return rv;
    } else {
      rv = NGHQ_OK;
    }
  }

  nghq_io_buf_new(&stream->send_buf, buf, buf_len, final, 0);

  return rv;
}

int nghq_promise_data (nghq_session *session, size_t len, int final,
                       void *request_user_data) {
  nghq_stream* stream;

  if (session == NULL) {
    return NGHQ_ERROR;
  }

  stream = nghq_stream_id_map_stream_search (session->transfers,
                                             request_user_data);
  if ((stream == NULL) || (stream->send_state > STATE_BODY)) {
    return NGHQ_REQUEST_CLOSED;
  }

  if (stream->long_data_frame_remaining) {
    return NGHQ_TOO_MUCH_DATA;
  }

  stream->long_data_frame_remaining = len;
  stream->flags |= STREAM_FLAG_LONG_DATA_FRAME_REQ;
  if (final) {
    stream->flags |= STREAM_FLAG_LONG_DATA_FRAME_FIN;
  }

  return NGHQ_OK;
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

  NGHQ_LOG_DEBUG (session, "Feeding %s%lu bytes of payload data for stream ID "
                  "%lu\n", (final?"final ":""), len, stream_id);

  if (stream_id == NGHQ_STREAM_ID_MAP_NOT_FOUND) {
    return NGHQ_ERROR;
  }

  stream = nghq_stream_id_map_find(session->transfers, stream_id);

  if (stream->send_state > STATE_BODY) {
    return NGHQ_REQUEST_CLOSED;
  }
  stream->send_state = STATE_BODY;

  frame = (nghq_io_buf *) calloc (1, sizeof(nghq_io_buf));

  if (stream->long_data_frame_remaining) {
    if (STREAM_LONG_DATA_FRAME_REQ(stream->flags)) {
      rv = create_data_frame (session, buf, len,
                              stream->long_data_frame_remaining, &frame->buf,
                              &frame->buf_len);
      stream->flags &= !STREAM_FLAG_LONG_DATA_FRAME_REQ;
    } else {
      size_t chunk_len = len;
      if (chunk_len > stream->long_data_frame_remaining) {
        chunk_len = stream->long_data_frame_remaining;
      }
      frame->buf = malloc (chunk_len);
      if (frame->buf == NULL) {
        return NGHQ_OUT_OF_MEMORY;
      }

      memcpy (frame->buf, buf, chunk_len);
      stream->long_data_frame_remaining -= chunk_len;

      if ((stream->long_data_frame_remaining == 0)
          && STREAM_LONG_DATA_FRAME_FIN(stream->flags)) {
        frame->complete = 1;
      }
    }
  } else {
    rv = create_data_frame (session, buf, len, len, &frame->buf,
                            &frame->buf_len);
    frame->complete = (final)?(1):(0);
  }

  frame->send_pos = frame->buf;
  frame->remaining = frame->buf_len;

  nghq_io_buf_push(&stream->send_buf, frame);

  return rv;
}

int nghq_end_request (nghq_session *session, nghq_error result,
                      void *request_user_data) {
  nghq_stream* stream = nghq_stream_id_map_stream_search (session->transfers,
                                                          request_user_data);
  if ((stream == NULL) &&
      ((session->mode == NGHQ_MODE_UNICAST) ||
          (session->role == NGHQ_ROLE_SERVER))) {
    uint8_t* buf;
    size_t buflen;
    int rv;
    stream = nghq_stream_id_map_stream_search (session->promises,
                                               request_user_data);
    if (stream == NULL) {
      return NGHQ_REQUEST_CLOSED;
    }
    /* Send a CANCEL_PUSH frame! */
    rv = create_cancel_push_frame (session, stream->push_id, &buf, &buflen);
    if (rv != NGHQ_OK) {
      return rv;
    }

    if (session->role == NGHQ_ROLE_CLIENT) {
      return nghq_queue_send_frame(session, NGHQ_CONTROL_CLIENT, buf, buflen);
    } else { /* NGHQ_ROLE_SERVER */
      return nghq_queue_send_frame(session, NGHQ_CONTROL_SERVER, buf, buflen);
    }
  }
  return nghq_stream_cancel(session, stream, result);
}

uint64_t nghq_get_max_client_requests (nghq_session *session) {
  return session->max_open_requests;
}

int nghq_set_max_client_requests (nghq_session *session, uint64_t max_requests){
  return NGHQ_OK;
}

uint64_t nghq_get_max_pushed (nghq_session *session) {
  return session->max_open_server_uni;
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

  rv = create_max_push_id_frame (session, session->max_push_promise, &buf,
                                 &buflen);
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
      /* @suppress("No break at end of case") */
    case STATE_TRAILERS:
      break;
    default:
      NGHQ_LOG_WARN (session, "Received HEADERS for stream %lu, but receive "
                     "state is done!\n", stream->stream_id);
      return NGHQ_REQUEST_CLOSED;
  }
  to_process = parse_headers_frame (session, session->hdr_ctx, frame->data,
                                    &hdrs, &num_hdrs);
  if (to_process < 0) {
    return to_process;
  }
  if (hdrs != NULL) {
    int rv;
    uint8_t flags = 0;

    if (frame->data->complete) {
      flags |= NGHQ_HEADERS_FLAGS_END_REQUEST;
    }

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
      flags |= NGHQ_HEADERS_FLAGS_TRAILERS;
    }

    rv = nghq_deliver_headers (session, flags, hdrs, num_hdrs,
                               stream->user_data);
    if (rv != 0) {
      return rv;
    }
  }

  return NGHQ_OK;
}

static int _nghq_stream_cancel_push_frame (nghq_session* session,
                                           nghq_stream* stream,
                                           nghq_stream_frame *frame) {
  uint64_t push_id;

  parse_cancel_push_frame (session, frame->data, &push_id);

  nghq_stream_id_map_remove(session->promises, push_id);

  return NGHQ_OK;
}

static int _nghq_stream_settings_frame (nghq_session* session,
                                        nghq_stream* stream,
                                        nghq_stream_frame *frame) {
  nghq_settings *new_settings;

  parse_settings_frame (session, frame->data, &new_settings);

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

  to_process = parse_push_promise_frame (session, session->hdr_ctx,
                                         frame->data, &push_id,
                                         &hdrs, &num_hdrs);

  if (to_process < 0) {
    return to_process;
  }
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
    uint8_t flags = 0;

    if (frame->data->complete) {
      flags |= NGHQ_HEADERS_FLAGS_END_REQUEST;
    }

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

    rv = nghq_deliver_headers (session, flags, hdrs, num_hdrs,
                               new_promised_stream->user_data);
    if (rv != NGHQ_OK) {
      return rv;
    }
  }

  NGHQ_LOG_DEBUG (session, "Received push promise on stream ID %lu with push ID"
                  " %lu\n", stream->stream_id, push_id);

  return NGHQ_OK;
}

static int _nghq_stream_goaway_frame (nghq_session* session,
                                      nghq_stream* stream,
                                      nghq_stream_frame *frame) {
  uint64_t last_stream_id;

  parse_goaway_frame (session, frame->data, &last_stream_id);

  return NGHQ_OK;
}

static int _nghq_stream_max_push_id_frame (nghq_session* session,
                                           nghq_stream* stream,
                                           nghq_stream_frame *frame) {
  uint64_t max_push_id;

  parse_max_push_id_frame (session, frame->data, &max_push_id);

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
  if (stream->stream_id == NGHQ_PUSH_PROMISE_STREAM && *pb) {
    /* Always pass back the first buffer for stream 4 on or after offset */
    if ((*pb)->offset <= offset && (*pb)->offset + (*pb)->buf_len > offset) {
      /* requested offset is within the first buffer, trim response */
      outbuf->buf = (*pb)->buf + (offset - (*pb)->offset);
      outbuf->buf_len = (*pb)->buf_len - (offset - (*pb)->offset);
      outbuf->send_pos = outbuf->buf;
      outbuf->remaining = outbuf->buf_len;
      outbuf->offset = offset;
      outbuf->complete = (*pb)->complete;
      return 1;
    } else if ((*pb)->offset > offset) {
      /* requested offset not in first buffer, just pass what's left */
      outbuf->buf = (*pb)->send_pos;
      outbuf->buf_len = (*pb)->remaining;
      outbuf->send_pos = outbuf->buf;
      outbuf->remaining = outbuf->buf_len;
      outbuf->offset = (*pb)->offset + (*pb)->buf_len - (*pb)->remaining;
      outbuf->complete = (*pb)->complete;
      return 1;
    }
  }
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
      if ((*pb)->send_pos == (*pb)->buf + (offset - (*pb)->offset)) {
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

static int _nghq_stream_frame_add (nghq_session *session, nghq_stream* stream,
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
    ssize_t to_process = parse_data_frame (session, data, &bodydata, &datalen);
    if (to_process < 0) return to_process;
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
    /* frame overlaps data, find first offset within frame */
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

  double timeout = session->transport_settings.stream_timeout;
  if (timeout > 0) {
    if (stream->timer_id != NULL) {
      /* If !NGHQ_OK (0), then couldn't reset the timer, so try making a new
       * one below. */
      if (session->callbacks.reset_timer_callback(session,
                                                  session->session_user_data,
                                                  stream->timer_id,
                                                  timeout) != NGHQ_OK) {
        stream->timer_id = NULL;
      }
    }
    /* Don't set timers on stream 0, as it may not be updated at the same
     * frequency as the object delivery channels. */
    if ((stream->timer_id == NULL) &&
        (stream->stream_id != NGHQ_PUSH_PROMISE_STREAM)) {
      stream->timer_id = session->callbacks.set_timer_callback (session,
                                                    timeout,
                                                    session->session_user_data,
                                                    _nghq_stream_timeout,
                                                    (void *) stream);
    }
  }

  if (end_of_stream) {
    stream->flags |= STREAM_FLAG_FIN_SEEN;
  }

  _nghq_insert_recv_stream_data(stream, data, datalen, off, end_of_stream);

  /* Add new frames */
  if (stream->stream_id == NGHQ_PUSH_PROMISE_STREAM && stream->recv_buf) {
    /* Always add frames for stream 0 from start of first available buffer */
    stream->next_recv_offset = stream->recv_buf->offset +
                               stream->recv_buf->buf_len -
                               stream->recv_buf->remaining;
  }
  while (_nghq_stream_recv_data_at(stream, stream->next_recv_offset,
                                   &frame_data) > 0) {
    if (SERVER_PUSH_STREAM(stream->stream_id) &&
        stream->next_recv_offset == 0) {
      size_t push_off = 0;
      if (_get_varlen_int (frame_data.buf, &push_off, frame_data.buf_len) != 1)
      {
        NGHQ_LOG_ERROR (session, "Expected the beginning of a server push "
                        "stream but didn't get one\n");
        return NGHQ_ERROR;
      }
      _get_varlen_int(frame_data.buf + push_off, &push_off, frame_data.buf_len);
      if (push_off > frame_data.buf_len) {
        NGHQ_LOG_ERROR (session, "Not enough data for push ID in stream %lu\n",
                        stream->stream_id);
        return NGHQ_ERROR;
      }
      stream->next_recv_offset = push_off;
      _nghq_stream_recv_pop_data(stream, 0, push_off);
      continue;
    }

    ssize_t size = parse_frame_header (&frame_data, &frame_type);

    if (size > 0) {
      _nghq_stream_frame_add(session, stream, frame_type, size,
                             frame_data.offset, &frame_data);
      stream->next_recv_offset = frame_data.offset+size;
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

          if (frame_data.offset < (*pf)->end_header_offset) {
            // first block of body frame, skip header
            hdr_bytes = (*pf)->end_header_offset - frame_data.offset;
          }
          data_used -= hdr_bytes;
          data += hdr_bytes;
          data_offset = frame_data.offset + hdr_bytes - (*pf)->data_offset_adjust;
          // send data immediately - not stored in DATA frames
          session->callbacks.on_data_recv_callback(session,
                                         last_data?NGHQ_DATA_FLAGS_END_DATA:0,
                                         data, data_used, data_offset,
                                         stream->user_data);
        }
        _nghq_stream_recv_pop_data(stream, frame_data.offset, used);
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
            NGHQ_LOG_ERROR (session, "Unknown frame type 0x%x\n",
                            frame->frame_type);
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

  if ((stream->active_frames == NULL) && STREAM_FIN_SEEN(stream->flags)) {
    nghq_stream_close (session, stream, QUIC_ERR_HTTP_NO_ERROR);
  }

  return NGHQ_OK;
}

int nghq_deliver_headers (nghq_session* session, uint8_t flags,
                          nghq_header **hdrs, size_t num_hdrs,
                          void *request_user_data) {
  int i, rv = NGHQ_OK;
  /* remember fin bit */
  uint8_t fin = flags & NGHQ_HEADERS_FLAGS_END_REQUEST;

  /* remove fin bit until last header */
  flags &= ~NGHQ_HEADERS_FLAGS_END_REQUEST;
  for (i = 0; i < num_hdrs; i++) {
    if (i == num_hdrs - 1) {
      /* put fin bit back on last header */
      flags |= fin;
    }
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
    if (session->handshake_complete) {
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
    }

    free (session->send_buf->buf);
    nghq_io_buf *pop = session->send_buf;
    session->send_buf = session->send_buf->next_buf;
    free (pop);

    if (rv > 0) rv = NGHQ_OK;
  }
  return rv;
}

/*
 * Call this method if you want to stop a stream that is currently running.
 */
int nghq_stream_cancel (nghq_session* session, nghq_stream *stream,
                        nghq_error error) {
  uint16_t app_error_code = QUIC_ERR_HTTP_NO_ERROR;
  switch (error) {
    case NGHQ_ERROR:
    case NGHQ_INTERNAL_ERROR:
      app_error_code = QUIC_ERR_HTTP_INTERNAL_ERROR;
      break;
    case NGHQ_NOT_INTERESTED:
    case NGHQ_CANCELLED:
    case NGHQ_REQUEST_CLOSED:
      app_error_code = QUIC_ERR_HTTP_REQUEST_CANCELLED;
      break;
    default:
      break;
  }
  if (session->role == NGHQ_ROLE_SERVER) {
    uint64_t pktnum;
    nghq_io_buf *buf = nghq_io_buf_alloc (NULL, session->packet_buf_len, 1, 0);
    ssize_t off = quic_transport_write_quic_header (session, buf->buf,
                                                    buf->buf_len, &pktnum);
    off += quic_transport_write_reset_stream (session, buf->buf + off,
                                              buf->buf_len - off, stream,
                                              app_error_code);
    buf->buf_len = quic_transport_encrypt (session, buf->buf, off, buf->buf,
                                           buf->buf_len);
    nghq_io_buf_push (&session->send_buf, buf);
  }

  nghq_stream_id_map_remove (session->transfers, stream->stream_id);

  if (session->callbacks.on_request_close_callback) {
    session->callbacks.on_request_close_callback (session, error,
                                                  stream->user_data);
  }

  return nghq_stream_ended (session, stream);
}

/*
 * Call this if a stream has naturally ended to clean up the stream object
 */
int nghq_stream_ended (nghq_session* session, nghq_stream *stream) {
  if (stream == NULL) return NGHQ_OK;

  nghq_io_buf_clear(&stream->send_buf);
  nghq_io_buf_clear(&stream->recv_buf);

  if (stream->timer_id) {
    session->callbacks.cancel_timer_callback (session,
                                              session->session_user_data,
                                              stream->timer_id);
    stream->timer_id = NULL;
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

  NGHQ_LOG_DEBUG (session, "Stream %lu is closing with code 0x%04X\n",
                  stream->stream_id, app_error_code);

  switch (app_error_code) {
    case QUIC_ERR_STOPPING:
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
    case QUIC_ERR_MALFORMED_CANCEL_PUSH_FRAME:
    case QUIC_ERR_MALFORMED_SETTINGS_FRAME:
    case QUIC_ERR_MALFORMED_PUSH_PROMISE_FRAME:
    case QUIC_ERR_MALFORMED_GOAWAY_FRAME:
    case QUIC_ERR_MALFORMED_MAX_PUSH_ID:
      status = NGHQ_HTTP_MALFORMED_FRAME;
      break;
    case QUIC_ERR_PACKET_LOSS:
      status = NGHQ_MISSING_DATA;
      break;
    default:
      NGHQ_LOG_ERROR(session, "Unknown HTTP/QUIC Error Code 0x%4X\n",
                     app_error_code);
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
  return NGHQ_NOT_IMPLEMENTED;
}

nghq_stream *nghq_stream_new (uint64_t stream_id) {
  nghq_stream *stream = nghq_stream_init();
  if (stream == NULL) {
    return NULL;
  }
  stream->stream_id = stream_id;
  return stream;
}

nghq_stream *nghq_req_stream_new (nghq_session* session) {
  return nghq_open_stream (session, NGHQ_STREAM_CLIENT_BIDI);
}

nghq_stream *nghq_open_stream (nghq_session* session, nghq_stream_type type) {
  int rv;
  nghq_stream *stream = nghq_stream_init();
  if (stream == NULL) return NULL;

  stream->stream_id = quic_transport_open_stream(session, type);
  if (type == NGHQ_STREAM_CLIENT_UNI) {
    if (session->role == NGHQ_ROLE_SERVER) {
      stream->send_state = STATE_DONE;
    } else {
      stream->recv_state = STATE_DONE;
    }
  } else if (type == NGHQ_STREAM_SERVER_UNI) {
    if (session->role == NGHQ_ROLE_SERVER) {
      stream->recv_state = STATE_DONE;
    } else {
      stream->send_state = STATE_DONE;
    }
  }
  if (stream->stream_id < NGHQ_OK) {
    NGHQ_LOG_ERROR (session, "Failed to open new request stream\n");
    free (stream);
    return NULL;
  }

  rv = nghq_stream_id_map_add (session->transfers, stream->stream_id, stream);
  if (rv != 0) {
    NGHQ_LOG_ERROR (session, "Failed to add new stream %lu to map\n",
                    stream->stream_id);
    session->next_stream_id[type]--;
    free (stream);
    return NULL;
  }

  return stream;
}

void nghq_close_all_streams (nghq_session *session, nghq_map_ctx **strm_ctx) {
  if (*strm_ctx != NULL) {
    nghq_stream *stream = nghq_stream_id_map_iterator(*strm_ctx, NULL);
    while (stream != NULL) {
      uint64_t stream_id = stream->stream_id;
      nghq_stream_ended(session, stream);
      stream = nghq_stream_id_map_remove (*strm_ctx, stream_id);
    }
    nghq_stream_id_map_destroy (*strm_ctx);
    *strm_ctx = NULL;
  }
}

PACKED_STRUCT(alpn_name)
struct alpn_name {
    uint8_t len;
    uint8_t name[];
};
END_PACKED_STRUCT(alpn_name)

static const struct alpn_name * const _draft29_alpns[] = {
        (const struct alpn_name *const)"\x06h3m-07",
        NULL};

static const struct alpn_name * const *_get_alpn_protocols()
{
    return _draft29_alpns;
}

ssize_t nghq_select_alpn (nghq_session *session, const uint8_t *buf,
                          size_t buflen, const uint8_t **proto)
{
    const struct alpn_name * const *alpn_protocols = _get_alpn_protocols ();

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
    const struct alpn_name * const *alpn_protocols = _get_alpn_protocols ();
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

uint8_t nghq_convert_session_id_string (const char *str, size_t len,
                                        uint8_t **buf)
{
  uint8_t *_buf, rv;
  size_t offset = 0;
  int i = 0, lower;
  if (len == 0) {
    len = strnlen(str, 40);
  }

  rv = (len / 2) + (len % 2);
  _buf = (uint8_t *) calloc (rv, 1);
  if (_buf == NULL) {
    return 0;
  }

  lower = len % 2;
  while (offset < len) {
    if ((str[offset] >= '0') && (str[offset] <= '9')) {
      _buf[i] |= (lower)?(str[offset] - 48):((str[offset] - 48) << 4);
    } else if ((str[offset] >= 'A') && (str[offset] <= 'F')) {
      _buf[i] |= (lower)?(str[offset] - 55):((str[offset] - 55) << 4);
    } else if ((str[offset] >= 'a') && (str[offset] <= 'f')) {
      _buf[i] |= (lower)?(str[offset] - 87):((str[offset] - 87) << 4);
    }

    ++offset;
    if (lower) {
      ++i;
      lower = 0;
    } else {
      lower = 1;
    }
  }

  *buf = _buf;
  return rv;
}

void nghq_free_session_id_string (uint8_t *buf)
{
  free (buf);
}

const char * nghq_strerror (int err) {
  switch (err) {
    case NGHQ_OK:
      return "OK";
    case NGHQ_ERROR:
      return "An error occured";
    case NGHQ_INTERNAL_ERROR:
      return "An internal error occured";
    case NGHQ_OUT_OF_MEMORY:
      return "Could not allocate memory";
    case NGHQ_NOT_IMPLEMENTED:
      return "Requested functionality not implemented in this version of nghq";
    case NGHQ_INCOMPATIBLE_METHOD:
      return "Incompatible connection method";
    case NGHQ_TOO_MUCH_DATA:
      return "Too much data in flight";
    case NGHQ_CANCELLED:
      return "Stream or session cancelled";
    case NGHQ_SESSION_CLOSED:
      return "Session closed";
    case NGHQ_EOF:
      return "An underlying file or data source was closed";
    case NGHQ_HDR_COMPRESS_FAILURE:
      return "Header (de)compression routine failed";
    case NGHQ_CRYPTO_ERROR:
      return "A crypto function failed";
    case NGHQ_NO_MORE_DATA:
      return "No more data was available";
    case NGHQ_SESSION_BLOCKED:
      return "The session is blocked by flow control";
    case NGHQ_REQUEST_BLOCKED:
      return "The request is blocked by flow control";
    case NGHQ_TOO_MANY_REQUESTS:
      return "An endpoint has made too many requests";
    case NGHQ_NOT_INTERESTED:
      return "Application is not interested";
    case NGHQ_CLIENT_ONLY:
      return "Client only";
    case NGHQ_SERVER_ONLY:
      return "Server only";
    case NGHQ_BAD_USER_DATA:
      return "Couldn't find matching user data";
    case NGHQ_INVALID_PUSH_LIMIT:
      return "Invalid push limit";
    case NGHQ_PUSH_LIMIT_REACHED:
      return "Reached the limit of available push promises";
    case NGHQ_PUSH_ALREADY_IN_CACHE:
      return "Push already in cache";
    case NGHQ_TRAILERS_NOT_PROMISED:
      return "Received trailing header that was not promised";
    case NGHQ_REQUEST_CLOSED:
      return "Request closed";
    case NGHQ_SETTINGS_NOT_RECOGNISED:
      return "Settings not recognised";
    case NGHQ_HTTP_CONNECT_ERROR:
      return "HTTP CONNECT method error";
    case NGHQ_HTTP_WRONG_STREAM:
      return "HTTP Wrong Stream";
    case NGHQ_HTTP_DUPLICATE_PUSH:
      return "HTTP Duplicate push";
    case NGHQ_HTTP_MALFORMED_FRAME:
      return "Malformed HTTP/3 frame";
    case NGHQ_HTTP_PUSH_REFUSED:
      return "HTTP Push refused";
    case NGHQ_HTTP_ALPN_FAILED:
      return "Unrecognised ALPN string";
    case NGHQ_HTTP_BAD_PUSH:
      return "Invalid Push ID";
    case NGHQ_TRANSPORT_ERROR:
      return "QUIC Transport error";
    case NGHQ_TRANSPORT_CLOSED:
      return "QUIC Session closed";
    case NGHQ_TRANSPORT_FINAL_OFFSET:
      return "QUIC Transport final offset";
    case NGHQ_TRANSPORT_FRAME_FORMAT:
      return "QUIC Transport frame could not be parsed";
    case NGHQ_TRANSPORT_PARAMETER:
      return "Invalid QUIC transport parameter";
    case NGHQ_TRANSPORT_VERSION:
      return "Incompatible QUIC transport version";
    case NGHQ_TRANSPORT_PROTOCOL:
      return "QUIC transport protocol error";
    case NGHQ_TRANSPORT_TIMEOUT:
      return "QUIC session has timed out";
    case NGHQ_TRANSPORT_BAD_SESSION_ID:
      return "Session ID did not match";
    case NGHQ_TRANSPORT_BAD_STREAM_ID:
      return "Bad stream ID";
  }
  return "(unknown)";
}

static int _check_timeout (nghq_session *session, nghq_ts *ts) {
  nghq_ts *to_comp = ts, deadline, offset;
  int rv = NGHQ_OK;
  if (!to_comp) {
    to_comp = (nghq_ts *) malloc (sizeof(nghq_ts));
    if (!to_comp) return NGHQ_OUT_OF_MEMORY;
    if (gettimeofday(to_comp, NULL)) {
      NGHQ_LOG_ERROR (session, "gettimeofday() failed: %s\n", strerror(errno));
      return NGHQ_INTERNAL_ERROR;
    }
  }

  offset.tv_sec = (time_t) session->transport_settings.idle_timeout;
  offset.tv_usec = 0;
  timeradd (&session->last_recv_ts, &offset, &deadline);

  if (timercmp(to_comp, &deadline, >=)) {
    NGHQ_LOG_DEBUG (session, "Idle timeout of %lu seconds has expired!\n",
                    session->transport_settings.idle_timeout);
    rv = NGHQ_TRANSPORT_TIMEOUT;
  }

  if (!ts) {
    free (to_comp);
  }

  return rv;
}

int nghq_check_timeout (nghq_session *session) {
  if (session->session_timed_out) return NGHQ_TRANSPORT_TIMEOUT;
  if (session->mode == NGHQ_MODE_MULTICAST) {
    return _check_timeout (session, NULL);
  }
  return NGHQ_NOT_IMPLEMENTED;
}

void nghq_update_timeout (nghq_session *session) {
  gettimeofday(&session->last_recv_ts, NULL);
  if (session->callbacks.set_timer_callback != NULL) {
    if (session->session_timeout_timer) {
      if (session->callbacks.reset_timer_callback (session,
                                      session->session_user_data,
                                      session->session_timeout_timer,
                                      session->transport_settings.idle_timeout))
        session->session_timeout_timer = NULL;
    }
    if (session->session_timeout_timer == NULL) {
      session->session_timeout_timer =
          session->callbacks.set_timer_callback (session,
                                       session->transport_settings.idle_timeout,
                                       session->session_user_data,
                                       _nghq_session_timeout, NULL);
    }
  }
}

uint32_t nghq_get_packet_number (nghq_session *session, const uint8_t *buf,
                                 size_t len, uint8_t *num_bytes)
{
  if (num_bytes != NULL) {
    *num_bytes = (buf[0] & 0x03) + 1;
  }
  return (uint32_t) get_packet_number(buf[0], buf + session->session_id_len + 1);
}

int nghq_set_loglevel (nghq_session *session, nghq_log_level max,
                       nghq_log_callback log_cb)
{
  if ((session == NULL) || (max < NGHQ_LOG_LEVEL_ALERT)
      || (max >= NGHQ_LOG_LEVEL_MAX)) {
    return NGHQ_ERROR;
  }
  session->log_level = max;
  session->log_cb = log_cb;

  return NGHQ_OK;
}

nghq_log_level nghq_get_loglevel_from_str (const char *lvl, size_t len) {
  /* The longest log level string is 5 characters (+ \n), this is a shortcut */
  if (len > 6) {
    return NGHQ_LOG_LEVEL_MAX;
  }
  if (strncasecmp(lvl, NGHQ_LOG_LEVEL_ALERT_STR, len) == 0) {
    return NGHQ_LOG_LEVEL_ALERT;
  }
  if (strncasecmp(lvl, NGHQ_LOG_LEVEL_ERROR_STR, len) == 0) {
    return NGHQ_LOG_LEVEL_ERROR;
  }
  if (strncasecmp(lvl, NGHQ_LOG_LEVEL_WARN_STR, len) == 0) {
    return NGHQ_LOG_LEVEL_WARN;
  }
  if (strncasecmp(lvl, NGHQ_LOG_LEVEL_INFO_STR, len) == 0) {
    return NGHQ_LOG_LEVEL_INFO;
  }
  if (strncasecmp(lvl, NGHQ_LOG_LEVEL_DEBUG_STR, len) == 0) {
    return NGHQ_LOG_LEVEL_DEBUG;
  }
  if (strncasecmp(lvl, NGHQ_LOG_LEVEL_TRACE_STR, len) == 0) {
    return NGHQ_LOG_LEVEL_TRACE;
  }
  return NGHQ_LOG_LEVEL_MAX;
}

const char * nghq_get_loglevel_str (nghq_log_level lvl) {
  return log_level_as_str (lvl);
}

// vim:ts=8:sts=2:sw=2:expandtab:
