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

#include "nghq/nghq.h"
#include "nghq_internal.h"
#include "frame_parser.h"
#include "frame_creator.h"
#include "header_compression.h"
#include "map.h"

nghq_session * _nghq_session_new_common(const nghq_callbacks *callbacks,
                                        const nghq_settings *settings,
                                        const nghq_transport_settings *transport,
                                        void *session_user_data) {
  nghq_session *session = (nghq_session *) malloc (sizeof(nghq_session));

  if (session == NULL) {
    return NULL;
  }

  session->mode = transport->mode;
  session->max_open_requests = transport->max_open_requests * 4;
  session->max_open_server_pushes = (transport->max_open_server_pushes * 4) + 3;
  session->max_push_promise = 0;


  memcpy(&session->callbacks, callbacks, sizeof(nghq_callbacks));
  memcpy(&session->settings, settings, sizeof(nghq_settings));
  memcpy(&session->transport_settings, transport,
         sizeof(nghq_transport_settings));

  session->transfers = nghq_stream_id_map_init();
  session->promises = nghq_stream_id_map_init();

  session->session_user_data = session_user_data;

  return session;
}

int _nghq_start_session(nghq_session *session) {
  if (session->mode == NGHQ_MODE_MULTICAST) {
    /* Just set defaults and return */
    session->highest_bidi_stream_id = 4;
    session->highest_uni_stream_id = NGHQ_MULTICAST_MAX_UNI_STREAM_ID;
    session->max_push_promise = NGHQ_MULTICAST_MAX_UNI_STREAM_ID;
    return NGHQ_OK;
  }

  /* Not implemented yet! */

  return NGHQ_ERROR;
}

nghq_session * nghq_session_client_new (const nghq_callbacks *callbacks,
                                        const nghq_settings *settings,
                                        const nghq_transport_settings *transport,
                                        void *session_user_data) {
  nghq_session *rv = _nghq_session_new_common (callbacks, settings, transport,
                                               session_user_data);

  if (rv != NULL) {
    rv->role = NGHQ_ROLE_CLIENT;
  }

  if (_nghq_start_session(rv) != NGHQ_OK) {
    free (rv);
    rv = NULL;
  }

  return rv;
}

nghq_session * nghq_session_server_new (const nghq_callbacks *callbacks,
                                        const nghq_settings *settings,
                                        const nghq_transport_settings *transport,
                                        void *session_user_data) {
  nghq_session *rv = _nghq_session_new_common (callbacks, settings, transport,
                                               session_user_data);

  if (rv != NULL) {
    rv->role = NGHQ_ROLE_SERVER;
  }

  if (_nghq_start_session(rv) != NGHQ_OK) {
    free (rv);
    rv = NULL;
  }

  return rv;
}

int nghq_session_close (nghq_session *session, nghq_error reason) {

}

int nghq_session_free (nghq_session *session) {
  free (session);
  return NGHQ_OK;
}

void nghq_io_buf_push (nghq_io_buf* list, nghq_io_buf* push) {
  while (list->next_buf != NULL) {
    list = list->next_buf;
  }
  list->next_buf = push;
  push->next_buf = NULL;
}

void nghq_io_buf_new (nghq_io_buf* list, uint8_t *buf, size_t buflen) {
  nghq_io_buf* frame = (nghq_io_buf *) malloc (sizeof(nghq_io_buf));
  if (frame == NULL) {
    return;
  }

  frame->buf = buf;
  frame->buf_len = buflen;
  frame->complete = 1;

  nghq_io_buf_push(list, frame);
}

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
  stream->user_data = NULL;
  stream->priority = 0;
  stream->recv_state = STATE_OPEN;
  stream->send_state = STATE_OPEN;
  return stream;
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
      /* errors */
      if (socket_rv == NGHQ_EOF) {
        return NGHQ_SESSION_CLOSED;
      }
      return NGHQ_ERROR;
    } else if (socket_rv == 0) {
      /* no more data to read */
      recv = 0;
    } else {
      nghq_io_buf_new(session->recv_buf, buf, buflen);
    }
  }

  while (session->recv_buf != NULL) {
    struct timeval tv;
    gettimeofday(&tv,NULL);
    uint64_t us_timestamp = (1000000 * tv.tv_sec) + tv.tv_usec;
    rv = ngtcp2_conn_recv(session->ngtcp2_session, session->recv_buf->buf,
                           session->recv_buf->buf_len, us_timestamp);

    free (session->recv_buf->buf);
    nghq_io_buf *pop = session->recv_buf;
    session->recv_buf = session->recv_buf->next_buf;
    free (pop);

    if (rv != 0) {
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
  /*
   * Go through all the streams and grab any packets that need sending
   *
   * TODO: This won't work particularly well when there's a lot of streams
   * running at once - it'll always send data from the lower streams even if
   * there's a lot of data waiting on higher number streams - change the list
   * of frames waiting to be sent into an all-streams structure?
   */
  nghq_stream *it = nghq_stream_id_map_iterator(it);
  int rv = NGHQ_NO_MORE_DATA;
  while ((rv != NGHQ_ERROR) && (rv != NGHQ_EOF)) {
    if (ngtcp2_conn_bytes_in_flight(session->ngtcp2_session) >= MAX_BYTES_IN_FLIGHT) {
      if (rv == NGHQ_NO_MORE_DATA) {
        return NGHQ_SESSION_BLOCKED;
      }
      break;
    }

    size_t datalen;

    nghq_io_buf *new_pkt = (nghq_io_buf *) malloc (sizeof(nghq_io_buf));
    new_pkt->buf = (uint8_t *) malloc(
        session->transport_settings->max_packet_size);
    new_pkt->buf_len = session->transport_settings->max_packet_size;

    struct timeval tv;
    gettimeofday(&tv,NULL);
    uint64_t us_timestamp = (1000000 * tv.tv_sec) + tv.tv_usec;

    ssize_t sent = ngtcp2_conn_write_stream(session->ngtcp2_session,
                                            new_pkt->buf, new_pkt->buf_len,
                                            &datalen, it->stream_id,
                                            it->send_buf->complete,
                                            it->send_buf->buf,
                                            it->send_buf->buf_len,
                                            us_timestamp);

    if (sent < 0) {
      switch (sent) {
        case NGTCP2_ERR_EARLY_DATA_REJECTED:
        case NGTCP2_ERR_STREAM_DATA_BLOCKED:
        case NGTCP2_ERR_STREAM_SHUT_WR:
        case NGTCP2_ERR_STREAM_NOT_FOUND:
          return 0;
      }
      rv = NGHQ_TRANSPORT_ERROR;
      break;
    }

    new_pkt->buf_len = sent;

    nghq_io_buf_push(session->send_buf, new_pkt);

    rv = nghq_write_send_buffer (session);
  }

  return rv;
}

int nghq_submit_request (nghq_session *session, const nghq_header **hdrs,
                         size_t num_hdrs, const uint8_t *req_body, size_t len,
                         void *request_user_data) {
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

  rv = nghq_feed_headers (session, hdrs, num_hdrs, request_user_data);
  if (rv != NGHQ_OK) {
    free (new_stream);
    return rv;
  }
  nghq_stream_id_map_add(session->transfers, new_stream->stream_id, new_stream);
  if (len > 0) {
    return (int)nghq_feed_payload_data(session, req_body, len, request_user_data);
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

  if (session->last_push_promise >= session->max_push_promise) {
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

  rv = create_push_promise_frame(session->hdr_ctx, ++session->last_push_promise,
                                 hdrs, num_hdrs, &push_promise_buf,
                                 &push_promise_len);

  if (rv != NGHQ_OK) {
    return rv;
  }

  nghq_io_buf* frame = (nghq_io_buf *) malloc (sizeof(nghq_io_buf));
  if (frame == NULL) {
    rv = NGHQ_OUT_OF_MEMORY;
    goto push_promise_frame_err;
  }

  nghq_stream *promised_stream = nghq_stream_init();
  if (promised_stream == NULL) {
    rv = NGHQ_OUT_OF_MEMORY;
    goto push_promise_stream_err;
  }

  promised_stream->push_id = session->last_push_promise;
  promised_stream->user_data = promised_request_user_data;

  frame->buf = push_promise_buf;
  frame->buf_len = push_promise_len;

  nghq_stream_id_map_add (session->promises, promised_stream->push_id, promised_stream);

  nghq_stream *init_stream = nghq_stream_id_map_find(session->transfers,
                                                     init_request_stream_id);
  nghq_io_buf_push(init_stream->send_buf, frame);

  return NGHQ_OK;

push_promise_stream_err:
  free (frame);
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
                       size_t num_hdrs, void *request_user_data) {
  uint8_t* buf;
  size_t buf_len;
  nghq_stream* stream;
  uint64_t stream_id;
  int headers_compressed = 0;
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
    /* Start of a server push, so open a new unidirectional stream */
    if (session->max_open_server_pushes <=
        nghq_stream_id_map_num_pushes(session->transfers)) {
      return NGHQ_TOO_MANY_REQUESTS;
    }

    stream = nghq_stream_id_map_find(session->promises, push_id);

    ngtcp2_conn_open_uni_stream(session->ngtcp2_session, &stream_id,
                                (void *) stream);

    stream->stream_id = stream_id;

    rv = create_headers_frame (session->hdr_ctx, (int64_t) push_id, hdrs,
                               num_hdrs, &buf, &buf_len);
    if (rv < 0) {
      return rv;
    }

    nghq_stream_id_map_add(session->transfers, stream_id, stream);
    nghq_stream_id_map_remove(session->promises, push_id);
  } else {
    stream = nghq_stream_id_map_find(session->transfers, stream_id);
    rv = create_headers_frame (session->hdr_ctx, -1, hdrs, num_hdrs, &buf,
                               &buf_len);

    if (rv < 0) {
      return rv;
    }
  }

  nghq_io_buf* frame = (nghq_io_buf *) malloc (sizeof(nghq_io_buf));
  if (frame == NULL) {
    return NGHQ_OUT_OF_MEMORY;
  }

  frame->buf = buf;
  frame->buf_len = buf_len;
  frame->complete = 1;

  nghq_io_buf_push(stream->send_buf, frame);

  return rv;
}

ssize_t nghq_feed_payload_data(nghq_session *session, const uint8_t *buf,
                               size_t len, void *request_user_data) {
  nghq_io_buf* frame;
  uint64_t stream_id;
  nghq_stream* stream;
  ssize_t rv;

  if (session == NULL) {
    return NGHQ_ERROR;
  }

  stream_id = nghq_stream_id_map_search(session->transfers, request_user_data);

  if (stream_id == NGHQ_STREAM_ID_MAP_NOT_FOUND) {
    return NGHQ_ERROR;
  }

  frame = (nghq_io_buf *) malloc (sizeof(nghq_io_buf));

  rv = create_data_frame (buf, len, &frame->buf, &frame->buf_len);
  frame->complete = 1;

  nghq_io_buf_push(stream->send_buf, frame);

  return rv;
}

int nghq_end_request (nghq_session *session, nghq_error result,
                      void *request_user_data) {

}

uint64_t nghq_get_max_client_requests (nghq_session *session) {
  return session->max_open_requests;
}

int nghq_set_max_client_requests (nghq_session *session, uint64_t max_requests){

}

uint64_t nghq_get_max_pushed (nghq_session *session) {
  return session->max_open_server_pushes;
}

int nghq_set_max_pushed(nghq_session *session, uint64_t max_pushed) {

}

uint64_t nghq_get_max_promises (nghq_session *session) {
  return session->max_push_promise - session->last_push_promise;
}

int nghq_set_max_promises (nghq_session* session, uint64_t max_push) {
  uint8_t* buf;
  size_t buflen;
  int rv;

  if (session->role != NGHQ_ROLE_CLIENT) {
    return NGHQ_CLIENT_ONLY;
  }
  if ((session->last_push_promise + max_push) < session->max_push_promise) {
    return NGHQ_INVALID_PUSH_LIMIT;
  }

  session->max_push_promise = session->last_push_promise + max_push;

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
                           uint64_t* data, size_t datalen) {
  if (stream->recv_buf == NULL) {
    nghq_io_buf_new(stream->recv_buf, NULL, 0);
  }

  stream->recv_buf->buf = (uint8_t *) realloc(stream->recv_buf->buf,
                                              stream->recv_buf->buf_len + datalen);

  memcpy(stream->recv_buf->buf + stream->recv_buf->buf_len, data, datalen);

  while (stream->recv_buf != NULL) {
    nghq_frame_type frame_type;
    ssize_t size = parse_frames (stream->recv_buf->buf,
                                 stream->recv_buf->buf_len, &frame_type);

    switch (frame_type) {
      case NGHQ_FRAME_TYPE_DATA: {
        uint8_t* outbuf = NULL;
        size_t outbuflen = 0;
        size = parse_data_frame (stream->recv_buf->buf,
                                 stream->recv_buf->buf_len, &outbuf,
                                 &outbuflen);

        if (outbuf != NULL) {
          session->callbacks.on_data_recv_callback(session, 0, outbuf,
                                                    outbuflen,
                                                    stream->user_data);
        }
        break;
      }
      case NGHQ_FRAME_TYPE_HEADERS: {
        nghq_header** hdrs = NULL;
        size_t num_hdrs;
        size = parse_headers_frame (session->hdr_ctx, stream->recv_buf->buf,
                                    stream->recv_buf->buf_len, &hdrs,
                                    &num_hdrs);

        if (hdrs != NULL) {
          int i;

          if (stream->started == 0) {
            session->callbacks.on_begin_headers_callback(session,
                NGHQ_HT_HEADERS, session->session_user_data, stream->user_data);
          }

          for (i = 0; i < num_hdrs; i++) {
            uint8_t flags = 0;
            if (stream->recv_state >= STATE_HDRS) {
              flags += NGHQ_HEADERS_FLAGS_TRAILERS;
            }
            session->callbacks.on_headers_callback (session, flags, hdrs[i],
                                                     stream->user_data);
          }
        }
        break;
      }
      case NGHQ_FRAME_TYPE_PRIORITY: {
        /* TODO */
        uint8_t flags;
        uint64_t request_id;
        uint64_t dependency_id;
        uint8_t weight;

        parse_priority_frame (stream->recv_buf->buf, stream->recv_buf->buf_len,
                              &flags, &request_id, &dependency_id, &weight);

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
        break;
      }
      case NGHQ_FRAME_TYPE_PUSH_PROMISE: {
        nghq_header** hdrs = NULL;
        size_t num_hdrs;
        uint64_t push_id;

        ssize_t rv = parse_push_promise_frame (session->hdr_ctx,
                                               stream->recv_buf->buf,
                                               stream->recv_buf->buf_len,
                                               &push_id, &hdrs, &num_hdrs);

        if (rv < stream->recv_buf->buf_len) {
          nghq_stream* new_promised_stream = nghq_stream_init();
          new_promised_stream->push_id = push_id;
          new_promised_stream->user_data = &new_promised_stream->push_id;
          nghq_stream_id_map_add(session->promises, push_id,
                                 new_promised_stream);
          if (hdrs != NULL) {
            int i;

            session->callbacks.on_begin_headers_callback(session,
                NGHQ_HT_PUSH_PROMISE, session->session_user_data,
                new_promised_stream->user_data);

            for (i = 0; i < num_hdrs; i++) {
              uint8_t flags = 0;
              session->callbacks.on_headers_callback (session, flags, hdrs[i],
                                               new_promised_stream->user_data);
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
          break;
        }

        if (session->max_push_promise > max_push_id) {
          break;
        }

        session->max_push_promise = max_push_id;

        break;
      }
    }
  }
}

int nghq_queue_send_frame (nghq_session* session, uint64_t stream_id,
                           uint8_t* buf, size_t buflen) {
  int rv = NGHQ_INTERNAL_ERROR;
  nghq_stream *stream = nghq_stream_id_map_find(session->transfers, stream_id);
  if (stream != NULL) {
    nghq_io_buf_new (stream->send_buf, buf, buflen);
    rv = NGHQ_OK;
  }
  return rv;
}

int nghq_write_send_buffer (nghq_session* session) {
  int rv = NGHQ_SESSION_BLOCKED;
  while (session->send_buf != NULL) {
    ssize_t written =
        session->callbacks->send_callback (session, session->send_buf->buf,
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

int nghq_stream_close (nghq_session* session, nghq_stream *stream,
                       uint16_t app_error_code) {
  nghq_error status;
  switch (app_error_code) {

  }
}

int nghq_change_max_stream_id (nghq_session* session, uint64_t max_stream_id) {

}
