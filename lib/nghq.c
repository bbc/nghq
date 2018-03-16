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

#include "nghq/nghq.h"
#include "nghq_internal.h"
#include "frame_parser.h"
#include "frame_creator.h"
#include "header_compression.h"

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

  session->transfers = nghq_stream_id_map_init();
  session->promises = nghq_stream_id_map_init();

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

nghq_stream * nghq_stream_init() {
  nghq_stream *stream = (nghq_stream *) malloc (sizeof(nghq_stream));
  if (stream == NULL) {
    return NULL;
  }
  stream->push_id = 0;
  stream->stream_id = 0;
  stream->send_buf = NULL;
  stream->recv_buf = NULL;
  stream->buf_idx = 0;
  stream->tx_offset = 0;
  stream->user_data = NULL;
  stream->priority = 0;
  stream->stream_state = STATE_OPEN;
  return stream;
}

int nghq_session_recv (nghq_session *session) {

}

int nghq_session_send (nghq_session *session) {

}

int nghq_submit_request (nghq_session *session, const nghq_header **hdrs,
                         size_t num_hdrs, uint8_t *req_body, size_t len,
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
      nghq_session_id_map_num_requests(session->transfers)) {
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
  nghq_session_id_map_add(session->transfers, new_stream->stream_id, new_stream);
  if (len > 0) {
    return nghq_feed_payload_data(session, 0, req_body, len, request_user_data);
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
    return NULL;
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

  nghq_stream_id_map_add (session->promises, promised_stream);

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

int nghq_feed_headers (nghq_session *session, nghq_header **hdrs,
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

    stream->stream_id(stream_id);

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

ssize_t nghq_feed_payload_data(nghq_session *session, uint8_t *buf, size_t len,
                               void *request_user_data) {
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

  rv = nghq_queue_send_frame(NGHQ_CONTROL_CLIENT, buf, buflen);

  return rv;
}






