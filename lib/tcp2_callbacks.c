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

#include "tcp2_callbacks.h"
#include "nghq_internal.h"
#include "debug.h"
#include "io_buf.h"
#include "map.h"
#include "util.h"

void nghq_transport_debug (void *user_data, const char *format, ...) {
  nghq_session *session = (nghq_session *) user_data;
#ifdef DEBUGOUT
  va_list args;
  va_start (args, format);
  vfprintf(stderr, format, args);
#endif
}

ssize_t nghq_transport_send_client_initial (ngtcp2_conn *conn, uint32_t flags,
                                            uint64_t *ppkt_num,
                                            const uint8_t **pdest,
                                            void *user_data) {
  DEBUG("nghq_transport_send_client_initial(%p, %x, %lu, %p, %p)\n",
        (void *)conn, flags, *ppkt_num, (void *) pdest, user_data);
  nghq_session *session = (nghq_session *) user_data;
  ssize_t params_size;
  uint8_t* buf;

  if (session->mode == NGHQ_MODE_MULTICAST) {
    params_size = nghq_get_transport_params (session, &buf);
    if (params_size < 0) {
      return params_size;
    }

    free(session->send_buf->buf);
    session->send_buf->buf = buf;
    session->send_buf->buf_len = params_size;
  }

  *ppkt_num = 0;
  const uint8_t *c_buf = buf;
  *pdest = c_buf;
  return session->send_buf->buf_len;
}

ssize_t nghq_transport_send_client_handshake (ngtcp2_conn *conn, uint32_t flags,
                                              const uint8_t **pdest,
                                              void *user_data) {
  DEBUG("nghq_transport_send_client_handshake(%p, %x, %p, %p)\n", (void *) conn,
        flags, (void *) pdest, user_data);
  nghq_session *session = (nghq_session *) user_data;

  ngtcp2_conn_handshake_completed(conn);

  return session->send_buf->buf_len;
}

int nghq_transport_recv_client_initial (ngtcp2_conn *conn, uint64_t conn_id,
                                        void *user_data) {
  DEBUG("nghq_transport_recv_client_initial(%p, %lu, %p)\n", (void *) conn,
        conn_id, user_data);
  int rv = ngtcp2_conn_set_handshake_tx_keys(conn, NULL, 0, NULL, 0);
  if (rv != 0) {
    ERROR("Couldn't set ngtcp2_conn_set_handshake_tx_keys: %s\n",
          ngtcp2_strerror(rv));
  }

  rv = ngtcp2_conn_set_handshake_rx_keys(conn, NULL, 0, NULL, 0);

  if (rv != 0) {
    ERROR("Couldn't set ngtcp2_conn_set_handshake_rx_keys: %s\n",
          ngtcp2_strerror(rv));
  }
  return 0;
}

ssize_t nghq_transport_send_server_handshake (ngtcp2_conn *conn,
                                              uint32_t flags,
                                              uint64_t *ppkt_num,
                                              const uint8_t **pdest,
                                              void *user_data) {
  DEBUG("nghq_transport_send_server_handshake(%p, %x, %lu, %p, %p)\n",
        (void *) conn, flags, (void *) ppkt_num, (void *) *pdest, user_data);
  nghq_session *session = (nghq_session *) user_data;
  nghq_stream *stream = nghq_stream_id_map_find(session->transfers, 0);
  if (stream == NULL) {
    ERROR("No stream0 object!\n");
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  if (ppkt_num != NULL) {
    *ppkt_num = 1;
  }
  *pdest = stream->send_buf->buf;
  if (session->mode == NGHQ_MODE_MULTICAST) {
    ngtcp2_conn_handshake_completed(session->ngtcp2_session);
  }
  return stream->send_buf->buf_len;
}

int nghq_transport_recv_stream0_data (ngtcp2_conn *conn, uint64_t offset,
                                      const uint8_t *data, size_t datalen,
                                      void *user_data) {
  DEBUG("nghq_transport_recv_stream0_data(%p, %p, %lu, %p)\n", (void *) conn,
        (void *) data, datalen, user_data);
  int rv = NGHQ_OK;
  nghq_session *session = (nghq_session *) user_data;

  if (session->mode == NGHQ_MODE_MULTICAST) {
    rv = nghq_feed_transport_params (session, data, datalen);
  } else {
    session->callbacks.recv_control_data_callback (session, data, datalen,
                                                   session->session_user_data);
  }

  return rv;
}

int nghq_transport_handshake_completed (ngtcp2_conn *conn, void *user_data) {
  DEBUG ("nghq_transport_handshake_completed(%p, %p)\n", (void *) conn,
         user_data);
  nghq_session *session = (nghq_session *) user_data;
  if ((session->mode == NGHQ_MODE_MULTICAST) &&
      (session->role == NGHQ_ROLE_CLIENT)) {
    /* This should open Stream 4 for us */
    nghq_req_stream_new(session);
  }
  session->handshake_complete = 1;
  return 0;
}

/* DEBUGGING ONLY */
int nghq_transport_recv_version_negotiation (ngtcp2_conn *conn,
                                             const ngtcp2_pkt_hd *hd,
                                             const uint32_t *sv, size_t nsv,
                                             void *user_data) {
  DEBUG ("nghq_transport_recv_version_negotiation(%p, (%x, %x, %lu, %lu, %u), "
         "%u, %lu, %p)\n", (void *) conn, hd->flags, hd->type, hd->conn_id,
         hd->pkt_num, hd->version, *sv, nsv, user_data);
  return 0;
}
/*/DEBUGGING ONLY */

int nghq_transport_recv_server_stateless_retry (ngtcp2_conn *conn,
                                                void *user_data) {
  DEBUG ("nghq_transport_recv_server_stateless_retry(%p, %p)\n", (void *) conn,
         user_data);
  return 0;
}

ssize_t nghq_transport_encrypt (ngtcp2_conn *conn, uint8_t *dest,
                                size_t destlen, const uint8_t *plaintext,
                                size_t plaintextlen, const uint8_t *key,
                                size_t keylen, const uint8_t *nonce,
                                size_t noncelen, const uint8_t *ad,
                                size_t adlen, void *user_data) {
  DEBUG ("nghq_transport_encrypt(%p, dest(%lu), plaintext(%lu), key(%lu), "
         "nonce(%lu), ad(%lu), %p)\n", (void *) conn, destlen, plaintextlen,
         keylen, noncelen, adlen, user_data);
  nghq_session *session = (nghq_session *) user_data;
  return session->callbacks.encrypt_callback (session, plaintext, plaintextlen,
                                              nonce, noncelen, ad, adlen,
                                              dest, destlen,
                                              session->session_user_data);
}

ssize_t nghq_transport_decrypt (ngtcp2_conn *conn, uint8_t *dest,
                                size_t destlen, const uint8_t *ciphertext,
                                size_t ciphertextlen, const uint8_t *key,
                                size_t keylen, const uint8_t *nonce,
                                size_t noncelen, const uint8_t *ad,
                                size_t adlen, void *user_data) {
  DEBUG ("nghq_transport_decrypt(%p, dest(%lu), ciphertext(%lu), key(%lu), "
         "nonce(%lu), ad(%lu), %p)\n", (void *) conn, destlen, ciphertextlen,
         keylen, noncelen, adlen, user_data);
  nghq_session *session = (nghq_session *) user_data;
  return session->callbacks.decrypt_callback (session, ciphertext,
                                              ciphertextlen, nonce, noncelen,
                                              ad, adlen, dest, destlen,
                                              session->session_user_data);
}

int nghq_transport_recv_stream_data (ngtcp2_conn *conn, uint64_t stream_id,
                                     uint8_t fin, uint64_t stream_offset,
                                     const uint8_t *data, size_t datalen,
                                     void *user_data, void *stream_user_data) {
  DEBUG ("nghq_transport_recv_stream_data(%p, %lu, %x, data(%lu), %p, %p)\n",
         (void *) conn, stream_id, fin, datalen, user_data, stream_user_data);
  nghq_session* session = (nghq_session *) user_data;
  nghq_stream* stream = nghq_stream_id_map_find(session->transfers, stream_id);
  size_t data_offset = 0;
  int rv;

  if (stream == NULL) {
    if (CLIENT_REQUEST_STREAM(stream_id)) {
      /* New stream time! */
      DEBUG("Seen start of new stream %lu\n", stream_id);
      stream = nghq_stream_new(stream_id);
      if (stream == NULL) {
        return NGTCP2_ERR_NOMEM;
      }
      nghq_stream_id_map_add(session->transfers, stream_id, stream);

      if ((stream_id == 4) && (session->mode == NGHQ_MODE_MULTICAST)) {
        /*
         * Don't feed the magic packet into nghq_recv_stream_data as it will
         * upset it. Just return 0 so that stream 4 is at least open, ready
         * to send our first PUSH_PROMISE
         */
        return 0;
      }
    } else if (SERVER_PUSH_STREAM(stream_id)) {
      /* Find the server push stream! */
      uint64_t push_id = _get_varlen_int(data, &data_offset);
      stream = nghq_stream_id_map_find(session->promises, push_id);
      if (stream == NULL) {
        ERROR("Received new server push stream %lu, but Push ID %lu has not "
              "been previously promised, or has already been started!\n",
              stream_id, push_id);
        return NGTCP2_ERR_CALLBACK_FAILURE;
      }
      nghq_stream_id_map_remove(session->promises, push_id);
      stream->stream_id = stream_id;
      nghq_stream_id_map_add(session->transfers, stream_id, stream);
      DEBUG("New server push stream %lu starts push promise %lu\n",
            stream_id, push_id);
    }
  }

  if (stream->stream_id != stream_id) {
    abort();
  }

  rv = nghq_recv_stream_data(session, stream, data + data_offset,
                           datalen - data_offset, stream_offset + data_offset);
  if (rv == NGHQ_NOT_INTERESTED) {
    /* Client has indicated it doesn't care about this stream anymore, so stop */
    nghq_stream_cancel (session, stream, 0);
  }
  return rv;
}

int nghq_transport_stream_close (ngtcp2_conn *conn, uint64_t stream_id,
                                 uint16_t app_error_code, void *user_data,
                                 void *stream_user_data) {
  DEBUG ("nghq_transport_stream_close(%p, %lu, %u, %p, %p)\n", (void *) conn,
         stream_id, app_error_code, user_data, stream_user_data);
  nghq_session* session = (nghq_session *) user_data;
  nghq_stream* stream = nghq_stream_id_map_find(session->transfers, stream_id);
  if (stream == NULL) {
    ERROR("Unknown stream ID %lu is closing\n", stream_id);
  }
  if (stream->stream_id != stream_id) {
    abort();
  }
  return nghq_stream_close(session, stream, app_error_code);
}

int nghq_transport_acked_stream_data_offset (ngtcp2_conn *conn,
                                             uint64_t stream_id,
                                             uint64_t offset, size_t datalen,
                                             void *user_data,
                                             void *stream_user_data) {
  DEBUG("nghq_transport_acked_stream_data_offset(%p, %lu, %lu, %lu, %p, %p)\n",
        (void *) conn, stream_id, offset, datalen, user_data, stream_user_data);
  return 0;
}

int nghq_transport_recv_stateless_reset (ngtcp2_conn *conn,
                                         const ngtcp2_pkt_hd *hd,
                                         const ngtcp2_pkt_stateless_reset *sr,
                                         void *user_data) {
  DEBUG("nghq_transport_recv_stateless_reset(%p, (%x, %x, %lu, %lu, %u), (%p), %p)\n",
        (void *) conn, hd->flags, hd->type, hd->conn_id, hd->pkt_num,
        hd->version, (void *) sr, user_data);
  return 0;
}

int nghq_transport_extend_max_stream_id (ngtcp2_conn *conn,
                                         uint64_t max_stream_id,
                                         void *user_data) {
  DEBUG("nghq_transport_extend_max_stream_id(%p, %lu, %p)\n", (void *) conn,
        max_stream_id, user_data);
  nghq_session* session = (nghq_session *) user_data;
  if (session->role == NGHQ_ROLE_CLIENT) {
    if ((max_stream_id % 4) == 0) {
      session->max_open_requests = max_stream_id;
    } else if ((max_stream_id % 4) == 2) {
      /* Future use? */
    }
  } else if (session->role == NGHQ_ROLE_SERVER) {
    if ((max_stream_id % 4) == 3) {
      session->max_open_server_pushes = max_stream_id;
    } else if ((max_stream_id % 4) == 1) {
      /* Future use? */
    }
  }
  return 0;
}

