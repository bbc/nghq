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

ssize_t nghq_transport_send_client_initial (ngtcp2_conn *conn, uint32_t flags,
                                            uint64_t *ppkt_num,
                                            const uint8_t **pdest,
                                            void *user_data) {
  DEBUG("nghq_transport_send_client_initial(%p, %x, %lu, %p, %p)\n",
        (void *)conn, flags, *ppkt_num, (void *) pdest, user_data);
  return 0;
}

ssize_t nghq_transport_send_client_handshake (ngtcp2_conn *conn, uint32_t flags,
                                              const uint8_t **pdest,
                                              void *user_data) {
  DEBUG("nghq_transport_send_client_handshake(%p, %x, %p, %p)\n", (void *) conn,
        flags, (void *) pdest, user_data);
  return 0;
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
        (void *) conn, flags, *ppkt_num, (void *) *pdest, user_data);
  nghq_session *session = (nghq_session *) user_data;
  nghq_stream *stream = nghq_stream_id_map_find(session->transfers, 0);
  if (stream == NULL) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  *ppkt_num = 1;
  *pdest = stream->send_buf->buf;
  return stream->send_buf->buf_len;
}

int nghq_transport_recv_stream0_data (ngtcp2_conn *conn, const uint8_t *data,
                                      size_t datalen, void *user_data) {
  DEBUG("nghq_transport_recv_stream0_data(%p, %p, %lu, %p)\n", (void *) conn,
        (void *) data, datalen, user_data);
  int rv;
  ngtcp2_transport_params params;
  nghq_session *session = (nghq_session *) user_data;

  if (session->mode == NGHQ_MODE_MULTICAST) {
    if (session->role == NGHQ_ROLE_SERVER) {
      rv = ngtcp2_decode_transport_params(&params,
             NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO, data, datalen);
    } else {
      rv = ngtcp2_decode_transport_params(&params,
             NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS, data, datalen);
    }
    if (rv != 0) {
      ERROR("ngtcp2_decode_transport_params failed: %s\n", ngtcp2_strerror(rv));
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }
  } else {
    /* Unicast: TODO */
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
  if (session->role == NGHQ_ROLE_SERVER) {
    rv = ngtcp2_conn_set_remote_transport_params(session->ngtcp2_session,
           NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO, &params);
    if (rv != 0) {
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }
  }
  return 0;
}

/* DEBUGGING ONLY */
int nghq_transport_send_pkt (ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd,
                             void *user_data) {
  DEBUG("nghq_transport_send_pkt(%p, (%x, %x, %lu, %lu, %u), %p)\n",
        (void *) conn, hd->flags, hd->type, hd->conn_id, hd->pkt_num,
        hd->version, user_data);
  return 0;
}

int nghq_transport_send_frame (ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd,
                               const ngtcp2_frame *fr, void *user_data) {
  DEBUG("nghq_transport_send_frame(%p, (%x, %x, %lu, %lu, %u), ..., %p)\n",
        (void *) conn, hd->flags, hd->type, hd->conn_id, hd->pkt_num,
        hd->version, user_data);
  nghq_session *session = (nghq_session *) user_data;
  if (session->mode == NGHQ_MODE_MULTICAST) {
    return nghq_mcast_swallow (session, hd, fr);
  }
  return 0;
}

int nghq_transport_recv_pkt (ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd,
                             void *user_data) {
  DEBUG ("nghq_transport_recv_pkt(%p, (%x, %x, %lu, %lu, %u), %p)\n",
        (void *) conn, hd->flags, hd->type, hd->conn_id, hd->pkt_num,
        hd->version, user_data);
  return 0;
}

int nghq_transport_recv_frame (ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd,
                               const ngtcp2_frame *fr, void *user_data) {
  DEBUG ("nghq_transport_recv_frame(%p, (%x, %x, %lu, %lu, %u), ..., %p)\n",
         (void *) conn, hd->flags, hd->type, hd->conn_id, hd->pkt_num,
         hd->version, user_data);
  return 0;
}
/*/DEBUGGING ONLY */

int nghq_transport_handshake_completed (ngtcp2_conn *conn, void *user_data) {
  DEBUG ("nghq_transport_handshake_completed(%p, %p)\n", (void *) conn,
         user_data);
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
                                     uint8_t fin, const uint8_t *data,
                                     size_t datalen, void *user_data,
                                     void *stream_user_data) {
  DEBUG ("nghq_transport_recv_stream_data(%p, %lu, %x, data(%lu), %p, %p)\n",
         (void *) conn, stream_id, fin, datalen, user_data, stream_user_data);
  nghq_session* session = (nghq_session *) user_data;
  nghq_stream* stream = nghq_stream_id_map_find(session->transfers, stream_id);
  if (stream == NULL) {
    /* New stream time! */
    DEBUG("Seen start of new stream %lu\n", stream_id);
    stream = nghq_stream_new(stream_id);
    if (stream == NULL) {
      return NGTCP2_ERR_NOMEM;
    }
    nghq_stream_id_map_add(session->transfers, stream_id, stream);
  }

  if (stream->stream_id != stream_id) {
    abort();
  }
  return nghq_recv_stream_data(session, stream, data, datalen);
}

int nghq_transport_stream_close (ngtcp2_conn *conn, uint64_t stream_id,
                                 uint16_t app_error_code, void *user_data,
                                 void *stream_user_data) {
  DEBUG ("nghq_transport_stream_close(%p, %lu, %u, %p, %p)\n", (void *) conn,
         stream_id, app_error_code, user_data, stream_user_data);
  nghq_session* session = (nghq_session *) user_data;
  nghq_stream* stream = (nghq_stream *) stream_user_data;
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

