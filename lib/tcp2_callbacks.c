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
#include "multicast.h"
#if DEBUGOUT
#include <stdio.h>
#endif
#include <string.h>

void nghq_transport_debug (void *user_data, const char *format, ...) {
#ifdef DEBUGOUT
  va_list args;
  va_start (args, format);
  vfprintf(stderr, format, args);
  putc('\n', stderr);
#endif
}

int nghq_transport_send_client_initial (ngtcp2_conn *conn, void *user_data) {
  DEBUG("nghq_transport_send_client_initial(%p, %p)\n",
        (void *)conn, user_data);
  nghq_session *session = (nghq_session *) user_data;
  ssize_t params_size;
  uint8_t* buf;

  if (session->mode == NGHQ_MODE_MULTICAST) {
    params_size = nghq_get_transport_params (session, &buf);
    if (params_size < 0) {
      return params_size;
    }
  } else {
    abort();
  }

  return ngtcp2_conn_submit_crypto_data (conn, NGTCP2_CRYPTO_LEVEL_INITIAL, buf,
                                         params_size);
}

ssize_t nghq_transport_send_client_handshake (ngtcp2_conn *conn, uint32_t flags,
                                              const uint8_t **pdest,
                                              void *user_data) {
  DEBUG("nghq_transport_send_client_handshake(%p, %x, %p, %p)\n", (void *) conn,
        flags, (void *) pdest, user_data);
  nghq_session *session = (nghq_session *) user_data;

  *pdest = malloc (session->send_buf->buf_len);
  if (!*pdest) return NGTCP2_ERR_NOMEM;

  ngtcp2_conn_handshake_completed(conn);

  return session->send_buf->buf_len;
}

int nghq_transport_recv_client_initial (ngtcp2_conn *conn,
                                        const ngtcp2_cid *dcid,
                                        void *user_data) {
#ifdef DEBUGOUT
  char dcid_hex[dcid->datalen*2 + 1];
  int i;
  for (i = 0; i < dcid->datalen; i++) {
    sprintf(dcid_hex + (i*2), "%02X", dcid->data[i]);
  }
  dcid_hex[dcid->datalen*2] = 0;
#endif
  DEBUG("nghq_transport_recv_client_initial(%p, %.*s, %p)\n", (void *) conn,
        dcid->datalen*2, dcid_hex, user_data);
  int rv = ngtcp2_conn_install_initial_key(conn, quic_mcast_magic,
                                           quic_mcast_magic, quic_mcast_magic,
                                           quic_mcast_magic, quic_mcast_magic,
                                           quic_mcast_magic,
                                           LENGTH_QUIC_MCAST_MAGIC,
                                           LENGTH_QUIC_MCAST_MAGIC);
  if (rv != 0) {
    ERROR("Couldn't set ngtcp2_conn_set_handshake_tx_keys: %s\n",
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

int nghq_transport_recv_crypto_data (ngtcp2_conn *conn,
                                     ngtcp2_crypto_level crypto_level,
                                     uint64_t offset, const uint8_t *data,
                                     size_t datalen, void *user_data) {
  DEBUG("nghq_transport_recv_crypto_data(%p, %p, %lu, %p)\n", (void *) conn,
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
    /* This should open Stream 0 for us */
    nghq_req_stream_new(session);
  }
  return 0;
}

/* DEBUGGING ONLY */
int nghq_transport_recv_version_negotiation (ngtcp2_conn *conn,
                                             const ngtcp2_pkt_hd *hd,
                                             const uint32_t *sv, size_t nsv,
                                             void *user_data) {
#ifdef DEBUGOUT
  char dcid_hex[hd->dcid.datalen];
  int i;
  for (i = 0; i < hd->dcid.datalen; i++) {
    sprintf(dcid_hex + (i*2), "%02X", hd->dcid.data[i]);
  }
#endif
  DEBUG ("nghq_transport_recv_version_negotiation(%p, (%x, %x, %.*s, %lu, %u), "
         "%u, %lu, %p)\n", (void *) conn, hd->flags, hd->type,
         hd->dcid.datalen*2, dcid_hex, hd->pkt_num, hd->version, *sv, nsv,
         user_data);
  return 0;
}
/*/DEBUGGING ONLY */

int nghq_transport_recv_server_stateless_retry (ngtcp2_conn *conn,
                                                void *user_data) {
  DEBUG ("nghq_transport_recv_server_stateless_retry(%p, %p)\n", (void *) conn,
         user_data);
  return 0;
}

int nghq_transport_encrypt (ngtcp2_conn *conn, uint8_t *dest,
                            const ngtcp2_crypto_aead *aead,
                            const uint8_t *plaintext, size_t plaintextlen,
                            const uint8_t *key, const uint8_t *nonce,
                            size_t noncelen, const uint8_t *ad, size_t adlen,
                            void *user_data) {
  DEBUG ("nghq_transport_encrypt(%p, dest(%lu), %p - aead(%p), plaintext(%lu),"
         "key(%lu), nonce(%lu), ad(%lu), %p)\n", (void *) conn, sizeof(dest),
         (void *) aead, aead->native_handle, plaintextlen, sizeof(key),
         noncelen, adlen, user_data);
  nghq_session *session = (nghq_session *) user_data;
  switch (session->callbacks.encrypt_callback (session, plaintext, plaintextlen,
                                              nonce, noncelen, ad, adlen, key,
                                              dest, session->session_user_data))
  {
    case NGHQ_OK:
      return 0;
    case NGHQ_CRYPTO_ERROR:
      return NGTCP2_ERR_TLS_DECRYPT;
    default:
      return NGTCP2_ERR_CALLBACK_FAILURE;
  }
}

int nghq_transport_decrypt (ngtcp2_conn *conn, uint8_t *dest,
                            const ngtcp2_crypto_aead *aead,
                            const uint8_t *ciphertext, size_t ciphertextlen,
                            const uint8_t *key, const uint8_t *nonce,
                            size_t noncelen, const uint8_t *ad, size_t adlen,
                            void *user_data) {
  DEBUG ("nghq_transport_decrypt(%p, dest(%lu),, %p - aead(%p) ciphertext(%lu),"
         "key(%lu), nonce(%lu), ad(%lu), %p)\n", (void *) conn, sizeof(dest),
         (void *) aead, aead->native_handle, ciphertextlen, sizeof(key),
         noncelen, adlen, user_data);
  nghq_session *session = (nghq_session *) user_data;
  switch (session->callbacks.decrypt_callback (session, ciphertext,
                                               ciphertextlen, key, nonce,
                                               noncelen, ad, adlen, dest,
                                               session->session_user_data)) {
    case NGHQ_OK:
      return 0;
    case NGHQ_CRYPTO_ERROR:
      return NGTCP2_ERR_TLS_DECRYPT;
    default:
      return NGTCP2_ERR_CALLBACK_FAILURE;
  }
}

static uint8_t _hp_mask[5] = {0, 0, 0, 0, 0};

int nghq_transport_hp_mask (ngtcp2_conn *conn, uint8_t *dest,
                            const ngtcp2_crypto_cipher *hp,
                            const uint8_t *hp_key, const uint8_t *sample,
                            void *user_data)
{
  /* TODO? */
  memcpy (dest, _hp_mask, 5);
  return 0;
}

int nghq_transport_recv_stream_data (ngtcp2_conn *conn, int64_t stream_id,
                                     int fin, uint64_t stream_offset,
                                     const uint8_t *data, size_t datalen,
                                     void *user_data, void *stream_user_data) {
  DEBUG ("nghq_transport_recv_stream_data(%p, %lu, %x, data(%lu), %p, %p)\n",
         (void *) conn, stream_id, fin, datalen, user_data, stream_user_data);
  nghq_session* session = (nghq_session *) user_data;
  nghq_stream* stream = nghq_stream_id_map_find(session->transfers, stream_id);
  size_t data_offset = 0;
  int rv;

  if (stream == NULL) {
    /* New stream time! */
    DEBUG("Seen start of new stream %lu\n", stream_id);
    stream = nghq_stream_new(stream_id);
    if (stream == NULL) {
      return NGTCP2_ERR_NOMEM;
    }
    nghq_stream_id_map_add(session->transfers, stream_id, stream);
    if (CLIENT_REQUEST_STREAM(stream_id)) {
      if ((stream_id == 0) && (session->mode == NGHQ_MODE_MULTICAST)) {
        /*
         * Don't feed the magic packet into nghq_recv_stream_data as it will
         * upset it. Just return 0 so that stream 0 is at least open, ready
         * to send our first PUSH_PROMISE
         */
        return 0;
      }
    }
  }

  if (SERVER_PUSH_STREAM(stream_id) && stream_offset==0 &&
        (_get_varlen_int(data, &data_offset, datalen) == 0x1)) {
    /* Find the server push stream! */
    nghq_stream* push_stream;
    uint64_t push_id = _get_varlen_int(data + data_offset, &data_offset, datalen);
    if (data_offset > datalen) {
      ERROR("Not enough data for push ID in stream data for stream %lu\n",
            stream_id);
      return NGHQ_ERROR;
    }
    push_stream = nghq_stream_id_map_find(session->promises, push_id);
    if (push_stream == NULL) {
      ERROR("Received new server push stream %lu, but Push ID %lu has not "
            "been previously promised, or has already been started!\n",
            stream_id, push_id);
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    /* copy over push information to stream */
    stream->push_id = push_id;
    stream->user_data = push_stream->user_data;

    nghq_stream_id_map_remove(session->promises, push_id);
    nghq_stream_ended(session, push_stream);

    DEBUG("Server push stream %lu starts push promise %lu\n",
          stream_id, push_id);
  }

  if (stream->stream_id != stream_id) {
    abort();
  }

  rv = nghq_recv_stream_data(session, stream, data, datalen, stream_offset, fin);

  if (rv == NGHQ_NOT_INTERESTED) {
    /* Client has indicated it doesn't care about this stream anymore, stop */
    nghq_stream_cancel (session, stream, 0);
  }
  return rv;
}

int nghq_transport_stream_open (ngtcp2_conn *conn, int64_t stream_id,
                                void *user_data) {
  DEBUG ("nghq_transport_stream_open(%p, %ld, %p)\n", (void *) conn, stream_id,
         user_data);
  /* TODO: Open a new NGHQ stream? */
  return 0;
}

int nghq_transport_stream_close (ngtcp2_conn *conn, int64_t stream_id,
                                 uint64_t app_error_code, void *user_data,
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

int nghq_transport_stream_reset (ngtcp2_conn *conn, int64_t stream_id,
                                 uint64_t final_size, uint64_t app_error_code,
                                 void *user_data, void *stream_user_data) {
  DEBUG("nghq_transport_stream_reset(%p, %ld, %lu, %lu, %p, %p)\n",
        (void *) conn, stream_id, final_size, app_error_code, user_data,
        stream_user_data);
  return nghq_transport_stream_close (conn, stream_id, app_error_code,
                                      user_data, stream_user_data);
}

int nghq_transport_acked_stream_data_offset (ngtcp2_conn *conn,
                                             int64_t stream_id,
                                             uint64_t offset, size_t datalen,
                                             void *user_data,
                                             void *stream_user_data) {
  DEBUG("nghq_transport_acked_stream_data_offset(%p, %lu, %lu, %lu, %p, %p)\n",
        (void *) conn, stream_id, offset, datalen, user_data, stream_user_data);
  return 0;
}

int nghq_transport_acked_crypto_offset (ngtcp2_conn *conn,
                                        ngtcp2_crypto_level crypto_level,
                                        uint64_t offset, size_t datalen,
                                        void *user_data) {
#if DEBUGOUT
  char *crypto_level_s;
  switch (crypto_level) {
    case NGTCP2_CRYPTO_LEVEL_INITIAL:
      crypto_level_s = "Initial";
      break;
    case NGTCP2_CRYPTO_LEVEL_HANDSHAKE:
      crypto_level_s = "Handshake";
      break;
    case NGTCP2_CRYPTO_LEVEL_APP:
      crypto_level_s = "Application";
      break;
    case NGTCP2_CRYPTO_LEVEL_EARLY:
      crypto_level_s = "Early";
      break;
    default:
      crypto_level_s = "Unknown";
  }
#endif
  DEBUG("nghq_transport_acked_crypto_offset(%p, %s, %lu, %lu, %p)\n",
        (void *) conn, crypto_level_s, offset, datalen, user_data);
  return 0;
}

int nghq_transport_recv_stateless_reset (ngtcp2_conn *conn,
                                         const ngtcp2_pkt_stateless_reset *sr,
                                         void *user_data) {
  DEBUG("nghq_transport_recv_stateless_reset(%p, (%p), %p)\n",
        (void *) conn, (void *) sr, user_data);
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

