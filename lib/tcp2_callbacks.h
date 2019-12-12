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

#ifndef LIB_TCP2_CALLBACKS_H_
#define LIB_TCP2_CALLBACKS_H_

#include <ngtcp2/ngtcp2.h>

void nghq_transport_debug (void *user_data, const char *format, ...);

int nghq_transport_send_client_initial (ngtcp2_conn *conn, void *user_data);

ssize_t nghq_transport_send_client_handshake (ngtcp2_conn *conn, uint32_t flags,
                                              const uint8_t **pdest,
                                              void *user_data);

int nghq_transport_recv_client_initial (ngtcp2_conn *conn,
                                        const ngtcp2_cid *dcid,
                                        void *user_data);

ssize_t nghq_transport_send_server_handshake (ngtcp2_conn *conn,
                                                uint32_t flags,
                                                uint64_t *ppkt_num,
                                                const uint8_t **pdest,
                                                void *user_data);

int nghq_transport_recv_crypto_data (ngtcp2_conn *conn,
                                     ngtcp2_crypto_level crypto_level,
                                     uint64_t offset, const uint8_t *data,
                                     size_t datalen, void *user_data);

/* DEBUGGING ONLY */
int nghq_transport_send_pkt (ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd,
                             void *user_data);

/*int nghq_transport_send_frame (ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd,
                               const ngtcp2_frame *fr, void *user_data);*/

int nghq_transport_recv_pkt (ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd,
                             void *user_data);

/*int nghq_transport_recv_frame (ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd,
                               const ngtcp2_frame *fr, void *user_data);*/
/*/DEBUGGING ONLY */

int nghq_transport_handshake_completed (ngtcp2_conn *conn, void *user_data);

/* DEBUGGING ONLY */
int nghq_transport_recv_version_negotiation (ngtcp2_conn *conn,
                                             const ngtcp2_pkt_hd *hd,
                                             const uint32_t *sv, size_t nsv,
                                             void *user_data);
/*/DEBUGGING ONLY */

int nghq_transport_recv_server_stateless_retry (ngtcp2_conn *conn,
                                                void *user_data);

int nghq_transport_encrypt (ngtcp2_conn *conn, uint8_t *dest,
                            const ngtcp2_crypto_aead *aead,
                            const uint8_t *plaintext, size_t plaintextlen,
                            const uint8_t *key, const uint8_t *nonce,
                            size_t noncelen, const uint8_t *ad, size_t adlen,
                            void *user_data);

int nghq_transport_decrypt (ngtcp2_conn *conn, uint8_t *dest,
                            const ngtcp2_crypto_aead *aead,
                            const uint8_t *ciphertext, size_t ciphertextlen,
                            const uint8_t *key, const uint8_t *nonce,
                            size_t noncelen, const uint8_t *ad, size_t adlen,
                            void *user_data);

int nghq_transport_hp_mask (ngtcp2_conn *conn, uint8_t *dest,
                            const ngtcp2_crypto_cipher *hp,
                            const uint8_t *hp_key, const uint8_t *sample,
                            void *user_data);

int nghq_transport_recv_stream_data (ngtcp2_conn *conn, int64_t stream_id,
                                     int fin, uint64_t stream_offset,
                                     const uint8_t *data, size_t datalen,
                                     void *user_data, void *stream_user_data);

int nghq_transport_stream_open (ngtcp2_conn *conn, int64_t stream_id,
                                void *user_data);

int nghq_transport_stream_close (ngtcp2_conn *conn, int64_t stream_id,
                                 uint64_t app_error_code, void *user_data,
                                 void *stream_user_data);

int nghq_transport_stream_reset (ngtcp2_conn *conn, int64_t stream_id,
                                 uint64_t final_size, uint64_t app_error_code,
                                 void *user_data, void *stream_user_data);

int nghq_transport_acked_stream_data_offset (ngtcp2_conn *conn,
                                             int64_t stream_id,
                                             uint64_t offset, size_t datalen,
                                             void *user_data,
                                             void *stream_user_data);

int nghq_transport_acked_crypto_offset (ngtcp2_conn *conn,
                                        ngtcp2_crypto_level crypto_level,
                                        uint64_t offset, size_t datalen,
                                        void *user_data);

int nghq_transport_recv_stateless_reset (ngtcp2_conn *conn,
                                         const ngtcp2_pkt_stateless_reset *sr,
                                         void *user_data);

int nghq_transport_extend_max_stream_id (ngtcp2_conn *conn,
                                         uint64_t max_stream_id,
                                         void *user_data);

#endif /* LIB_TCP2_CALLBACKS_H_ */
