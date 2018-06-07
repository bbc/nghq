#ifndef _NGHQ_CRYPTO_FNS_OPENSSL_H_
#define _NGHQ_CRYPTO_FNS_OPENSSL_H_
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

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

extern void crypto_init();
extern bool crypto_hmac_sha1(const uint8_t *key, size_t key_len,
                             const uint8_t *data, size_t data_len,
                             uint8_t *result);
extern bool crypto_hmac_sha256(const uint8_t *key, size_t key_len,
                               const uint8_t *data, size_t data_len,
                               uint8_t *result);
extern bool crypto_random_bytes(uint8_t *data, size_t dlen);
extern bool crypto_pkcs5_pbkdf2_hmac_sha1(const char *pass, size_t pass_len,
                                          const uint8_t* salt, size_t salt_len,
                                          size_t iterations, int keybits,
                                          uint8_t *key_data);
extern size_t crypto_base64_encoded_length(size_t binary_len);
extern void crypto_base64_encode_data(char *encoded, const uint8_t *data,
                                      size_t data_len);
extern size_t crypto_base64_max_decoded_length(size_t encoded_len);
extern size_t crypto_base64_decode_data(uint8_t *data, size_t data_len,
                                        const char *encoded,
                                        size_t encoded_len);
extern void *crypto_sha256_init();
extern void crypto_sha256_free(void *ctx);
extern void crypto_sha256_append_data(void *ctx, const char *buffer,
                                      size_t buffer_len);
extern void crypto_sha256_finish(void *ctx, uint8_t *buffer);
extern size_t crypto_sha256_digest_length();
extern void crypto_pubcert_free(void *cert);
extern void *crypto_pubcert_from_pem_file(FILE *pem_fp, void **cert);
extern void crypto_pubcert_from_buffer(const void *data, size_t len,
                                       void **cert);
extern void *crypto_pubcert_copy(void *other_cert);
extern int crypto_pubcert_verify(const void *data, size_t len,
                                 const uint8_t *signature, size_t sig_len,
                                 void *cert);
extern int crypto_pubcert_check_ip(void *cert, const void *inaddr,
                                   size_t inaddr_len);
extern int crypto_pubcert_check_host(void *cert, const char *hostname,
                                     size_t hostname_len);
extern const char *crypto_pubcert_type_string(void *cert);
extern void crypto_privkey_free(void *key);
extern void *crypto_privkey_from_pem_file(FILE *fp, void **key);
extern void crypto_privkey_from_buffer(const void *data, size_t len,
                                       void **key);
extern void *crypto_privkey_copy(void *other_key);
extern void *crypto_privkey_sign(const void *data, size_t len, size_t *ret_len,
                                 void *key);
extern void crypto_privkey_free_data(void *data);
extern const char *crypto_privkey_type_string(void *key);

#ifdef __cplusplus
} // extern "C"
#endif

#endif //_NGHQ_CRYPTO_FNS_OPENSSL_H_

// vim:ts=8:sts=4:sw=4:expandtab:
