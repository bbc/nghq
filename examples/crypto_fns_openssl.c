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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/opensslv.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h>

#include "crypto_fns_openssl.h"

void
crypto_init()
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
#else
    OPENSSL_init_crypto(0, NULL);
    OPENSSL_init_ssl(0, NULL);
#endif
}

bool
crypto_hmac_sha1(const uint8_t *key, size_t key_len, const uint8_t *data,
                 size_t data_len, uint8_t *result)
{
    return HMAC(EVP_sha1(), key, key_len, data, data_len, result, NULL);
}

bool
crypto_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data,
                   size_t data_len, uint8_t *result)
{
    return HMAC(EVP_sha256(), key, key_len, data, data_len, result, NULL);
}

bool
crypto_random_bytes(uint8_t *data, size_t dlen)
{
    return RAND_bytes(data, dlen) == 1;
}

bool
crypto_pkcs5_pbkdf2_hmac_sha1(const char *pass, size_t pass_len,
                              const uint8_t* salt, size_t salt_len,
                              size_t iterations, int keybits, uint8_t *key_data)
{
    return PKCS5_PBKDF2_HMAC_SHA1(pass, (int)pass_len, salt, (int)salt_len,
                                  (int)iterations, keybits, key_data) == 1;
}

size_t
crypto_base64_encoded_length(size_t binary_len)
{
    return ((binary_len+2)/3)*4+1;
}

void
crypto_base64_encode_data(char *encoded, const uint8_t *data, size_t data_len)
{
    EVP_EncodeBlock((uint8_t*)encoded, data, data_len);
}

size_t
crypto_base64_max_decoded_length(size_t encoded_len)
{
    return ((encoded_len+3)/4)*3;
}

size_t
crypto_base64_decode_data(uint8_t *data, size_t data_len, const char *encoded,
                          size_t encoded_len)
{
    // OpenSSL unhelpfully returns the decoded size including the padding
    size_t decoded_len = EVP_DecodeBlock(data, (const uint8_t*)encoded,
                                         encoded_len);
    // Subtract one for each padding character at the end of the decoded block
    // to get the real data size.
    if (encoded_len > 0 && encoded[encoded_len-1] == '=') decoded_len--;
    if (encoded_len > 0 && encoded[encoded_len-2] == '=') decoded_len--;

    return decoded_len;
}

void *
crypto_sha256_init()
{
    SHA256_CTX *ret = calloc(1, sizeof(SHA256_CTX));
    if (ret) SHA256_Init(ret);
    return ret;
}

void
crypto_sha256_free(void *ctx)
{
    if (ctx) free(ctx);
}

void
crypto_sha256_append_data(void *ctx, const char *buffer,
                                  size_t buffer_len)
{
    if (!ctx) return;
    SHA256_Update((SHA256_CTX*)ctx, buffer, buffer_len);
}

void
crypto_sha256_finish(void *ctx, uint8_t *buffer)
{
    if (!buffer) return;
    if (!ctx) {
        memset(buffer, 0, SHA256_DIGEST_LENGTH);
        return;
    }
    SHA256_Final(buffer, (SHA256_CTX*)ctx);
}

size_t crypto_sha256_digest_length()
{
    return SHA256_DIGEST_LENGTH;
}

void
crypto_pubcert_free(void *cert)
{
    X509_free((X509*)cert);
}

void *
crypto_pubcert_from_pem_file(FILE *pem_fp, void **cert)
{
    return PEM_read_X509(pem_fp, (X509**)cert, NULL, NULL);
}

void
crypto_pubcert_from_buffer(const void *data, size_t len, void **cert)
{
    BIO *bp = BIO_new_mem_buf(data, len);
    PEM_read_bio_X509(bp, (X509**)cert, NULL, NULL);
    BIO_free(bp);
}

void *
crypto_pubcert_copy(void *other_cert)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    /*
     * X509_up_ref doesn't exist in older versions of OpenSSL, so actually
     * copy the structure.
     */

    BIO *bio = BIO_new(BIO_s_mem());
    X509 *copycert = NULL;
    PEM_write_bio_X509 (bio, (X509*)other_cert);
    copycert = PEM_read_bio_X509 (bio, NULL, 0, NULL);
    return (void *) copycert;
#else
    X509_up_ref((X509*)other_cert);
    return other_cert;
#endif
}

int
crypto_pubcert_verify(const void *data, size_t len, const uint8_t *signature,
                      size_t sig_len, void *cert)
{
    /* verify the certificate before checking the signature */
    X509_STORE_CTX *x509_ctx = X509_STORE_CTX_new();
    X509_STORE *x509_ca_store = X509_STORE_new();
    if (X509_STORE_load_locations(x509_ca_store, X509_get_default_cert_file(),
                                  X509_get_default_cert_dir())
            != 1) {
        fprintf(stderr, "Unable to load CA bundle '%s':", X509_get_default_cert_file());
        for (unsigned long err = ERR_get_error(); err; err = ERR_get_error()) {
            fprintf(stderr, "   %lu:%s:%s:%s", err, ERR_lib_error_string(err),
                    ERR_func_error_string(err), ERR_reason_error_string(err));
        }
        return 0;
    }
    X509_STORE_CTX_init(x509_ctx, x509_ca_store, (X509*)cert,
                        NULL);
    if (X509_verify_cert(x509_ctx) != 1) {
        fprintf(stderr, "Certificate failed verification: %s",
                X509_verify_cert_error_string(
                    X509_STORE_CTX_get_error(x509_ctx)));
        X509_STORE_CTX_free(x509_ctx);
        X509_STORE_free(x509_ca_store);
        return 0;
    }
    X509_STORE_CTX_free(x509_ctx);
    X509_STORE_free(x509_ca_store);

    EVP_PKEY *pub_key = X509_get_pubkey((X509*)cert);
    if (pub_key == NULL) {
        fprintf(stderr, "No public key in certificate.");
        return 0;
    }

    EVP_MD_CTX *ctx;
    ctx = EVP_MD_CTX_create();

    const EVP_MD* md = EVP_get_digestbyname("SHA256");
    if (md == NULL) {
        fprintf(stdout, "Failed to get digest handler for SHA256.");
        EVP_MD_CTX_destroy(ctx);
        return 0;
    }

    int rc;

    rc = EVP_DigestVerifyInit(ctx, NULL, md, NULL, pub_key);
    if (rc != 1) {
        fprintf(stdout, "Could not initialise verify context.");
        EVP_MD_CTX_destroy(ctx);
        return 0;
    }

    rc = EVP_DigestVerifyUpdate(ctx, data, len);
    if (rc != 1) {
        fprintf(stdout, "Could not add data to be verified.");
        EVP_MD_CTX_destroy(ctx);
        return 0;
    }

    rc = EVP_DigestVerifyFinal(ctx, signature, sig_len);
    if (rc != 1) {
        fprintf(stdout, "Verification failed.");
        EVP_MD_CTX_destroy(ctx);
        return 0;
    }

    EVP_MD_CTX_destroy(ctx);
    return 1;
}

int
crypto_pubcert_check_ip(void *cert, const void *inaddr, size_t inaddr_len)
{
    return X509_check_ip((X509*)cert, (const unsigned char*)inaddr, inaddr_len,
                         0);
}

int
crypto_pubcert_check_host(void *cert, const char *hostname, size_t hostname_len)
{
    return X509_check_host((X509*)cert, hostname, hostname_len, 0, NULL);
}

const char *
crypto_pubcert_type_string(void *cert)
{
    const char *ret = NULL;

    if (cert) {
        EVP_PKEY *pub_key = X509_get_pubkey((X509*)cert);
        switch (EVP_PKEY_id(pub_key)) {
        case EVP_PKEY_RSA:
            ret = "rsa-sha256";
            break;
        case EVP_PKEY_DSA:
            ret = "dsa-sha256";
            break;
        case EVP_PKEY_EC:
            ret = "ec-sha256";
            break;
        default:
            break;
        }
    }

    return ret;
}

void crypto_privkey_free(void *key)
{
    EVP_PKEY_free((EVP_PKEY*)key);
}

void *
crypto_privkey_from_pem_file(FILE *fp, void **key)
{
    return PEM_read_PrivateKey(fp, (EVP_PKEY**)key, NULL, NULL);
}

void
crypto_privkey_from_buffer(const void *data, size_t len, void **key)
{
    BIO *bp = BIO_new_mem_buf(data, len);
    PEM_read_bio_PrivateKey(bp, (EVP_PKEY**)key, NULL, NULL);
    BIO_free(bp);
}

void *
crypto_privkey_copy(void *other_key)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    /*
     * EVP_PKEY_up_ref doesn't exist in older versions of OpenSSL, so actually
     * copy the structure.
     */
    EVP_PKEY* copykey = EVP_PKEY_new();
    EVP_PKEY_copy_parameters(copykey, (EVP_PKEY*)other_key);
    return (void *) copykey;
#else
    // Don't actually copy, just up the ref count
    EVP_PKEY_up_ref((EVP_PKEY*)other_key);
    return other_key;
#endif
}

void *
crypto_privkey_sign(const void *data, size_t len, size_t *ret_len, void *key)
{
    EVP_MD_CTX *ctx;
    const EVP_MD* md;
    int rc;
    
    *ret_len = 0;
    ctx = EVP_MD_CTX_create();
    md = EVP_get_digestbyname("SHA256");
    if (md == NULL) {
        fprintf(stdout, "Failed to get digest handler for SHA256.");
        EVP_MD_CTX_destroy(ctx);
        return NULL;
    }

    rc = EVP_DigestSignInit(ctx, NULL, md, NULL, (EVP_PKEY*)key);
    if (rc != 1) {
        fprintf(stdout, "Failed to initialise the signature context.");
        EVP_MD_CTX_destroy(ctx);
        return NULL;
    }

    rc = EVP_DigestSignUpdate(ctx, data, len);
    if (rc != 1) {
        fprintf(stdout, "Failed to add data to sign.");
        EVP_MD_CTX_destroy(ctx);
        return NULL;
    }

    size_t req = 0;
    rc = EVP_DigestSignFinal(ctx, NULL, &req);
    if (rc != 1) {
        fprintf(stdout, "Failed to get signed data size.");
        EVP_MD_CTX_destroy(ctx);
        return NULL;
    }

    size_t first_req = req;
    uint8_t *sig_buf = (uint8_t*) malloc (req);
    rc = EVP_DigestSignFinal(ctx, sig_buf, &req);
    if (rc != 1) {
        fprintf(stdout, "Failed to get signature.");
        EVP_MD_CTX_destroy(ctx);
        free(sig_buf);
        return NULL;
    }

    if (first_req < req) {
        fprintf(stderr, "Signature larger than buffer (%zu < %zu).",
                              first_req, req);
        EVP_MD_CTX_destroy(ctx);
        free(sig_buf);
        return NULL;
    }

    EVP_MD_CTX_destroy(ctx);

    *ret_len = req;
    return sig_buf;
}

void
crypto_privkey_free_data(void *data)
{
    free(data);
}

const char *
crypto_privkey_type_string(void *key)
{
    const char *ret = NULL;
    if (key != 0) {
        switch (EVP_PKEY_id((EVP_PKEY*)key)) {
        case EVP_PKEY_RSA:
            ret = "rsa-sha256";
            break;
        case EVP_PKEY_DSA:
            ret = "dsa-sha256";
            break;
        case EVP_PKEY_EC:
            ret = "ec-sha256";
            break;
        default:
            break;
        }
    }
    return ret;
}

// vim:ts=8:sts=4:sw=4:expandtab:
