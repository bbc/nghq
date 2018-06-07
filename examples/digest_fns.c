#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "crypto_fns_openssl.h"

#include "digest_fns.h"

void *
digest_ctx_new()
{
    return crypto_sha256_init();
}

void
digest_ctx_add_data(void *ctx, const uint8_t *data, size_t data_length)
{
    crypto_sha256_append_data(ctx, (const char*)data, data_length);
}

char *
digest_ctx_get_digest_hdr_value(void *ctx)
{
    static const char sha256_prefix[] = "sha256=";
    size_t hash_length;
    size_t hdr_length;
    char *value;

    if (!ctx) return NULL;

    hash_length = crypto_sha256_digest_length();

    hdr_length = sizeof(sha256_prefix) +
            crypto_base64_encoded_length(hash_length);
    value = malloc(hdr_length);

    if (value) {
        uint8_t buffer[hash_length];
        crypto_sha256_finish(ctx, buffer);
        memcpy(value, sha256_prefix, sizeof(sha256_prefix)-1);
        crypto_base64_encode_data(value+sizeof(sha256_prefix)-1, buffer,
                                  crypto_sha256_digest_length());
        value[hdr_length-1] = '\0';
    }

    return value;
}

void
digest_ctx_free_digest_hdr_value(void *ctx, char *digest_hdr_value)
{
    free(digest_hdr_value);
}

void
digest_ctx_free(void *context)
{
    if (context == NULL) return;
    crypto_sha256_free(context);
}

// vim:ts=8:sts=4:sw=4:expandtab:
