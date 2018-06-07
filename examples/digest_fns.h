#ifndef _NGHQ_DIGEST_FNS_H_
#define _NGHQ_DIGEST_FNS_H_

#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

extern void *digest_ctx_new();
extern void digest_ctx_add_data(void *ctx, const uint8_t *data, size_t data_length);
extern char *digest_ctx_get_digest_hdr_value(void *ctx);
extern void digest_ctx_free_digest_hdr_value(void *ctx, char *digest_hdr_value);
extern void digest_ctx_free(void *ctx);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif //_NGHQ_DIGEST_FNS_H_

// vim:ts=8:sts=4:sw=4:expandtab:
