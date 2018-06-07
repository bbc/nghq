#ifndef _NGHQ_SIGNATURE_FNS_H_
#define _NGHQ_SIGNATURE_FNS_H_

#include <stdbool.h>
#include <sys/types.h>

#include "nghq/nghq.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

extern char *signature_hdr_value(void *private_key, const char *key_id,
                                 const char **hdrs_list,
                                 const nghq_header **headers,
                                 size_t headers_length,
                                 const nghq_header **req_headers,
                                 size_t req_headers_length);

extern void signature_hdr_value_free(char *hdr_value);

extern bool signature_hdr_check(void *public_key, const char *hdr_value,
                                const nghq_header **headers,
                                size_t headers_length, 
                                const nghq_header **req_headers,
                                size_t req_headers_length);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif //_NGHQ_SIGNATURE_FNS_H_

// vim:ts=8:sts=4:sw=4:expandtab:
