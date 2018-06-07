#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "nghq/nghq.h"

#include "crypto_fns_openssl.h"

#include "signature_fns.h"

static char *
_add_header_block(char *result, size_t *len, const char *hdr,
                  const nghq_header **headers, size_t headers_length)
{
    bool found_header = false;
    for (size_t i=0; i<headers_length; i++) {
        if (strncasecmp(headers[i]->name, hdr, headers[i]->name_len) == 0 &&
            hdr[headers[i]->name_len] == '\0') {
            size_t old_len = *len;
            if (found_header) {
                *len += 1;
            }
            *len += headers[i]->value_len;
            result = realloc(result, *len);
            if (found_header) {
                result[old_len] = ',';
                old_len++;
            }
            memcpy(result+old_len, headers[i]->value, headers[i]->value_len);
            found_header = true;
        }
    }
    return result;
}

static char *
_make_block(const char **hdrs_list, const nghq_header **headers, 
            size_t headers_length, const nghq_header **req_headers,
            size_t req_headers_length, char **hl_str)
{
    char *result = NULL;
    size_t result_len = 0;
    size_t hl_str_len = 0;

    *hl_str = NULL;

    for (const char **hl_it = hdrs_list; *hl_it; hl_it++) {
        size_t hdr_len = strlen(*hl_it);
        bool found_header = false;

        /* Add header name onto the headers list string (hl_str) */ 
        *hl_str = realloc(*hl_str, hl_str_len + hdr_len + 1);
        if (hl_str_len != 0) {
            (*hl_str)[hl_str_len-1] = ' ';
        }
        strcpy((*hl_str) + hl_str_len, *hl_it);
        hl_str_len += hdr_len + 1;

        /* Add header name to output block */
        result = realloc(result, result_len + hdr_len + 1);
        memcpy(result + result_len, *hl_it, hdr_len);
        result_len += hdr_len + 1;
        result[result_len-1] = ':';
        
        if (strcmp("(request-target)", *hl_it) == 0) {
            result = _add_header_block(result, &result_len, ":method", req_headers, req_headers_length);
            result = realloc(result, ++result_len);
            result[result_len-1] = ' ';
            result = _add_header_block(result, &result_len, ":path", req_headers, req_headers_length);
        } else {
            result = _add_header_block(result, &result_len, *hl_it, headers, headers_length);
        }

        /* Add new line */
        result = realloc(result, result_len+1);
        result[result_len] = '\n';
        result_len++;
    }

    /* NUL terminate the block */
    result = realloc(result, result_len+1);
    result[result_len] = '\0';

    return result;
}

static void
_free_block(char *block, char *hdrs_list)
{
    free(block);
    free(hdrs_list);
}

char *
signature_hdr_value(void *private_key, const char *key_id,
                    const char **hdrs_list, const nghq_header **headers,
                    size_t headers_length, const nghq_header **req_headers,
                    size_t req_headers_length)
{
    static const char key_id_str[] = "keyId=\"";
    static const char alg_str[] = "\",algorithm=";
    static const char hdrs_str[] = ",headers=\"";
    static const char sig_str[] = "\",signature=\"";
    static const char end_str[] = "\"";

    char *block, *hdrs_list_str = NULL, *result, *tmp;
    const char *key_alg = NULL;
    size_t sig_len = 0;
    size_t signed_headers = 0;
    void *sig;
    size_t b64_sig_len, hdr_len;

    block = _make_block(hdrs_list, headers, headers_length, req_headers,
                        req_headers_length, &hdrs_list_str);

    sig = crypto_privkey_sign(block, strlen(block), &sig_len, private_key);
    key_alg = crypto_privkey_type_string(private_key);
    
    b64_sig_len = crypto_base64_encoded_length(sig_len);

    hdr_len = sizeof(key_id_str)-1 + sizeof(alg_str)-1 + sizeof(hdrs_str)-1 +
            sizeof(sig_str)-1 + sizeof(end_str) + strlen(key_id) +
            strlen(key_alg) + strlen(hdrs_list_str) + b64_sig_len;

    result = malloc(hdr_len);
    tmp = stpcpy(result, key_id_str);
    tmp = stpcpy(tmp, key_id);
    tmp = stpcpy(tmp, alg_str);
    tmp = stpcpy(tmp, key_alg);
    tmp = stpcpy(tmp, hdrs_str);
    tmp = stpcpy(tmp, hdrs_list_str);
    tmp = stpcpy(tmp, sig_str);
    crypto_base64_encode_data(tmp, sig, sig_len);
    strcpy(result+hdr_len-sizeof(end_str)-1, end_str);

    _free_block(block, hdrs_list_str);
    crypto_privkey_free_data(sig);

    return result;
}

void
signature_hdr_value_free(char *hdr_value)
{
    free(hdr_value);
}

bool
signature_hdr_check(void *public_key, const char *hdr_value,
                    const nghq_header **headers, size_t headers_length,
                    const nghq_header **req_headers, size_t req_headers_length)
{
    // TODO: add signature check routine
    return true;
}

// vim:ts=8:sts=4:sw=4:expandtab:
