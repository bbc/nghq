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

#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "header_compression.h"
#include "debug.h"
#include "lsqpack.h"

struct nghq_hdr_compression_ctx {
  struct lsqpack_enc *encoder;
  struct lsqpack_dec *decoder;
};

int nghq_init_hdr_compression_ctx(nghq_hdr_compression_ctx **ctx) {
  *ctx = (nghq_hdr_compression_ctx *) malloc(sizeof(nghq_hdr_compression_ctx));
  if (*ctx == NULL) {
    return NGHQ_OUT_OF_MEMORY;
  }

  (*ctx)->encoder = NULL;
  (*ctx)->decoder = NULL;
  return NGHQ_OK;
}

ssize_t nghq_inflate_hdr (nghq_session *session, nghq_hdr_compression_ctx *ctx,
                          uint8_t* hdr_block, size_t block_len, int final_block,
                          nghq_header ***hdrs, size_t* num_hdrs) {
  struct lsqpack_header_list *hlist;
  unsigned int i;
  if (ctx->decoder == NULL) {
    ctx->decoder = (struct lsqpack_dec *) malloc (sizeof(struct lsqpack_dec));
    lsqpack_dec_init (ctx->decoder, NULL, 0, 0, NULL);
  }

  enum lsqpack_read_header_status rv =
      lsqpack_dec_header_in (ctx->decoder, (void *) hdr_block, 0, block_len,
                             (const unsigned char **) &hdr_block, block_len,
                             &hlist, NULL, NULL);
  switch (rv) {
    case LQRHS_BLOCKED:
    case LQRHS_NEED:
      NGHQ_LOG_DEBUG (session, "Header block incomplete, more bytes required\n");
      return block_len;
    case LQRHS_ERROR:
      NGHQ_LOG_ERROR (session, "Error in ls-qpack\n");
      return NGHQ_HDR_COMPRESS_FAILURE;
    default:;
  }

  *hdrs = (nghq_header**) malloc (hlist->qhl_count * sizeof(nghq_header*));
  if (*hdrs == NULL) {
    NGHQ_LOG_ERROR (session, "Failed to allocate %u header entries: %s\n",
                    hlist->qhl_count, strerror(errno));
    return NGHQ_OUT_OF_MEMORY;
  }

  *num_hdrs = hlist->qhl_count;

  for (i = 0; i < hlist->qhl_count; i++) {
    (*hdrs)[i] = (nghq_header *) malloc (sizeof(nghq_header));
    struct lsqpack_header *hdr = hlist->qhl_headers[i];
    (*hdrs)[i]->name = (uint8_t *) strndup (hdr->qh_name, hdr->qh_name_len);
    (*hdrs)[i]->value = (uint8_t *) strndup (hdr->qh_value, hdr->qh_value_len);
    (*hdrs)[i]->name_len = hdr->qh_name_len;
    (*hdrs)[i]->value_len = hdr->qh_value_len;
  }

  lsqpack_dec_destroy_header_list (hlist);

  return 0;
}

/* TODO: Make this buffer a bit more deterministic? Is 1000 bytes too much? */
#define QPACK_HEADER_BUF_LEN 1000
#define LSQPACK_DEFAULT_ENCODER_FLAGS LQEF_NEVER_INDEX | LQEF_NO_DYN

int nghq_deflate_hdr (nghq_session *session, nghq_hdr_compression_ctx *ctx,
                      const nghq_header **hdrs, size_t num_hdrs,
                      uint8_t** hdr_block, size_t* block_len) {
  unsigned char header_buf[QPACK_HEADER_BUF_LEN];
  unsigned char *out_buf;
  size_t header_buf_len = 0, zero = 0;
  /* TODO: Pass through the stream ID, if it's required? */
  int i, rv;
  enum lsqpack_enc_status enc_status;

  if (ctx->encoder == NULL) {
    ctx->encoder = (struct lsqpack_enc *) malloc (sizeof(struct lsqpack_enc));
    lsqpack_enc_preinit (ctx->encoder, NULL);
  }

  rv = lsqpack_enc_start_header (ctx->encoder, 0, 0);
  if (rv) {
    NGHQ_LOG_ERROR (session, "lsqpack_enc_start_header failed\n");
    return NGHQ_HDR_COMPRESS_FAILURE;
  }

  for (i = 0; i < num_hdrs; i++) {
    size_t hdr_buf_written = QPACK_HEADER_BUF_LEN - header_buf_len;
    enc_status = lsqpack_enc_encode (ctx->encoder, NULL, &zero,
                             header_buf + header_buf_len, &hdr_buf_written,
                             (const char *) hdrs[i]->name, hdrs[i]->name_len,
                             (const char *) hdrs[i]->value, hdrs[i]->value_len,
                             LSQPACK_DEFAULT_ENCODER_FLAGS);

    if (enc_status == LQES_NOBUF_ENC) {
      NGHQ_LOG_ERROR (session, "lsqpack failed trying to write to dynamic table"
                      " encoder buffer!\n");
      return NGHQ_ERROR;
    } else if (enc_status == LQES_NOBUF_HEAD) {
      NGHQ_LOG_DEBUG (session, "Not enough room in the header buffer, try "
                      "again!");
      /* This will drop us out of the for loop */
      num_hdrs = i;
    }

    header_buf_len += hdr_buf_written;
  }

  *block_len = lsqpack_enc_header_block_prefix_size(ctx->encoder)
                  + header_buf_len;
  out_buf = (unsigned char *) malloc (*block_len);
  if (out_buf == NULL) {
    NGHQ_LOG_ERROR(session, "Failed to allocate %lu bytes for header block: "
                   "%s\n", *block_len, strerror(errno));
    return NGHQ_OUT_OF_MEMORY;
  }

  rv = (int) lsqpack_enc_end_header (ctx->encoder, out_buf, *block_len, 0);
  memcpy (out_buf + rv, header_buf, header_buf_len);

  *hdr_block = (uint8_t *) out_buf;

  return num_hdrs;
}

void nghq_free_hdr_compression_ctx(nghq_hdr_compression_ctx *ctx) {
  if (ctx != NULL) {
    if (ctx->encoder != NULL) {
      lsqpack_enc_cleanup (ctx->encoder);
      free (ctx->encoder);
      ctx->encoder = NULL;
    }
    if (ctx->decoder != NULL) {
      lsqpack_dec_cleanup (ctx->decoder);
      free (ctx->decoder);
      ctx->decoder = NULL;
    }
  }
  free (ctx);
  ctx = NULL;
}
