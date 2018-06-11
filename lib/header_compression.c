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

#include "header_compression.h"
#include "debug.h"
#include <nghttp2/nghttp2.h>

struct nghq_hdr_compression_ctx {
  nghttp2_hd_inflater *inflater;
  nghttp2_hd_deflater *deflater;
};

struct _temp_list {
  nghq_header   *header;
  struct _temp_list *next;
};

int _create_header (struct _temp_list **node, uint8_t* name, size_t namelen,
                     uint8_t* value, size_t valuelen) {
  *node = (struct _temp_list *) malloc (sizeof(struct _temp_list));
  if (*node == NULL) {
    return NGHQ_OUT_OF_MEMORY;
  }
  (*node)->header = (nghq_header *) malloc (sizeof(nghq_header));
  if ((*node)->header == NULL) {
    return NGHQ_OUT_OF_MEMORY;
  }

  (*node)->header->name = (uint8_t *) malloc (namelen + 1);
  if ((*node)->header->name == NULL) {
    return NGHQ_OUT_OF_MEMORY;
  }
  (*node)->header->name_len = namelen;
  memcpy((*node)->header->name, name, namelen);
  (*node)->header->name[namelen] = 0;

  (*node)->header->value = (uint8_t *) malloc (valuelen + 1);
  if ((*node)->header->value == NULL) {
    return NGHQ_OUT_OF_MEMORY;
  }
  (*node)->header->value_len = valuelen;
  memcpy((*node)->header->value, value, valuelen);
  (*node)->header->value[valuelen] = 0;

  return NGHQ_OK;
}

int nghq_init_hdr_compression_ctx(nghq_hdr_compression_ctx **ctx) {
  *ctx = (nghq_hdr_compression_ctx *) malloc(sizeof(nghq_hdr_compression_ctx));
  if (*ctx == NULL) {
    return NGHQ_OUT_OF_MEMORY;
  }

  (*ctx)->inflater = NULL;
  (*ctx)->deflater = NULL;
  return NGHQ_OK;
}

ssize_t nghq_inflate_hdr (nghq_hdr_compression_ctx *ctx, uint8_t* hdr_block,
                          size_t block_len, int final_block,
                          nghq_header ***hdrs, size_t* num_hdrs) {
  int inflate_flags=0, i;
  *num_hdrs = 0;
  //ssize_t remaining = block_len;

  /*
   * We store the header in a linked list before moving to an array when we know
   * how long the number of headers we're dealing with is. Means we don't have
   * to constantly realloc, but means it's easier for end applications to
   * address specific headers.
   */
  struct _temp_list *list = NULL;
  struct _temp_list *end_list = NULL;

  if (ctx == NULL) {
    return NGHQ_ERROR;
  }
  if (ctx->inflater == NULL) {
    if (nghttp2_hd_inflate_new(&ctx->inflater) != 0) {
      return NGHQ_HDR_COMPRESS_FAILURE;
    }
  }

  while (!(inflate_flags & NGHTTP2_HD_INFLATE_FINAL)) {
    nghttp2_nv nv_out;
    ssize_t processed = nghttp2_hd_inflate_hd2(ctx->inflater, &nv_out,
                                               &inflate_flags, hdr_block,
                                               block_len, final_block);

    if (processed < 0) {
      ERROR("nghttp2_hd_inflate_hd2 failed: %s\n",
            nghttp2_strerror(processed));
      return NGHQ_HDR_COMPRESS_FAILURE;
    }

    hdr_block += (size_t) processed;
    block_len -= (size_t) processed;

    if (inflate_flags & NGHTTP2_HD_INFLATE_EMIT) {
      DEBUG("Inflated header - %.*s: %.*s\n", (int)nv_out.namelen, nv_out.name, (int)nv_out.valuelen, nv_out.value);
      if (list == NULL) {
        int rv = _create_header(&list, nv_out.name, nv_out.namelen,
                                nv_out.value, nv_out.valuelen);
        if (rv != NGHQ_OK) {
          ERROR("Failed to create header!\n");
          return rv;
        }
        end_list = list;
        end_list->next = NULL;
      } else {
        int rv = _create_header(&end_list->next, nv_out.name, nv_out.namelen,
                                nv_out.value, nv_out.valuelen);
        if (rv != NGHQ_OK) {
          ERROR("Failed to create header!\n");
          return rv;
        }
        end_list = end_list->next;
      }
      (*num_hdrs)++;
    }
    if ((inflate_flags & NGHTTP2_HD_INFLATE_EMIT) == 0 && block_len == 0) {
      break;
    }
  }

  if (inflate_flags & NGHTTP2_HD_INFLATE_FINAL) {
    nghttp2_hd_inflate_end_headers(ctx->inflater);
  }

  *hdrs = (nghq_header**) malloc (*num_hdrs * sizeof(nghq_header*));

  /*
   * Fill the array of headers with the headers we created in the linked list,
   * and delete the linked list as we go.
   */
  for (i = 0; i < *num_hdrs; i++) {
    struct _temp_list *last = NULL;
    (*hdrs)[i] = list->header;
    last = list;
    list = list->next;
    free (last);
  }

  /* The number of bytes left that weren't processable */
  return block_len;
}

int nghq_deflate_hdr (nghq_hdr_compression_ctx *ctx, const nghq_header **hdrs,
                      size_t num_hdrs, uint8_t** hdr_block, size_t* block_len) {
  nghttp2_nv nva[num_hdrs];
  int i;
  ssize_t rv;

  if (ctx == NULL) {
    return NGHQ_ERROR;
  }
  if (ctx->deflater == NULL) {
    /* Dynamic table size MUST be zero to use HPACK in QUIC! */
    if (nghttp2_hd_deflate_new(&ctx->deflater, 0) != 0) {
      return NGHQ_HDR_COMPRESS_FAILURE;
    }
  }

  for (i = 0; i < num_hdrs; i++) {
    DEBUG("Compressing header - %.*s: %.*s\n", (int)hdrs[i]->name_len,
          hdrs[i]->name, (int)hdrs[i]->value_len, hdrs[i]->value);
    nva[i].name = hdrs[i]->name;
    nva[i].namelen = hdrs[i]->name_len;
    nva[i].value = hdrs[i]->value;
    nva[i].valuelen = hdrs[i]->value_len;
  }

  /*
   * This gives an upper bound, but not actually how much data will be written.
   */
  *block_len = nghttp2_hd_deflate_bound(ctx->deflater, nva, num_hdrs);

  *hdr_block = (uint8_t *) malloc (*block_len);

  rv = nghttp2_hd_deflate_hd(ctx->deflater, *hdr_block, *block_len, nva,
                                     num_hdrs);

  if (rv == NGHTTP2_ERR_NOMEM) {
    return NGHQ_OUT_OF_MEMORY;
  } else if (rv == NGHTTP2_ERR_HEADER_COMP) {
    return NGHQ_HDR_COMPRESS_FAILURE;
  } else if (rv == NGHTTP2_ERR_INSUFF_BUFSIZE) {
    return NGHQ_HDR_COMPRESS_FAILURE;
  }
  *block_len = rv;
  return num_hdrs;
}

void nghq_free_hdr_compression_ctx(nghq_hdr_compression_ctx *ctx) {
  if (ctx != NULL) {
    if (ctx->inflater != NULL) {
      nghttp2_hd_inflate_del(ctx->inflater);
    }
    if (ctx->deflater != NULL) {
      nghttp2_hd_deflate_del(ctx->deflater);
    }
  }
  free (ctx);
}
