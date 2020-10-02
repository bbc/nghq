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

#ifndef LIB_HEADER_COMPRESSION_H_
#define LIB_HEADER_COMPRESSION_H_

#include "nghq/nghq.h"

struct nghq_hdr_compression_ctx;
typedef struct nghq_hdr_compression_ctx nghq_hdr_compression_ctx;

int nghq_init_hdr_compression_ctx(nghq_hdr_compression_ctx **ctx);

/**
 * @brief Decompress headers
 *
 * @param ctx The header compression context
 * @param hdr_block The compressed header block
 * @param block_len The length of @p hdr_block
 * @param final_block This is the final block of header data
 * @param hdrs An array of name-value pair headers that have been decompressed
 * @param num_hdrs The size of the array @p hdrs
 *
 * @return The number of bytes left in @p hdr_block that were not processed and
 *    should be fed back into this function when more HEADERS data has been
 *    received.
 * @return NGHQ_HDR_COMPRESS_FAILURE if decompression fails
 * @return NGHQ_OUT_OF_MEMORY if function could not allocate returned headers
 * @return NGHQ_ERROR if @p ctx is not initialised
 */
ssize_t nghq_inflate_hdr (nghq_session *session, nghq_hdr_compression_ctx *ctx,
                          uint8_t* hdr_block, size_t block_len, int final_block,
                          nghq_header ***hdrs, size_t* num_hdrs);

/**
 * @brief Compress headers
 *
 * This function will allocate space to write out the compressed headers as a
 * Headers Block. The caller is responsible for freeing @p hdr_block when it is
 * done.
 *
 * @param ctx The header compression context
 * @param hdrs An array of name-value pair headers that need compressing
 * @param num_hdrs The size of the array @p hdrs
 * @param hdr_block The compressed header block
 * @param block_len The length of @p hdr_block
 *
 * @return The number of headers that were compressed on success
 * @return NGHQ_HDR_COMPRESS_FAILURE if compression fails
 * @return NGHQ_OUT_OF_MEMORY if function could not allocate buffer @p hdr_block
 * @return NGHQ_ERROR if @p ctx is not initialised
 */
int nghq_deflate_hdr (nghq_session *session, nghq_hdr_compression_ctx *ctx,
                      const nghq_header **hdrs, size_t num_hdrs,
                      uint8_t** hdr_block, size_t* block_len);

void nghq_free_hdr_compression_ctx(nghq_hdr_compression_ctx *ctx);

#endif /* LIB_HEADER_COMPRESSION_H_ */
