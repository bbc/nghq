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

#ifndef LIB_MAP_H_
#define LIB_MAP_H_

#include <stdint.h>
#include "nghq_internal.h"

struct nghq_map_ctx;
typedef struct nghq_map_ctx nghq_map_ctx;

#define NGHQ_STREAM_ID_MAP_NOT_FOUND 0xFFFFFFFFFFFFFFFFULL

nghq_map_ctx *nghq_stream_id_map_init();
int nghq_stream_id_map_add (nghq_map_ctx *ctx, uint64_t stream_id,
                            nghq_stream* stream_data);
void* nghq_stream_id_map_find (nghq_map_ctx *ctx, uint64_t stream_id);
uint64_t nghq_stream_id_map_search (nghq_map_ctx *ctx, void* user_data);
nghq_stream *nghq_stream_id_map_stream_search(nghq_map_ctx *ctx,
                                              void* user_data);

int nghq_stream_id_map_remove (nghq_map_ctx *ctx, uint64_t stream_id);

size_t nghq_stream_id_map_num_requests (nghq_map_ctx *ctx);
size_t nghq_stream_id_map_num_pushes (nghq_map_ctx *ctx);

void nghq_stream_id_map_destroy (nghq_map_ctx *ctx);

#endif /* LIB_MAP_H_ */
