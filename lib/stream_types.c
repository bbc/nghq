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
#include <stdlib.h>
#include "stream_types.h"
#include "nghq/nghq.h"

nghq_stream_type get_stream_type (const uint8_t* buf, size_t* bytes) {
  nghq_stream_type rv = buf[0];
  *bytes += 1;

  return rv;
}

int create_push_stream_header(int64_t push_id, 
                              uint8_t** stream_header, size_t* stream_header_len) {
  size_t push_id_len = 0;

  if (push_id >= 0) {
    push_id_len = _make_varlen_int(NULL, (uint64_t) push_id);
  } else {
    return NGHQ_INTERNAL_ERROR;
  }

  *stream_header_len = sizeof(nghq_stream_type) + push_id_len;

  *stream_header = (uint8_t *) malloc((*stream_header_len));
  if (*stream_header == NULL) {
    return NGHQ_OUT_OF_MEMORY;
  }

  *stream_header[0] = NGHQ_STREAM_TYPE_PUSH;
  _make_varlen_int(*stream_header + 1, (uint64_t) push_id);

  return NGHQ_OK;
}

int create_unbound_push_stream_header(uint8_t** stream_header, size_t* stream_header_len) {
  *stream_header_len = sizeof(nghq_stream_type);

  *stream_header = (uint8_t *) malloc((*stream_header_len));
  if (*stream_header == NULL) {
    return NGHQ_OUT_OF_MEMORY;
  }

  *stream_header[0] = NGHQ_STREAM_TYPE_UNBOUND_PUSH;

  return NGHQ_OK;
}