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
#include <assert.h>

#include "frame_creator.h"
#include "header_compression.h"
#include "util.h"

/**
 * Calculate the size of a new frame header suitable for the passed-in payload
 * length for the given type and with the set flags. If the payload length is
 * too big for the frame, this changes the value of payload_len to say how much
 * data can fit into the frame. This function then returns the total frame size.
 */
size_t _calculate_frame_size (size_t* payload_len) {
  int done = 0;
  size_t rv = 0;

  size_t header_varlen_int_length = _make_varlen_int(NULL,
                                                     (uint64_t) *payload_len);

  return rv;
}

/*
 *     0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           Length (i)       ...|    Type (8)   |   Flags (8)   |  Frame HDR
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Returns the length of the header (which should be sizeof(buf) - payload_len)
 */
size_t _create_frame_header (size_t payload_len, nghq_frame_type type,
                           uint8_t flags, uint8_t* buf) {
  size_t off = _make_varlen_int(buf, payload_len);
  assert(off > 0);
  buf[off++] = type;
  buf[off++] = flags;
  return off;
}

void _create_frame (nghq_frame_type type, uint8_t flags, const uint8_t* payload,
                    size_t payload_len, uint8_t* frame, size_t frame_length) {
  size_t header_length = _create_frame_header (payload_len, type, flags, frame);

  /* Something has gone very wrong if this asserts... */
  assert(frame_length == (header_length + payload_len));

  memcpy(frame + header_length, payload, payload_len);
}

/*
 *     0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           Length (i)       ...|    Type (8)   |   Flags (8)   |  Frame HDR
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ===========
 * |                         Body Block (*)                        |  DATA
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  Payload
 */
ssize_t create_data_frame(const uint8_t* block, size_t block_len,
                          uint8_t** frame, size_t* frame_len) {
  size_t block_to_write = block_len;

  if (block == NULL) {
    return NGHQ_ERROR;
  }

  *frame_len = _calculate_frame_size (&block_to_write);

  *frame = (uint8_t *) malloc(*frame_len);
  if (*frame == NULL) {
    return NGHQ_OUT_OF_MEMORY;
  }

  _create_frame(NGHQ_FRAME_TYPE_DATA, 0, block, block_to_write, *frame,
                *frame_len);

  return (ssize_t) block_to_write;
}

/*
 *     0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Optional Push Stream Header                |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ===========
 * |           Length (i)       ...|    Type (8)   |   Flags (8)   |  Frame HDR
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ===========
 * |                        Header Block (*)                       |  HEADERS
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  Payload
 */
ssize_t create_headers_frame(nghq_hdr_compression_ctx* ctx, int64_t push_id,
                             const nghq_header** hdrs, size_t num_hdrs,
                             uint8_t** frame, size_t* frame_len) {
  size_t frame_length, header_length, block_to_write;
  int hdrs_compressed;
  uint8_t* hdr_block;
  size_t push_stream_header_len = 0;

  if (hdrs == NULL) {
    return NGHQ_ERROR;
  }

  hdrs_compressed = nghq_deflate_hdr (ctx, hdrs, num_hdrs, &hdr_block,
                                      &block_to_write);

  *frame_len = _calculate_frame_size (&block_to_write);

  if (push_id >= 0) {
    push_stream_header_len = _make_varlen_int(NULL, (uint64_t) push_id);
  }

  *frame = (uint8_t *) malloc((*frame_len) + push_stream_header_len);
  if (*frame == NULL) {
    return NGHQ_OUT_OF_MEMORY;
  }

  if (push_id >= 0) {
    _make_varlen_int(*frame, (uint64_t) push_id);
  }

  _create_frame(NGHQ_FRAME_TYPE_HEADERS, 0, hdr_block, block_to_write,
                *frame + push_stream_header_len, *frame_len);

  *frame_len += push_stream_header_len;

  return (ssize_t) hdrs_compressed;
}

/*
 *     0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           Length (i)       ...|    Type (8)   |   Flags (8)   |  Frame HDR
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ===========
 * |                 Prioritised Request ID (i)                  ...  PRIORITY
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  Payload
 * |                  Stream Dependency ID (i)                   ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Weight (8)  |
 * +-+-+-+-+-+-+-+-+
 */
int create_priority_frame(uint8_t flags, uint64_t request_id,
                          uint64_t dependency_id, uint8_t weight,
                          uint8_t** frame, size_t* frame_len) {
  size_t header_length, payload_length, off;

  payload_length = _make_varlen_int(NULL, request_id) +
      _make_varlen_int(NULL, dependency_id) + 1;
  assert(payload_length > 2);

  *frame_len = _calculate_frame_size(&payload_length);

  *frame = (uint8_t *) malloc(*frame_len);
  if (*frame == NULL) {
    return NGHQ_OUT_OF_MEMORY;
  }

  header_length = _create_frame_header (payload_length,
                                        NGHQ_FRAME_TYPE_PRIORITY, flags, *frame);

  assert ((header_length + payload_length) == *frame_len);

  off = header_length;
  off += _make_varlen_int((*frame) + off, request_id);
  off += _make_varlen_int((*frame) + off, dependency_id);
  (*frame)[off] = weight;

  return NGHQ_OK;
}

/*
 *     0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           Length (i)       ...|    Type (8)   |   Flags (8)   |  Frame HDR
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ===========
 * |                          Push ID (i)                        ... CANCEL_PUSH
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  Payload
 */
int create_cancel_push_frame(uint64_t push_id, uint8_t** frame,
                             size_t* frame_len) {
  size_t header_length, push_id_length;

  push_id_length = _make_varlen_int(NULL, push_id);
  assert(push_id_length > 0);

  *frame_len = _calculate_frame_size(&push_id_length);

  *frame = (uint8_t *) malloc(*frame_len);
  if (*frame == NULL) {
    return NGHQ_OUT_OF_MEMORY;
  }

  header_length = _create_frame_header (push_id_length,
                                        NGHQ_FRAME_TYPE_CANCEL_PUSH, 0, *frame);

  _make_varlen_int((*frame) + header_length, push_id);

  return NGHQ_OK;
}

/*
 *     0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           Length (i)      ... |    Type (8)   |   Flags (8)   |  Frame HDR
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ===========
 * |         Identifier (16)       |            Length (i)       ...  SETTINGS
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  Payload
 * |                          Contents (?)                       ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
int create_settings_frame(nghq_settings* settings, uint8_t** frame,
                              size_t* frame_len) {
  /* TODO */
  return NGHQ_ERROR;
}

/*
 *     0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           Length (i)       ...|    Type (8)   |   Flags (8)   |  Frame HDR
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ===========
 * |                          Push ID (i)                        ...  PUSH_
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  PROMISE
 * |                       Header Block (*)                      ...  Payload
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
ssize_t create_push_promise_frame(nghq_hdr_compression_ctx *ctx,
                                  uint64_t push_id, const nghq_header** hdrs,
                                  size_t num_hdrs, uint8_t** frame,
                                  size_t* frame_len) {
  size_t  header_length, block_to_write, push_id_length, payload_length;
  int hdrs_compressed;
  uint8_t* hdr_block;

  if (hdrs == NULL) {
    return NGHQ_ERROR;
  }

  push_id_length = _make_varlen_int(NULL, push_id);
  assert(push_id_length > 0);

  hdrs_compressed = nghq_deflate_hdr (ctx, hdrs, num_hdrs, &hdr_block,
                                      &block_to_write);

  payload_length = block_to_write + push_id_length;

  *frame_len = _calculate_frame_size (&payload_length);

  *frame = (uint8_t *) malloc(*frame_len);
  if (*frame == NULL) {
    return NGHQ_OUT_OF_MEMORY;
  }

  header_length = _create_frame_header (block_to_write,
                                        NGHQ_FRAME_TYPE_HEADERS, 0, *frame);

  /* Something has gone very wrong if this asserts... */
  assert(*frame_len == (header_length + payload_length));

  memcpy(*frame + header_length, hdr_block, block_to_write);

  return (ssize_t) hdrs_compressed;
}

/*
 *     0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           Length (i)       ...|    Type (8)   |   Flags (8)   |  Frame HDR
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ===========
 * |                         Stream ID (i)                       ...  GOAWAY
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  Payload
 */
int create_goaway_frame(uint64_t last_stream_id, uint8_t** frame,
                            size_t* frame_len) {
  size_t header_length, last_stream_id_length;

  last_stream_id_length = _make_varlen_int(NULL, last_stream_id);
  assert(last_stream_id_length > 0);

  *frame_len = _calculate_frame_size(&last_stream_id_length);

  *frame = (uint8_t *) malloc(*frame_len);
  if (*frame == NULL) {
    return NGHQ_OUT_OF_MEMORY;
  }

  header_length = _create_frame_header (last_stream_id_length,
                                        NGHQ_FRAME_TYPE_GOAWAY, 0, *frame);

  _make_varlen_int((*frame) + header_length, last_stream_id);

  return NGHQ_OK;
}

/*
 *     0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           Length (i)       ...|    Type (8)   |   Flags (8)   |  Frame HDR
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ===========
 * |                      Maximum Push ID (i)                    ... MAX_PUSH_ID
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  Payload
 */
int create_max_push_id_frame(uint64_t max_push_id, uint8_t** frame,
                                 size_t* frame_len) {
  size_t header_length, max_push_id_length;

  max_push_id_length = _make_varlen_int(NULL, max_push_id);
  assert(max_push_id_length > 0);

  *frame_len = _calculate_frame_size(&max_push_id_length);

  *frame = (uint8_t *) malloc(*frame_len);
  if (*frame == NULL) {
    return NGHQ_OUT_OF_MEMORY;
  }

  header_length = _create_frame_header (max_push_id_length,
                                        NGHQ_FRAME_TYPE_MAX_PUSH_ID, 0, *frame);

  _make_varlen_int((*frame) + header_length, max_push_id);

  return NGHQ_OK;
}
