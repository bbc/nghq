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
#include "nghq_internal.h"
#include "debug.h"

/**
 * Calculate the size of a new frame header suitable for the passed-in payload
 * length for the given type and with the set flags. If the payload length is
 * too big for the frame, this changes the value of payload_len to say how much
 * data can fit into the frame. This function then returns the total frame size.
 */
size_t _calculate_frame_size (uint64_t payload_len, nghq_frame_type type) {
  return _make_varlen_int(NULL, payload_len) + _make_varlen_int(NULL, type)
      + payload_len;
}

/*
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                           Type (i)                          ...  Frame
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  Header
 * |                          Length (i)                         ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Returns the length of the header (which should be sizeof(buf) - payload_len)
 */
size_t _create_frame_header (size_t payload_len, nghq_frame_type type,
                             uint8_t* buf) {
  size_t off = _make_varlen_int(buf, type);
  off += _make_varlen_int(buf+off, payload_len);
  assert(off > 0);
  return off;
}

void _create_frame (nghq_frame_type type, size_t len, const uint8_t* payload,
                    size_t payload_len, uint8_t* frame, size_t frame_length) {
  size_t header_length = _create_frame_header (len, type, frame);

  /* Something has gone very wrong if this asserts... */
  assert(frame_length == (header_length + payload_len));

  memcpy(frame + header_length, payload, payload_len);
}

/*
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                           Type (i)                          ...  Frame
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  Header
 * |                          Length (i)                         ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ===========
 * |                         Body Block (*)                        |  DATA
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  Payload
 */
ssize_t create_data_frame(nghq_session *session, const uint8_t* block,
                          size_t block_len, size_t full_len, uint8_t** frame,
                          size_t* frame_len) {
  size_t block_to_write = block_len;

  if (block == NULL) {
    return NGHQ_ERROR;
  }

  /* The full length might be longer than this block if nghq_promise_data() was
   * used */
  *frame_len = _make_varlen_int(NULL, full_len)
      + _make_varlen_int(NULL, NGHQ_FRAME_TYPE_DATA) + block_to_write;

  *frame = (uint8_t *) malloc(*frame_len);
  if (*frame == NULL) {
    return NGHQ_OUT_OF_MEMORY;
  }

  _create_frame(NGHQ_FRAME_TYPE_DATA, full_len, block, block_to_write, *frame,
                *frame_len);

  NGHQ_LOG_DEBUG (session, "Created DATA frame of size %lu bytes with %lu\n",
                  full_len, block_to_write);

  return (ssize_t) block_to_write;
}

/*
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Optional Push Stream Header                |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ===========
 * |                           Type (i)                          ...  Frame
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  Header
 * |                          Length (i)                         ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ===========
 * |                        Header Block (*)                       |  HEADERS
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  Payload
 */
ssize_t create_headers_frame(nghq_session *session,
                             nghq_hdr_compression_ctx* ctx, int64_t push_id,
                             const nghq_header** hdrs, size_t num_hdrs,
                             uint8_t** frame, size_t* frame_len) {
  size_t block_to_write;
  int hdrs_compressed;
  uint8_t* hdr_block;
  size_t push_stream_header_len = 0;

  if (hdrs == NULL) {
    return NGHQ_ERROR;
  }

  hdrs_compressed = nghq_deflate_hdr (session, ctx, hdrs, num_hdrs, &hdr_block,
                                      &block_to_write);

  *frame_len = _calculate_frame_size (block_to_write, NGHQ_FRAME_TYPE_HEADERS);

  if (push_id >= 0) {
    /* Add extra byte for stream type of 0x01.
     *
     * TODO: Should we move the push header to something more generic? Is there
     * anything guaranteeing that we will only be sending a push header infront
     * of a HEADERS frame?
     */
    push_stream_header_len = _make_varlen_int(NULL, (uint64_t) push_id) + 1;
  }

  *frame = (uint8_t *) malloc((*frame_len) + push_stream_header_len);
  if (*frame == NULL) {
    return NGHQ_OUT_OF_MEMORY;
  }

  if (push_id >= 0) {
    /*
     *  0                   1                   2                   3
     *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                           0x01 (i)                          ...
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                          Push ID (i)                        ...
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     */
    *frame[0] = 0x01;
    _make_varlen_int(*frame + 1, (uint64_t) push_id);
    NGHQ_LOG_DEBUG (session, "Added Push ID of %lu before HEADERS frame\n",
                    push_id);
  }

  _create_frame(NGHQ_FRAME_TYPE_HEADERS, block_to_write, hdr_block,
                block_to_write, *frame + push_stream_header_len, *frame_len);

  NGHQ_LOG_DEBUG (session, "Created HEADERS frame of size %lu bytes with %lu "
                  "headers\n", block_to_write, num_hdrs);

  free(hdr_block);

  *frame_len += push_stream_header_len;

  return (ssize_t) hdrs_compressed;
}


/*
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                           Type (i)                          ...  Frame
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  Header
 * |                          Length (i)                         ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ===========
 * |                          Push ID (i)                        ... CANCEL_PUSH
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  Payload
 */
int create_cancel_push_frame(nghq_session *session, uint64_t push_id,
                             uint8_t** frame, size_t* frame_len) {
  size_t header_length, push_id_length;

  push_id_length = _make_varlen_int(NULL, push_id);
  assert(push_id_length > 0);

  *frame_len = _calculate_frame_size(push_id_length,
                                     NGHQ_FRAME_TYPE_CANCEL_PUSH);

  *frame = (uint8_t *) malloc(*frame_len);
  if (*frame == NULL) {
    return NGHQ_OUT_OF_MEMORY;
  }

  header_length = _create_frame_header (push_id_length,
                                        NGHQ_FRAME_TYPE_CANCEL_PUSH, *frame);

  NGHQ_LOG_DEBUG (session, "Created CANCEL_PUSH frame for Push ID %lu\n",
                  push_id);

  _make_varlen_int((*frame) + header_length, push_id);

  return NGHQ_OK;
}

/*
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                           Type (i)                          ...  Frame
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  Header
 * |                          Length (i)                         ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ===========
 * |         Identifier (16)       |            Length (i)       ...  SETTINGS
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  Payload
 * |                          Contents (?)                       ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
int create_settings_frame(nghq_session* session, nghq_settings* settings,
                          uint8_t** frame, size_t* frame_len) {
  /* TODO */
  return NGHQ_ERROR;
}

/*
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                           Type (i)                          ...  Frame
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  Header
 * |                          Length (i)                         ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ===========
 * |                          Push ID (i)                        ...  PUSH_
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  PROMISE
 * |                       Header Block (*)                      ...  Payload
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
ssize_t create_push_promise_frame(nghq_session *session,
                                  nghq_hdr_compression_ctx *ctx,
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

  hdrs_compressed = nghq_deflate_hdr (session, ctx, hdrs, num_hdrs, &hdr_block,
                                      &block_to_write);
  if (hdrs_compressed < 0) {
    return (ssize_t) hdrs_compressed;
  }

  payload_length = block_to_write + push_id_length;

  *frame_len = _calculate_frame_size (payload_length,
                                      NGHQ_FRAME_TYPE_PUSH_PROMISE);

  *frame = (uint8_t *) malloc(*frame_len);
  if (*frame == NULL) {
    return NGHQ_OUT_OF_MEMORY;
  }

  header_length = _create_frame_header (payload_length,
                                        NGHQ_FRAME_TYPE_PUSH_PROMISE,
                                        *frame);

  /* Something has gone very wrong if this asserts... */
  assert(*frame_len == (header_length + payload_length));

  _make_varlen_int(*frame + header_length, push_id);

  memcpy(*frame + header_length + push_id_length, hdr_block, block_to_write);

  NGHQ_LOG_DEBUG (session, "Created PUSH_PROMISE frame for push ID %lu of size "
                  "%lu bytes with %lu headers\n", push_id, block_to_write,
                  num_hdrs);

  free (hdr_block);

  return (ssize_t) hdrs_compressed;
}

/*
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                           Type (i)                          ...  Frame
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  Header
 * |                          Length (i)                         ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ===========
 * |                         Stream ID (i)                       ...  GOAWAY
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  Payload
 */
int create_goaway_frame(nghq_session *session, uint64_t last_stream_id,
                        uint8_t** frame, size_t* frame_len) {
  size_t header_length, last_stream_id_length;

  last_stream_id_length = _make_varlen_int(NULL, last_stream_id);
  assert(last_stream_id_length > 0);

  *frame_len = _calculate_frame_size(last_stream_id_length,
                                     NGHQ_FRAME_TYPE_GOAWAY);

  *frame = (uint8_t *) malloc(*frame_len);
  if (*frame == NULL) {
    return NGHQ_OUT_OF_MEMORY;
  }

  header_length = _create_frame_header (last_stream_id_length,
                                        NGHQ_FRAME_TYPE_GOAWAY, *frame);

  _make_varlen_int((*frame) + header_length, last_stream_id);

  NGHQ_LOG_DEBUG (session, "Created GOAWAY frame with last stream ID %lu\n",
                  last_stream_id);

  return NGHQ_OK;
}

/*
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                           Type (i)                          ...  Frame
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  Header
 * |                          Length (i)                         ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ===========
 * |                      Maximum Push ID (i)                    ... MAX_PUSH_ID
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  Payload
 */
int create_max_push_id_frame(nghq_session *session, uint64_t max_push_id,
                             uint8_t** frame, size_t* frame_len) {
  size_t header_length, max_push_id_length;

  max_push_id_length = _make_varlen_int(NULL, max_push_id);
  assert(max_push_id_length > 0);

  *frame_len = _calculate_frame_size(max_push_id_length,
                                     NGHQ_FRAME_TYPE_MAX_PUSH_ID);

  *frame = (uint8_t *) malloc(*frame_len);
  if (*frame == NULL) {
    return NGHQ_OUT_OF_MEMORY;
  }

  header_length = _create_frame_header (max_push_id_length,
                                        NGHQ_FRAME_TYPE_MAX_PUSH_ID, *frame);

  _make_varlen_int((*frame) + header_length, max_push_id);

  NGHQ_LOG_DEBUG (session, "Created MAX_PUSH_ID frame with max push ID %lu\n",
                  max_push_id);

  return NGHQ_OK;
}
