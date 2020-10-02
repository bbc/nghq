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
#include <arpa/inet.h>

#include "frame_parser.h"
#include "header_compression.h"
#include "util.h"
#include "debug.h"

/*
 * Parse the frame header - returns the length of the frame payload, excluding
 * the generic H3 header itself.
 */
static uint64_t _get_frame_payload_length (uint8_t* buf, nghq_frame_type *type,
                                           size_t *header_offset) {
  *header_offset = 0;
  nghq_frame_type t = _get_varlen_int(buf, header_offset, 16);
  if (type != NULL) *type = t;
  return _get_varlen_int(buf + *header_offset, header_offset, 16);
}

/*
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                           Type (i)                          ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                          Length (i)                         ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

ssize_t parse_frame_header (nghq_io_buf* buf, nghq_frame_type *type) {
  uint64_t frame_length = 0;
  size_t header_offset = 0;

  if (buf == NULL) return 0;

  *type = _get_varlen_int(buf->send_pos, &header_offset, 16);
  frame_length = _get_varlen_int(buf->send_pos + header_offset, &header_offset, 16);

  if (*type < NGHQ_FRAME_TYPE_DATA || *type > NGHQ_FRAME_TYPE_MAX_PUSH_ID) {
    return NGHQ_ERROR;
  }

  return frame_length + header_offset;
}

/*
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                           Type (i)                          ...  Frame
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  Header
 * |                          Length (i)                         ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ===========
 * |                           Data (*)                            |  DATA
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  Payload
 */
ssize_t parse_data_frame (nghq_session *session, nghq_io_buf* buf,
                          uint8_t** data, size_t *data_len) {
  size_t header_len;
  nghq_frame_type frame_type;

  *data_len = (size_t) _get_frame_payload_length(buf->send_pos, &frame_type,
                                                 &header_len);

  if (frame_type != NGHQ_FRAME_TYPE_DATA) {
    return NGHQ_ERROR;
  }

  *data = buf->send_pos + header_len;
  buf->send_pos += *data_len + header_len;
  buf->remaining -= *data_len + header_len;

  NGHQ_LOG_DEBUG (session, "Received DATA frame of length %lu\n", *data_len);

  return 0;
}

/*
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                           Type (i)                          ...  Frame
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  Header
 * |                          Length (i)                         ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ===========
 * |                    Encoded Field Section (*)                  |  HEADERS
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  Payload
 */
ssize_t parse_headers_frame (nghq_session *session,
                             nghq_hdr_compression_ctx* ctx, nghq_io_buf* buf,
                             nghq_header*** hdrs, size_t* num_hdrs) {
  size_t header_len = 0, expected_header_block_len;
  ssize_t result;
  nghq_frame_type type;
  expected_header_block_len =
      _get_frame_payload_length(buf->send_pos, &type, &header_len);

  if (type != NGHQ_FRAME_TYPE_HEADERS) {
    return NGHQ_ERROR;
  }

  if (expected_header_block_len + header_len > buf->remaining) {
    return expected_header_block_len + header_len;
  }

  result = nghq_inflate_hdr(session, ctx, buf->send_pos + header_len,
                            expected_header_block_len, 1, hdrs, num_hdrs);

  if (result < 0) return result;

  buf->send_pos += expected_header_block_len + header_len;
  buf->remaining -= expected_header_block_len + header_len;

  NGHQ_LOG_DEBUG (session, "Received HEADERS frame of length %lu with %lu "
                  "headers\n", expected_header_block_len, *num_hdrs);

  return 0;
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
int parse_cancel_push_frame (nghq_session *session, nghq_io_buf* buf,
                             uint64_t* push_id) {
  size_t off = 0;
  nghq_frame_type type;
  uint64_t frame_length = _get_frame_payload_length(buf->send_pos, &type, &off);

  if (type != NGHQ_FRAME_TYPE_CANCEL_PUSH) {
    return NGHQ_ERROR;
  }

  frame_length += off;

  if (buf->remaining < frame_length) {
    return frame_length;
  }

  *push_id = _get_varlen_int(buf->send_pos+off, &off, frame_length);
  if (off > frame_length) {
    return NGHQ_HTTP_MALFORMED_FRAME;
  }

  buf->send_pos += frame_length;
  buf->remaining -= frame_length;

  NGHQ_LOG_DEBUG (session, "Received CANCEL_PUSH frame for push ID %lu\n",
                  *push_id);

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
 * |                        Identifier (i)                       ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                           Value (i)                         ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                       [Identifier (i)]                      ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                          [Value (i)]                        ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                             [...]                             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
int parse_settings_frame (nghq_session *session, nghq_io_buf* buf,
                          nghq_settings** settings) {
  size_t off = 0;
  nghq_frame_type type;
  uint64_t frame_length;
  int rv = NGHQ_OK;
  int seen_max_header_list_size = 0;
  int seen_num_placeholders = 0;

  frame_length = _get_frame_payload_length(buf->send_pos, &type, &off);

  if (type != NGHQ_FRAME_TYPE_SETTINGS) {
    return NGHQ_ERROR;
  }

  frame_length += off;

  if (buf->remaining < frame_length) {
    return frame_length;
  }

  if (settings == NULL) {
    *settings = malloc(sizeof(nghq_settings));
    if (*settings == NULL) {
      return NGHQ_OUT_OF_MEMORY;
    }
    (*settings)->max_header_list_size =
        NGHQ_SETTINGS_DEFAULT_MAX_HEADER_LIST_SIZE;
    (*settings)->number_of_placeholders =
        NGHQ_SETTINGS_DEFAULT_NUM_PLACEHOLDERS;
  }

  while (rv == NGHQ_OK && off < frame_length) {
    uint64_t id = _get_varlen_int(buf->send_pos + off, &off, frame_length);
    uint64_t value = _get_varlen_int(buf->send_pos + off, &off, frame_length);

    switch (id) {
      case NGHQ_SETTINGS_MAX_HEADER_LIST_SIZE:
        if (seen_max_header_list_size++) {
          rv = NGHQ_HTTP_MALFORMED_FRAME;
        } else {
          (*settings)->max_header_list_size = value;
        }
        break;
      case NGHQ_SETTINGS_NUM_PLACEHOLDERS:
        if (seen_num_placeholders++) {
          rv = NGHQ_HTTP_MALFORMED_FRAME;
        } else {
          (*settings)->number_of_placeholders = value;
        }
    }
  }

  if (rv == NGHQ_OK) {
    buf->send_pos += frame_length;
    buf->remaining -= frame_length;
  }

  return rv;
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
 * |                   Encoded Field Section (*)                 ...  Payload
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
ssize_t parse_push_promise_frame (nghq_session *session,
                                  nghq_hdr_compression_ctx *ctx,
                                  nghq_io_buf* buf, uint64_t* push_id,
                                  nghq_header ***hdrs, size_t* num_hdrs) {
  size_t push_header_len = 0, push_id_len = 0, frame_payload_len;
  ssize_t result;
  nghq_frame_type type;
  frame_payload_len =
      _get_frame_payload_length(buf->send_pos, &type, &push_header_len);

  if (type != NGHQ_FRAME_TYPE_PUSH_PROMISE) {
    return NGHQ_ERROR;
  }

  if (buf->remaining < push_header_len + frame_payload_len) {
    return push_header_len + frame_payload_len;
  }

  *push_id = _get_varlen_int(buf->send_pos + push_header_len, &push_id_len, push_header_len + frame_payload_len);
  if (push_id_len > push_header_len + frame_payload_len) {
    return NGHQ_HTTP_MALFORMED_FRAME;
  }

  result = nghq_inflate_hdr(session, ctx,
                            buf->send_pos + push_header_len + push_id_len,
                            frame_payload_len - push_id_len, 1, hdrs,
                            num_hdrs);

  if (result == NGHQ_OK) {
    buf->send_pos += push_header_len + frame_payload_len;
    buf->remaining -= push_header_len + frame_payload_len;
  }

  NGHQ_LOG_DEBUG (session, "Received PUSH_PROMISE frame for push ID %lu with "
                  "%lu headers\n", *push_id, *num_hdrs);

  return result;
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
int parse_goaway_frame (nghq_session *session, nghq_io_buf* buf,
                        uint64_t* last_stream_id) {
  size_t off = 0;
  nghq_frame_type type;
  uint64_t frame_length = _get_frame_payload_length(buf->send_pos, &type, &off);

  if (type != NGHQ_FRAME_TYPE_GOAWAY) {
    return NGHQ_ERROR;
  }

  frame_length += off;

  if (buf->remaining < frame_length) {
    return frame_length;
  }

  *last_stream_id = _get_varlen_int(buf->send_pos + off, &off, frame_length);
  if (off > frame_length) {
    return NGHQ_HTTP_MALFORMED_FRAME;
  }

  buf->send_pos += frame_length;
  buf->remaining -= frame_length;

  NGHQ_LOG_DEBUG (session, "Received GOAWAY frame with last stream ID %lu\n",
                  *last_stream_id);

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
int parse_max_push_id_frame (nghq_session *session, nghq_io_buf* buf,
                             uint64_t* max_push_id) {
  size_t off = 0;
  nghq_frame_type type;
  uint64_t frame_length = _get_frame_payload_length(buf->send_pos, &type, &off);

  if (type != NGHQ_FRAME_TYPE_MAX_PUSH_ID) {
    return NGHQ_ERROR;
  }

  frame_length += off;

  if (buf->remaining < frame_length) {
    return frame_length;
  }

  *max_push_id = _get_varlen_int(buf->send_pos + off, &off, frame_length);
  if (off > frame_length) {
    return NGHQ_HTTP_MALFORMED_FRAME;
  }

  buf->send_pos += frame_length;
  buf->remaining -= frame_length;

  NGHQ_LOG_DEBUG (session, "Received MAX_PUSH_ID frame with max push ID %lu\n",
                  *max_push_id);

  return NGHQ_OK;
}
