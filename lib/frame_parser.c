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



/*
 * Parse the frame header - returns the length of the frame. @p buf *must* be
 * at least 10 bytes long in order to contain a complete HTTP/QUIC frame header
 */
static uint64_t _parse_frame_header (uint8_t* buf, nghq_frame_type *type,
                              uint8_t *flags, size_t *length_size) {
  uint64_t len = _get_varlen_int(buf, length_size, 10);
  *type = buf[*length_size];
  if (flags != NULL) {
    *flags = buf[++(*length_size)];
  }
  *length_size += 2; /* Type + flags */
  return len;
}

ssize_t parse_frame_header (nghq_io_buf* buf, nghq_frame_type *type) {
  uint64_t frame_length = 0;
  size_t header_length = 0;

  if (buf == NULL) return 0;

  if (buf->remaining < 10) {
    /*
     * Check short buffers are long enough for a full HTTP/QUIC header, so we
     * don't have any risk of overflowing when parsing
     */
    if ((buf->send_pos[0] & 0xC0) == _VARLEN_INT_62_BIT) {
      return 0;
    }
    if (((buf->send_pos[0] & 0xC0) == _VARLEN_INT_30_BIT) &&
        (buf->remaining < 6)) {
      return 0;
    }
    if (((buf->send_pos[0] & 0xC0) == _VARLEN_INT_14_BIT) &&
        (buf->remaining < 4)) {
      return 0;
    }
    if (buf->remaining < 3) {
      return 0;
    }
  }

  frame_length =
      _parse_frame_header (buf->send_pos, type, NULL, &header_length);

  if (*type == NGHQ_FRAME_TYPE_BAD) {
    return NGHQ_ERROR;
  }

  return frame_length + header_length;
}

/*
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           Length (i)       ...|    Type (8)   |   Flags (8)   |  Frame HDR
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ===========
 * |                         Body Block (*)                        |  DATA
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  Payload
 */
ssize_t parse_data_frame (nghq_io_buf* buf, uint8_t** data, size_t *data_len) {
  size_t varint_len = 0;
  *data_len = _get_varlen_int(buf->send_pos, &varint_len, 10);

  if (buf->send_pos[varint_len] != NGHQ_FRAME_TYPE_DATA) {
    return NGHQ_ERROR;
  }

  if (*data_len > buf->remaining - varint_len - 2) {
    /* not enough data, return NULL data and size wanted */
    *data = NULL;
    return *data_len + varint_len + 2;
  }

  *data = buf->send_pos + varint_len + 2;
  buf->send_pos += *data_len + varint_len + 2;
  buf->remaining -= *data_len + varint_len + 2;
  return 0;
}

/*
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           Length (i)       ...|    Type (8)   |   Flags (8)   |  Frame HDR
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ===========
 * |                        Header Block (*)                       |  HEADERS
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  Payload
 */
ssize_t parse_headers_frame (nghq_hdr_compression_ctx* ctx, nghq_io_buf* buf,
                             nghq_header*** hdrs, size_t* num_hdrs) {
  size_t header_len = 0, expected_header_block_len;
  ssize_t result;
  nghq_frame_type type;
  expected_header_block_len =
      _parse_frame_header(buf->send_pos, &type, NULL, &header_len);

  if (type != NGHQ_FRAME_TYPE_HEADERS) {
    return NGHQ_ERROR;
  }

  if (expected_header_block_len + header_len > buf->remaining) {
    return expected_header_block_len + header_len;
  }

  result = nghq_inflate_hdr(ctx, buf->send_pos + header_len,
                            expected_header_block_len, 1, hdrs, num_hdrs);

  if (result < 0) return result;

  buf->send_pos += expected_header_block_len + header_len;
  buf->remaining -= expected_header_block_len + header_len;

  return 0;
}

/*
 *  0                   1                   2                   3
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
int parse_priority_frame (nghq_io_buf* buf, uint8_t* flags,
                          uint64_t* request_id, uint64_t* dependency_id,
                          uint8_t* weight) {
  size_t off = 0;
  nghq_frame_type type;
  uint64_t frame_length = _parse_frame_header(buf->send_pos, &type, flags, &off);

  if (type != NGHQ_FRAME_TYPE_PRIORITY) {
    return NGHQ_ERROR;
  }

  frame_length += off;

  if (buf->remaining < frame_length) {
    return frame_length;
  }

  *request_id = _get_varlen_int(buf->send_pos+off, &off, frame_length);
  if (off > frame_length) {
    return NGHQ_HTTP_MALFORMED_FRAME;
  }
  *dependency_id = _get_varlen_int(buf->send_pos+off, &off, frame_length);
  if (off >= frame_length) {
    return NGHQ_HTTP_MALFORMED_FRAME;
  }
  *weight = buf->send_pos[off];

  buf->send_pos += frame_length;
  buf->remaining -= frame_length;

  return NGHQ_OK;
}

/*
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           Length (i)       ...|    Type (8)   |   Flags (8)   |  Frame HDR
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ===========
 * |                          Push ID (i)                        ... CANCEL_PUSH
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  Payload
 */
int parse_cancel_push_frame (nghq_io_buf* buf, uint64_t* push_id) {
  size_t off = 0;
  nghq_frame_type type;
  uint64_t frame_length = _parse_frame_header(buf->send_pos, &type, NULL, &off);

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

  return NGHQ_OK;
}

/*
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           Length (i)      ... |    Type (8)   |   Flags (8)   |  Frame HDR
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ===========
 * |         Identifier (16)       |            Length (i)       ...  SETTINGS
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  Payload
 * |                          Contents (?)                       ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
int parse_settings_frame (nghq_io_buf* buf, nghq_settings** settings) {
  size_t off = 0;
  nghq_frame_type type;
  uint64_t frame_length;
  int rv = NGHQ_OK;
  int seen_header_table_size = 0;
  int seen_max_header_list_size = 0;

  frame_length = _parse_frame_header(buf->send_pos, &type, NULL, &off);

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
    (*settings)->header_table_size = NGHQ_SETTINGS_DEFAULT_HEADER_TABLE_SIZE;
    (*settings)->max_header_list_size =
        NGHQ_SETTINGS_DEFAULT_MAX_HEADER_LIST_SIZE;
  }

  while (rv == NGHQ_OK && off < frame_length) {
    int16_t id;
    uint64_t len;

    if (off + 2 > frame_length) {
      rv = NGHQ_HTTP_MALFORMED_FRAME;
      break;
    }
    id = get_int16_from_buf(buf->send_pos + off);
    off += 2;

    len = _get_varlen_int(buf->send_pos + off, &off, frame_length);
    if (off > frame_length) {
      rv = NGHQ_HTTP_MALFORMED_FRAME;
      break;
    }

    if (off + len <= frame_length) {
      switch (id) {
        case NGHQ_SETTINGS_HEADER_TABLE_SIZE:
          if (seen_header_table_size) {
            rv = NGHQ_HTTP_MALFORMED_FRAME;
          } else {
            (*settings)->header_table_size =
                _get_varlen_int(buf->send_pos + off, &off, frame_length);
            seen_header_table_size = 1;
            if (off > frame_length) {
              rv = NGHQ_HTTP_MALFORMED_FRAME;
            }
          }
          break;
        case NGHQ_SETTINGS_MAX_HEADER_LIST_SIZE:
          if (seen_max_header_list_size) {
            rv = NGHQ_HTTP_MALFORMED_FRAME;
          } else {
            (*settings)->max_header_list_size =
                _get_varlen_int(buf->send_pos + off, &off, frame_length);
            seen_max_header_list_size = 1;
            if (off > frame_length) {
              rv = NGHQ_HTTP_MALFORMED_FRAME;
            }
          }
          break;
        default:
          rv = NGHQ_HTTP_MALFORMED_FRAME;
      }
    } else {
      rv = NGHQ_HTTP_MALFORMED_FRAME;
    }
    off += len;
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
 * |           Length (i)       ...|    Type (8)   |   Flags (8)   |  Frame HDR
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ===========
 * |                          Push ID (i)                        ...  PUSH_
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  PROMISE
 * |                       Header Block (*)                      ...  Payload
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
ssize_t parse_push_promise_frame (nghq_hdr_compression_ctx *ctx,
                                  nghq_io_buf* buf, uint64_t* push_id,
                                  nghq_header ***hdrs, size_t* num_hdrs) {
  size_t push_header_len = 0, push_id_len = 0, frame_payload_len;
  ssize_t result;
  nghq_frame_type type;
  frame_payload_len =
      _parse_frame_header(buf->send_pos, &type, NULL, &push_header_len);

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

  result = nghq_inflate_hdr(ctx, buf->send_pos + push_header_len + push_id_len,
                          frame_payload_len - push_id_len, 1, hdrs,
                          num_hdrs);

  if (result == NGHQ_OK) {
    buf->send_pos += push_header_len + frame_payload_len;
    buf->remaining -= push_header_len + frame_payload_len;
  }

  return result;
}

/*
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           Length (i)       ...|    Type (8)   |   Flags (8)   |  Frame HDR
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ===========
 * |                         Stream ID (i)                       ...  GOAWAY
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  Payload
 */
int parse_goaway_frame (nghq_io_buf* buf, uint64_t* last_stream_id) {
  size_t off = 0;
  nghq_frame_type type;
  uint64_t frame_length = _parse_frame_header(buf->send_pos, &type, NULL, &off);

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

  return NGHQ_OK;
}

/*
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           Length (i)       ...|    Type (8)   |   Flags (8)   |  Frame HDR
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ===========
 * |                      Maximum Push ID (i)                    ... MAX_PUSH_ID
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  Payload
 */
int parse_max_push_id_frame (nghq_io_buf* buf, uint64_t* max_push_id) {
  size_t off = 0;
  nghq_frame_type type;
  uint64_t frame_length = _parse_frame_header(buf->send_pos, &type, NULL, &off);

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

  return NGHQ_OK;
}
