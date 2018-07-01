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

#ifndef LIB_STREAM_TYPES_H_
#define LIB_STREAM_TYPES_H_

#include <stdint.h>

/* Using an enum would require casting every time, just use macros... */
typedef uint8_t nghq_stream_type;
#define NGHQ_STREAM_TYPE_CONTROL 0x43
#define NGHQ_STREAM_TYPE_PUSH 0x50
#define NGHQ_STREAM_TYPE_UNBOUND_PUSH 0xF0

#define NGHQ_STREAM_TYPE_BAD 0xFF

/*
 * A function to get a stream header. @p buf *must* be 1 byte long to
 * contain a full stream type. This function assumes the byte appears at 0
 * on buf and adds the byte read, so you can use it to keep track of a buffer offset
 * on repeated calls to the library.
 */

nghq_stream_type get_stream_type (const uint8_t* buf, size_t* bytes);

/*
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |Stream Type (8)|                  Push ID (i)                ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Returns NGHQ_OUT_OF_MEMORY or NGHQ_OK
 */
int create_push_stream_header(int64_t push_id, 
                              uint8_t** stream_header, size_t* stream_header_len);

/*
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |Stream Type (8)| 
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Returns NGHQ_OUT_OF_MEMORY or NGHQ_OK
 */
int create_unbound_push_stream_header(uint8_t** stream_header, size_t* stream_header_len);


#endif /* LIB_STEAM_TYPES_H_ */
