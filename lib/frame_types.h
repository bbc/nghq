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

#ifndef LIB_FRAME_TYPES_H_
#define LIB_FRAME_TYPES_H_

#include <stdint.h>
#include <stdbool.h>

/* Using an enum would require casting every time, just use macros... */
typedef uint64_t nghq_frame_type;
#define NGHQ_FRAME_TYPE_DATA 0x0LL
#define NGHQ_FRAME_TYPE_HEADERS 0x1LL
#define NGHQ_FRAME_TYPE_CANCEL_PUSH 0x3LL
#define NGHQ_FRAME_TYPE_SETTINGS 0x4LL
#define NGHQ_FRAME_TYPE_PUSH_PROMISE 0x5LL
#define NGHQ_FRAME_TYPE_GOAWAY 0x7LL
#define NGHQ_FRAME_TYPE_MAX_PUSH_ID 0xDLL

#define NGHQ_FRAME_TYPE_BAD 0xFF

#define NGHQ_SETTINGS_FLAG_PUSH_PRIORITY 0x04
#define NGHQ_SETTINGS_FLAG_PUSH_DEPENDENT 0x02
#define NGHQ_SETTINGS_FLAG_EXCLUSIVE 0x01

#endif /* LIB_FRAME_TYPES_H_ */
