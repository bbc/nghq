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

#ifndef LIB_IO_BUF_H_
#define LIB_IO_BUF_H_

#include <stdint.h>
#include <stddef.h>

/* A linked list of buffered frames that need sending/receiving. */
typedef struct nghq_io_buf {
  uint8_t *buf;
  size_t  buf_len;
  uint8_t *send_pos;
  size_t  remaining;
  int     complete;

  struct nghq_io_buf *next_buf;
} nghq_io_buf;

/**
 * @brief Constructs a new IO Buffer object and pushes it to the end of the list
 *
 * @param list The IO buffer list to add @p buf to
 * @param buf The buffer to add to the list
 * @param buflen The length of @p buf
 */
int nghq_io_buf_new (nghq_io_buf** list, uint8_t *buf, size_t buflen);

/**
 * @brief Pushes an IO Buffer object to the end of the list
 *
 * @param list The IO buffer list to add @p push to
 * @param push The IO buffer to push
 */
void nghq_io_buf_push (nghq_io_buf** list, nghq_io_buf* push);

/**
 * @brief Pops a buffer from the front of the list.
 *
 * This method will delete the IO Buffer and change the front of the list,
 * so be careful not to hold any references to the old list value anywhere as
 * it will no longer be valid.
 */
void nghq_io_buf_pop (nghq_io_buf** list);

#endif /* LIB_IO_BUF_H_ */
