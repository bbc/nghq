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

#include "io_buf.h"
#include "nghq/nghq.h"

#include <stdlib.h>

int nghq_io_buf_new (nghq_io_buf** list, uint8_t *buf, size_t buflen, int fin) {
  nghq_io_buf* io_buf = (nghq_io_buf *) malloc (sizeof(nghq_io_buf));
  if (io_buf == NULL) {
    return NGHQ_OUT_OF_MEMORY;
  }

  io_buf->send_pos = io_buf->buf = buf;
  io_buf->remaining = io_buf->buf_len = buflen;
  io_buf->complete = (fin)?(1):(0);

  nghq_io_buf_push(list, io_buf);
  return NGHQ_OK;
}

void nghq_io_buf_push (nghq_io_buf** list, nghq_io_buf* push) {
  nghq_io_buf *p = *list;
  if (p == NULL) {
    *list = push;
    push->next_buf = NULL;
    return;
  }
  while (p->next_buf != NULL) {
    p = p->next_buf;
  }
  p->next_buf = push;
  push->next_buf = NULL;
}

void nghq_io_buf_pop (nghq_io_buf** list) {
  nghq_io_buf* node = *list;
  if (node == NULL) {
    return;
  }
  *list = node->next_buf;
  free (node->buf);
  node->send_pos = node->buf = NULL;
  node->remaining = node->buf_len = 0;
  node->complete = 0;
  free (node);
}

void nghq_io_buf_clear (nghq_io_buf** list) {
  while (*list != NULL) {
    nghq_io_buf* node = *list;
    *list = node->next_buf;
    free (node->buf);
    node->send_pos = node->buf = NULL;
    node->remaining = node->buf_len = 0;
    node->complete = 0;
    free (node);
  }
}
