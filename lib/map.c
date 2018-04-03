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

#include <stdint.h>
#include <stdlib.h>

#include "map.h"

/*
 * TODO: Replace with an actual map implementation, not just a linked list which
 * will suffice for the hackathon, but will not be acceptable for an actual
 * implementation!
 */

typedef struct _stream_id_list_node {
  uint64_t stream_id;
  nghq_stream* stream_data;
  struct _stream_id_list_node* prev;
  struct _stream_id_list_node* next;
} _stream_id_list_node;

struct nghq_map_ctx {
  _stream_id_list_node *begin;
  _stream_id_list_node *end;

  size_t size;
};

nghq_map_ctx * nghq_stream_id_map_init() {
  nghq_map_ctx * map = (nghq_map_ctx *) malloc(sizeof(nghq_map_ctx));
  map->begin = NULL;
  map->end = NULL;
  map->size = 0;
  return map;
}

int nghq_stream_id_map_add (nghq_map_ctx *ctx, uint64_t stream_id,
                            nghq_stream* stream_data) {
  if (ctx == NULL) {
    return NGHQ_ERROR;
  }

  _stream_id_list_node *node =
      (_stream_id_list_node*) malloc(sizeof(_stream_id_list_node));
  if (node == NULL) {
    return NGHQ_ERROR;
  }
  node->stream_id = stream_id;
  node->stream_data = stream_data;

  if (ctx->end == NULL) {  /* First element */
    ctx->begin = node;
    ctx->end = node;
    node->prev = NULL;
    node->next = NULL;
  } else {
    node->prev = ctx->end;
    ctx->end->next = node;
    ctx->end = node;
    node->next = NULL;
  }

  ctx->size++;

  return NGHQ_OK;
}

nghq_stream *nghq_stream_id_map_find (nghq_map_ctx *ctx, uint64_t stream_id) {
  _stream_id_list_node *find;
  nghq_stream *rv = NULL;

  if (ctx == NULL) {
    return NULL;
  }

  find = ctx->begin;

  while (find != NULL) {
    if (find->stream_id == stream_id) {
      rv = find->stream_data;
      break;
    }
    find = find->next;
  }

  return rv;
}

uint64_t nghq_stream_id_map_search (nghq_map_ctx *ctx, void* user_data) {
  _stream_id_list_node *find;
  uint64_t rv = NGHQ_STREAM_ID_MAP_NOT_FOUND;

  if (ctx == NULL) {
    return NGHQ_STREAM_ID_MAP_NOT_FOUND;
  }

  find = ctx->begin;

  while (find != NULL) {
    if (find->stream_data->user_data == user_data) {
      rv = find->stream_id;
      break;
    }
    find = find->next;
  }

  return rv;
}

nghq_stream *nghq_stream_id_map_stream_search(nghq_map_ctx* ctx,
                                              void* user_data) {
  _stream_id_list_node *find;
  nghq_stream* rv = NULL;

  if (ctx == NULL) {
    return NULL;
  }

  find = ctx->begin;

  while (find != NULL) {
    if (find->stream_data->user_data == user_data) {
      rv = find->stream_data;
      break;
    }
    find = find->next;
  }

  return rv;
}

nghq_stream *nghq_stream_id_map_iterator (nghq_map_ctx* ctx, nghq_stream *prev) {
  _stream_id_list_node *find;
  nghq_stream* rv = NULL;

  if ((ctx == NULL) || (ctx->size == 0)){
    return NULL;
  }

  if (prev == NULL) {
    return ctx->begin->stream_data;
  }

  find = ctx->begin;

  while (find != NULL) {
    if (find->stream_data == prev) {
      if (find->next == NULL) {
        rv = NULL;
      } else {
        rv = find->next->stream_data;
      }
      break;
    }
    find = find->next;
  }

  return rv;
}

int nghq_stream_id_map_remove (nghq_map_ctx *ctx, uint64_t stream_id) {
  _stream_id_list_node *find;

  if (ctx == NULL) {
    return NGHQ_ERROR;
  }

  find = ctx->begin;

  while (find != NULL) {
    if (find->stream_id == stream_id) {
      if (find == ctx->begin) {
        if (find->next == NULL) {  /* The only item */
          ctx->begin = NULL;
          ctx->end = NULL;
        } else {
          ctx->begin = find->next;
          ctx->begin->prev = NULL;
        }
      } else if (find == ctx->end) {
        if (find->prev == NULL) {  /* The only item */
          ctx->begin = NULL;
          ctx->end = NULL;
        } else {
          ctx->end = find->prev;
          ctx->end->next = NULL;
        }
      } else {
        find->prev->next = find->next;
        find->next->prev = find->prev;
      }
      free (find);
      ctx->size--;
      return NGHQ_OK;
    }
    find = find->next;
  }

  return NGHQ_ERROR;
}

size_t nghq_stream_id_map_num_requests (nghq_map_ctx *ctx) {
  size_t num = 0;
  _stream_id_list_node *node = ctx->begin;

  while (node != NULL) {
    if ((node->stream_data->stream_id % 4) == 0) {
      num++;
    }
    node = node->next;
  }

  return num;
}

size_t nghq_stream_id_map_num_pushes (nghq_map_ctx *ctx) {
  size_t num = 0;
  _stream_id_list_node *node = ctx->begin;

  while (node != NULL) {
    if ((node->stream_data->stream_id % 4) == 3) {
      num++;
    }
    node = node->next;
  }

  return num;
}

void nghq_stream_id_map_destroy (nghq_map_ctx *ctx) {
  _stream_id_list_node *find;

  if (ctx == NULL) {
    return;
  }

  find = ctx->begin;
  ctx->begin = NULL;
  ctx->end = NULL;
  ctx->size = 0;

  while (find != NULL) {
    _stream_id_list_node *prev;
    prev = find;
    find = find->next;
    free (prev);
  }

  free (ctx);
}
