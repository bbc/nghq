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

#include "util.h"
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/time.h>

uint16_t get_uint16_from_buf (const uint8_t* buf) {
  uint16_t rv;
  memcpy (&rv, buf, 2);
  return ntohs(rv);
}
int16_t get_int16_from_buf (const uint8_t* buf) {
  int16_t rv;
  memcpy (&rv, buf, 2);
  return (int16_t) ntohs(rv);
}

void put_uint16_in_buf (uint8_t* buf, uint16_t n) {
  n = htons(n);
  memcpy (buf, (uint8_t *)&n, 2);
}
void put_int16_in_buf (uint8_t* buf, int16_t n) {
  put_uint16_in_buf (buf, (uint16_t) n);
}

uint32_t get_uint24_from_buf (const uint8_t* buf) {
  uint32_t rv = 0;
  memcpy (((uint8_t *) &rv) + 1, buf, 3);
  return ntohl(rv);
}

void put_uint24_in_buf (uint8_t* buf, uint32_t n) {
  n = htonl(n);
  memcpy (buf, ((uint8_t *) &n) + 1, 3);
}

uint32_t get_uint32_from_buf (const uint8_t* buf) {
  uint32_t rv;
  memcpy (&rv, buf, 4);
  return ntohl(rv);
}
int32_t get_int32_from_buf (const uint8_t* buf) {
  int32_t rv;
  memcpy (&rv, buf, 4);
  return (int32_t) ntohl(rv);
}

void put_uint32_in_buf (uint8_t* buf, uint32_t n) {
  n = htonl(n);
  memcpy (buf, (uint8_t *)&n, 4);
}
void put_int32_in_buf (uint8_t* buf, int32_t n) {
  put_uint32_in_buf (buf, (uint32_t)n);
}

uint64_t get_uint64_from_buf (const uint8_t* buf) {
  uint64_t rv;
  memcpy (&rv, buf, 8);
  return bswap64(rv);
}
int64_t get_int64_from_buf (const uint8_t* buf) {
  int64_t rv;
  memcpy (&rv, buf, 8);
  return bswap64(rv);
}

void put_uint64_in_buf (uint8_t* buf, uint64_t n) {
  n = bswap64(n);
  memcpy (buf, (uint8_t *)&n, 8);
}
void put_int64_in_buf (uint8_t* buf, int64_t n) {
  put_uint64_in_buf( buf, (uint64_t)n);
}

#define PKTNUM_1BYTE_BASE_MASK(x) (x & 0xFFFFFFFFFFFFFF00)
#define PKTNUM_1BYTE_UPPER_QUARTILE(x) ((uint8_t) x) >= 192
#define PKTNUM_1BYTE_LOWER_QUARTILE(x) ((uint8_t) x) < 64

#define PKTNUM_2BYTE_BASE_MASK(x) (x & 0xFFFFFFFFFFFF0000)
#define PKTNUM_2BYTE_UPPER_QUARTILE(x) ((uint16_t) x) >= 49152
#define PKTNUM_2BYTE_LOWER_QUARTILE(x) ((uint16_t) x) < 16384

#define PKTNUM_3BYTE_BASE_MASK(x) (x & 0xFFFFFFFFFF000000)
#define PKTNUM_3BYTE_UPPER_QUARTILE(x) (x & 0xFFFFFF) >= 12582912
#define PKTNUM_3BYTE_LOWER_QUARTILE(x) (x & 0xFFFFFF) < 4194304

#define PKTNUM_4BYTE_BASE_MASK(x) (x & 0xFFFFFFFF00000000)
#define PKTNUM_4BYTE_UPPER_QUARTILE(x) ((uint32_t) x) >= 3221225472
#define PKTNUM_4BYTE_LOWER_QUARTILE(x) ((uint32_t) x) < 1073741824

uint64_t get_packet_number (uint8_t first_byte, const uint8_t *buf,
                            uint64_t base) {
  uint64_t pkt_num = 0;
  switch (first_byte & 0x03) {
    case 0:
      pkt_num = (uint64_t) buf[0];
      break;
    case 1:
      pkt_num = (uint64_t) get_uint16_from_buf (buf);
      break;
    case 2:
      pkt_num = (uint64_t) get_uint24_from_buf (buf);
      break;
    case 3:
      pkt_num = (uint64_t) get_uint32_from_buf (buf);
  }

  /* If base is zero, this is either the first packet, or we don't want to
   * calculate the full number. We also don't want to do anything on the very
   * lowest quartile as this could get messy with wraps back to the top of the
   * number space!
   */
  if (base > 64) {
    switch (first_byte & 0x03) {
      case 0:
        if (PKTNUM_1BYTE_UPPER_QUARTILE(base) &&
            PKTNUM_1BYTE_LOWER_QUARTILE(pkt_num)) {
          /* Probably a wrapping packet number */
          pkt_num |= PKTNUM_1BYTE_BASE_MASK((base + 0x100));
        } else if (PKTNUM_1BYTE_LOWER_QUARTILE(base) &&
                   PKTNUM_1BYTE_UPPER_QUARTILE(pkt_num)) {
          /* Probably an out-of-order packet */
          pkt_num |= PKTNUM_1BYTE_BASE_MASK((base - 0x100));
        } else {
          pkt_num |= PKTNUM_1BYTE_BASE_MASK(base);
        }
        break;
      case 1:
        if (PKTNUM_2BYTE_UPPER_QUARTILE(base) &&
            PKTNUM_2BYTE_LOWER_QUARTILE(pkt_num)) {
          /* Probably a wrapping packet number */
          pkt_num |= PKTNUM_2BYTE_BASE_MASK((base + 0x10000));
        } else if (PKTNUM_2BYTE_LOWER_QUARTILE(base) &&
                   PKTNUM_2BYTE_UPPER_QUARTILE(pkt_num)) {
          /* Probably an out-of-order packet */
          pkt_num |= PKTNUM_2BYTE_BASE_MASK((base - 0x10000));
        } else {
          pkt_num |= PKTNUM_2BYTE_BASE_MASK(base);
        }
        break;
      case 2:
        if (PKTNUM_3BYTE_UPPER_QUARTILE(base) &&
            PKTNUM_3BYTE_LOWER_QUARTILE(pkt_num)) {
          /* Probably a wrapping packet number */
          pkt_num |= PKTNUM_3BYTE_BASE_MASK((base + 0x1000000));
        } else if (PKTNUM_3BYTE_LOWER_QUARTILE(base) &&
                   PKTNUM_3BYTE_UPPER_QUARTILE(pkt_num)) {
          /* Probably an out-of-order packet */
          pkt_num |= PKTNUM_3BYTE_BASE_MASK((base - 0x1000000));
        } else {
          pkt_num |= PKTNUM_3BYTE_BASE_MASK(base);
        }
        break;
      case 3:
        if (PKTNUM_4BYTE_UPPER_QUARTILE(base) &&
            PKTNUM_4BYTE_LOWER_QUARTILE(pkt_num)) {
          /* Probably a wrapping packet number */
          pkt_num |= PKTNUM_4BYTE_BASE_MASK((base + 0x100000000));
        } else if (PKTNUM_4BYTE_LOWER_QUARTILE(base) &&
                   PKTNUM_4BYTE_UPPER_QUARTILE(pkt_num)) {
          /* Probably an out-of-order packet */
          pkt_num |= PKTNUM_4BYTE_BASE_MASK((base - 0x100000000));
        } else {
          pkt_num |= PKTNUM_4BYTE_BASE_MASK(base);
        }
        break;
    }
  }

  return pkt_num;
}

size_t put_packet_number (uint64_t pkt_num, size_t len,
                          uint8_t *buf, size_t buf_len) {
  /* Shave it down to 32 bits */
  uint32_t wire_pkt_num = (uint32_t) pkt_num;
  switch(len) {
    case 1:
      buf[0] = (uint8_t) wire_pkt_num;
      break;
    case 2:
      put_uint16_in_buf (buf, (uint16_t) wire_pkt_num);
      break;
    case 3:
      put_uint24_in_buf (buf, (uint32_t) wire_pkt_num);
      break;
    case 4:
      put_uint32_in_buf (buf, wire_pkt_num);
      break;
  }
  return len;
}

uint64_t get_timestamp_now () {
  struct timeval tv;
  gettimeofday(&tv,NULL);
  return ((1000000 * tv.tv_sec) + tv.tv_usec);
}

/*
 * ngtcp2 has some routines for this, but they're not exposed by the public
 * API, which is unfortunate. So I've cribbed these from -
 * https://github.com/ngtcp2/ngtcp2/blob/master/lib/ngtcp2_conv.c
 */

/*
 * Create a new variable length integer into the memory provided in @p buf, and
 * return the number of bytes that were used to write it. If the number was
 * too big, then it returns 0.
 *
 * If @p buf is NULL, this only calculates how big the buffer would need to be.
 */
size_t _make_varlen_int (uint8_t* buf, uint64_t n) {
  size_t rv;
  if (n < _VARLEN_INT_MAX_6_BIT) {
    if (buf != NULL) {
      buf[0] = (uint8_t) n;
    }
    rv = 1;
  } else if (n < _VARLEN_INT_MAX_14_BIT) {
    if (buf != NULL) {
      put_uint16_in_buf (buf, (uint16_t) n);
      buf[0] |= _VARLEN_INT_14_BIT;

    }
    rv = 2;
  } else if (n < _VARLEN_INT_MAX_30_BIT) {
    if (buf != NULL) {
      put_uint32_in_buf (buf, (uint32_t) n);
      buf[0] |= _VARLEN_INT_30_BIT;
    }
    rv = 4;
  } else if (n < _VARLEN_INT_MAX_62_BIT) {
    if (buf != NULL) {
      put_uint64_in_buf (buf, (uint64_t) n);
      buf[0] |= _VARLEN_INT_62_BIT;
    }
    rv = 8;
  } else {
    /* Couldn't actually encode this integer (>62 bits) */
    rv = 0;
  }
  return rv;
}

/*
 * A function to get a variable length integer, as well as how many bytes long
 * it was to adjust buffer offsets. @p buf *must* be at least 8 bytes long to
 * contain a full varlen. It will assume bytes starts at 0 on buf and add the
 * number of bytes read on, so you can use it to keep track of a buffer offset
 * on repeated calls to the library.
 */

uint64_t _get_varlen_int (const uint8_t* buf, size_t* bytes, size_t max_bytes) {
  uint64_t rv = 0;
  union {
    char b[8];
    uint16_t n16;
    uint32_t n32;
    uint64_t n64;
  } n;

  switch (buf[0] & 0xC0) {
    case _VARLEN_INT_6_BIT:
      *bytes += 1;
      rv = (uint64_t) buf[0];
      break;
    case _VARLEN_INT_14_BIT:
      if (*bytes + 2 <= max_bytes) {
        memcpy(&n, buf, 2);
        n.b[0] &= 0x3f;
        rv = (uint64_t) ntohs(n.n16);
      }
      *bytes += 2;
      break;
    case _VARLEN_INT_30_BIT:
      if (*bytes + 4 <= max_bytes) {
        memcpy(&n, buf, 4);
        n.b[0] &= 0x3f;
        rv = (uint64_t) ntohl(n.n32);
      }
      *bytes += 4;
      break;
    case _VARLEN_INT_62_BIT:
      if (*bytes + 8 <= max_bytes) {
        memcpy(&n, buf, 8);
        n.b[0] &= 0x3f;
        rv = (uint64_t) bswap64(n.n64);
      }
      *bytes += 8;
      break;
  }

  return rv;
}

uint64_t rand64 () {
  uint64_t n;

  n = (uint64_t) rand();
  n |= ((uint64_t) rand()) << 32;

  return n;
}
