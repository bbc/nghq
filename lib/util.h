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

#ifndef LIB_UTIL_H_
#define LIB_UTIL_H_

#include <stdint.h>
#include <sys/types.h>

#ifdef WORDS_BIGENDIAN
#define bswap64(N) (N)
#else /* !WORDS_BIGENDIAN */
#define bswap64(N) \
  ((uint64_t)(ntohl((uint32_t)(N))) << 32 | ntohl((uint32_t)((N) >> 32)))
#endif /* !WORDS_BIGENDIAN */

uint16_t get_uint16_from_buf (const uint8_t* buf);
int16_t get_int16_from_buf (const uint8_t* buf);

void put_uint16_in_buf (uint8_t* buf, uint16_t n);
void put_int16_in_buf (uint8_t* buf, int16_t n);

uint32_t get_uint24_from_buf (const uint8_t* buf);
void put_uint24_in_buf (uint8_t* buf, uint32_t n);

uint32_t get_uint32_from_buf (const uint8_t* buf);
int32_t get_int32_from_buf (const uint8_t* buf);

void put_uint32_in_buf (uint8_t* buf, uint32_t n);
void put_int32_in_buf (uint8_t* buf, int32_t n);

uint64_t get_uint64_from_buf (const uint8_t* buf);
int64_t get_int64_from_buf (const uint8_t* buf);

void put_uint64_in_buf (uint8_t* buf, uint64_t n);
void put_int64_in_buf (uint8_t* buf, int64_t n);

uint64_t get_packet_number (uint8_t first_byte, const uint8_t *buf,
                            uint64_t base);
size_t put_packet_number (uint64_t pkt_num, size_t len, uint8_t *buf,
                          size_t buf_len);

uint64_t get_timestamp_now();

/*
 * 62 bit max: 0x3FFFFFFFFFFFFFFF (4611686018427387903)
 * 30 bit max: 0x3FFFFFFF
 * 14 bit max: 0x3FFF
 * 6 bit max: 0x3F
 */
#define _VARLEN_INT_MAX_62_BIT 0x4000000000000000ULL
#define _VARLEN_INT_MAX_30_BIT 0x40000000
#define _VARLEN_INT_MAX_14_BIT 0x4000
#define _VARLEN_INT_MAX_6_BIT 0x40

#define _VARLEN_INT_62_BIT 0xC0
#define _VARLEN_INT_30_BIT 0x80
#define _VARLEN_INT_14_BIT 0x40
#define _VARLEN_INT_6_BIT 0x00

size_t _make_varlen_int (uint8_t* buf, uint64_t n);
uint64_t _get_varlen_int (const uint8_t* buf, size_t* bytes, size_t max_bytes);

uint64_t rand64();

#endif /* LIB_UTIL_H_ */
