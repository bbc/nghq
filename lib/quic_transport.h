/*
 * quic_transport.h
 *
 *  Created on: 24 Jan 2020
 *      Author: samuelh
 */

#ifndef LIB_QUIC_TRANSPORT_H_
#define LIB_QUIC_TRANSPORT_H_

#include <stdint.h>
#include <sys/types.h>
#include "nghq_internal.h"

/*
 * @return NGHQ_TRANSPORT_ERROR if this isn't a compatible QUIC packet.
 */
ssize_t quic_transport_packet_parse (nghq_session *ctx, uint8_t *buf,
                                     size_t len, uint64_t ts);


ssize_t quic_transport_write_stream (nghq_session *ctx, nghq_stream *stream,
                                     uint8_t *buf_in, size_t len_in,
                                     uint8_t *buf_out, size_t buf_out_len,
                                     int fin, size_t *buf_written);

int64_t quic_transport_open_stream (nghq_session *ctx, nghq_stream_type type);

#endif /* LIB_QUIC_TRANSPORT_H_ */
