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
 * @brief Read and process a QUIC Packet
 *
 * @param ctx The NGHQ session context
 * @param buf The received QUIC packet
 * @param len The length of the QUIC packet
 * @param ts A timestamp that indicates when this packet was received.
 *
 * @return NGHQ_OK if the whole packet was read
 * @return NGHQ_TRANSPORT_ERROR if this isn't a compatible QUIC packet.
 * @return NGHQ_TRANSPORT_BAD_SESSION_ID if the session ID doesn't match this
 *              session.
 * @return NGHQ_CRYPTO_ERROR if the underlying decryption call fails.
 *
 */
ssize_t quic_transport_packet_parse (nghq_session *ctx, uint8_t *buf,
                                     size_t len, uint64_t ts);

/**
 * @brief Write a QUIC packet header
 *
 * This function will write a QUIC packet header into the buffer provided at
 * @p buf, and increment the packet number. If for any reason the packet that
 * this header is used for is not sent, then quic_transport_abandon_packet MUST
 * be called before this function is called again, otherwise you will have
 * packet number discontinuity on the wire.
 *
 * @param ctx The NGHQ Session context
 * @param buf The buffer to write the packet header into
 * @param len The length of the packet header
 * @param pktnum A reference to the new packet number, required should you ever
 *            call quic_transport_abandon_packet.
 * @return The length of the QUIC packet header written into @p buf
 * @return NGHQ_ERROR If the packet header couldn't be written.
 */
ssize_t quic_transport_write_quic_header (nghq_session *ctx, uint8_t *buf,
                                          size_t len, uint64_t *pktnum);

/**
 * @brief Roll back allocating a packet number for a new QUIC packet
 *
 * Takes a buffer @p buf as an argument to a QUIC packet. If the packet number
 * matches the last-sent packet number as assigned in
 * quic_transport_write_quic_header, then the packet number is rolled back. This
 * function must be called before any call to quic_transport_encrypt
 * successfully returns.
 *
 * @param ctx The NGHQ Session context.
 * @param buf The buffer containing a packet header
 * @param len The length of the packet header
 * @param pktnum The full version of the packet number in the header.
 */
void quic_transport_abandon_packet (nghq_session *ctx, uint8_t *buf,
                                    size_t len, uint64_t pktnum);

/**
 * @brief Create a stream frame in a QUIC packet to be sent
 *
 * This function will take some stream data in @p buf_in and create a QUIC
 * packet and stream frame header in the buffer passed to @p buf_out.
 *
 * This function returns the number of bytes of @p buf_in that were succesfully
 * written into the resultant QUIC packet. If this value is not equal to that
 * of @p len_in, then the output buffer could not contain the full payload.
 * Callers should then call this function again with a fresh @p buf_out buffer
 * and @p buf_in offset against the previous return value, and @p len_in
 * decreased appropriately. Then you will have a series of QUIC packets that
 * need to be sent.
 *
 * @param ctx The NGHQ session context
 * @param stream The stream context that this buffer is to be sent on
 * @param buf_in A buffer containing one or more HTTP/3 frames
 * @param len_in The length of the buffer @p buf_in
 * @param buf_out A buffer to contain the resulting QUIC packet. The buffer must
 *            be pre-allocated, and must not overlap with the buffer @p buf_in.
 * @param buf_out_len The length of the allocated buffer in @p buf_out
 * @param fin Set the fin bit in this packet if it is the last packet. If the
 *            whole buffer in @p buf_in cannot be used, then the FIN bit will
 *            not be set and this function should be called again.
 * @param buf_written The number of bytes of @p buf_in that were written
 *
 * @return The size of the resulting QUIC stream frame, which will be less than
 *            or equal to @p buf_out_len.
 * @return NGHQ_CRYPTO_ERROR if the underlying encryption callback fails
 */
ssize_t quic_transport_write_stream (nghq_session *ctx, nghq_stream *stream,
                                     uint8_t *buf_in, size_t len_in,
                                     uint8_t *buf_out, size_t buf_out_len,
                                     int fin, size_t *buf_written);

/**
 * @brief Encrypt a QUIC transport packet.
 *
 * If the client has provided an encrypt function, then this will call it and
 * apply any appropriate header protection.
 *
 * @param ctx The NGHQ session context
 * @param buf_in The clear buffer to be encrypted
 * @param len_in The length of the buffer at @p buf_in
 * @param buf_out The buffer to write the encrypted header into. If there is no
 *            encryption overhead, then this may be the same as @p buf_in.
 * @param len_out The length of the buffer at @p buf_len
 * @return The length of the encrypted packet in @p buf_out
 * @return NGHQ_INTERNAL_ERROR if @p buf_out was not long enough.
 * @return NGHQ_CRYPTO_ERROR if the encrypt callback failed.
 */
ssize_t quic_transport_encrypt (nghq_session *ctx,
                                uint8_t *buf_in, size_t len_in,
                                uint8_t *buf_out, size_t len_out);

/**
 * @brief Write a RESET_STREAM frame
 *
 * @param ctx The NGHQ session context
 * @param buf The buffer to write the stream into
 * @param len The length of the buffer @p buf_in
 * @param stream The stream to be reset.
 * @param error_code The QUIC Application Error code to reset the stream with
 * @return The length of the RESET_STREAM frame, or NGHQ_ERROR.
 */
ssize_t quic_transport_write_reset_stream (nghq_session *ctx, uint8_t *buf,
                                           size_t len, nghq_stream* stream,
                                           uint64_t error_code);

/**
 * @brief Open the next available stream for a given type.
 */
int64_t quic_transport_open_stream (nghq_session *ctx, nghq_stream_type type);

#endif /* LIB_QUIC_TRANSPORT_H_ */
