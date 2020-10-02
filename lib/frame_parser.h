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

#ifndef LIB_FRAME_PARSER_H_
#define LIB_FRAME_PARSER_H_

#include "nghq/nghq.h"
#include "frame_types.h"
#include "io_buf.h"

/* Forward declarations: */
struct nghq_hdr_compression_ctx;
typedef struct nghq_hdr_compression_ctx nghq_hdr_compression_ctx;

/**
 * @brief Parse a buffer for a HTTP/QUIC frame.
 *
 * @param buf The IO buffer to look for the frame in
 * @param type The type of HTTP/QUIC frame that is found
 *
 * @return The number of bytes of @p buf that contains the frame. Returns 0 if
 *         the buffer does not contain a complete frame.
 * @return NGHQ_ERROR if no frames could be found
 */
ssize_t parse_frame_header (nghq_io_buf* buf, nghq_frame_type *type);

/**
 * @brief Pull the data out of a HTTP/QUIC data frame
 *
 * This is a very simple function that will provide the data block and length
 * from within a buffer that has been previously identified in parse_frames().
 *
 * This function aims to be zero copy, so simply adjusts the offset of @p buf
 * and stores in @p data and adjusts @p data_len accordingly. If you want to
 * free @p buf before using @p data, then the caller will need to do a copy
 * themselves.
 *
 * This function will update @p buf send_pos and remaining values to reflect
 * the buffer after this frame has been parsed.
 *
 * @param buf The IO buffer to look for the DATA frame in
 * @param data The output buffer for the data block within the frame
 * @param data_len The length of data in @p data
 *
 * @return The number of bytes of @p data_len that still need to be read
 * @return NGHQ_ERROR if no DATA frame was found at @p buf
 */
ssize_t parse_data_frame (nghq_session *session, nghq_io_buf* buf,
                          uint8_t** data, size_t *data_len);

/**
 * @brief Parse a HTTP/QUIC HEADERS  frame
 *
 * This function will take the HEADERS frame, feed it through the header
 * decompression and provide back an array of name-value pairs.
 *
 * The caller should buffer up packets until this function returns 0, which
 * means a full HEADERS frame was processed.
 *
 * This function will update @p buf send_pos and remaining values to reflect
 * the buffer after this frame has been parsed.
 *
 * @param ctx The header compression context to decompress the headers
 * @param buf The IO buffer to look for the HEADERS frame in
 * @param hdrs An array of name-value pairs of headers to be passed back
 * @param num_hdrs The number of entries in the array @p hdrs.
 *
 * @return The number of bytes of header block that still needs to be processed
 * @return NGHQ_ERROR if no HEADERS frame was found at @p buf
 * @return NGHQ_HDR_COMPRESS_FAILURE if the header compression failed
 */
ssize_t parse_headers_frame (nghq_session *session,
                             nghq_hdr_compression_ctx* ctx, nghq_io_buf* buf,
                             nghq_header*** hdrs, size_t* num_hdrs);

/**
 * @brief Parse a HTTP/QUIC CANCEL_PUSH frame
 *
 * This function does not check if @p push_id is a valid Push ID, this function
 * merely parses.
 *
 * This function will update @p buf send_pos and remaining values to reflect
 * the buffer after this frame has been parsed.
 *
 * @param buf The IO buffer to look for the PRIORITY frame in
 * @param push_id The cancelled push ID
 *
 * @return NGHQ_OK, unless no CANCEL_PUSH frame was found at @p buf, then
 *    NGHQ_ERROR
 */
int parse_cancel_push_frame (nghq_session *session, nghq_io_buf* buf,
                             uint64_t* push_id);

/**
 * @brief Parse a HTTP/QUIC SETTINGS frame
 *
 * If @p settings is NULL, then this function will allocate memory.
 * Otherwise, it will fill out the provided structure.
 *
 * This function will update @p buf send_pos and remaining values to reflect
 * the buffer after this frame has been parsed.
 *
 * @param buf The IO buffer to look for the SETTINGS frame in
 * @param settings An nghq_settings structure
 *
 * @return NGHQ_OK if this call succeeds
 * @return NGHQ_ERROR if no SETTINGS frame was found at @p buf
 * @return NGHQ_HTTP_MALFORMED_FRAME if sender sent multiple of same parameter
 * @return NGHQ_SETTINGS_NOT_RECOGNISED if sender sent a parameter we don't
 *    recognise
 * @return NGHQ_OUT_OF_MEMORY if @p settings was NULL and this function failed
 *    to allocate memory for the structure itself.
 */
int parse_settings_frame (nghq_session *session, nghq_io_buf* buf,
                          nghq_settings** settings);

/**
 * @brief Parse a HTTP/QUIC PUSH_PROMISE frame
 *
 * This function will update @p buf send_pos and remaining values to reflect
 * the buffer after this frame has been parsed.
 *
 * @param ctx The header compression context to decompress the headers
 * @param buf The IO buffer to look for the PUSH_PROMISE frame in
 * @param push_id The promised Push ID
 * @param hdrs An array of name-value pair request headers
 * @param num_hdrs The size of the array @p hdrs
 *
 * @return The number of bytes of header block that still needs to be processed
 * @return NGHQ_ERROR if no SETTINGS frame was found at @p buf
 * @return NGHQ_OUT_OF_MEMORY if this function failed to allocate memory
 * @return NGHQ_HDR_COMPRESS_FAILURE if the header decompression failed
 */
ssize_t parse_push_promise_frame (nghq_session *session,
                                  nghq_hdr_compression_ctx *ctx,
                                  nghq_io_buf* buf, uint64_t* push_id,
                                  nghq_header ***hdrs, size_t* num_hdrs);

/**
 * @brief Parse a GOAWAY frame
 *
 * This function will update @p buf send_pos and remaining values to reflect
 * the buffer after this frame has been parsed.
 *
 * @param buf The IO buffer to look for the GOAWAY frame in
 * @param last_stream_id The last Stream ID that will finish processing
 *
 * @return NGHQ_OK, unless no GOAWAY frame was found at @p buf, then NGHQ_ERROR
 */
int parse_goaway_frame (nghq_session *session, nghq_io_buf* buf,
                        uint64_t* last_stream_id);

/**
 * @brief Parse a MAX_PUSH_ID frame
 *
 * This function will update @p buf send_pos and remaining values to reflect
 * the buffer after this frame has been parsed.
 *
 * @param buf The IO buffer to look for the MAX_PUSH_ID frame in
 * @param max_push_id The maximum value for a Push ID that the server can use
 *
 * @return NGHQ_OK, unless no MAX_PUSH_ID frame was found at @p buf, then
 *    NGHQ_ERROR
 */
int parse_max_push_id_frame (nghq_session *session, nghq_io_buf* buf,
                             uint64_t* max_push_id);


#endif /* LIB_FRAME_PARSER_H_ */
