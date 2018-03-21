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

/******************************************************************************
 ******************************************************************************
 * NOTE: A lot of the functions in here MAY throw assertions and abort if you
 *       give them silly values to go into varints!
 ******************************************************************************
 ******************************************************************************
 */

#ifndef LIB_FRAME_CREATOR_H_
#define LIB_FRAME_CREATOR_H_

#include "nghq/nghq.h"
#include "frame_types.h"

/* Forward declarations: */
struct nghq_hdr_compression_ctx;
typedef struct nghq_hdr_compression_ctx nghq_hdr_compression_ctx;

/* TODO: Add a get/set method so the application can inform us of MTU sizes */
#define MAX_FRAME_LENGTH 1350

/**
 * @brief Package a block of data into a HTTP/QUIC data frame
 *
 * This function will allocate memory for a new DATA frame, and then copy data
 * from @p block into the new buffer up to the length of @p block_len or a
 * maximum frame size, whichever is smaller. The resulting frame will be passed
 * back in @p frame, and the caller is responsible for freeing (transfer: full).
 *
 * @param block The buffer containing the data block to package
 * @param block_len The length of @p block
 * @param frame The buffer to return the packaged frame in
 * @param frame_len The length of @p frame
 *
 * @return The number of bytes from @p block that was written into @p frame
 * @return NGHQ_ERROR if @p block is NULL
 * @return NGHQ_OUT_OF_MEMORY if memory for the new DATA frame couldn't be
 *    allocated
 */
ssize_t create_data_frame(const uint8_t* block, size_t block_len,
                          uint8_t** frame, size_t* frame_len);

/**
 * @brief Package a series of name-value pair headers into a HEADERS frame
 *
 * This function will compress a series of name-value pair headers, and then
 * allocate memory for a new HEADERS frame, which will be passed back in
 * @p frame. The caller is responsible for freeing the frame memory.
 *
 * This function guarantees that the order of headers in the array @p hdrs will
 * be maintained.
 *
 * If the header compression fails midway through the array of headers, this
 * function will return the number of headers that were successfully compressed.
 * The caller can then call again with the remaining headers, and the problem
 * header will return NGHQ_HDR_COMPRESS_FAILURE and no change in the header
 * compression context will have occured.
 *
 * @param ctx The header compression context
 * @param push_id -1 if no push stream header needed, otherwise the push ID
 * @param hdrs An array of name-value pair headers to be compressed
 * @param num_hdrs The number of entries in @p hdrs.
 * @param frame The buffer to return the packaged frame in
 * @param frame_len The length of @p frame
 *
 * @return The number of headers that were successfully compressed
 * @return NGHQ_ERROR if @p hdrs is NULL
 * @return NGHQ_OUT_OF_MEMORY if memory for the new HEADERS frame couldn't be
 *    allocated
 * @return NGHQ_HDR_COMPRESS_FAILURE if the headers couldn't be compressed.
 */
ssize_t create_headers_frame(nghq_hdr_compression_ctx* ctx, int64_t push_id,
                             const nghq_header** hdrs, size_t num_hdrs,
                             uint8_t** frame, size_t* frame_len);

/**
 * @brief Package a HTTP/QUIC PRIORITY frame
 *
 * The caller is responsible for freeing the allocated frame memory in @p frame.
 *
 * @param flags The flags to set on the PRIORTIY frame
 * @param request_id The prioritised request's Stream ID
 * @param dependency_id The dependent request's Stream ID
 * @param weight The priority weight for the given stream
 * @param frame The buffer to return the packaged frame in
 * @param frame_len The length of @p frame
 *
 * @return NGHQ_OK on success
 * @return NGHQ_OUT_OF_MEMORY if memory for the new PRIORITY frame couldn't be
 *    allocated
 */
int create_priority_frame(uint8_t flags, uint64_t request_id,
                          uint64_t dependency_id, uint8_t weight,
                          uint8_t** frame, size_t* frame_len);

/**
 * @brief Package a HTTP/QUIC CANCEL_PUSH frame
 *
 * The caller is responsible for freeing the allocated frame memory in @p frame.
 *
 * @param push_id The Push ID that's being cancelled
 * @param frame The buffer to return the packaged frame in
 * @param frame_len The length of @p frame
 *
 * @return NGHQ_OK on success
 * @return NGHQ_OUT_OF_MEMORY if memory for the new PRIORITY frame couldn't be
 *    allocated
 */
int create_cancel_push_frame(uint64_t push_id, uint8_t** frame,
                             size_t* frame_len);

/**
 * @brief Package a HTTP/QUIC SETTTINGS frame
 *
 * TODO: Change this so it doesn't pull everything from settings...? Maybe do
 * it as a varargs thing?
 *
 * The caller is responsible for freeing the allocated frame memory in @p frame.
 *
 * @param settings The settings frame to serialise into the frame
 * @param frame The buffer to return the packaged frame in
 * @param frame_len The length of @p frame
 *
 * @return NGHQ_OK on success
 * @return NGHQ_OUT_OF_MEMORY if memory for the new PRIORITY frame couldn't be
 *    allocated
 */
int create_settings_frame(nghq_settings* settings, uint8_t** frame,
                              size_t* frame_len);

/**
 * @brief Package a new Push ID and some compressed headers into a PUSH_PROMISE
 *
 * This function will compress a series of name-value pair headers, and then
 * allocate memory for a new PUSH_PROMISE frame, which will be passed back in
 * @p frame. The caller is responsible for freeing the frame memory.
 *
 * This function guarantees that the order of headers in the array @p hdrs will
 * be maintained.
 *
 * @param ctx The header compression context to compress the headers
 * @param push_id The Push ID to promise
 * @param hdrs An array of name-value pair request headers
 * @param num_hdrs The size of the array @p hdrs
 * @param frame The buffer to return the packaged frame in
 * @param frame_len The length of @p frame
 *
 * @return The number of headers that were successfully compressed
 * @return NGHQ_ERROR if @p hdrs is NULL
 * @return NGHQ_OUT_OF_MEMORY if memory for the new HEADERS frame couldn't be
 *    allocated
 * @return NGHQ_HDR_COMPRESS_FAILURE if the headers couldn't be compressed.
 */
ssize_t create_push_promise_frame(nghq_hdr_compression_ctx *ctx,
                                  uint64_t push_id, const nghq_header** hdrs,
                                  size_t num_hdrs, uint8_t** frame,
                                  size_t* frame_len);

/**
 * @brief Package a new HTTP/QUIC GOAWAY frame
 *
 * @param last_stream_id The last Stream ID that we promise to process
 * @param frame The buffer to return the packaged frame in
 * @param frame_len The length of @p frame
 *
 * @return NGHQ_OK on success
 * @return NGHQ_OUT_OF_MEMORY if memory for the new PRIORITY frame couldn't be
 *    allocated
 */
int create_goaway_frame(uint64_t last_stream_id, uint8_t** frame,
                            size_t* frame_len);

/**
 * @brief Package a new HTTP/QUIC MAX_PUSH_ID frame
 *
 * @param max_push_id The maximum value for a Push ID that the server can use
 * @param frame The buffer to return the packaged frame in
 * @param frame_len The length of @p frame
 *
 * @return NGHQ_OK on success
 * @return NGHQ_OUT_OF_MEMORY if memory for the new PRIORITY frame couldn't be
 *    allocated
 */
int create_max_push_id_frame(uint64_t max_push_id, uint8_t** frame,
                                 size_t* frame_len);

#endif /* LIB_FRAME_CREATOR_H_ */
