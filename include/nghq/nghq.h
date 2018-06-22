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

#ifndef NGHQ_H
#define NGHQ_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

/*
 * Type declarations
 */

/* An opaque type that tracks a given nghq session */
struct nghq_session;
typedef struct nghq_session nghq_session;

struct nghq_callbacks;
typedef struct nghq_callbacks nghq_callbacks;

typedef enum {
  NGHQ_OK = 0,
  /* General client errors */
  NGHQ_ERROR = -1,
  NGHQ_INTERNAL_ERROR = -2,
  NGHQ_OUT_OF_MEMORY = -3,
  /* Connection errors */
  NGHQ_INCOMPATIBLE_METHOD = -10,
  NGHQ_TOO_MUCH_DATA = -11,
  NGHQ_CANCELLED = -12,
  NGHQ_SESSION_CLOSED = -13,
  NGHQ_EOF = -14,
  /* Header Compression errors */
  NGHQ_HDR_COMPRESS_FAILURE = -20,
  /* Crypto errors */
  NGHQ_CRYPTO_ERROR = -30,
  /* Flow control errors */
  NGHQ_NO_MORE_DATA = -40,
  NGHQ_SESSION_BLOCKED = -41,
  NGHQ_REQUEST_BLOCKED = -42,
  NGHQ_TOO_MANY_REQUESTS = -43,
  /* Application errors */
  NGHQ_NOT_INTERESTED = -50,
  NGHQ_CLIENT_ONLY = -51,
  NGHQ_SERVER_ONLY = -52,
  NGHQ_BAD_USER_DATA = -53,
  NGHQ_INVALID_PUSH_LIMIT = -54,
  NGHQ_PUSH_LIMIT_REACHED = -55,
  NGHQ_PUSH_ALREADY_IN_CACHE = -56,
  NGHQ_TRAILERS_NOT_PROMISED = -57,
  NGHQ_REQUEST_CLOSED = -58,
  NGHQ_SETTINGS_NOT_RECOGNISED = -59,
  /* HTTP/QUIC errors */
  NGHQ_HTTP_CONNECT_ERROR = -70,
  NGHQ_HTTP_WRONG_STREAM = -71,
  NGHQ_HTTP_DUPLICATE_PUSH = -72,
  NGHQ_HTTP_MALFORMED_FRAME = -73,
  NGHQ_HTTP_PUSH_REFUSED = -74,
  NGHQ_HTTP_ALPN_FAILED = -75,
  /* QUIC Transport / ngtcp2 errors */
  NGHQ_TRANSPORT_ERROR = -100,
  NGHQ_TRANSPORT_CLOSED = -101,
  NGHQ_TRANSPORT_FINAL_OFFSET = -102,
  NGHQ_TRANSPORT_FRAME_FORMAT = -103,
  NGHQ_TRANSPORT_PARAMETER = -104,
  NGHQ_TRANSPORT_VERSION = -105,
  NGHQ_TRANSPORT_PROTOCOL = -106,
  NGHQ_TRANSPORT_TIMEOUT = -107,
} nghq_error;

typedef enum {
  NGHQ_HT_HEADERS,
  NGHQ_HT_PUSH_PROMISE,
  NGHQ_MAX
} nghq_headers_type;

typedef struct {
  int32_t header_table_size;
  int32_t max_header_list_size;
} nghq_settings;

typedef enum {
  NGHQ_MODE_UNICAST,
  NGHQ_MODE_MULTICAST,
  NGHQ_MODE_MAX
} nghq_mode;

typedef struct {
  nghq_mode mode;
  uint32_t max_open_requests;
  uint32_t max_open_server_pushes;

  uint16_t idle_timeout;
  uint16_t max_packet_size;
  uint8_t ack_delay_exponent;

  uint64_t init_conn_id;

  uint32_t max_stream_data;
  uint64_t max_data;
} nghq_transport_settings;

#define NGHQ_SETTINGS_HEADER_TABLE_SIZE 0x0001
#define NGHQ_SETTINGS_MAX_HEADER_LIST_SIZE 0x0006
/*
 * TODO: Sanitise these defaults - header table size MUST be 0 in draft-09, and
 * SETTINGS_MAX_HEADER_LIST_SIZE says to assume 16,384 octets until otherwise
 * specified by the server.
 */
#define NGHQ_SETTINGS_DEFAULT_HEADER_TABLE_SIZE 0
#define NGHQ_SETTINGS_DEFAULT_MAX_HEADER_LIST_SIZE 16384

typedef struct {
  uint8_t*        name;
  size_t          name_len;
  uint8_t*        value;
  size_t          value_len;
} nghq_header;

#define NGHQ_HEADERS_FLAGS_END_REQUEST 0x1
#define NGHQ_HEADERS_FLAGS_TRAILERS 0x2

#define NGHQ_DATA_FLAGS_END_DATA 0x1

/*
 * NGHQ Session Functions
 */

/**
 * @brief Create a new NGHQ client session
 *
 * This function will manage setting up the QUIC transport connection, given the
 * callbacks specified in @p callbacks. This function will allocate a new
 * nghq_session object to reference this new session, and initialise it for
 * client use given the settings specified in @p settings. The library will make
 * an internal copy of @p callbacks and @p settings, so the application can
 * dispose of these structures after this function has completed. The
 * @p session_user_data is an arbitrary user supplied data pointer, which will
 * be passed to all the session callback functions.
 *
 * This function
 *
 * @param callbacks Session and Request callbacks structure
 * @param settings The HTTP/QUIC settings to be negotiated
 * @param transport The underlying QUIC connection settings
 * @param session_user_data User-supplied data pointer for callbacks
 *
 * @return Initialised NGHQ Session object on success, or NULL if it failed.
 */
extern nghq_session * nghq_session_client_new (const nghq_callbacks *callbacks,
                                               const nghq_settings *settings,
                                               const nghq_transport_settings *transport,
                                               void *session_user_data);

/**
 * @brief Create a new NGHQ server session
 *
 * This function will manage setting up the QUIC transport connection, given the
 * callbacks specified in @p callbacks. This function will allocate a new
 * nghq_session object to reference this new session, and initialise it for
 * server use given the settings specified in @p settings. The library will make
 * an internal copy of @p callbacks and @p settings, so the application can
 * dispose of these structures after this function has completed. The
 * @p session_user_data is an arbitrary user supplied data pointer, which will
 * be passed to all the session callback functions.
 *
 * This function
 *
 * @param callbacks Session and Request callbacks structure
 * @param settings The HTTP/QUIC settings to be negotiated
 * @param transport The underlying QUIC connection settings
 * @param session_user_data User-supplied data pointer for callbacks
 *
 * @return Initialised NGHQ Session object on success, or NULL if it failed.
 */
extern nghq_session * nghq_session_server_new (const nghq_callbacks *callbacks,
                                               const nghq_settings *settings,
                                               const nghq_transport_settings *transport,
                                               void *session_user_data);

/**
 * @brief Informs the remote peer that you wish to tear down the session. You
 * should have closed all running requests with nghq_end_request() before
 * calling this function.
 *
 * If @p reason is NGHQ_OK, then this will be treated as a graceful shutdown.
 * The only other allowed value for @p reason is NGHQ_INTERNAL_ERROR, any other
 * value for @p reason will be treated as an internal error and send
 * NGHQ_INTERNAL_ERROR anyway.
 *
 * @param session A running NGHQ session
 * @param reason The reason for closing the session
 *
 * @return NGHQ_OK, unless @p session is not a valid session, then
 *    NGHQ_SESSION_CLOSED
 */
extern int nghq_session_close (nghq_session *session, nghq_error reason);

/**
 * @brief Free a session
 *
 * Frees all resources associated with a session. There is no guarantee that
 * this will do anything more than free data, so you should properly close all
 * your requests and end the session properly first before calling this function
 *
 * @param session A session that has been closed by nghq_session_close()
 *
 * @return 0
 */
extern int nghq_session_free (nghq_session *session);

/*
 * Session Data functions
 */

/**
 * @brief Make nghq fetch data from the session and process it.
 *
 * This function calls nghq_recv_callback() until it has no more data to
 * provide, and then processes the packets that have been received.
 *
 * @param session A running NGHQ session
 *
 * @return NGHQ_OK if the call succeeds and work was done.
 * @return NGHQ_ERROR if nghq_recv_callback fails
 * @return NGHQ_CRYPTO_ERROR if there was a crypto error when reading packets
 * @return NGHQ_NO_MORE_DATA If there was no data to be read
 * @return NGHQ_OUT_OF_MEMORY If an internal part of the library failed to
 *    allocate memory
 * @return NGHQ_SESSION_CLOSED If the session has been closed, the application
 *    should call nghq_session_free() and close the underlying connection.
 */
extern int nghq_session_recv (nghq_session *session);

/**
 * @brief Make nghq process data to be sent, and call the send callback.
 *
 * This function calls nghq_send_callback() until there is nothing left to send,
 * or the sending interface cannot accept any more data to send.
 *
 * @param session A running NGHQ session
 *
 * @return NGHQ_OK if the call succeeds
 * @return NGHQ_ERROR if nghq_send_callback fails
 * @return NGHQ_NO_MORE_DATA if there was no data to send
 * @return NGHQ_SESSION_BLOCKED if no data could be sent as there were too many
 *    bytes in flight
 * @return NGHQ_OUT_OF_MEMORY if an internal part of the library failed to
 *    allocate memory
 * @return NGHQ_SESSION_CLOSED If the session has been closed, the application
 *    should call nghq_session_free() and close the underlying connection.
 */
extern int nghq_session_send (nghq_session *session);

/**
 * @brief Retrieve transport parameter buffer
 *
 * When the library is in unicast mode, this method should be called to get the
 * QUIC TransportParameters which need to be encoded into the TLS extension.
 * In effect, this will be a binary representation of the parameters passed in
 * to nghq_session_{client|server}_new.
 *
 * This method will allocate the memory for @p buf.
 *
 * @param session A running NGHQ session
 * @param buf A pointer to the buffer to put the TransportParameters into
 *
 * @return The size of @p buf
 * @return NGHQ_SESSION_CLOSED if the session has been closed
 * @return NGHQ_OUT_OF_MEMORY if an internal part of the library failed to
 *    allocate memory
 */
extern ssize_t nghq_get_transport_params (nghq_session *session, uint8_t **buf);

/**
 * @brief Feed received TransportParameters into the library
 *
 * During the handshake, the application will need to read the contents of the
 * QUIC TransportParameters TLS extension and feed this data into the library.
 *
 * @param session A running NGHQ session
 * @param buf A buffer containing the TransportParameters
 * @param buflen The size of @p buf
 *
 * @return NGHQ_OK if the call succeeds
 * @return NGHQ_INTERNAL_ERROR if this call fails internally
 * @return NGHQ_SESSION_CLOSED if the session has been closed
 * @return NGHQ_TRANSPORT_VERSION if no supported protocol version is available
 *    in the peer's TransportParameters.
 * @return NGHQ_TRANSPORT_PROTOCOL if the TransportParameters are malformed
 */
extern int nghq_feed_transport_params (nghq_session *session,
                                       const uint8_t *buf, size_t buflen);

/**
 * @brief Select the HTTP/QUIC protocol version to use from ALPN
 *
 * During the handshake, the client will supply one or more supported HTTP/QUIC
 * versions via ALPN. The server application should feed this version string in
 * to the library here.
 *
 * If nghq supports one of the versions specified by the client, then the chosen
 * version will be returned in @p proto. If nghq supports none of the versions
 * specified by the client, this call will return with an error code and the
 * value of @p proto is undefined. It is expected that the application will reply
 * to the connected client with a TLS Alert if this function fails. You *must
 * not* free any values returned in @p proto.
 *
 * @pstsm session A running NGHQ session
 * @param buf The ALPN string
 * @param buflen The length of the ALPN string
 * @param proto The chosen HTTP/QUIC protocol version to be used
 *
 * @return The size of the ALPN string in @p proto
 * @return NGHQ_SERVER_ONLY if @p session was a client session
 * @return NGHQ_HTTP_ALPN_FAILED if no supported version was found in @p buf
 */
extern ssize_t nghq_select_alpn (nghq_session *session,
                                 const uint8_t *buf, size_t buflen,
                                 const uint8_t **proto);

/*
 * Session Callbacks
 */

/**
 * @brief Used to pull data from the socket
 *
 * The implementer of this function should put at most @p len bytes of data into
 * @p data, and return the number of bytes that it actually wrote.
 *
 * If there is no more data to be received (i.e. the socket buffer has been
 * completely drained, and any further attempt to read would block) then this
 * function must return 0. If the underlying data source is closed, then this
 * function should return NGHQ_EOF. This will be treated as a connection error,
 * and will cause the session to be closed. For any other error, it is
 * acceptable to return NGHQ_ERROR. Any other return code will be treated as
 * NGHQ_EOF and end the session.
 */
typedef ssize_t (*nghq_recv_callback) (nghq_session *session,
                                       uint8_t *data, size_t len,
                                       void *session_user_data);

/**
 * @brief Decrypt protected QUIC payloads
 *
 * A protected payload from a QUIC packet needs decrypting with the
 * session security context. The callback provides the AEAD nonce in @p nonce,
 * which is a buffer of length @p noncelen.
 *
 * The encrypted data can be found in @p encrypted and is a buffer of size
 * @p encrypted_len. This should be decrypted into the buffer @p clear which has
 * a size of @p clear_len.
 *
 * @return The number of bytes that were written into @p clear. If the
 *    decryption operation fails for any reason, then this function should
 *    return NGHQ_CRYPTO_ERROR.
 */

typedef ssize_t (*nghq_decrypt_callback) (nghq_session *session,
                                          const uint8_t *encrypted,
                                          size_t encrypted_len,
                                          const uint8_t *nonce, size_t noncelen,
                                          const uint8_t *ad, size_t adlen,
                                          uint8_t *clear, size_t clear_len,
                                          void *session_user_data);

/**
 * @brief Encrypt an unprotected QUIC payload
 *
 * A payload for a new QUIC packet that needs encrypting with the session
 * security context. The callback provides the AEAD nonce in @p nonce, which is
 * a buffer of length @p noncelen.
 *
 * The data to be encrypted can be found in @p clear and is a buffer of size
 * @p clear_len. This should be decrypted into the buffer @p encrypted which has
 * a size of @p encrypted_len.
 *
 * @return The number of bytes that were written into @p encrypted_len. If the
 *    encryption operation fails for any reason, then this function should
 *    return NGHQ_CRYPTO_ERROR.
 */
typedef ssize_t (*nghq_encrypt_callback) (nghq_session *session,
                                          const uint8_t *clear,
                                          size_t clear_len,
                                          const uint8_t *nonce, size_t noncelen,
                                          const uint8_t *ad, size_t adlen,
                                          uint8_t *encrypted,
                                          size_t encrypted_len,
                                          void *session_user_data);

/**
 * @brief Used to push completed QUIC packets to the socket
 *
 * The implementer of this function should send the contents of the buffer
 * @p data on the socket. The length of the buffer pointed to by @p data is
 * given by @p len.
 *
 * @return The number of bytes that were written. If no more data can be sent
 *    (i.e. the socket buffer is full and will not accept any more data, and any
 *    further attempt to send would block) then this function must return 0. If
 *    the underlying connection is closed, then this function should return
 *    NGHQ_EOF. This will be treated as a connection error, and will cause the
 *    session to be closed. For any other error, it is acceptable to return
 *    NGHQ_ERROR.
 */
typedef ssize_t (*nghq_send_callback) (nghq_session *session,
                                       const uint8_t *data, size_t len,
                                       void *session_user_data);

/**
 * @brief Library informs application of state changes in the session
 *
 * An informational callback from the session to advise the client application
 * on the status of the session. This callback may never be called in the
 * lifetime of a session, but may be triggered for example by the remote peer
 * closing the connection. In which case, @p status would likely be one of
 * NGHQ_SESSION_CLOSED (on reception of a GOAWAY frame), NGHQ_TRANSPORT_CLOSED
 * (the underlying QUIC stream is closed without an error), NGHQ_INTERNAL_ERROR
 * (something bad happened internally that we can't deal with),
 * or any of the other NGHQ_TRANSPORT error codes.
 */
typedef void (*nghq_session_status_callback) (nghq_session *session,
                                              nghq_error status,
                                              void *session_user_data);

/**
 * @brief Delivers control data
 *
 * This callback is to deliver control data from stream 0 that the client
 * application will need to deal with. This is most likely to be the handshake
 * packets, and the application should call nghq_feed_transport_params when it
 * has the TransportParameters from the QUIC Transport Parameters TLS Extension
 *
 * @return NGHQ_OK if this callback succeeds, otherwise an error code may be
 *    returned.
 */
typedef int (*nghq_recv_control_data_callback) (nghq_session *session,
                                                const uint8_t *data,
                                                size_t len,
                                                void *session_user_data);

/**
 * @brief Signify the arrival of the first HEADERS
 *
 * This function will be called when the library has received either a HEADERS
 * frame for a new stream or PUSH_PROMISE frame. The @p type is defined by the
 * nghq_headers_type enum, and can be either NGHQ_HT_HEADERS or
 * NGHQ_HT_PUSH_PROMISE.
 *
 * If the @p type is NGHQ_HT_HEADERS and this is a client instance, then this
 * will be the start of the server's response to a request. If this is a server
 * instance, then this will be the start of a new client request. The
 * request_user_data will be the same pointer that was passed into
 * nghq_submit_request().
 *
 * If the @p type is NGHQ_HT_PUSH_PROMISE and this is a client instance, then
 * this will be the start of a Push Promise from the server. Server instances
 * will never receive PUSH_PROMISE frames from clients, so should never see this
 * type. It is expected that the client application will call
 * nghq_set_request_user_data to set the stream data for the pushed response.
 * The @p request_user_data that is passed in with this function is guaranteed
 * to be unique to the request or push promise, and the client may use this as a
 * reference if it prefers to keep it's own state pointers, but the actual value
 * is an opaque type and cannot be used for application storage. Any
 * modification of this value directly will cause undefined behaviour. However,
 * by supplying this as the first argument to nghq_set_request_user_data(),
 * you may override it with your own pointer, in order to use the
 * request_user_data as application storage.
 *
 * @return NGHQ_OK if happy to receive the data for this request or response, or
 *    NGHQ_NOT_INTERESTED and the request will be closed
 */
typedef int (*nghq_on_begin_headers_callback) (nghq_session *session,
                                               nghq_headers_type type,
                                               void *session_user_data,
                                               void *request_user_data);

/**
 * @brief Deliver a HTTP header to the application as a name-value pair
 *
 * If the @p flags param satisfies the bitmask NGHQ_HEADERS_FLAGS_END_REQUEST
 * then this callback is the last callback for a request and you should not
 * expect any data for the request. If the @p flags param satisfies the bitmask
 * NGHQ_HEADERS_FLAGS_TRAILERS then these are trailing headers.
 *
 * @return NGHQ_OK, unless you want to receive no more data from this
 *    request/response, then you may return NGHQ_NOT_INTERESTED
 */
typedef int (*nghq_on_headers_callback) (nghq_session *session, uint8_t flags,
                                         nghq_header *hdr,
                                         void *request_user_data);

/**
 * @brief Receive request or response data
 *
 * This function will be called when the library has a chunk of data for a
 * request has been received. If the @p flags parameter satisfies the bitmask
 * NGHQ_DATA_FLAGS_END_DATA then this is the last callback for a request.
 *
 * The buffer @p data is the block of data, of length @p len at offset @p off.
 * When in multicast mode, there may be gaps where the offset in a new call
 * to this callback will be greater than the previous offset plus the length.
 * This indicates that there was multicast packet loss.
 *
 * @return NGHQ_OK, unless you want to receive no more data from this
 *    request/response, then you may return NGHQ_NOT_INTERESTED
 */
typedef int (*nghq_on_data_recv_callback) (nghq_session *session, uint8_t flags,
                                           const uint8_t *data, size_t len,
                                           size_t off, void *request_user_data);

/**
 * @brief Server has cancelled a push promise
 *
 * Inform the application that the server has cancelled a push promise. This may
 * happen before the promised request has been started, or even mid-delivery of
 * the promised request. If this happens mid-delivery of the promised request,
 * then you should expect a call to nghq_on_request_close().
 *
 * The return code for this callback is not checked, as it is merely an
 * informational callback. However, future versions of the library may use this
 * return code, so you should return NGHQ_OK here for safety.
 *
 * @param session A running NGHQ request
 * @param request_user_data The user data supplied by
 *    nghq_on_begin_headers_callback, or set manually via
 *    nghq_set_request_user_data().
 *
 * @return NGHQ_OK
 */
typedef int (*nghq_on_push_cancel_callback) (nghq_session *session,
                                             void *request_user_data);

/**
 * @brief Inform an application that a request has closed
 *
 * Inform the application that a given request has been completed and the
 * application can expect no more data to be sent. The value in status indicates
 * the reason why the request was closed. If it's NGHQ_OK, then the transfer
 * completed successfully (receiving a HTTP-level error like a 404 would still
 * mean the transfer has completed successfully). All other errors are listed at
 * the bottom of this page.
 *
 * @return NGHQ_OK
 */
typedef int (*nghq_on_request_close_callback) (nghq_session *session,
                                               nghq_error status,
                                               void *request_user_data);

/*
 * Make requests
 */

/**
 * @brief Submit a new request to a server
 *
 * Submits a request in the form of at least one HEADERS frame, and optionally
 * some DATA frames.
 *
 * This function may only be called if @p session is a client session.
 *
 * If req_body is not NULL, and if the :method specified as one of the
 * name-value pairs in @p hdrs is a method that allows request message bodies,
 * then @p req_body contains @p len bytes of data which will be sent as part of
 * the request. You may also leave this as NULL and feed in data using
 * nghq_feed_payload_data().
 *
 * @return NGHQ_OK if the request is successfully submitted.
 * @return NGHQ_CLIENT_ONLY if @p session is that of a server instance.
 * @return NGHQ_TOO_MUCH_DATA if @p len bytes of @p req_body is too much to send
 *    in one go before needing to call nghq_session_send(). Use
 *    nghq_feed_payload_data().
 * @return NGHQ_TOO_MANY_REQUESTS if there are too many open requests.
 * @return NGHQ_SESSION_BLOCKED if the new request could not be made due to flow
 *    control.
 */
extern int nghq_submit_request (nghq_session *session, const nghq_header **hdrs,
                                size_t num_hdrs, const uint8_t *req_body,
                                size_t len, int final, void *request_user_data);

/**
 * @brief Submit a push promise to a client
 *
 * Submits a PUSH_PROMISE frame. This function may only be called if session is
 * a server session.
 *
 * When running in unicast mode, @p init_request_user_id must be a pointer to
 * the request_user_data used by a currently running request. In multicast mode,
 * @p init_request_user_data should be set to NULL (it will be ignored
 * internally).
 *
 * @return NGHQ_OK if the call succeeds.
 * @return NGHQ_REQUEST_CLOSED if the init request was closed
 * @return NGHQ_SERVER_ONLY if @p session is that of a client instance.
 * @return NGHQ_PUSH_LIMIT_REACHED If the client's MAX_PUSH_ID limit has been
 *    reached
 * @return NGHQ_REQUEST_BLOCKED if the new request could not be made due to flow
 *    control.
 */
extern int nghq_submit_push_promise (nghq_session *session,
                                     void * init_request_user_data,
                                     const nghq_header **hdrs, size_t num_hdrs,
                                     void *promised_request_user_data);

/**
 * @brief Change request user data
 *
 * Allows the application to change the pointer used as request_user_data in
 * callbacks related to requests or push promises. This may be done at any time
 * while a request is open.
 *
 * @param session A running NGHQ session
 * @param current_user_data The existing user data
 * @param new_user_data The new user data pointer to replace @p current_user_data
 *
 * @return NGHQ_OK on success
 * @return NGHQ_BAD_USER_DATA if @p current_user_data doesn't match any
 *    request_user_data stored within the library.
 */
extern int nghq_set_request_user_data(nghq_session *session,
                                      void * current_user_data,
                                      void * new_user_data);

/**
 * @brief Change session user data
 *
 * Allows the application to change the pointer used as session_user_data in
 * callbacks related to the session. This may be done at any time while a
 * session is open.
 *
 * @param session A running NGHQ session
 * @param current_user_data The existing user data
 * @param new_user_data The new user data pointer to replace @p current_user_data
 *
 * @return NGHQ_OK on success
 * @return NGHQ_BAD_USER_DATA if @p current_user_data doesn't match the
 *    session_user_data stored within the library.
 */
extern int nghq_set_session_user_data(nghq_session *session,
                                      void * current_user_data,
                                      void * new_user_data);

/**
 * @brief Send headers for a request/response
 *
 * Used to add a number of HTTP headers to either the request or response of a
 * transfer.
 *
 * If @p request_user_data relates to an as-yet unstarted promise (i.e. the
 * @p promised_request_user_data as supplied to nghq_submit_push_promise()),
 * this will cause the library to start the process of sending the new
 * server-pushed resource, beginning with the headers.
 *
 * If this is called after the first call to nghq_feed_payload_data(), then
 * these headers will be assumed to be HTTP trailing headers.
 *
 * If @p final is set to a non-zero value, then this call will also set the
 * final bit in the QUIC header and close the request.
 *
 * @return NGHQ_OK if the call succeeds
 * @return NGHQ_TRAILERS_NOT_PROMISED if headers in a trailing headers block
 *    were not declared in the Trailers: header
 * @return NGHQ_TOO_MANY_REQUESTS if there are too many server-pushes open
 *    (see nghq_set_max_pushed())
 * @return NGHQ_REQUEST_CLOSED if the request is closed
 */
extern int nghq_feed_headers (nghq_session *session, const nghq_header **hdrs,
                              size_t num_hdrs, int final,
                              void *request_user_data);

/**
 * @brief Send a block of request or response data
 *
 * Feeds @p len bytes of data @p buf into a request or response represented by
 * request_user_data.
 *
 * Internally, this will buffer up the data, create the packets and then
 * nghq_session_send() will send them.
 *
 * If @p final is set to a non-zero value, then this call will also set the
 * final bit in the QUIC header and close the request.
 *
 * @return The number of bytes that were written. If this is lower than len, you
 *    should call nghq_session_send() to send packets before attempting to add
 *    any more.
 * @return NGHQ_REQUEST_BLOCKED if sending more packets is blocked by flow
 *    control.
 * @return NGHQ_REQUEST_CLOSED if the request is closed
 */
extern ssize_t nghq_feed_payload_data(nghq_session *session, const uint8_t *buf,
                                      size_t len, int final,
                                      void *request_user_data);

/**
 * @brief End the request
 *
 * This method closes a request with the given result. Only one peer needs to
 * call this method, the other end should receive an
 * nghq_on_request_close_callback(). Once called, this instance may not send
 * any more data for this request.
 *
 * If nghq_submit_request, nghq_feed_headers or nghq_feed_payload_data were
 * called with their 'final' argument set to a non-zero value, then it is
 * not necessary to call this method as the stream will be closed implicitly.
 *
 * @return NGHQ_OK If the request is closed
 * @return NGHQ_REQUEST_CLOSED if the request was already closed
 */
extern int nghq_end_request (nghq_session *session, nghq_error result,
                             void *request_user_data);

/*
 * Connection calls
 */

/**
 * @brief Get how many client-initiated requests are allowed to be open at once
 *
 * This only applies to client-initiated requests, not server pushes. To see how
 * many server pushes are allowed, use nghq_get_max_pushed().
 */
extern uint64_t nghq_get_max_client_requests (nghq_session *session);

/**
 * @brief Set the number of allowed open client-initiated requests
 *
 * Change the limit on maximum number of client-initiated requests that can be
 * open. Unlike nghq_set_max_promises this value sets the maximum number of open
 * requests, and does not need periodically increasing as more requests are
 * made. This value does not effect the maximum number of server pushes that can
 * be open at once, for that use nghq_set_max_pushed().
 *
 * @return NGHQ_TOO_MANY_REQUESTS if @p max_requests is lower than the number of
 *    currently open requests, otherwise NGHQ_OK.
 */
extern int nghq_set_max_client_requests (nghq_session *session,
                                         uint64_t max_requests);

/**
 * @brief Get how many server-pushes are allowed to be open at once
 *
 * This only applies to server-pushed resources, and not client-initiated
 * requests. To see how many client-initiated requests are allowed, use
 * nghq_get_max_client_requests().
 */
extern uint64_t nghq_get_max_pushed (nghq_session *session);

/**
 * @brief Set the number of allowed open server-pushes
 *
 * Change the limit on maximum number of server pushes that can be open. Unlike
 * nghq_set_max_promises this value sets the maximum number of open requests,
 * and does not need periodically increasing as more requests are made. This
 * value does not effect the maximum number of client-initiated requests that
 * can be open at once, for that use nghq_set_max_client_requests().
 *
 * @return NGHQ_TOO_MANY_REQUESTS if @p max_pushed is lower than the number of
 *    currently open server pushes, otherwise NGHQ_OK.
 */
extern int nghq_set_max_pushed(nghq_session *session, uint64_t max_pushed);

/**
 * @brief Get the number of allowed push promises
 *
 * This function gets how many push promises the client is still happy to
 * receive. For example, if an application submitted nghq_set_max_promises(10),
 * and three (3) push promises have since been acknowledged by the client then
 * this function would return seven (7).
 */
extern uint64_t nghq_get_max_promises (nghq_session *session);

/**
 * @brief Set the number of allowed push promises
 *
 * Submits a MAX_PUSH_ID frame to the server, indicating how many push promises
 * the client is willing to accept. The value given for @p max_push is the
 * number of new push promises that the server will be allowed to send, and is
 * not the number that will be sent in the MAX_PUSH_ID frame. For example, if
 * the application initially sets the @p max_push value as 10, the value in the
 * MAX_PUSH_ID frame will be 10. The client then receives 5 push promises from
 * the server, before calling nghq_set_max_promises again with a @p max_push of
 * 10, the library will then send a new MAX_PUSH_ID frame with a value of 15, as
 * this is 10 more than it has currently received.
 *
 * This only effects the number of promises that the server can send, not the
 * number of pushed requests that it can make. This is controlled by
 * nghq_set_max_pushed(). For example, given the following:
 *
 *    nghq_set_max_pushed(session, 10);
 *    nghq_set_max_promises(session, 30);
 *
 * The server would be able to send 30 Push Promises to the client, but may only
 * open 10 server pushes at a time. Once a server push request is completed,
 * then the server can open another until all 30 push promises are delivered or
 * cancelled.
 *
 * @return NGHQ_OK if this call succeeds
 * @return NGHQ_INVALID_PUSH_LIMIT if @p max_push is lower than the number that
 *    would be returned by nghq_get_max_promises()
 * @return NGHQ_CLIENT_ONLY if @p session is a server instance.
 */
extern int nghq_set_max_promises (nghq_session* session, uint64_t max_push);

struct nghq_callbacks {
  nghq_recv_callback              recv_callback;
  nghq_decrypt_callback           decrypt_callback;
  nghq_encrypt_callback           encrypt_callback;
  nghq_send_callback              send_callback;
  nghq_session_status_callback    session_status_callback;
  nghq_recv_control_data_callback recv_control_data_callback;
  nghq_on_begin_headers_callback  on_begin_headers_callback;
  nghq_on_headers_callback        on_headers_callback;
  nghq_on_data_recv_callback      on_data_recv_callback;
  nghq_on_push_cancel_callback    on_push_cancel_callback;
  nghq_on_request_close_callback  on_request_close_callback;
};

#ifdef __cplusplus
}
#endif

#endif /* NGHQ_H */
