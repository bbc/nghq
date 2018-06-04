# Public API Reference

* [Session Set-up](#session-set-up)
    * [nghq_session_client_new](#nghq_session_client_new)
    * [nghq_session_server_new](#nghq_session_server_new)
    * [nghq_session_close](#nghq_session_close)
    * [nghq_session_free](#nghq_session_free)
* [Session Data](#session-data)
    * [nghq_session_recv](#nghq_session_recv)
    * [nghq_session_send](#nghq_session_send)
    * [nghq_get_transport_params](#nghq_get_transport_params)
    * [nghq_feed_transport_params](#nghq_feed_transport_params)
    * [nghq_select_alpn](#nghq_select_alpn)
* [Session Callbacks](#session-callbacks)
    * [nghq_recv_callback](#nghq_recv_callback)
    * [nghq_decrypt_callback](#nghq_decrypt_callback)
    * [nghq_encrypt_callback](#nghq_encrypt_callback)
    * [nghq_send_callback](#nghq_send_callback)
    * [nghq_session_status_callback](#nghq_session_status_callback)
    * [nghq_recv_control_data_callback](#nghq_recv_control_data_callback)
* [Application Data Received Callbacks](#application-data-received-callbacks)
    * [nghq_on_begin_headers_callback](#nghq_on_begin_headers_callback)
    * [nghq_on_headers_callback](#nghq_on_headers_callback)
    * [nghq_on_data_recv_callback](#nghq_on_data_recv_callback)
    * [nghq_on_push_cancel_callback](#nghq_on_push_cancel_callback)
    * [nghq_on_request_close_callback](#nghq_on_request_close_callback)
    * [nghq_set_request_user_data](#nghq_set_request_user_data)
    * [nghq_set_session_user_data](#nghq_set_session_user_data)
* [Request Data](#request-data)
    * [nghq_feed_headers](#nghq_feed_headers)
    * [nghq_feed_payload_data](#nghq_feed_payload_data)
    * [nghq_end_request](#nghq_end_request)
* [Client Specific Calls](#client-specific-calls)
    * [nghq_submit_request](#nghq_submit_request)
* [Server Specific Calls](#server-specific-calls)
    * [nghq_submit_push_promise](#nghq_submit_push_promise)
* [Connection Calls](#connection-calls)
    * [nghq_get_max_client_requests](#nghq_get_max_client_requests)
    * [nghq_set_max_client_requests](#nghq_set_max_client_requests)
    * [nghq_get_max_pushed](#nghq_get_max_pushed)
    * [nghq_set_max_pushed](#nghq_set_max_pushed)
    * [nghq_get_max_promises](#nghq_get_max_promises)
    * [nghq_set_max_promises](#nghq_set_max_promises)
* [Types](#types)
    * [nghq_session](#nghq_session)
    * [nghq_callbacks](#nghq_callbacks)
    * [nghq_error](#nghq_error)


## Session Set-up
### nghq_session_client_new
```c
nghq_session * nghq_session_client_new (const nghq_callbacks *callbacks, const nghq_settings *settings, const nghq_transport_settings *transport, void *session_user_data)
```

This method will allocate a new [nghq_session](#nghq_session) object and initialise it for client use. The library will make an internal copy of callbacks, settings and transport, so the application can dispose of these structures after this function has completed. The session_user_data is an arbitrary user supplied data pointer, which will be passed to all the session callback functions. It's a good idea to store things like security contexts, keys, socket file descriptors and any other data that you will need to perform the callbacks in this data structure.

Internally, this function will perform the handshakes and set up the underlying QUIC connection for HTTP/QUIC. It is expected that this method will rely on the Session Callbacks to manage the handshake phase, and the application is expected to manage the security contexts needed in [nghq_decrypt_callback](#nghq_decrypt_callback) and [nghq_encrypt_callback](#nghq_encrypt_callback).

### nghq_session_server_new
```c
nghq_session * nghq_session_server_new (const nghq_callbacks *callbacks, const nghq_settings *settings, const nghq_transport_settings *transport, void *session_user_data)
```

This method will allocate a new [nghq_session](#nghq_session) object and initialise it for server use. The library will make an internal copy of callbacks, settings and transport, so the application can dispose of these structures after this function has completed. The session_user_data is an arbitrary user supplied data pointer, which will be passed to all the session callback functions. It's a good idea to store things like security contexts, keys, socket file descriptors and any other data that you will need to perform the callbacks in this data structure.

Internally, this function will perform the handshakes and set up the underlying QUIC connection for HTTP/QUIC. It is expected that this method will rely on the Session Callbacks to manage the handshake phase, and the application is expected to manage the security contexts needed in [nghq_decrypt_callback](#nghq_decrypt_callback) and [nghq_encrypt_callback](#nghq_encrypt_callback).

### nghq_session_close
```c
int nghq_session_close (nghq_session *session, nghq_error reason)
```

Inform the remote peer that you wish to tear down the session. You should have closed all running requests with [nghq_end_request()](#nghq_end_request) before calling this function.

If reason is NGHQ_OK, then this will be treated as a graceful shutdown. The only other allowed value for reason is NGHQ_INTERNAL_ERROR, any other value for reason will be treated as an internal error and send NGHQ_INTERNAL_ERROR anyway.

Always returns NGHQ_OK, unless session is not a valid session (it may have already shut down)

### nghq_session_free
```c
int nghq_session_free (nghq_session *session)
```
Frees all resources associated with a session. There is no guarantee that this will do anything more than free data, so you should properly close all your requests and end the session properly first before calling this function.

Always returns NGHQ_OK.

## Session Data
### nghq_session_recv
```c
int nghq_session_recv(nghq_session *session)
```
Calls nghq_recv_callback until it has no more data to provide.

Returns NGHQ_OK if the call succeeds.

If there was no data available to be read, then this function will return the error code NGHQ_NO_MORE_DATA and the application should wait on data to become available from it's socket (i.e. wait in a call to select or epoll) before calling this function again. This should not be treated as a showstopping error, and is more an informational result.

If the receive callback function fails, then this returns the error code NGHQ_ERROR. If one of the encrypt or decrypt functions failed, then this returns the error code NGHQ_CRYPTO_ERROR.

If an internal part of the library failed to allocate memory, then this function will return NGHQ_OUT_OF_MEMORY.

If the session has been closed, then this will return NGHQ_SESSION_CLOSED and the application should call [nghq_session_free()](#nghq_session_free) and close the underlying connection.

### nghq_session_send
```c
int nghq_session_send(nghq_session *session)
```
Calls nghq_send_callback until there is nothing left to send, or the sending interface cannot accept any more data to send. You should call this method after every call to [nghq_session_recv](#nghq_session_recv), or any of [nghq_submit_request](#nghq_submit_request), [nghq_submit_push_promise](#nghq_submit_push_promise), [nghq_feed_headers](#nghq_feed_headers), [nghq_feed_payload_data](#nghq_feed_payload_data), and [nghq_end_request](#nghq_end_request).

Returns NGHQ_OK if the call succeeds.

If there was no data to be sent, then this function will return the error code NGHQ_NO_MORE_DATA. Differentiates from sending until the internal buffer is empty, and is a purely informational return code. This should not be treated as a showstopping error.

If the send callback function fails, then this returns the error code NGHQ_ERROR. If one of the encrypt or decrypt functions failed, then this returns the error code NGHQ_CRYPTO_ERROR.

If an internal part of the library failed to allocate memory, then this function will return NGHQ_OUT_OF_MEMORY. If the session has been closed, then this will return NGHQ_SESSION_CLOSED and the application should call [nghq_session_free()](#nghq_session_free) and close the underlying connection.

### nghq_get_transport_params
```c
ssize_t nghq_get_transport_params (nghq_session *session, uint8_t **buf)
```
This function is used during the handshake phase in a unicast connection. The application will need to get an encoded form of the QUIC TransportParameters structure which needs to be encoded into the quic_transport_params TLS extension. This method will allocate the memory for buf, and it is the application's responsibility to free it once it has used it. When operating in multicast mode, you must not call this function as it may confuse the internals of the library.

For the client, this will effectively be a binary representation of the parameters passed in to [nghq_session_client_new](#nghq_session_client_new).

Returns the size of the buffer allocated in buf if the call succeeds.

If an internal part of the library failed to allocate memory, then this function will return NGHQ_OUT_OF_MEMORY. If the session has been closed, then this will return NGHQ_SESSION_CLOSED and the application should call [nghq_session_free()](#nghq_session_free) and close the underlying connection.

### nghq_feed_transport_params
```c
int nghq_feed_transport_params (nghq_session *session, const uint8_t *buf, size_t buflen)
```
This function is used during the handshake phase in a unicast connection. The application will need to put the contents of the quic_transport_params TLS extension into buf so nghq can read them. Once this function returns, it is safe to delete buf.

Returns NGHQ_OK if the call succeeds.

If this call fails internally for an unknown reason, then this function will return NGHQ_INTERNAL_ERROR. If the session has been closed, then this will return NGHQ_SESSION_CLOSED and the application should call [nghq_session_free()](#nghq_session_free) and close the underlying connection.

If the peer's quic_transport_params does not advertise a protocol version that this instance supports, then this call will return the error code NGHQ_TRANSPORT_VERSION. If the TransportParameters are malformed, then this call will return the error code NGHQ_TRANSPORT_PROTOCOL. Both failures indicate that we cannot communicate with the remote peer.

### nghq_select_alpn
```c
ssize_t nghq_select_alpn (nghq_session *session, const uint8_t *buf, size_t buflen, const uint8_t **proto)
```
This function is only to be used by a server instance during the handshake phase in a unicast connection. The application will supply an ALPN record in the ClientHello message, which should be provided to this function. nghq will then look through the list of ALPN protocols and choose the one it prefers, if a compatible protocol version is available. The application will reply to the remote peer via the TLS handshake with which protocol version the server has chosen to use.

The application must not free any values returned in proto.

Returns the length of the chosen ALPN protocol in proto if the call succeeds on negotiating an application protocol version.

If this call is made on a client instance, then this will return the error code NGHQ_SERVER_ONLY. If no supported protocol was found in buf, then this call will return the error code NGHQ_HTTP_ALPN_FAILED.

## Session Callbacks
### nghq_recv_callback
```c
ssize_t (*nghq_recv_callback) (nghq_session *session, const uint8_t *data, size_t len, void *session_user_data)
```
Used to pull data from the socket.

The implementer of this function should put at most len bytes of data into data, and return the number of bytes that it actually wrote.

If there is no more data to be received (i.e. the socket buffer has been completely drained, and any further attempt to read would block) then this function must return 0. If the underlying data source is closed, then this function should return NGHQ_EOF. This will be treated as a connection error, and will cause the session to be closed. For any other error, it is acceptable to return NGHQ_ERROR. Any other return code will be treated as NGHQ_EOF and end the session.

### nghq_decrypt_callback
```c
ssize_t (*nghq_decrypt_callback) (nghq_session *session, uint8_t *encrypted, size_t encrypted_len, const uint8_t *nonce, size_t noncelen, const uint8_t *ad, size_t adlen, uint8_t *clear, size_t clear_len, void *session_user_data)
```
The protected payload from a QUIC packet that needs decrypting with the session security context. The callback provides the AEAD nonce in nonce, which is a buffer of length noncelen.

The encrypted data can be found in encrypted and is a buffer of size encrypted_len. This should be decrypted into the buffer clear which has a size of clear_len.

This should return the number of bytes that were written into clear. If the decryption operation fails for any reason, then this function should return NGHQ_CRYPTO_ERROR.

### nghq_encrypt_callback
```c
ssize_t (*nghq_encrypt_callback) (nghq_session *session, uint8_t **clear, size_t clear_len, const uint8_t *nonce, size_t noncelen, const uint8_t *ad, size_t adlen, uint8_t *encrypted, size_t encrypted_len, void *session_user_data)
```
The payload for a new QUIC packet that needs encrypting with the session security context. The callback provides the AEAD nonce in nonce, which is a buffer of length noncelen.

The data to be encrypted can be found in clear and is a buffer of size clear_len. This should be decrypted into the buffer encrypted which has a size of encrypted_len.

This should return the number of bytes that were written into encrypted_len. If the encryption operation fails for any reason, then this function should return NGHQ_CRYPTO_ERROR.

### nghq_send_callback
```c
ssize_t (*nghq_send_callback) (nghq_session *session, const uint8_t *data, size_t len, void *session_user_data)
```
Used to push data to the socket.

The implementer of this function should send data. The length of the buffer pointed to by data is given by len. It should return the number of bytes that were written.

If no more data can be sent (i.e. the socket buffer is full and will not accept any more data, and any further attempt to send would block) then this function must return 0. If the underlying connection is closed, then this function should return NGHQ_EOF. This will be treated as a connection error, and will cause the session to be closed. For any other error, it is acceptable to return NGHQ_ERROR.

### nghq_session_status_callback
```c
void (*nghq_session_status_callback) (nghq_session *session, nghq_error status, void *session_user_data)
```
An informational callback from the session to advise the client application on the status of the session. This callback may never be called in the lifetime of a session, but may be triggered for example by the remote peer closing the connection. In which case, status would likely be one of NGHQ_SESSION_CLOSED (on reception of a GOAWAY frame), NGHQ_TRANSPORT_CLOSED (the underlying QUIC stream is closed without an error), NGHQ_INTERNAL_ERROR (something bad happened internally that we can't deal with), or any of the other NGHQ_TRANSPORT error codes.

### nghq_recv_control_data_callback
```c
int (*nghq_recv_control_data_callback) (nghq_session *session, const uint8_t *data, size_t len, void *session_user_data)
```
This callback is to deliver control data from the remote peer that the application will need to deal with. This is most likely to be the handshake packets, and the application should call nghq_feed_transport_params when it has the TransportParameters from the quic_transport_params TLS extension.

Application should return NGHQ_OK if this callback succeeds, any other value will be treated as an error.

## Application Data Received Callbacks
### nghq_on_begin_headers_callback
```c
int (*nghq_on_begin_headers_callback)(nghq_session *session, nghq_headers_type type, void *session_user_data, void *request_user_data)
```
This function will be called when the library has received either a HEADERS frame for a new stream or PUSH_PROMISE frame. The type is defined by the nghq_headers_type enum, and can be either NGHQ_HT_HEADERS or NGHQ_HT_PUSH_PROMISE.

If the type is NGHQ_HT_HEADERS and this is a client instance, then this will be the start of the server's response to a request. If this is a server instance, then this will be the start of a new client request. The request_user_data will be the same pointer that was passed into [nghq_submit_request()](#nghq_submit_request).

If the type is NGHQ_HT_PUSH_PROMISE and this is a client instance, then this will be the start of a Push Promise from the server. Server instances will never receive PUSH_PROMISE frames from clients, so should never see this type. It is expected that the client application will call nghq_set_request_user_data to set the stream data for the pushed response. The request_user_data that is passed in with this function is guaranteed to be unique to the request or push promise, and the client may use this as a reference if it prefers to keep it's own state pointers, but the actual value is an opaque type and cannot be used for application storage. Any modification of this value directly will cause undefined behaviour. However, by supplying this as the first argument to [nghq_set_request_user_data()](#nghq_set_request_user_data), you may override it with your own pointer, in order to use the request_user_data as application storage.

You should return NGHQ_OK from this function if you are happy to continue receiving this request. If you do not wish to continue receiving this request, you may return NGHQ_NOT_INTERESTED and the request will be closed.

### nghq_on_headers_callback
```c
int (*nghq_on_headers_callback)(nghq_session *session, uint8_t flags, nghq_header *hdr, void *request_user_data)
```
This functions delivers a HTTP header to the client as a name-value pair in the nghq_header structure defined below:
```c
struct nghq_header {
    uint8_t *name;
    size_t   namelen;
    uint8_t *value;
    size_t   valuelen;
};
```
For example:
```c
nghq_header hdr = {":method", 7, "GET", 3};
```
If the flags variable satisfies the bitmask NGHQ_HEADERS_FLAGS_END_REQUEST then this callback is the last callback for a request and you should not expect any data for the request. If the flags variable satisfies the bitmask NGHQ_HEADERS_FLAGS_TRAILERS then these are trailing headers.

You should return NGHQ_OK from this function if you successfully handled the header. If you are no longer interested in processing this request, then you may return the error code NGHQ_NOT_INTERESTED.

### nghq_on_data_recv_callback
```c
int (*nghq_on_data_recv_callback)(nghq_session *session, uint8_t flags, const uint8_t *data, size_t len, size_t off, void *request_user_data)
```
This function will be called when the library has a chunk of data of length len at offset off in the resource body for a request has been received. If the flags variable satisfies the bitmask NGHQ_DATA_FLAGS_END_DATA then this is the last callback for a request.

You should return NGHQ_OK from this function, unless you are no longer interested in processing this request, then you may return the error code NGHQ_NOT_INTERESTED.

### nghq_on_push_cancel_callback
```c
int (*nghq_on_push_cancel_callback) (nghq_session *session, void *request_user_data)
```
Inform the application that the server has cancelled a push promise. This may happen before the promised request has been started, or even mid-delivery of the promised request. If this happens mid-delivery of the promised request, then you should expect a call to [nghq_on_request_close_callback()](#nghq_on_request_close_callback).

The return code for this callback is not checked, as it is merely an informational callback. However, future versions of the library may use this return code, so you should return NGHQ_OK here for safety.

### nghq_on_request_close_callback
```c
int (*nghq_on_request_close_callback) (nghq_session *session, nghq_error status, void *request_user_data)
```
Inform the application that a given request has been completed and the application can expect no more data to be sent. The value in status indicates the reason why the request was closed. If it's NGHQ_OK, then the transfer completed successfully (receiving a HTTP-level error like a 404 would still mean the transfer has completed successfully). All other errors are listed at the bottom of this page.

The return code for this callback is not checked, as it is merely an informational callback. However, future versions of the library may use this return code, so you should return 0 here for safety.

Request and Session Identification
### nghq_set_request_user_data
```c
int nghq_set_request_user_data(nghq_session *session, void * current, void * new)
```
Allows the application to change the pointer used as request_user_data in callbacks related to requests or push promises. This may be done at any time while a request is open.

If the current pointer does not match any request_user_data pointer stored within the library, or if new is NULL, then this function will return the error code NGHQ_BAD_USER_DATA.

### nghq_set_session_user_data
```c
int nghq_set_session_user_data(nghq_session *session, void * current, void * new)
```
Allows the application to change the pointer used as session_user_data and provided as part of callbacks. This may be done at any time while a connection is open.

If the current pointer does not match the session_user_data that was provided to either [nghq_session_client_new()](#nghq_session_client_new) or [nghq_session_server_new()](#nghq_session_server_new), or if new is NULL, then this function will return the error code NGHQ_BAD_USER_DATA.

## Request Data
### nghq_feed_headers
```c
int nghq_feed_headers(nghq_session *session, const nghq_header **hdrs, size_t num_hdrs, int final, void *request_user_data)
```
Used to add num_hdrs HTTP headers from the array hdrs to either the request or response of a transfer. If final is non-zero, then this indicates that the application has no more data to send for this request. You should not call [nghq_feed_headers()](#nghq_feed_headers) or [nghq_feed_payload_data()](#nghq_feed_payload_data) again for this request, and you will not need to call [nghq_end_request()](#nghq_end_request).

If request_user_data relates to an as-yet unstarted promise (i.e. the promised_request_user_data as supplied to [nghq_submit_push_promise()](#nghq_submit_push_promise)), this will cause the server push to start the process of sending the new server-pushed resource, beginning with the headers.

If this is called after the first call to [nghq_feed_payload_data()](#nghq_feed_payload_data), then these headers will be assumed to be HTTP trailing headers. If any of the headers in hdrs have not been declared in a Trailers header, then this function will return NGHQ_TRAILERS_NOT_PROMISED.

### nghq_feed_payload_data
```c
ssize_t nghq_feed_payload_data(nghq_session *session, uint8_t *buf, size_t len, int final, void *request_user_data)
```
Feeds len bytes of data buf into a request or response represented by request_user_data. If final is non-zero, then this indicates that the application has no more data to send for this request. You should not call [nghq_feed_headers()](#nghq_feed_headers) or [nghq_feed_payload_data()](#nghq_feed_payload_data) again for this request, and you will not need to call [nghq_end_request()](#nghq_end_request).

Internally, this will buffer up the data, create the packets and then [nghq_session_send()](#nghq_session_send) will send them.

If the call is successful, this function will return the number of bytes that were written. If this is lower than len, you should call [nghq_session_send()](#nghq_session_send) and get the packets sent before attempting to send any more.

If the call is to start a new push promise, but there are already too many server-pushes for resources open (see [nghq_set_max_pushed()](#nghq_set_max_pushed)), then this function will return the error code NGHQ_TOO_MANY_REQUESTS.

### nghq_end_request
```c
int nghq_end_request(nghq_session *session, nghq_error result, void *request_user_data)
```
Close a request with the given result. This function also works with promised resources which have not been converted into running requests yet, just pass the promised user data as the request_user_data argument.

If [nghq_submit_request()](#nghq_submit_request), [nghq_feed_headers()](#nghq_feed_headers) or [nghq_feed_payload_data()](#nghq_feed_payload_data) were called with their 'final' argument set to a non-zero value, then it is not necessary to call this method as the stream will be closed implicitly.

If the call is successful, this function will return 0 and the stream will be closed and request_user_data can be safely freed.
If a given request has received a [nghq_on_request_close_callback()](#nghq_on_request_close_callback), or the request_user_data argument is otherwise not recognised as relating to a running request, then this function will return NGHQ_REQUEST_CLOSED. 

## Client Specific Calls
### nghq_submit_request
```c
int nghq_submit_request(nghq_session *session, const nghq_headers *hdrs, uint8_t *req_body, size_t len, int final, void *request_user_data)
```
Submits a request in the form of at least one HEADERS frame, and optionally some DATA frames.

This function may only be called if session is a client session.

If req_body is not NULL, and if the :method specified as one of the name-value pairs in hdrs is a method that allows request message bodies, then req_body contains len bytes of data which will be sent as part of the request. You may also leave this as NULL and feed in data using [nghq_feed_payload_data()](#nghq_feed_payload_data). If the amount of data in req_body is more than can be serialised into packets before needing to call [nghq_session_send()](#nghq_session_send), then this function may return NGHQ_TOO_MUCH_DATA. None of the data in req_body will have been sent, and the application should use [nghq_feed_payload_data()](#nghq_feed_payload_data) instead.

If final is non-zero, then this indicates that the client has no more data to send for this request. You should not call [nghq_feed_headers()](#nghq_feed_headers) or [nghq_feed_payload_data()](#nghq_feed_payload_data) for this request.

Returns NGHQ_OK if the request is succesfully submitted. If there are already too many requests open (see [nghq_set_max_client_requests()](#nghq_set_max_client_requests)), then this function will return the error code NGHQ_TOO_MANY_REQUESTS. If it's not possible to start a new request because of the underlying flow control, then this may return NGHQ_SESSION_BLOCKED, you should try waiting until some more packets have been acknowledged and then try again.

## Server Specific Calls
### nghq_submit_push_promise
```c
int nghq_submit_push_promise(nghq_session *session, void * init_request_user_data, const nghq_header **hdrs, size_t num_hdrs, void *promised_request_user_data)
```
Submits a PUSH_PROMISE frame. 

This function may only be called if session is a server session.

When running in unicast mode, init_request_user_id must be a pointer to the request_user_data used by a currently running request. In multicast mode, init_request_user_data should be set to NULL (it will be ignored internally). The headers in hdrs will be the client's "request", as provided in the PUSH_PROMISE.

To cancel a push promise before actually sending it (server), or cancel a push promise before reception has started (client), then call [nghq_end_request()](#nghq_end_request) as you would for a normal request, providing the promised user data as the request_user_data object.

Returns NGHQ_OK if the call succeeds. If the client's MAX_PUSH_ID limit has been reached, then this function will return the error code of NGHQ_PUSH_LIMIT_REACHED. If it's not possible to send the PUSH_PROMISE frame with the request specified because of the underlying flow control, then this may return NGHQ_REQUEST_BLOCKED.

## Connection Calls
### nghq_get_max_client_requests
```c
uint64_t nghq_get_max_client_requests(nghq_session *session)
```
This function returns how many client-initiated requests are allowed to be open at once. This only applies to client-initiated requests, not server pushes. To see how many server pushes are allowed, use [nghq_get_max_pushed()](#nghq_get_max_pushed).

### nghq_set_max_client_requests
```c
int nghq_set_max_client_requests(nghq_session *session, uint64_t max_requests)
```
Change the limit on maximum number of client-initiated requests that can be open. Unlike [nghq_set_max_promises()](#nghq_set_max_promises) this value sets the maximum number of open requests, and does not need periodically increasing as more requests are made. This value does not effect the maximum number of server pushes that can be open at once, for that use [nghq_set_max_pushed()](#nghq_set_max_pushed).

If the value set as max_requests is lower than the number of currently open requests, then this function returns the error code of NGHQ_TOO_MANY_REQUESTS. The application can then close some requests and then retry.

### nghq_get_max_pushed
```c
uint64_t nghq_get_max_pushed(nghq_session *session)
```
This function returns how many server pushed requests are allowed to be open at once. This only applies to server-pushed resources, and not client-initiated requests. To see how many client-initiated requests are allowed, use [nghq_get_max_client_requests()](#nghq_get_max_client_requests).

### nghq_set_max_pushed
```c
int nghq_set_max_pushed(nghq_session *session, uint64_t max_requests)
```
Change the limit on maximum number of server pushes that can be open. Unlike [nghq_set_max_promises()](#nghq_set_max_promises) this value sets the maximum number of open requests, and does not need periodically increasing as more requests are made. This value does not effect the maximum number of client-initiated requests that can be open at once, for that use [nghq_set_max_client_requests()](#nghq_set_max_client_requests).

If the value set as max_requests is lower than the number of currently open requests, then this function returns the error code of NGHQ_TOO_MANY_REQUESTS. The application can then close some pushed requests and then retry.

### nghq_get_max_promises
```c
uint64_t nghq_get_max_promises(nghq_session *session)
```
This function gets how many push promises the client is still happy to receive. For example, if an application submitted nghq_set_max_promises(10), and three (3) push promises have been acknowledged by the client then this function would return seven (7).

A return of 0 indicates that the client will not accept any more push promises. This function may also be called from a server instance.

### nghq_set_max_promises
```c
int nghq_set_max_promises(nghq_session* session, uint64_t max_push)
```
Submits a MAX_PUSH_ID frame to the server, indicating how many push promises the client is willing to accept. The value given for max_push is the number of new push promises that the server will be allowed to send, and is not the number that will be sent in the MAX_PUSH_ID frame. For example, if the application initially sets the max_push value as 10, the value in the MAX_PUSH_ID frame will be 10. The client then receives 5 push promises from the server, before calling nghq_set_max_promises again with a max_push of 10, the library will then send a new MAX_PUSH_ID frame with a value of 15, as this is 10 more than it has currently received.

This only effects the number of promises that the server can send, not the number of pushed requests that it can make. This is controlled by [nghq_set_max_pushed()](#nghq_set_max_pushed). For example, given the following:

```c
nghq_set_max_pushed(session, 10);
nghq_set_max_promises(session, 30);
```
The server would be able to send 30 Push Promises to the client, but may only open 10 server pushes at a time. Once a server push request is completed, then the server can open another until all 30 push promises are delivered or cancelled. 

If you attempt to set a number lower than that which would be returned by [nghq_get_max_promises()](#nghq_get_max_promises), then this function will return the error code NGHQ_INVALID_PUSH_LIMIT.

If you attempt to call this method while running as a server, it will return the error code NGHQ_CLIENT_ONLY.

## Types
### nghq_session
An opaque type to track a given QUIC connection. Every successful call to nghq_session_*_new will return a unique pointer of this type. Application code should not attempt to use any values inside this object directly.

### nghq_callbacks
A structure containing pointers to all the callbacks that the library will attempt to call. If any callback is not going to be implemented, then it should be set as NULL, and the library will not call them. However, if it is a required callback then this will cause an internal error, and subsequent calls to nghq_session_(*) functions will return NGHQ_INTERNAL_ERROR.
```c
struct nghq_callbacks {
    /* Session Callbacks */
    nghq_recv_callback              recv_callback;
    nghq_send_callback              send_callback;
    nghq_decrypt_callback           decrypt_callback;
    nghq_encrypt_callback           encrypt_callback;
    nghq_session_status_callback    session_status_callback;
    nghq_recv_control_data_callback recv_control_data_callback;
  
    /* Application Data Received Callbacks */
    nghq_on_begin_headers_callback  on_begin_headers_callback;
    nghq_on_headers_callback        on_headers_callback;
    nghq_on_data_recv_callback      on_data_recv_callback;
    nghq_on_push_cancel_callback    on_push_cancel_callback;
    nghq_on_request_close_callback  on_request_close_callback;
};
```
### nghq_error
All the errors below are defined as macros so they can be returned on any signed integer type (they are all negative), but there is also an nghq_error type which maps all of these to an enum:

| Error Code | Reason |
|------------|--------|
| NGHQ_OK	| OK (=0) |
| NGHQ_ERROR | General error |
| NGHQ_INTERNAL_ERROR | A critical failure happened inside the library - the session is no longer sane and should be shut down. |
| NGHQ_OUT_OF_MEMORY | A part of the library internals could not request more memory from the system |
| NGHQ_INCOMPATIBLE_METHOD | The method specified could not be used for what the client wants to do (i.e. specifying a GET method and then trying to add a request body) |
| NGHQ_TOO_MUCH_DATA | Returned by nghq_submit_request if the associated body data is too large to serialise in one go, and the application should use nghq_feed_payload_data instead. |
| NGHQ_CANCELLED | The client cancelled the request |
| NGHQ_SESSION_CLOSED | The session was closed (i.e. a connection error and this session object is no longer usable). |
| NGHQ_EOF | The remote peer closed the connection |
| NGHQ_HDR_COMPRESS_FAILURE | A general header compression failure |
| NGHQ_CRYPTO_ERROR | The application can return these in either nghq_decrypt or nghq_encrypt indicating that it couldn't perform |
| NGHQ_NO_MORE_DATA | Returned by nghq_recv_callback and nghq_send_callback if there is no longer any data available to receive or send. |
| NGHQ_SESSION_BLOCKED | An attempt to send more data for the whole session than is permitted by the underlying flow control |
| NGHQ_REQUEST_BLOCKED | An attempt to send more data for a request than is permitted by the underlying flow control |
| NGHQ_TOO_MANY_REQUESTS | An attempt to open a new request or push promise could not be made because there were already too many open requests (see nghq_set_maximum_requests()) |
| NGHQ_NOT_INTERESTED | The application is no longer interested in continuing with the stream. Will close the stream. |
| NGHQ_CLIENT_ONLY | An attempt to use a client method when running as a server |
| NGHQ_SERVER_ONLY | An attempt to use a server method when running as a client |
| NGHQ_BAD_USER_DATA | A provided user data pointer was invalid or could not be used |
| NGHQ_INVALID_PUSH_LIMIT | An attempt to lower the MAX_PUSH_ID below a value already submitted to the server |
| NGHQ_PUSH_LIMIT_REACHED | An attempt to submit a push promise when we have already reached the maximum number of pushes allowed by a client |
| NGHQ_PUSH_ALREADY_IN_CACHE | The server attempted to push content which the client already has |
| NGHQ_TRAILERS_NOT_PROMISED | An attempt to send trailing headers that had not been explicitly promised in the Trailers header |
| NGHQ_REQUEST_CLOSED | The request indicated has been completed or does not exist. |
| NGHQ_SETTINGS_NOT_RECOGNISED | A settings structure could not be read |
| NGHQ_HTTP_CONNECT_ERROR | A HTTP CONNECT request could not contact the remote peer |
| NGHQ_HTTP_WRONG_STREAM | The remote peer sent data on the wrong stream ID |
| NGHQ_HTTP_DUPLICATE_PUSH | We received or attempted to send a push promise that has already been promised |
| NGHQ_HTTP_MALFORMED_FRAME | A received HTTP frame could not be parsed |
| NGHQ_HTTP_PUSH_REFUSED | The application or remote peer refused a push promise |
| NGHQ_HTTP_ALPN_FAILED | A supported HTTP/QUIC application protocol version could not be negotiated via ALPN. |
| NGHQ_TRANSPORT_ERROR | A general failure of the QUIC transport layer |
| NGHQ_TRANSPORT_CLOSED | The remote peer closed the connection without specifying an error |
| NGHQ_TRANSPORT_FINAL_OFFSET | An enpoint received a STREAM frame containing data that exceeded the final offset |
| NGHQ_TRANSPORT_FRAME_FORMAT | An enpoint received a frame that was badly formatted |
| NGHQ_TRANSPORT_PARAMETER | An enpoint received transport parameters that were badly formatted |
| NGHQ_TRANSPORT_VERSION | The endpoints failed to negotiate a version |
| NGHQ_TRANSPORT_PROTOCOL | An endpoint detected an error with protocol compliance |
| NGHQ_TRANSPORT_TIMEOUT | The underlying transport timed out on sending or receiving data |