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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <getopt.h>
#include <netdb.h>

#include <ev.h>

#include "nghq/nghq.h"
#include "multicast_interfaces.h"

#define _STR(a) #a
#define STR(a) _STR(a)
#define DEFAULT_MCAST_GRP_V4  "232.0.0.1"
#define DEFAULT_MCAST_GRP_V6  "ff3e::8000:1"
#define DEFAULT_MCAST_PORT    2000
#define DEFAULT_SRC_ADDR_V4   "127.0.0.1"
#define DEFAULT_CONNECTION_ID 1

typedef enum ReceivingHeaders {
    HEADERS_REQUEST = 0,
    HEADERS_RESPONSE
} ReceivingHeaders;

typedef struct push_request {
    ReceivingHeaders headers_incoming;
} push_request;

typedef struct session_data {
    nghq_session *session;
    ev_io socket_readable;
    ev_idle recv_idle;
    int socket;
} session_data;

static ssize_t recv_cb (nghq_session *session, uint8_t *data, size_t len,
                        void *session_user_data)
{
    session_data *sdata = (session_data*)session_user_data;
    ssize_t result;
    result = recv(sdata->socket, data, len, 0);
    if (result < 0) {
      if (errno != EWOULDBLOCK && errno != EAGAIN) {
        return NGHQ_ERROR;
      }
      return 0;
    }
    printf("Received %zd bytes of data\n", result);
    return result;
}

static ssize_t decrypt_cb (nghq_session *session, const uint8_t *encrypted,
                           size_t encrypted_len, const uint8_t *nonce,
                           size_t noncelen, const uint8_t *ad, size_t adlen,
                           uint8_t *clear, size_t clear_len,
                           void *session_user_data)
{
    /*session_data *sdata = (session_data*)session_user_data;*/
    if (encrypted_len > clear_len) return NGHQ_CRYPTO_ERROR;
    memcpy(clear, encrypted, encrypted_len);
    return encrypted_len;
}

static ssize_t encrypt_cb (nghq_session *session, const uint8_t *clear,
                           size_t clear_len, const uint8_t *nonce,
                           size_t noncelen, const uint8_t *ad, size_t adlen,
                           uint8_t *encrypted, size_t encrypted_len,
                           void *session_user_data)
{
    /* session_data *sdata = (session_data*)session_user_data; */
    if (clear_len > encrypted_len) return NGHQ_CRYPTO_ERROR;
    memcpy(encrypted, clear, clear_len);
    return clear_len;
}

static ssize_t send_cb (nghq_session *session, const uint8_t *data, size_t len,
                        void *session_user_data)
{
    /* session_data *sdata = (session_data*)session_user_data; */
    return len;
}

static void session_status_cb (nghq_session *session, nghq_error status,
                               void *session_user_data)
{
    /* session_data *sdata = (session_data*)session_user_data; */
}

static int recv_control_data_cb (nghq_session *session, const uint8_t *buf,
                                 size_t buflen, void *session_user_data)
{
  return NGHQ_OK;
}

static int on_begin_headers_cb (nghq_session *session, nghq_headers_type type,
                                void *session_user_data,
                                void *request_user_data)
{
    session_data *data = (session_data*)session_user_data;
    if (type == NGHQ_HT_PUSH_PROMISE) {
        push_request *new_request = calloc(1, sizeof(push_request));
        nghq_set_request_user_data(session, request_user_data, new_request);
    } else {
        push_request *req = (push_request*)request_user_data;
        req->headers_incoming = HEADERS_RESPONSE;
    }
}

static int on_headers_cb (nghq_session *session, uint8_t flags,
                          nghq_header *hdr, void *request_user_data)
{
    push_request *req = (push_request*)request_user_data;
    printf("%c> %.*s: %.*s\n",
           ((req->headers_incoming==HEADERS_REQUEST)?'P':'H'),
           (int) hdr->name_len, hdr->name, (int) hdr->value_len, hdr->value);
}

static int on_data_recv_cb (nghq_session *session, uint8_t flags,
                            const uint8_t *data, size_t len, size_t off,
                            void *request_user_data)
{
    printf("Received %zu bytes\n", len);
    printf("Body: %s\n", data);
}

static int on_push_cancel_cb (nghq_session *session, void *request_user_data)
{
    printf("Push cancelled\n");
}

static int on_request_close_cb  (nghq_session *session, nghq_error status,
                                 void *request_user_data)
{
    printf("Request finished\n");
}

static nghq_callbacks g_callbacks = {
    recv_cb,
    decrypt_cb,
    encrypt_cb,
    send_cb,
    session_status_cb,
    recv_control_data_cb,
    on_begin_headers_cb,
    on_headers_cb,
    on_data_recv_cb,
    on_push_cancel_cb,
    on_request_close_cb
};

static nghq_settings g_settings = {
    NGHQ_SETTINGS_DEFAULT_HEADER_TABLE_SIZE,     /* header_table_size */
    NGHQ_SETTINGS_DEFAULT_MAX_HEADER_LIST_SIZE,  /* max_header_list_size */
};

static nghq_transport_settings g_trans_settings = {
    NGHQ_MODE_MULTICAST,  /* mode */
    16,                   /* max_open_requests */
    16,                   /* max_open_server_pushes */
    60,                   /* idle_timeout (seconds) */
    1500,                 /* max_packet_size */
    0,  /* use default */ /* ack_delay_exponent */
    1                     /* connection id */
};

static void socket_readable_cb (EV_P_ ev_io *w, int revents)
{
    session_data *data = (session_data*)(w->data);
    ev_io_stop (EV_DEFAULT_UC_ w);
    ev_idle_start (EV_DEFAULT_UC_ &data->recv_idle);
}

static void recv_idle_cb (EV_P_ ev_idle *w, int revents)
{
    session_data *data = (session_data*)(w->data);
    ev_idle_stop (EV_DEFAULT_UC_ w);
    printf("Data waiting on socket, calling nghq_session_recv\n");
    int rv = nghq_session_recv (data->session);
    if (rv != NGHQ_OK) {
      fprintf(stderr, "nghq_session_recv failed with %d\n", rv);
    }
    ev_io_start (EV_DEFAULT_UC_ &data->socket_readable);
}

static int
_name_and_port_to_sockaddr(struct sockaddr *addr, socklen_t addr_len,
                            const char *addr_str, unsigned short port)
{
    struct addrinfo hints = {
        AI_ADDRCONFIG, AF_UNSPEC, 0, 0, 0, NULL, NULL, NULL
    };
    struct addrinfo *addresses = NULL;
    addr->sa_family = AF_UNSPEC;
    if (getaddrinfo(addr_str, NULL, &hints, &addresses)) return 0;
    for (struct addrinfo *ai = addresses; ai; ai = ai->ai_next) {
        if ((ai->ai_family == AF_INET || ai->ai_family == AF_INET6) &&
            addr_len >= ai->ai_addrlen) {
            memcpy(addr, ai->ai_addr, ai->ai_addrlen);
            switch (ai->ai_family) {
            case AF_INET:
                ((struct sockaddr_in*)addr)->sin_port = htons(port);
                break;
            case AF_INET6:
                ((struct sockaddr_in6*)addr)->sin6_port = htons(port);
                break;
            }
            freeaddrinfo(addresses);
            return 1;
        }
    }
    freeaddrinfo(addresses);
    return 0;
}

static void sigint_cb (struct ev_loop *loop, ev_signal *w, int revents)
{
    ev_break (loop, EVBREAK_ALL);
}

int main(int argc, char *argv[])
{
    session_data this_session;
    struct sockaddr_storage mcast_addr;
    struct sockaddr_storage src_addr;
    struct group_source_req gsr;

    static const char short_opts[] = "hi:p:";
    static const struct option long_opts[] = {
        {"help", 0, NULL, 'h'},
        {"connection-id", 1, NULL, 'i'},
        {"port", 1, NULL, 'p'},
        {NULL, 0, NULL, 0}
    };

    int help = 0;
    int usage = 0;
    int err_out = 0;
    g_trans_settings.init_conn_id = DEFAULT_CONNECTION_ID;
    unsigned short recv_port = DEFAULT_MCAST_PORT;
    const char *mcast_grp = DEFAULT_MCAST_GRP_V4;
    const char *src_ip = DEFAULT_SRC_ADDR_V4;
    const char *default_mcast_grp = NULL;
    const char *default_src_ip = NULL;
    int opt;
    int option_index = 0;

    mcast_ifc_list *ifcs = NULL;

    ifcs = get_multicast_interfaces();
    if (ifcs) {
        static char ip_buf[INET6_ADDRSTRLEN];
        if (getnameinfo(ifcs->ifc_addr, ifcs->ifc_addrlen, ip_buf, sizeof(ip_buf), NULL, 0, NI_NUMERICHOST) == 0) {
            src_ip = ip_buf;
        }
        if (ifcs->ifc_addr->sa_family == AF_INET6) {
            mcast_grp = DEFAULT_MCAST_GRP_V6;
        }
    }

    default_src_ip = src_ip;
    default_mcast_grp = mcast_grp;

    while ((opt = getopt_long(argc, argv, short_opts, long_opts, &option_index)) != -1) {
        switch (opt) {
        case 'h':
            help = 1;
            usage = 1;
            break;
        case 'i':
            g_trans_settings.init_conn_id = atoi(optarg);
            break;
        case 'p':
            recv_port = atoi(optarg);
            break;
        default:
            usage = 1;
            err_out = 1;
            break;
        }
    }

    /* error if more than 2 optional arguments left over */
    if (optind+2 < argc) {
        usage = 1;
        err_out = 1;
    }

    if (usage) {
      fprintf(err_out?stderr:stdout,
"Usage: %s [-h] [-p <port>] [-i <id>] [<mcast-grp> [<src-addr>]]\n",
              argv[0]);
    }
    if (help) {
      printf("\n"
"Options:\n"
"  --help          -h        Display this help text.\n"
"  --port          -p <port> UDP port number to receive on [default: " STR(DEFAULT_MCAST_PORT) "].\n"
"  --connection-id -i <id>   The connection ID to expect [default: " STR(DEFAULT_CONNECTION_ID) "].\n"
"\n"
"Arguments:\n"
"  <mcast-grp> The multicast group to receive on [default: %s].\n"
"  <src-addr>  The multicast source address [default: %s].\n"
"\n", default_mcast_grp, default_src_ip);
    }
    if (usage) {
      return err_out;
    }

    if (optind < argc) {
        mcast_grp = argv[optind];
    }

    if (optind+1 < argc) {
        src_ip = argv[optind+1];
    }

    /* Initialise libev */
    ev_default_loop (0);

    ev_signal signal_watcher;
    ev_signal_init (&signal_watcher, sigint_cb, SIGINT);
    ev_signal_start (EV_DEFAULT_UC_ &signal_watcher);

    /* make the connection */
    if (!_name_and_port_to_sockaddr((struct sockaddr*)&mcast_addr, sizeof(mcast_addr), mcast_grp, recv_port)) {
        fprintf(stderr, "Unable to resolve multicast address \"%s\".\n",
                mcast_grp);
        exit(3);
    }

    if (!_name_and_port_to_sockaddr((struct sockaddr*)&src_addr, sizeof(src_addr), src_ip, 0)) {
        fprintf(stderr, "Unable to resolve source address \"%s\".\n",
                src_ip);
        exit(3);
    }

    if (mcast_addr.ss_family != src_addr.ss_family) {
        fprintf(stderr,
"Multicast group and source address must be the same address family.\n");
        exit(2);
    }

    gsr.gsr_interface = 0;
    socklen_t addrlen = 0;
    int sol = SOL_IP;
    switch (mcast_addr.ss_family) {
    case AF_INET:
        addrlen = sizeof(struct sockaddr_in);
        /* sol = SOL_IP; */
        break;
    case AF_INET6:
        addrlen = sizeof(struct sockaddr_in6);
        sol = SOL_IPV6;
        break;
    }
    memcpy(&gsr.gsr_group, &mcast_addr, addrlen);
    memcpy(&gsr.gsr_source, &src_addr, addrlen);

    this_session.socket = socket (mcast_addr.ss_family,
                                  SOCK_DGRAM|SOCK_NONBLOCK, 0);
    bind (this_session.socket, (struct sockaddr*)&mcast_addr,
            addrlen);
    setsockopt (this_session.socket, sol, MCAST_JOIN_SOURCE_GROUP, &gsr,
                sizeof(gsr));

    /* create libev events */
    ev_io_init (&this_session.socket_readable, socket_readable_cb,
            this_session.socket, EV_READ);
    this_session.socket_readable.data = &this_session;

    ev_idle_init (&this_session.recv_idle, recv_idle_cb);
    this_session.recv_idle.data = &this_session;

    /* initialise the client */
    this_session.session = nghq_session_client_new (&g_callbacks, &g_settings,
                                       &g_trans_settings, &this_session);

    ev_io_start (EV_DEFAULT_UC_ &this_session.socket_readable);

    ev_run (EV_DEFAULT_UC_ 0);

    ev_io_stop (EV_DEFAULT_UC_ &this_session.socket_readable);
    ev_idle_stop (EV_DEFAULT_UC_ &this_session.recv_idle);

    /* tidy up */
    nghq_session_free (this_session.session);
    setsockopt(this_session.socket, IPPROTO_IP, MCAST_LEAVE_SOURCE_GROUP, &gsr,
           sizeof(gsr));
    close(this_session.socket);

    return 0;
}

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
