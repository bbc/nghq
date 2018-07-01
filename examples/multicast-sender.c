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
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
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
#define DEFAULT_IFC_ADDR_V4   "127.0.0.1"
#define DEFAULT_MCAST_GRP_V6  "ff3e::8000:1"
#define DEFAULT_MCAST_PORT    2000
#define DEFAULT_MCAST_TTL     1
#define DEFAULT_CONNECTION_ID 1

typedef struct server_session {
    nghq_session *session;
    ev_io socket_writable;
    ev_idle send_idle;
    int socket;
    struct sockaddr_storage mcast_addr;
    struct sockaddr_storage send_addr;
} server_session;

static char method_hdr[] = ":method";
static char method_value[] = "GET";
static const nghq_header method_header = {
    method_hdr, sizeof(method_hdr)-1, method_value, sizeof(method_value)-1
};
static char path_hdr[] = ":path";
static char path_value[] = "/testfile.txt";
static const nghq_header path_header = {
    path_hdr, sizeof(path_hdr)-1, path_value, sizeof(path_value)-1
};
static char host_hdr[] = ":authority";
static char host_value[] = "localhost";
static const nghq_header host_header = {
    host_hdr, sizeof(host_hdr)-1, host_value, sizeof(host_value)-1
};
static char user_agent_hdr[] = "User-Agent";
static char user_agent_value[] = "NGHQ-Example/1.0 (Linux) NGHQ/20180321 NGHQ-Server/1.0";
static const nghq_header user_agent_header = {
    user_agent_hdr, sizeof(user_agent_hdr)-1, user_agent_value, sizeof(user_agent_value)-1
};

static const nghq_header *g_request_hdrs[] = {
  &method_header, &path_header, &host_header, &user_agent_header
};

static char status_hdr[] = ":status";
static char status_value[] = "200";
static const nghq_header status_header = {
  status_hdr, sizeof(status_hdr)-1, status_value, sizeof(status_value)-1
};

static char server_hdr[] = "Server";
static char server_value[] = "NGHQ-Server/1.0 (GNU/Linux)";
static const nghq_header server_header = {
  server_hdr, sizeof(server_hdr)-1, server_value, sizeof(server_value)-1
};
static char date_hdr[] = "Date";
static char date_value[] = "Wed, 21 Mar 2018 14:52:45 GMT";
static const nghq_header date_header = {
  date_hdr, sizeof(date_hdr)-1, date_value, sizeof(date_value)-1
};
static char content_type_hdr[] = "Content-Type";
static char content_type_value[] = "text/plain; charset=UTF-8";
static const nghq_header content_type_header = {
  content_type_hdr, sizeof(content_type_hdr)-1, content_type_value, sizeof(content_type_value)-1
};

static const nghq_header *g_response_hdrs[] = {
  &status_header, &server_header, &date_header, &content_type_header
};

static const char g_response[] = "This is a test of the multicast HTTP/QUIC server push!";

static server_session g_server_session;

static ssize_t recv_cb (nghq_session *session, uint8_t *data, size_t len,
                        void *session_user_data)
{
    /* server_session *sdata = (server_session*)session_user_data; */
    return NGHQ_ERROR;
}

static ssize_t decrypt_cb (nghq_session *session, const uint8_t *encrypted,
                           size_t encrypted_len, const uint8_t *nonce,
                           size_t noncelen, const uint8_t *ad, size_t adlen,
                           uint8_t *clear, size_t clear_len,
                           void *session_user_data)
{
    /* server_session *sdata = (server_session*)session_user_data; */
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
    /* server_session *sdata = (server_session*)session_user_data; */
    if (clear_len > encrypted_len) return NGHQ_CRYPTO_ERROR;
    memcpy(encrypted, clear, clear_len);
    return clear_len;
}

static ssize_t send_cb (nghq_session *session, const uint8_t *data, size_t len,
                        void *session_user_data)
{
    server_session *sdata = (server_session*)session_user_data;
    ssize_t result = sendto(sdata->socket, data, len, 0,
			    (struct sockaddr*)(&sdata->mcast_addr),
                            sizeof(sdata->mcast_addr));
    if (result == EWOULDBLOCK) {
	return NGHQ_OK;
    }
    if (result < 0) {
	return NGHQ_ERROR;
    }
    return result;
}

static void session_status_cb (nghq_session *session, nghq_error status,
                               void *session_user_data)
{
    /* server_session *sdata = (server_session*)session_user_data; */
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
    /* server_session *sdata = (server_session*)session_user_data; */
    if (type == NGHQ_HT_PUSH_PROMISE) {
	/* can't push to a server */
	return NGHQ_ERROR;
    }
    /* incoming request - but we're multicast - so this is an error! */
    /* TODO: interpret the request for unicast server */
    return NGHQ_ERROR;
}

static int on_headers_cb (nghq_session *session, uint8_t flags,
                          nghq_header *hdr, void *request_user_data)
{
    /* push_request *req = (push_request*)request_user_data; */
    /* printf("%c> %*s: %*s\n", ((req->headers_incoming==HEADERS_REQUEST)?'P':'H'),
            hdr->name_len, hdr->name, hdr->value_len, hdr->value); */
}

static int on_data_recv_cb (nghq_session *session, uint8_t flags,
                            const uint8_t *data, size_t len, size_t off,
                            void *request_user_data)
{
    printf("Received %zu bytes\n", len);
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
    NGHQ_USP_ENABLED                             /* unbound_push */
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

static void socket_writable_cb (EV_P_ ev_io *w, int revents)
{
    server_session *sdata = (server_session*)(w->data);
    ev_io_stop (EV_DEFAULT_UC_ w);
    ev_idle_start (EV_DEFAULT_UC_ &sdata->send_idle);
}

static void send_idle_cb (EV_P_ ev_idle *w, int revents)
{
    int rv;
    server_session *sdata = (server_session*)(w->data);
    ev_idle_stop (EV_DEFAULT_UC_ w);
    rv = nghq_session_send (sdata->session);
    if (rv != NGHQ_OK) {
      ev_break (EV_DEFAULT_UC_ EVBREAK_ALL);
    }
    ev_io_start (EV_DEFAULT_UC_ &sdata->socket_writable);
}

static int
_name_and_port_to_sockaddr (struct sockaddr *addr, socklen_t addr_len,
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

static int
_match_sockaddr (const struct sockaddr *addr1, const struct sockaddr *addr2)
{
    if (addr1 == addr2) return 1;
    if (addr1->sa_family != addr2->sa_family) return 0;
    switch (addr1->sa_family) {
    case AF_INET: {
            const struct sockaddr_in *sin1 = (const struct sockaddr_in*)addr1;
            const struct sockaddr_in *sin2 = (const struct sockaddr_in*)addr2;
            if (sin1->sin_port != sin2->sin_port) return 0;
            if (sin1->sin_addr.s_addr != sin2->sin_addr.s_addr) return 0;
        }
        break;
    case AF_INET6: {
            const struct sockaddr_in6 *sin1 = (const struct sockaddr_in6*)addr1;
            const struct sockaddr_in6 *sin2 = (const struct sockaddr_in6*)addr2;
            if (sin1->sin6_port != sin2->sin6_port) return 0;
            if (!IN6_ARE_ADDR_EQUAL(&sin1->sin6_addr, &sin2->sin6_addr))
                return 0;
        }
        break;
    default:
	/* don't know how to compare, so just declare them not equal */
        return 0;
    }
    return 1;
}

static void
_bind_socket_interface (int sock, const struct sockaddr *addr, unsigned int idx)
{
    switch (addr->sa_family) {
    case AF_INET: {
            const struct sockaddr_in *sin = (const struct sockaddr_in*)addr;
	    setsockopt (sock, SOL_IP, IP_MULTICAST_IF, &(sin->sin_addr.s_addr),
                        sizeof (sin->sin_addr.s_addr));
            bind (sock, addr, sizeof (struct sockaddr_in));
        }
        break;
    case AF_INET6: {
            setsockopt (sock, SOL_IPV6, IPV6_MULTICAST_IF, &idx, sizeof (idx));
            bind (sock, addr, sizeof (struct sockaddr_in6));
        }
        break;
    default:
	fprintf (stderr, "Unknown address family, aborting.\n");
	exit(3);
    }
}

int main(int argc, char *argv[])
{
    struct sockaddr_in mcast_addr;
    int promise_request_user_data;
    int result;
    int i;
    static const int on = 1;

    static const char short_opts[] = "hi:p:t:";
    static const struct option long_opts[] = {
        {"help", 0, NULL, 'h'},
        {"connection-id", 1, NULL, 'i'},
        {"port", 1, NULL, 'p'},
        {"ttl", 1, NULL, 't'},
        {NULL, 0, NULL, 0}
    };

    int help = 0;
    int usage = 0;
    int err_out = 0;
    int ttl = DEFAULT_MCAST_TTL;
    g_trans_settings.init_conn_id = DEFAULT_CONNECTION_ID;
    unsigned short send_port = DEFAULT_MCAST_PORT;
    const char *mcast_grp = DEFAULT_MCAST_GRP_V4;
    const char *ifc_ip = DEFAULT_IFC_ADDR_V4;
    unsigned int ifc_idx = 0;
    const char *default_mcast_grp = NULL;
    const char *default_ifc_ip = NULL;
    int opt;
    int option_index = 0;
    int usp_enabled = 1;

    mcast_ifc_list *ifcs = NULL;

    ifcs = get_multicast_interfaces();
    if (ifcs) {
	static char ip_buf[INET6_ADDRSTRLEN];
        if (getnameinfo(ifcs->ifc_addr, ifcs->ifc_addrlen, ip_buf, sizeof(ip_buf), NULL, 0, NI_NUMERICHOST) == 0) {
	    ifc_ip = ip_buf;
	}
	if (ifcs->ifc_addr->sa_family == AF_INET6) {
	    mcast_grp = DEFAULT_MCAST_GRP_V6;
	}
    }

    default_ifc_ip = ifc_ip;
    default_mcast_grp = mcast_grp;

    while ((opt = getopt_long(argc, argv, short_opts, long_opts, &option_index)) != -1) {
        switch (opt) {
        case 'h':
            help = 1;
            usage = 1;
            break;
        case 'i':
            g_trans_settings.init_conn_id = atoi (optarg);
            break;
        case 'p':
            send_port = atoi (optarg);
            break;
	case 't':
	    ttl = atoi (optarg);
	    if (ttl<1) ttl = 1;
            if (ttl>255) ttl = 255;
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
"Usage: %s [-h] [-p <port>] [-i <id>] [-t <ttl>] [<mcast-grp> [<ifc-addr>]]\n",
              argv[0]);
    }
    if (help) {
      printf("\n"
"Options:\n"
"  --help          -h        Display this help text.\n"
"  --port          -p <port> UDP port number to send to [default: " STR(DEFAULT_MCAST_PORT) "].\n"
"  --connection-id -i <id>   The connection ID to expect [default: " STR(DEFAULT_CONNECTION_ID) "].\n"
"  --ttl           -t <ttl>  The TTL to use for multicast [default: " STR(DEFAULT_MCAST_TTL) "].\n"
"\n"
"Arguments:\n"
"  <mcast-grp> The multicast group to send on [default: %s].\n"
"  <ifc-addr>  The source interface address [default: %s].\n"
"\n", default_mcast_grp, default_ifc_ip);
    }
    if (usage) {
      return err_out;
    }

    if (optind < argc) {
        mcast_grp = argv[optind];
    }

    if (optind+1 < argc) {
        ifc_ip = argv[optind+1];
    }

    /* Initialise libev */
    ev_default_loop (0);

    /* configure the group address */
    if (!_name_and_port_to_sockaddr(
                         (struct sockaddr*)&g_server_session.mcast_addr,
                         sizeof(g_server_session.mcast_addr),
                         mcast_grp, send_port)) {
        fprintf(stderr, "Unable to resolve multicast address \"%s\".\n",
                mcast_grp);
        exit(3);
    }

    /* configure the sending address */
    if (!_name_and_port_to_sockaddr(
                         (struct sockaddr*)&g_server_session.send_addr,
                         sizeof(g_server_session.send_addr),
                         ifc_ip, 0)) {
        fprintf(stderr, "Unable to resolve source address \"%s\".\n", ifc_ip);
        exit(3);
    }

    if (g_server_session.mcast_addr.ss_family !=
        g_server_session.send_addr.ss_family) {
        fprintf(stderr, "Multicast group and source interface address must be in the same address family.\n");
	exit(2);
    }

    for (mcast_ifc_list *ifc = ifcs; ifc; ifc = ifc->ifc_next) {
        if (_match_sockaddr((struct sockaddr*)&g_server_session.send_addr,
                            ifc->ifc_addr)) {
            ifc_idx = ifc->ifc_idx;
	    break;
	}
    }

    /* Create sending socket */
    g_server_session.socket = socket (g_server_session.mcast_addr.ss_family,
                                      SOCK_DGRAM|SOCK_NONBLOCK, 0);

    /* configure send interface */
    _bind_socket_interface (g_server_session.socket,
                            (struct sockaddr*)&g_server_session.send_addr,
                            ifc_idx);
    if (g_server_session.mcast_addr.ss_family == AF_INET) {
        setsockopt (g_server_session.socket, SOL_IP, IP_MULTICAST_LOOP, &on,
		    sizeof(on));
        setsockopt (g_server_session.socket, SOL_IP, IP_MULTICAST_TTL, &ttl,
                    sizeof(ttl));
    } else {
	setsockopt (g_server_session.socket, SOL_IPV6, IPV6_MULTICAST_LOOP, &on,
                    sizeof(on));
	setsockopt (g_server_session.socket, SOL_IPV6, IPV6_MULTICAST_HOPS,
		    &ttl, sizeof(ttl));
    }

    ev_io_init (&g_server_session.socket_writable, socket_writable_cb,
		g_server_session.socket, EV_WRITE);
    g_server_session.socket_writable.data = &g_server_session;

    ev_idle_init (&g_server_session.send_idle, send_idle_cb);
    g_server_session.send_idle.data = &g_server_session;

    g_server_session.session = nghq_session_server_new (&g_callbacks,
					&g_settings, &g_trans_settings,
					&g_server_session);

    ev_io_start (EV_DEFAULT_UC_ &g_server_session.socket_writable);

    /* Make the push promise */
    printf("Submitting Push Promise with headers:\n");
    for (i = 0; i < sizeof(g_request_hdrs)/sizeof(g_request_hdrs[0]); i++) {
      printf("\t%s: %s\n", g_request_hdrs[i]->name, g_request_hdrs[i]->value);
    }
    if (usp_enabled == 1) {
        result = nghq_submit_unbound_push_promise (g_server_session.session, 
                g_request_hdrs,
                        sizeof(g_request_hdrs)/sizeof(g_request_hdrs[0]),
                        &promise_request_user_data);
    } else {
        result = nghq_submit_push_promise (g_server_session.session, NULL,
                g_request_hdrs,
                        sizeof(g_request_hdrs)/sizeof(g_request_hdrs[0]),
                        &promise_request_user_data);
    }

    ev_run(EV_DEFAULT_UC_ EVRUN_ONCE);

    printf("Starting server push with headers:\n");
    for (i = 0; i < sizeof(g_response_hdrs)/sizeof(g_response_hdrs[0]); i++) {
      printf("\t%s: %s\n", g_response_hdrs[i]->name, g_response_hdrs[i]->value);
    }
    result = nghq_feed_headers (g_server_session.session, g_response_hdrs,
		     sizeof(g_response_hdrs)/sizeof(g_response_hdrs[0]), 0,
		     &promise_request_user_data);

    ev_run(EV_DEFAULT_UC_ EVRUN_ONCE);

    printf("Payload for server push: %s\n", g_response);
    result = nghq_feed_payload_data (g_server_session.session, g_response,
                     sizeof(g_response), 1, &promise_request_user_data);

    ev_run(EV_DEFAULT_UC_ 0);

    ev_io_stop (EV_DEFAULT_UC_ &g_server_session.socket_writable);
    ev_idle_stop (EV_DEFAULT_UC_ &g_server_session.send_idle);

    nghq_session_free (g_server_session.session);
    close (g_server_session.socket);

    return 0;
}
