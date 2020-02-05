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
#include <stdbool.h>
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

static uint8_t _default_session_id[] = {
    0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x20, 0x49, 0x44 /* "Session ID" */
};

#define _STR(a) #a
#define STR(a) _STR(a)
#define DEFAULT_MCAST_GRP_V4      "232.0.0.1"
#define DEFAULT_MCAST_GRP_V6      "ff3e::8000:1"
#define DEFAULT_MCAST_PORT        2000
#define DEFAULT_SRC_ADDR_V4       "127.0.0.1"
#define DEFAULT_SESSION_ID        _default_session_id
#define DEFAULT_SESSION_ID_LENGTH sizeof(_default_session_id)
#define DEFAULT_FAKE_REORDER      0 /* don't deliberately reorder packets */
#define DEFAULT_DROP_PACKET       0 /* don't deliberately drop packets */

#define OPT_ARG_DEFAULT_FAKE_REORDER   3 /* reorder every 3rd packet */
#define OPT_ARG_DEFAULT_DROP_PACKET    7 /* drop every 7th packet */

typedef enum ReceivingHeaders {
  HEADERS_REQUEST = 0,
  HEADERS_RESPONSE
} ReceivingHeaders;

typedef struct push_request {
  ReceivingHeaders headers_incoming;
  bool text_body;
  bool final_request;
} push_request;

typedef struct push_request_list {
  push_request *req;
  struct push_request_list *next;
} push_request_list;

static push_request_list *push_requests;

typedef struct session_data {
  nghq_session *session;
  ev_io socket_readable;
  ev_idle recv_idle;
  int socket;
  int do_fake_reorder;
  int do_drop_packet;
} session_data;

static ssize_t recv_cb (nghq_session *session, uint8_t *data, size_t len,
                        void *session_user_data)
{
  session_data *sdata = (session_data*)session_user_data;
  static int fake_reorder = -1;
  static int drop_packet = -1;
  ssize_t result;
  static uint8_t *tmp_data = NULL;
  static ssize_t tmp_size = 0;

  if (fake_reorder < 0) fake_reorder = sdata->do_fake_reorder;
  if (drop_packet < 0) drop_packet = sdata->do_drop_packet;

  if (tmp_data) {
    result = (tmp_size < len)?tmp_size:len;
    memcpy (data, tmp_data, result);
    if (result == tmp_size) {
      free (tmp_data);
      tmp_data = NULL;
    } else {
      memmove(tmp_data, tmp_data + result, tmp_size - result);
    }
    tmp_size -= result;
  } else {
    if (sdata->do_drop_packet) {
      drop_packet--;
      if (drop_packet<=0) {
        uint8_t buf[len];
        drop_packet = sdata->do_drop_packet;
        result = recv(sdata->socket, buf, len, 0);
        if (result <= 0) {
          drop_packet = 1;
          if (result < 0 && errno != EWOULDBLOCK && errno != EAGAIN) {
            return NGHQ_ERROR;
          }
          return 0;
        }
      }
    }
    if (sdata->do_fake_reorder) {
      fake_reorder--;
      if (fake_reorder<=0) {
        fake_reorder = sdata->do_fake_reorder;
        tmp_data = (uint8_t*)malloc(len);
        result = recv(sdata->socket, tmp_data, len, 0);
        if (result <= 0) {
          free (tmp_data);
          tmp_data = NULL;
          fake_reorder = 1;
          if (result < 0 && errno != EWOULDBLOCK && errno != EAGAIN) {
            return NGHQ_ERROR;
          }
          return 0;
        }
        tmp_size = result;
      }
    }
    result = recv(sdata->socket, data, len, 0);
  }

  if (result < 0) {
    if (errno != EWOULDBLOCK && errno != EAGAIN) {
      return NGHQ_ERROR;
    }
    return 0;
  }
  printf("packet recv: Received %zd bytes of data\n", result);
  return result;
}

static int decrypt_cb (nghq_session *session, const uint8_t *encrypted,
                       size_t encrypted_len, const uint8_t *key,
                       const uint8_t *nonce, size_t noncelen, const uint8_t *ad,
                       size_t adlen, uint8_t *clear, void *session_user_data)
{
    memcpy(clear, encrypted, encrypted_len);
    return 0;
}

static int encrypt_cb (nghq_session *session, const uint8_t *clear,
                       size_t clear_len, const uint8_t *nonce,
                       size_t noncelen, const uint8_t *ad, size_t adlen,
                       const uint8_t *key, uint8_t *encrypted,
                       void *session_user_data)
{
    memcpy(encrypted, clear, clear_len);
    return 0;
}

static ssize_t send_cb (nghq_session *session, const uint8_t *data, size_t len,
                        void *session_user_data)
{
    /* session_data *sdata = (session_data*)session_user_data; */
    return NGHQ_ERROR;
}

static void session_status_cb (nghq_session *session, nghq_error status,
                               void *session_user_data)
{
    /* session_data *sdata = (session_data*)session_user_data; */
    printf("session status: %p = %i\n", session_user_data, status);
}

static int recv_control_data_cb (nghq_session *session, const uint8_t *buf,
                                 size_t buflen, void *session_user_data)
{
  return NGHQ_OK;
}

static int on_begin_headers_cb (nghq_session *session,
                                void *session_user_data,
                                void *request_user_data)
{
    //session_data *data = (session_data*)session_user_data;
    push_request *req = (push_request*)request_user_data;
    req->headers_incoming = HEADERS_RESPONSE;
    return NGHQ_OK;
}

static int on_begin_promise_cb (nghq_session *session, void* session_user_data,
                                void *request_user_data,
                                void *promise_user_data)
{
    //session_data *data = (session_data*) session_user_data;
    push_request *new_request = calloc(1, sizeof(push_request));
    nghq_set_request_user_data(session, promise_user_data, new_request);
    push_request_list *it = push_requests;
    push_request_list *new_entry = calloc (1, sizeof (push_request_list));
    new_entry->req = new_request;
    if (it == NULL) {
      push_requests = new_entry;
    } else {
      while (it != NULL) {
        if (it->next == NULL) {
          it->next = new_entry;
          break;
        }
        it = it->next;
      }
    }
    return NGHQ_OK;
}

static int on_headers_cb (nghq_session *session, uint8_t flags,
                          nghq_header *hdr, void *request_user_data)
{
    push_request *req = (push_request*)request_user_data;
    static const char content_type_field[] = "content-type";
    static const char content_type_text[] = "text/";
    static const char connection_field[] = "connection";
    static const char connection_close_value[] = "close";

    printf("%c> %.*s: %.*s\n",
           ((req->headers_incoming==HEADERS_REQUEST)?'P':'H'),
           (int) hdr->name_len, hdr->name, (int) hdr->value_len, hdr->value);

    if (req->headers_incoming!=HEADERS_REQUEST &&
        hdr->name_len == sizeof(content_type_field)-1 &&
        hdr->value_len >= sizeof(content_type_text) &&
        strncasecmp((const char*)hdr->name, content_type_field, hdr->name_len) == 0 &&
        strncasecmp((const char*)hdr->value, content_type_text,
                    sizeof(content_type_text)-1) == 0) {
        req->text_body = true;
    }
    if (req->headers_incoming!=HEADERS_REQUEST &&
        hdr->name_len == sizeof(connection_field)-1 &&
        hdr->value_len == sizeof(connection_close_value)-1 &&
        strncasecmp((const char*)hdr->name, connection_field, hdr->name_len) == 0 &&
        strncasecmp((const char*)hdr->value, connection_close_value,
                    hdr->value_len) == 0) {
        req->final_request = true;
    }

    return NGHQ_OK;
}

static int on_data_recv_cb (nghq_session *session, uint8_t flags,
                            const uint8_t *data, size_t len, size_t off,
                            void *request_user_data)
{
    push_request *req = (push_request*)request_user_data;

    printf("Received %zu bytes of body data (offset=%zu).\n", len, off);
    if (req->text_body) {
        printf("Body:\n%.*s\n", (int) len, data);
    } else {
        printf("Body is binary, not displaying.\n");
    }

    return NGHQ_OK;
}

static int on_push_cancel_cb (nghq_session *session, void *request_user_data)
{
    printf("Push cancelled\n");
    return NGHQ_OK;
}

static int on_request_close_cb  (nghq_session *session, nghq_error status,
                                 void *request_user_data)
{
    push_request *req = (push_request *) request_user_data;
    push_request_list *prev = NULL, *it = push_requests;
    while (it != NULL) {
      if (it->req == req) {
        if (prev == NULL) {
          push_requests = it->next;
        } else {
          prev->next = it->next;
        }

        if (it->req->final_request) {
          printf("Server signalled session close\n");
          nghq_session_close (session, NGHQ_OK);
          ev_break (EV_DEFAULT_UC_ EVBREAK_ALL);
        }

        free(it->req);
        free(it);
      }
      prev = it;
      it = it->next;
    }
    printf("Request finished\n");
    return NGHQ_OK;
}

typedef struct timer_data {
  ev_timer          timer;
  nghq_session     *session;
  nghq_timer_event  event_fn;
  void             *nghq_data;
} timer_data;

static void timer_event (EV_P_ ev_timer *w, int revent)
{
  timer_data *timer = (timer_data*)w;

  ev_timer_stop (EV_A_ w);

  timer->event_fn (timer->session, timer, timer->nghq_data);

  if (!ev_is_active(w)) free(timer);
}

static void *set_timer_cb (nghq_session *session, double seconds, void *session_user_data, nghq_timer_event fn, void *nghq_data)
{
  timer_data *timer = (timer_data*)calloc(1, sizeof(timer_data));
  timer->session = session;
  timer->event_fn = fn;
  timer->nghq_data = nghq_data;
  ev_timer_init (&timer->timer, timer_event, ev_time () + seconds, 0);
  ev_timer_start (EV_DEFAULT_UC_ &timer->timer);
  return timer;
}

static int cancel_timer_cb (nghq_session *session, void *session_user_data, void *timer_id)
{
  timer_data *timer = (timer_data*)timer_id;
  if (timer_id == NULL) return NGHQ_ERROR;
  if (!ev_is_active(&timer->timer)) return NGHQ_ERROR;
  ev_timer_stop (EV_DEFAULT_UC_ &timer->timer);
  if (ev_is_pending(&timer->timer)) {
    ev_clear_pending (EV_DEFAULT_UC_ &timer->timer);
  }
  free (timer);
  return NGHQ_OK;
}

static int reset_timer_cb (nghq_session *session, void *session_user_data, void *timer_id, double seconds)
{
  timer_data *timer = (timer_data*)timer_id;
  if (timer_id == NULL) return NGHQ_ERROR;
  if (ev_is_active(&timer->timer)) {
    ev_timer_stop (EV_DEFAULT_UC_ &timer->timer);
  }
  ev_timer_set (&timer->timer, ev_time () + seconds, 0);
  ev_timer_start (EV_DEFAULT_UC_ &timer->timer);
  return NGHQ_OK;
}

static nghq_callbacks g_callbacks = {
    recv_cb,
    decrypt_cb,
    encrypt_cb,
    send_cb,
    session_status_cb,
    recv_control_data_cb,
    on_begin_headers_cb,
    on_begin_promise_cb,
    on_headers_cb,
    on_data_recv_cb,
    on_push_cancel_cb,
    on_request_close_cb,
    set_timer_cb,
    cancel_timer_cb,
    reset_timer_cb
};

static nghq_settings g_settings = {
    NGHQ_SETTINGS_DEFAULT_MAX_HEADER_LIST_SIZE,   /* max_header_list_size */
    NGHQ_SETTINGS_DEFAULT_NUM_PLACEHOLDERS,       /* number_of_placeholders */
};

static nghq_transport_settings g_trans_settings = {
    NGHQ_MODE_MULTICAST,         /* mode */
    16,                          /* max_open_requests */
    16,                          /* max_open_server_pushes */
    60,                          /* idle_timeout (seconds) */
    1400,                        /* max_packet_size */
    0,  /* use default */        /* ack_delay_exponent */
    NULL, 0,                     /* session_id and session_id_len */
    UINT32_C(2)*1024*1024*1024,  /* max_stream_data */
    4611686018427387903ULL,      /* max_data - 2^62 max value */
    NULL,                        /* destination_address */
    0,                           /* destination_address_len */
    NULL,                        /* source_address */
    0                            /* source_address_len */
};

static void socket_readable_cb (EV_P_ ev_io *w, int revents)
{
    ev_io_stop (EV_A_ w);
    session_data *data = (session_data*)(w->data);
    ev_idle_start (EV_A_ &data->recv_idle);
}

static void recv_idle_cb (EV_P_ ev_idle *w, int revents)
{
    session_data *data = (session_data*)(w->data);
    int rv;

    ev_idle_stop (EV_A_ w);
    printf("Data waiting on socket, calling nghq_session_recv\n");

    do {
        rv = nghq_session_recv (data->session);
    } while (rv == NGHQ_OK);

    if (rv != NGHQ_NO_MORE_DATA) {
      fprintf(stderr, "nghq_session_recv failed with %d\n", rv);
    } else {
      fprintf(stderr, "Waiting for new packet data.\n");
    }

    ev_io_start (EV_A_ &data->socket_readable);
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

    static const char short_opts[] = "d::hi:p:r::";
    static const struct option long_opts[] = {
        {"help", 0, NULL, 'h'},
        {"session-id", 1, NULL, 'i'},
        {"port", 1, NULL, 'p'},
        {"reorder-every", 2, NULL, 'r'},
        {"drop-every", 2, NULL, 'd'},
        {NULL, 0, NULL, 0}
    };

    int help = 0;
    int usage = 0;
    int err_out = 0;
    g_trans_settings.session_id = DEFAULT_SESSION_ID;
    g_trans_settings.session_id_len = DEFAULT_SESSION_ID_LENGTH;
    unsigned short recv_port = DEFAULT_MCAST_PORT;
    const char *mcast_grp = DEFAULT_MCAST_GRP_V4;
    const char *src_ip = DEFAULT_SRC_ADDR_V4;
    const char *default_mcast_grp = NULL;
    const char *default_src_ip = NULL;
    int opt;
    int option_index = 0;

    this_session.do_fake_reorder = DEFAULT_FAKE_REORDER;
    this_session.do_drop_packet = DEFAULT_DROP_PACKET;

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
    free_multicast_interfaces(ifcs);

    default_src_ip = src_ip;
    default_mcast_grp = mcast_grp;

    while ((opt = getopt_long(argc, argv, short_opts, long_opts, &option_index)) != -1) {
        switch (opt) {
        case 'd':
            if (optarg) {
                this_session.do_drop_packet = atoi(optarg);
                if (this_session.do_drop_packet<0) {
                    this_session.do_drop_packet = 0;
                }
            } else {
                this_session.do_drop_packet = OPT_ARG_DEFAULT_DROP_PACKET;
            }
            break;
        case 'h':
            help = 1;
            usage = 1;
            break;
        case 'i':
            g_trans_settings.session_id_len = nghq_convert_session_id_string (
                optarg, 0, &g_trans_settings.session_id);
            break;
        case 'p':
            recv_port = atoi(optarg);
            break;
        case 'r':
            if (optarg) {
                this_session.do_fake_reorder = atoi(optarg);
                if (this_session.do_fake_reorder<0) {
                    this_session.do_fake_reorder = 0;
                }
            } else {
                this_session.do_fake_reorder = OPT_ARG_DEFAULT_FAKE_REORDER;
            }
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
"Usage: %s [-h] [-p <port>] [-i <id>] [-d[<n>]] [-r[<n>]]\n"
"                         [<mcast-grp> [<src-addr>]]\n",
              argv[0]);
    }
    if (help) {
      printf("\n"
"Options:\n"
"  --help          -h         Display this help text.\n"
"  --port          -p <port>  UDP port number to receive on [default: " STR(DEFAULT_MCAST_PORT) "].\n"
"  --session-id    -i <id>    The session ID to expect [default: " STR(DEFAULT_SESSION_ID) "].\n"
"  --drop-every    -d [<n>]   Drop every nth packet (n=" STR(OPT_ARG_DEFAULT_DROP_PACKET) " if not given)\n"
"                             [default: no dropped packets].\n"
"  --reorder-every -r [<n>]   Reorder every nth packet (n=" STR(OPT_ARG_DEFAULT_FAKE_REORDER) " if not given)\n"
"                             [default: no reordering].\n"
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

    memset(&gsr, 0, sizeof(gsr));
    gsr.gsr_interface = 0;
    socklen_t addrlen = 0;
    int sol = SOL_IP;
    static const int on = 1;
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
    setsockopt (this_session.socket, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    setsockopt (this_session.socket, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
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

/* vim:ts=8:sts=2:sw=2:expandtab:
 */
