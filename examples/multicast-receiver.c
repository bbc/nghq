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

#include <ev.h>

#include <nghq/nghq.h>

#define _STR(a) #a
#define STR(a) _STR(a)
#define DEFAULT_MCAST_GRP     "232.0.0.1"
#define DEFAULT_MCAST_PORT    2000
#define DEFAULT_SRC_ADDR      "127.0.0.1"
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
                            const uint8_t *data, size_t len,
                            void *request_user_data)
{
    printf("Received %zu bytes\n", len);
    printf("Body: %s\n", data);
}

static int on_push_cancel_cb (nghq_session *session, void *request_user_data)
{
    printf("Push cancelled");
}

static int on_request_close_cb  (nghq_session *session, nghq_error status,
                                 void *request_user_data)
{
    printf("Request finished");
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

int main(int argc, char *argv[])
{
    session_data this_session;
    struct sockaddr_in mcast_addr;
    struct sockaddr_in src_addr;
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
    unsigned int connection_id = DEFAULT_CONNECTION_ID;
    unsigned short recv_port = DEFAULT_MCAST_PORT;
    const char *mcast_grp = DEFAULT_MCAST_GRP;
    const char *src_ip = DEFAULT_SRC_ADDR;
    int opt;
    int option_index = 0;
    while ((opt = getopt_long(argc, argv, short_opts, long_opts, &option_index)) != -1) {
        switch (opt) {
        case 'h':
            help = 1;
            usage = 1;
            break;
        case 'i':
            connection_id = atoi(optarg);
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
"  <mcast-grp> The multicast group to receive on [default: " DEFAULT_MCAST_GRP "].\n"
"  <src-addr>  The multicast source address [default: " DEFAULT_SRC_ADDR "].\n"
"\n");
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

    /* make the connection */
    mcast_addr.sin_family = AF_INET;
    mcast_addr.sin_addr.s_addr = inet_addr (mcast_grp);
    mcast_addr.sin_port = htons(recv_port);

    src_addr.sin_family = AF_INET;
    src_addr.sin_addr.s_addr = inet_addr (src_ip);
    src_addr.sin_port = 0;

    gsr.gsr_interface = 0;
    memcpy(&gsr.gsr_group, &mcast_addr, sizeof(mcast_addr));
    memcpy(&gsr.gsr_source, &src_addr, sizeof(src_addr));

    this_session.socket = socket (AF_INET, SOCK_DGRAM|SOCK_NONBLOCK, 0);
    bind (this_session.socket, (struct sockaddr*)&mcast_addr,
            sizeof(mcast_addr));
    setsockopt (this_session.socket, IPPROTO_IP, MCAST_JOIN_SOURCE_GROUP, &gsr,
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
