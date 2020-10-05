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

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <getopt.h>
#include <netdb.h>
#include <time.h>
#include <fcntl.h>
#include <dirent.h>
#include <inttypes.h>
#include <time.h>

#include <ev.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "nghq/nghq.h"
#include "multicast_interfaces.h"

#if HAVE_OPENSSL
#include "crypto_fns_openssl.h"
#include "digest_fns.h"
#include "signature_fns.h"
#endif

#define AUTHORITY_MAX_LEN     128
#define PATH_MAX_LEN          4096
#define DATE_MAX_LEN          32

/*
 * Worst case QUIC + STREAM + Stream Type + Push Stream + H3 header = ~80 bytes
 */
#define MAX_PACKET_LEN        1470
/* MAX_PAYLOAD_LEN - maximum block size used in stream data */
/*** ngtcp2 bug means that payload must fit in a packet. ***/
//#define MAX_PAYLOAD_LEN              (MAX_PACKET_LEN-29)
#define MAX_PAYLOAD_LEN       16384

static uint8_t _default_session_id[] = {
    0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x20, 0x49, 0x44 /* "Session ID" */
};

#define _STR(a) #a
#define STR(a) _STR(a)
#define DEFAULT_MCAST_GRP_V4      "232.0.0.1"
#define DEFAULT_IFC_ADDR_V4       "127.0.0.1"
#define DEFAULT_MCAST_GRP_V6      "ff3e::8000:1"
#define DEFAULT_MCAST_PORT        2000
#define DEFAULT_MCAST_TTL         1
#define DEFAULT_SESSION_ID        _default_session_id
#define DEFAULT_SESSION_ID_LENGTH sizeof(_default_session_id)
#define DEFAULT_AUTHORITY         "localhost"
#define DEFAULT_PATH_PREFIX       "/"
#define DEFAULT_URL_PREFIX        "https://" DEFAULT_AUTHORITY DEFAULT_PATH_PREFIX
#define DEFAULT_DEBUG_LEVEL       "INFO"
#if HAVE_OPENSSL
#define DEFAULT_PRIVATE_KEY_FILE "sender.key"
#define DEFAULT_KEY_ID           "sender.pem"
#endif

typedef struct server_session {
    nghq_session *session;
    ev_io socket_writable;
    ev_idle send_idle;
    ev_idle recv_idle; // for faked acks
    int socket;
    struct sockaddr_storage mcast_addr;
    struct sockaddr_storage send_addr;
    int single_data_frame;
} server_session;

static char method_hdr[] = ":method";
static char method_value[] = "GET";
static const nghq_header method_header = {
    (uint8_t*)method_hdr, sizeof(method_hdr)-1,
    (uint8_t*)method_value, sizeof(method_value)-1
};
static char scheme_hdr[] = ":scheme";
static char scheme_value[] = "https";
static nghq_header scheme_header = {
    (uint8_t*)scheme_hdr, sizeof(scheme_hdr)-1,
    (uint8_t*)scheme_value, sizeof(scheme_value)-1
};
static char path_hdr[] = ":path";
static nghq_header path_header = {
    (uint8_t*)path_hdr, sizeof(path_hdr)-1, NULL, 0
};
static char host_hdr[] = ":authority";
static nghq_header host_header = {
    (uint8_t*)host_hdr, sizeof(host_hdr)-1, NULL, 0
};
static char user_agent_hdr[] = "user-agent";
static char user_agent_value[] = "NGHQ-Example/1.0 (Linux) NGHQ/20180321 NGHQ-Server/1.0";
static const nghq_header user_agent_header = {
    (uint8_t*)user_agent_hdr, sizeof(user_agent_hdr)-1,
    (uint8_t*)user_agent_value, sizeof(user_agent_value)-1
};

#if HAVE_OPENSSL
static char signature_hdr[] = "signature";
static nghq_header req_signature_header = {
    (uint8_t*)signature_hdr, sizeof(signature_hdr)-1, NULL, 0
};
#endif

static const nghq_header *g_request_hdrs[] = {
    &method_header, &scheme_header, &host_header, &path_header,
    &user_agent_header
#if HAVE_OPENSSL
    , &req_signature_header
#endif
};

static char status_hdr[] = ":status";
static char status_value[] = "200";
static const nghq_header status_header = {
    (uint8_t*)status_hdr, sizeof(status_hdr)-1,
    (uint8_t*)status_value, sizeof(status_value)-1
};

static char server_hdr[] = "server";
static char server_value[] = "NGHQ-Server/1.0 (GNU/Linux)";
static const nghq_header server_header = {
    (uint8_t*)server_hdr, sizeof(server_hdr)-1,
    (uint8_t*)server_value, sizeof(server_value)-1
};
static char date_hdr[] = "date";
static nghq_header date_header = {
    (uint8_t*)date_hdr, sizeof(date_hdr)-1, NULL, 0
};
static char content_type_hdr[] = "content-type";
static nghq_header content_type_header = {
    (uint8_t*)content_type_hdr, sizeof(content_type_hdr)-1, NULL, 0
};

static char connection_hdr[] = "connection";
static char connection_close_value[] = "close";
static const nghq_header connection_close_header = {
    (uint8_t*)connection_hdr, sizeof(connection_hdr)-1,
    (uint8_t*)connection_close_value, sizeof(connection_close_value)-1
};

#if HAVE_OPENSSL
static char digest_hdr[] = "digest";
static nghq_header digest_header = {
    (uint8_t*)digest_hdr, sizeof(digest_hdr)-1, NULL, 0
};

static nghq_header resp_signature_header = {
    (uint8_t*)signature_hdr, sizeof(signature_hdr)-1, NULL, 0
};
#endif

static const nghq_header *g_response_hdrs[] = {
    &status_header, &server_header, &date_header, &content_type_header
#if HAVE_OPENSSL
    , &digest_header, &resp_signature_header
#endif
    , &connection_close_header
};

static server_session g_server_session;

#if HAVE_OPENSSL
static const char *g_private_key_file = DEFAULT_PRIVATE_KEY_FILE;
static const char *g_key_id = DEFAULT_KEY_ID;

static void *_load_private_key()
{
    void *key = NULL;
    FILE *f;

    f = fopen(g_private_key_file, "rb");
    if (!f) {
        fprintf(stderr, "Failed to read private key file '%s'.\n", g_private_key_file);
        return NULL;
    }
    crypto_privkey_from_pem_file(f, &key);
    fclose(f);
    return key;
}

static char *_make_digest(int fd)
{
    off_t curr_offset;
    char *result = NULL;
    static uint8_t buffer[4096];
    size_t bytes_read;
    void *ctx;

    curr_offset = lseek(fd, 0, SEEK_CUR);

    ctx = digest_ctx_new();
    do {
        bytes_read = read(fd, buffer, sizeof(buffer));
        if (bytes_read > 0) {
            digest_ctx_add_data(ctx, buffer, bytes_read);
        }
    } while (bytes_read > 0);
    lseek(fd, curr_offset, SEEK_SET);

    result = digest_ctx_get_digest_hdr_value(ctx);
    digest_ctx_free(ctx);

    return result;
}

static void _free_digest(char *digest_hdr_value)
{
    digest_ctx_free_digest_hdr_value(NULL, digest_hdr_value);
}

static char *_make_signature(const char **hdrs_list,
                const nghq_header **sig_headers, size_t sig_headers_num,
                const nghq_header **req_headers, size_t req_headers_num)
{
    static void *private_key = NULL;

    if (!private_key) {
        private_key = _load_private_key();
        if (!private_key) return NULL;
    }

    return signature_hdr_value(private_key, g_key_id, hdrs_list, sig_headers,
                               sig_headers_num, req_headers, req_headers_num);
}

static void _free_signature(char *sig_hdr_value)
{
    signature_hdr_value_free(sig_hdr_value);
}
#endif

static const char *mime_type(const char *filename)
{
    static const struct {
        const char *suffix;
        const char *mime;
    } mime_types[] = {
        {".css",  "text/css; charset=UTF-8"},
        {".doc",  "application/msword"},
        {".eps",  "application/postscript"},
        {".gif",  "image/gif"},
        {".htm",  "text/html; charset=UTF-8"},
        {".html", "text/html; charset=UTF-8"},
        {".jpg",  "image/jpeg"},
        {".js",   "application/javascript"},
        {".json", "application/json"},
        {".mpd",  "application/dash+xml"},
        {".mpg",  "video/mpeg"},
        {".pdf",  "application/pdf"},
        {".png",  "image/png"},
        {".ps",   "application/postscript"},
        {".rdf",  "application/rdf+xml"},
        {".rtf",  "application/rtf"},
        {".svg",  "image/svg+xml"},
        {".tif",  "image/tiff"},
        {".txt",  "text/plain; charset=UTF-8"},
    };
    size_t filename_len = strlen(filename);

    for (size_t i=0; i<(sizeof(mime_types)/sizeof(mime_types[0])); i++) {
        if (strcmp(filename+filename_len-strlen(mime_types[i].suffix), mime_types[i].suffix) == 0) {
            return mime_types[i].mime;
        }
    }
    return "application/octet-stream";
}

static void _send_file(const char *filename, size_t filename_skip_chars,
                       const char *path_prefix, int final)
{
    static intptr_t promise_request_user_data = 0;
    static char date_str[DATE_MAX_LEN];
    size_t path_len;
    size_t file_size;
    char *path_str;
    int fd;
    int i;
    int result;
    int num_resp_hdrs = sizeof(g_response_hdrs)/sizeof(g_response_hdrs[0]);
    struct timespec now;

    /* open file to send */
    fd = open(filename, O_RDONLY);
    if (fd < 0) {
      printf("Unable to open '%s' for reading, skipping...\n", filename);
      return;
    }
    file_size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);

    /* Set Date header */
    clock_gettime(CLOCK_REALTIME_COARSE, &now);
    strftime(date_str, sizeof(date_str)-1, "%a, %e %b %Y %H:%M:%S GMT", gmtime(&now.tv_sec));
    date_header.value = (uint8_t*)date_str;
    date_header.value_len = strlen(date_str);

    /* Set :path header */
    path_len = strlen(filename) - filename_skip_chars + strlen(path_prefix) + 1;
    path_str = malloc(path_len + 1);
    sprintf(path_str,"%s/%s", path_prefix, filename+filename_skip_chars);
    path_header.value = (uint8_t*)path_str;
    path_header.value_len = path_len;

    /* Set Content-Type header */
    content_type_header.value = (uint8_t*)mime_type(filename);
    content_type_header.value_len = strlen((char*)content_type_header.value);

#if HAVE_OPENSSL
    /* Set Digest header */
    digest_header.value = (uint8_t*)_make_digest(fd);
    if (!digest_header.value) {
        fprintf(stderr, "Unable to create Digest header for '%s', skipping...\n", filename);
        free(path_str);
        return;
    }
    digest_header.value_len = strlen((char*)digest_header.value);

    /* Set promise request Signature header */
    static const char *req_sig_hdrs[] = { "(request-target)", ":scheme",
                                          ":authority", NULL };
    req_signature_header.value = (uint8_t*)_make_signature(req_sig_hdrs,
        g_request_hdrs, sizeof(g_request_hdrs)/sizeof(g_request_hdrs[0]),
        g_request_hdrs, sizeof(g_request_hdrs)/sizeof(g_request_hdrs[0]));
    if (!req_signature_header.value) {
        fprintf(stderr, "Unable to create Signature headers for '%s', skipping...\n", filename);
        _free_digest((char*)digest_header.value);
        free(path_str);
        return;
    }
    req_signature_header.value_len = strlen((char*)req_signature_header.value);

    /* Set response Signature header */
    static const char *resp_sig_hdrs[] = { "(request-target)", "date",
                                           "content-type", "digest", NULL };
    resp_signature_header.value = (uint8_t*)_make_signature(resp_sig_hdrs,
        g_response_hdrs, sizeof(g_response_hdrs)/sizeof(g_response_hdrs[0]),
        g_request_hdrs, sizeof(g_request_hdrs)/sizeof(g_request_hdrs[0]));
    if (!resp_signature_header.value) {
        fprintf(stderr, "Unable to create Signature headers for '%s', skipping...\n", filename);
        _free_digest((char*)digest_header.value);
        _free_signature((char*)req_signature_header.value);
        free(path_str);
        return;
    }
    resp_signature_header.value_len = strlen((char*)resp_signature_header.value);
#endif //HAVE_OPENSSL

    promise_request_user_data++;

    /* Make the push promise */
    printf("Submitting Push Promise with headers:\n");
    for (i = 0; i < sizeof(g_request_hdrs)/sizeof(g_request_hdrs[0]); i++) {
      printf("\t%s: %s\n", g_request_hdrs[i]->name, g_request_hdrs[i]->value);
    }
    result = nghq_submit_push_promise (g_server_session.session, NULL,
                     g_request_hdrs,
                     sizeof(g_request_hdrs)/sizeof(g_request_hdrs[0]),
                     (void*)promise_request_user_data);
    if (result != NGHQ_OK) {
      fprintf (stderr, "Failed to submit new push promise for %s: %s\n",
               path_str, nghq_strerror(result));
      return;
    }

    ev_idle_start(EV_DEFAULT_UC_ &g_server_session.send_idle);
    ev_run(EV_DEFAULT_UC_ 0);

    if (!final) {
      --num_resp_hdrs;
    }
    printf("Starting server push with %d headers:\n", num_resp_hdrs);
    for (i = 0; i < num_resp_hdrs; i++) {
      printf("\t%s: %s\n", g_response_hdrs[i]->name, g_response_hdrs[i]->value);
    }
    result = nghq_feed_headers (g_server_session.session, g_response_hdrs,
                     num_resp_hdrs, 0, (void*)promise_request_user_data);
    if (result != NGHQ_OK) {
      fprintf (stderr, "Failed to feed headers for server push %s: %s\n",
               path_str, nghq_strerror(result));
      return;
    }

    free(path_str);
#if HAVE_OPENSSL
    _free_digest((char*)digest_header.value);
    digest_header.value = NULL;
    digest_header.value_len = 0;
    _free_signature((char*)req_signature_header.value);
    req_signature_header.value = NULL;
    req_signature_header.value_len = 0;
    _free_signature((char*)resp_signature_header.value);
    resp_signature_header.value = NULL;
    resp_signature_header.value_len = 0;
#endif

    if (g_server_session.single_data_frame) {
        result = nghq_promise_data (g_server_session.session, file_size, 1,
                                    (void *) promise_request_user_data);
        if (result != NGHQ_OK) {
          fprintf(stderr, "Failed to promise a DATA frame of %lu bytes: %s\n",
                  file_size, nghq_strerror(result));
        }
    }

    printf("Payload for server push:\n");
    size_t sent_bytes = 0;
    while (fd >= 0) {
        static unsigned char read_buffer[MAX_PAYLOAD_LEN];
        ssize_t res;
        res = read(fd, read_buffer, sizeof(read_buffer));
        if (res <= 0) {
            close(fd);
            fd = -1;
        } else {
            sent_bytes += res;

            int off = 0;
            while (res > 0) {
                do {
                    result = nghq_feed_payload_data (g_server_session.session,
                                              read_buffer + off, res,
                                              sent_bytes == file_size,
                                              (void*)promise_request_user_data);
                    ev_idle_start(EV_DEFAULT_UC_ &g_server_session.send_idle);
                    ev_run(EV_DEFAULT_UC_ EVRUN_ONCE);
                    printf("_send_file: result = %i\n", result);
                } while (result == NGHQ_REQUEST_BLOCKED);
                if (result == NGHQ_REQUEST_CLOSED) {
                    res = 0;
                } else {
                    res -= result;
                    off += result;
                }
            }
        }
    }
    /* flush data out */
    ev_idle_start(EV_DEFAULT_UC_ &g_server_session.send_idle);
    ev_run(EV_DEFAULT_UC_ 0);
}

typedef struct path_list {
    struct path_list *next;
    char *path;
} path_list;

static void _insert_path_list(path_list **list_root, const char *path)
{
    path_list *new_item = (path_list*) malloc (sizeof(path_list));
    new_item->path = strdup(path);
    if (*list_root == NULL) {
        new_item->next = NULL;
        *list_root = new_item;
    } else if (strcmp((*list_root)->path, path) > 0) {
        new_item->next = *list_root;
        *list_root = new_item;
    } else {
        path_list *p = *list_root;
        while (p->next && strcmp(p->next->path, path) < 0) p = p->next;
        new_item->next = p->next;
        p->next = new_item;
    }
}

static void _free_path_list(path_list **list_root)
{
    if (*list_root == NULL) return;
    for (path_list *p = *list_root; p;) {
        path_list *to_del = p;
        p = p->next;
        free(to_del->path);
        free(to_del);
    }
    *list_root = NULL;
}

static void _send_file_or_dir(const char *file_or_dir,
                              size_t filename_skip_chars,
                              const char *path_prefix,
                              int recursive, int final)
{
    struct stat stats;
    if (lstat(file_or_dir, &stats) != 0) return;

    if (S_ISDIR(stats.st_mode)) {
        DIR *dir = opendir(file_or_dir);
        path_list *list = NULL;
        for (struct dirent *ent = readdir(dir); ent != NULL;
             ent = readdir(dir)) {
            if (ent->d_name[0] == '.' &&
                (ent->d_name[1] == '\0' ||
                 (ent->d_name[1] == '.' && ent->d_name[2] == '\0'))) continue;
            _insert_path_list(&list, ent->d_name);
        }
        for (path_list *path_it = list; path_it; path_it = path_it->next) {
            char *file_path;
            file_path = malloc(strlen(file_or_dir) + strlen(path_it->path) + 2);
            sprintf(file_path, "%s/%s", file_or_dir, path_it->path);
            if (lstat(file_path, &stats) != 0) {
                free(file_path);
                continue;
            }
            if ((S_ISDIR(stats.st_mode) && recursive) ||
                !S_ISDIR(stats.st_mode))
                _send_file_or_dir(file_path, filename_skip_chars, path_prefix,
                                  recursive, !(path_it->next));
            free(file_path);
        }
        _free_path_list(&list);
        closedir(dir);
    } else if (S_ISREG(stats.st_mode)) {
        _send_file(file_or_dir, filename_skip_chars, path_prefix, final);
    }
}

static void copy_string(char *dest, const char *src, size_t len)
{
  if (len > 0) memcpy(dest, src, len);
  dest[len] = '\0';
}

static void do_file_send(const char *authority, const char *path_prefix,
                         const char *send_dir, int recursive)
{
    size_t dir_prefix_len = strlen(send_dir);
    static const char curr_dir[] = ".";
    static char tmp_dir[PATH_MAX_LEN];

    if (dir_prefix_len>=PATH_MAX_LEN) {
        fprintf(stderr, "error: Sending directory path too long!\n");
        return;
    }

    /* calculate how many characters to skip in the filename to get the
     * file path relative to the top dir and remove trailing '/'. */
    if (dir_prefix_len == 0) {
        /* case where top directory is the empty string, use current dir */
        send_dir = curr_dir;
        dir_prefix_len = 2;
    } else if (send_dir[dir_prefix_len - 1] == '/') {
        copy_string(tmp_dir, send_dir, dir_prefix_len - 1);
        send_dir = tmp_dir;
    } else {
        dir_prefix_len++;
    }

    /* set authority for all transfers */
    host_header.value = (uint8_t*)authority;
    host_header.value_len = strlen(authority);

    _send_file_or_dir(send_dir, dir_prefix_len, path_prefix, recursive, 1);
}

static ssize_t recv_cb (nghq_session *session, uint8_t *data, size_t len,
                        void *session_user_data)
{
    /* server_session *sdata = (server_session*)session_user_data; */
    return NGHQ_OK; // no more data - just do faked acks
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
    server_session *sdata = (server_session*)session_user_data;
    socklen_t sa_len = (sdata->mcast_addr.ss_family == AF_INET)?sizeof(struct sockaddr_in):sizeof(struct sockaddr_in6);
    ssize_t result = sendto(sdata->socket, data, len, 0,
                            (struct sockaddr*)(&sdata->mcast_addr), sa_len);

    ev_idle_start(EV_DEFAULT_UC_ &sdata->recv_idle); // need to fake ack

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

static int on_begin_headers_cb (nghq_session *session,
                                void *session_user_data,
                                void *request_user_data)
{
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
    return NGHQ_OK;
}

static int on_data_recv_cb (nghq_session *session, uint8_t flags,
                            const uint8_t *data, size_t len, size_t off,
                            void *request_user_data)
{
    printf("Received %zu bytes\n", len);
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
  ev_timer_init (&timer->timer, timer_event, seconds, 0);
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
  ev_timer_set (&timer->timer, seconds, 0);
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
    NULL,
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
    0x3FFFFFFFFFFFFFFFULL,       /* max_open_server_pushes */
    60,                          /* idle_timeout (seconds) */
    MAX_PACKET_LEN,              /* max_packet_size */
    0,  /* use default */        /* ack_delay_exponent */
    NULL, 0,                     /* session_id and session_id_len */
    UINT32_C(2)*1024*1024*1024,  /* max_stream_data */
    4611686018427387903ULL,      /* max_data - 2^62 max value */
    NULL,                        /* destination_address */
    0,                           /* destination_address_len */
    NULL,                        /* source_address */
    0,                           /* source_address_len */
    NGHQ_PKTNUM_LEN_AUTO,        /* packet_number_length */
    0,                           /* encryption_overhead */
    5                            /* stream_timeout */
};

static void recv_idle_cb (EV_P_ ev_idle *w, int revents)
{
    int rv;
    server_session *sdata = (server_session*)(w->data);

    ev_idle_stop(EV_A_ w);

    rv = nghq_session_recv (sdata->session);
    printf("recv_idle_cb: nghq_session_recv returned %i\n", rv);

    if (rv == NGHQ_OK) {
        /* not finished yet, continue receiving */
        ev_idle_start(EV_A_ w);
    }
}

static void socket_writable_cb (EV_P_ ev_io *w, int revents)
{
    server_session *sdata = (server_session*)(w->data);
    ev_io_stop (EV_A_ w);
    ev_idle_start (EV_A_ &sdata->send_idle);
}

static void send_idle_cb (EV_P_ ev_idle *w, int revents)
{
    int rv;
    server_session *sdata = (server_session*)(w->data);
    ev_idle_stop (EV_A_ w);

    rv = nghq_session_send (sdata->session);

    fprintf(stderr, "send_idle_cb: nghq_session_send returned %i.\n", rv);

    switch (rv) {
    case NGHQ_OK:
        /* not finished yet, continue sending */
        ev_idle_start (EV_A_ w);
        break;
    case NGHQ_NO_MORE_DATA:
        /* nothing left to send */
        ev_break (EV_A_ EVBREAK_ONE);
        break;
    case NGHQ_SESSION_BLOCKED:
        ev_io_start (EV_A_ &sdata->socket_writable);
        break;
    default:
        ev_break (EV_A_ EVBREAK_ONE);
        fprintf(stderr, "send_idle_cb: nghq_session_send returned %i.\n", rv);
    }
}

static void log_cb (nghq_session *session, nghq_log_level lvl, const char* msg,
                    size_t len) {
    char timestr[30];
    struct timespec tp;

    clock_gettime (CLOCK_REALTIME, &tp);

    strftime(timestr, 30, "%Y-%m-%d %H:%M:%S", localtime (&tp.tv_sec));
    fprintf(stderr, "%s.%ld [%s] %s", timestr, tp.tv_nsec / 1000000,
            nghq_get_loglevel_str(lvl), msg);
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
            setsockopt (sock, SOL_IP, IP_MULTICAST_IF, &(sin->sin_addr),
                        sizeof (sin->sin_addr));
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

static int parse_url(const char *url, const char **authority, const char **path)
{
    static char auth[AUTHORITY_MAX_LEN];
    static const char default_path[] = "/";
    size_t i;

    if (strncmp(url, "https://", 8) != 0) return 0;

    for (i=0; i<sizeof(auth) && url[8+i] && url[8+i] != '/'; i++) {
        auth[i] = url[8+i];
    }

    if (i == sizeof(auth)) return 0;

    auth[i] = '\0';

    *authority = auth;

    if (!url[8+i]) {
        *path = default_path;
    } else {
        *path = url+8+i;
    }

    return 1;
}

int main(int argc, char *argv[])
{
    static const int on = 1;

    static const char short_opts[] = "hi:p:t:u:sD:";
    static const struct option long_opts[] = {
        {"help", 0, NULL, 'h'},
        {"session-id", 1, NULL, 'i'},
        {"port", 1, NULL, 'p'},
        {"ttl", 1, NULL, 't'},
        {"url-prefix", 1, NULL, 'u'},
        {"single-data", 0, NULL, 's'},
        {"debug", 1, NULL, 'd'},
        {NULL, 0, NULL, 0}
    };

    int help = 0;
    int usage = 0;
    int err_out = 0;
    int ttl = DEFAULT_MCAST_TTL;
    g_trans_settings.session_id = DEFAULT_SESSION_ID;
    g_trans_settings.session_id_len = DEFAULT_SESSION_ID_LENGTH;
    unsigned short send_port = DEFAULT_MCAST_PORT;
    const char *mcast_grp = DEFAULT_MCAST_GRP_V4;
    const char *ifc_ip = DEFAULT_IFC_ADDR_V4;
    const char *authority = DEFAULT_AUTHORITY;
    const char *path_prefix = DEFAULT_PATH_PREFIX;
    const char *send_dir = NULL;
    unsigned int ifc_idx = 0;
    const char *default_mcast_grp = NULL;
    const char *default_ifc_ip = NULL;
    const char *debug_level = DEFAULT_DEBUG_LEVEL;
    int opt;
    int option_index = 0;

    mcast_ifc_list *ifcs = NULL;

    bzero ((void *) &g_server_session, sizeof(server_session));

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
            g_trans_settings.session_id_len = nghq_convert_session_id_string (
                optarg, 0, &g_trans_settings.session_id);
            break;
        case 'p':
            send_port = atoi (optarg);
            break;
        case 't':
            ttl = atoi (optarg);
            if (ttl<1) ttl = 1;
            if (ttl>255) ttl = 255;
            break;
        case 'u':
            if (!parse_url(optarg, &authority, &path_prefix)) {
                fprintf(stderr, "Unable to recognise '%s' as a URL", optarg);
                usage = 1;
                err_out = 1;
            }
            break;
        case 's':
            g_server_session.single_data_frame = 1;
            break;
        case 'D':
            debug_level = optarg;
            break;
        default:
            usage = 1;
            err_out = 1;
            break;
        }
    }

    /* must have 1 to 3 arguments */
    if (optind+1 > argc || optind+3 < argc) {
        usage = 1;
        err_out = 1;
    }

    if (usage) {
      fprintf(err_out?stderr:stdout,
"Usage: %s [-h] [-s] [-d] [-p <port>] [-i <id>] [-t <ttl>] [-u <url-prefix>] [<mcast-grp> [<ifc-addr>]] <send-directory>\n",
              argv[0]);
    }
    if (help) {
      printf("\n"
"Options:\n"
"  --help          -h          Display this help text.\n"
"  --port          -p <port>   UDP port number to send to [default: " STR(DEFAULT_MCAST_PORT) "].\n"
"  --session-id    -i <id>     The session ID to send [default: " STR(DEFAULT_SESSION_ID) "].\n"
"  --ttl           -t <ttl>    The TTL to use for multicast [default: " STR(DEFAULT_MCAST_TTL) "].\n"
"  --url-prefix    -u <url>    The URL prefix to transmit with the files [default: " DEFAULT_URL_PREFIX "].\n"
"  --single-data   -s          Package all files in a single HTTP/3 DATA frame.\n"
"  --debug         -D <level>  Specify the debug level, one of ALERT, ERROR, WARN, INFO, DEBUG or TRACE [default: " DEFAULT_DEBUG_LEVEL "].\n"
"\n"
"Arguments:\n"
"  <mcast-grp>      The multicast group to send on [default: %s].\n"
"  <ifc-addr>       The source interface address [default: %s].\n"
"  <send-directory> The directory containing the files to send.\n"
"\n", default_mcast_grp, default_ifc_ip);
    }
    if (usage) {
      free_multicast_interfaces(ifcs);
      return err_out;
    }

    if (optind+1 < argc) {
        mcast_grp = argv[optind];
    }

    if (optind+2 < argc) {
        ifc_ip = argv[optind+1];
    }

    send_dir = argv[argc-1];

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

    free_multicast_interfaces(ifcs);

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

    ev_idle_init (&g_server_session.recv_idle, recv_idle_cb);
    g_server_session.recv_idle.data = &g_server_session;

    g_server_session.session = nghq_session_server_new (&g_callbacks,
                                        &g_settings, &g_trans_settings,
                                        &g_server_session);

    if (g_server_session.session == NULL) {
        fprintf(stderr, "Failed to get nghq instance!\n");
        return -1;
    }

    nghq_set_loglevel (g_server_session.session,
                       nghq_get_loglevel_from_str (debug_level,
                                                   strnlen(debug_level, 6)),
                       log_cb);

    ev_io_start (EV_DEFAULT_UC_ &g_server_session.socket_writable);

    do_file_send (authority, path_prefix, send_dir, 1 /* recursive */);

    ev_run (EV_DEFAULT_UC_ 0);

    ev_io_stop (EV_DEFAULT_UC_ &g_server_session.socket_writable);
    ev_idle_stop (EV_DEFAULT_UC_ &g_server_session.send_idle);

    nghq_session_free (g_server_session.session);
    close (g_server_session.socket);

    return 0;
}
