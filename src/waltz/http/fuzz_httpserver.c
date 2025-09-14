#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <poll.h>
#include <errno.h>

#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"
#include "fd_http_server_private.h"
#include "fd_http_server.h"

#define FD_HTTP_SERVER_GUI_MAX_CONNS             4
#define FD_HTTP_SERVER_GUI_MAX_REQUEST_LEN       2048
#define FD_HTTP_SERVER_GUI_MAX_WS_CONNS          4
#define FD_HTTP_SERVER_GUI_MAX_WS_RECV_FRAME_LEN 2048
#define FD_HTTP_SERVER_GUI_MAX_WS_SEND_FRAME_CNT 8192
#define FD_HTTP_SERVER_GUI_OUTGOING_BUFFER_SZ    (1UL<<28UL) /* 256MiB reserved for buffering GUI websockets */

const fd_http_server_params_t PARAMS = {
  .max_connection_cnt    = FD_HTTP_SERVER_GUI_MAX_CONNS,
  .max_ws_connection_cnt = FD_HTTP_SERVER_GUI_MAX_WS_CONNS,
  .max_request_len       = FD_HTTP_SERVER_GUI_MAX_REQUEST_LEN,
  .max_ws_recv_frame_len = FD_HTTP_SERVER_GUI_MAX_WS_RECV_FRAME_LEN,
  .max_ws_send_frame_cnt = FD_HTTP_SERVER_GUI_MAX_WS_SEND_FRAME_CNT,
  .outgoing_buffer_sz    = FD_HTTP_SERVER_GUI_OUTGOING_BUFFER_SZ,
};

struct Unstructured {
    uchar const *data;
    ulong size;
    ulong used;
};

uchar rand_uchar(struct Unstructured *u) {
    if (sizeof(uchar) + u->used < u->size) {
        uchar v = *(uchar *)(u->data + u->used);
        u->used += sizeof(uchar);
        return v;
    }
    return (uchar) rand();
}

uint rand_uint(struct Unstructured *u) {
    if (sizeof(uint) + u->used < u->size) {
        uint v = *(uint *)(u->data + u->used);
        u->used += sizeof(uint);
        return v;
    }
    return (uint) rand();
}

ulong rand_ulong(struct Unstructured *u) {
    if (sizeof(ulong) + u->used < u->size) {
        ulong v = *(ulong *)(u->data + u->used);
        u->used += sizeof(ulong);
        return v;
    }
    return ((ulong)rand()) << 32 | ((ulong)rand());
}

void rand_bytes(struct Unstructured *u, size_t len, uchar *p) {
    if (len + u->used < u->size) {
        memcpy(p, u->data + u->used, len);
        u->used += len;
    } else {
        for (ulong i = 0; i < len; ++i) {
            p[i] = (uchar) rand();
        }
    }
}

void build_http_req(struct Unstructured *u, uchar *buf, int *len, int *use_websocket);
void build_ws_req(struct Unstructured *u, uchar *buf, int *len);

static fd_http_server_t *http_server = NULL;
uint16_t port = 0;
static int clients_fd[FD_HTTP_SERVER_GUI_MAX_CONNS * 2] = {-1};
static char clients_ws_fd[FD_HTTP_SERVER_GUI_MAX_CONNS * 2] = {0};
static uint clients_fd_cnt = 0;

void reset_clients_fd(void) {
  clients_fd_cnt = 0;
  for (ulong i = 0; i < FD_HTTP_SERVER_GUI_MAX_CONNS * 2; ++i) {
    clients_fd[i] = -1;
    clients_ws_fd[i] = 0;
  }
}

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  atexit( fd_halt );
  fd_log_level_core_set(3); /* crash on warning log */

  /* Disable parsing error logging */
  fd_log_level_stderr_set(4);

  reset_clients_fd();

  return 0;
}

typedef struct {
    uint32_t state;
} Xorshift;

void xorshift_init(Xorshift* x, uint32_t seed) {
    x->state = seed ? seed : 1;
}

uint32_t xorshift_next(Xorshift* x) {
    uint32_t s = x->state;
    s ^= s << 13;
    s ^= s >> 17;
    s ^= s << 5;
    x->state = s;
    return s;
}

static Xorshift poll_rng;

void
fd_http_server_close( fd_http_server_t * http,
                      ulong              conn_id,
                      int                reason );

void
fd_http_server_ws_close( fd_http_server_t * http,
                         ulong              ws_conn_id,
                         int                reason );
int
fd_http_server_ws_send( fd_http_server_t * http,
                        ulong              ws_conn_id );

int
fd_http_server_ws_broadcast( fd_http_server_t * http );

void
fd_http_server_printf( fd_http_server_t * http,
                       char const *       fmt,
                       ... );

void
fd_http_server_memcpy( fd_http_server_t * http,
                       uchar const *      data,
                       ulong              data_len );

void
fd_http_server_stage_trunc( fd_http_server_t * http,
                             ulong len );

void
fd_http_server_unstage( fd_http_server_t * http );

int
fd_http_server_stage_body( fd_http_server_t *          http,
                           fd_http_server_response_t * response );

void random_api_call(Xorshift *u) {
    switch(xorshift_next(u) % 4) {
        case 0:
        {
            ulong pos = xorshift_next(u) % (FD_HTTP_SERVER_GUI_MAX_WS_CONNS);
            if (http_server->pollfds[ pos + http_server->max_conns ].fd != -1)
                fd_http_server_ws_send(http_server, pos);
        }
        break;
        case 1:
        {
            fd_http_server_ws_broadcast(http_server);
        }
        break;
        case 2:
        {
            char data[128];
            uint len = xorshift_next(u) % 128;
            memset(data, 0xcc, len);
            fd_http_server_memcpy(http_server, (uchar *)data, len);
        }
        break;
        case 3:
        {
            char data[128];
            uint len = xorshift_next(u) % 128;
            memset(data, 0xcc, len);
            fd_http_server_printf(http_server, "%s", data);
        }
        break;
    }
}

void open_callback( ulong conn_id, int sockfd, void * ctx ) {
    (void)conn_id;
    (void)sockfd;
    (void)ctx;

    for (uint i = 0; i < xorshift_next(&poll_rng) % 3; ++i) {
        random_api_call(&poll_rng);
    }
}

void close_callback( ulong conn_id, int reason, void * ctx ) {
    (void)conn_id;
    (void)reason;
    (void)ctx;

    for (uint i = 0; i < xorshift_next(&poll_rng) % 3; ++i) {
        random_api_call(&poll_rng);
    }
}

fd_http_server_response_t request_callback( fd_http_server_request_t const * request ) {
    fd_http_server_response_t resp;
    memset(&resp, 0, sizeof(fd_http_server_response_t));

    switch(xorshift_next(&poll_rng) % 7) {
        case 0:
        {
            resp.status = 200;
            resp.upgrade_websocket = xorshift_next(&poll_rng) % 2;
            resp.compress_websocket = xorshift_next(&poll_rng) % 2;
        }
        break;
        case 1:
        {
            resp.status = 204;
        }
        break;
        case 2:
        {
            resp.status = 400;
        }
        break;
        case 3:
        {
            resp.status = 404;
        }
        break;
        case 4:
        {
            resp.status = 405;
        }
        break;
        case 5:
        {
            resp.status = 500;
        }
        break;
        default:
        {
            resp.status = xorshift_next(&poll_rng);
        }
        break;
    }

    if (xorshift_next(&poll_rng) % 2 == 0) {
        resp.content_type = "Any content_type";
    }

    if (xorshift_next(&poll_rng) % 2 == 0) {
        resp.cache_control = "Any cache_control";
    }

    if (xorshift_next(&poll_rng) % 2 == 0) {
        resp.content_encoding = "Any content_encoding";
    }

    if (xorshift_next(&poll_rng) % 2 == 0) {
        resp.access_control_allow_origin = "Any access_control_allow_origin";
    }

    if (xorshift_next(&poll_rng) % 2 == 0) {
        resp.access_control_allow_methods = "Any access_control_allow_methods";
    }

    if (xorshift_next(&poll_rng) % 2 == 0) {
        resp.access_control_allow_headers = "Any access_control_allow_headers";
    }

    if (xorshift_next(&poll_rng) % 2 == 0) {
        resp.access_control_max_age = ((ulong)(&poll_rng) << 32) | (ulong)xorshift_next(&poll_rng);
    }

    if (xorshift_next(&poll_rng) % 2 == 0) {
        resp.static_body = (const uchar *) "resp_body";
        resp.static_body_len = 9;
    }

    if (request->headers.upgrade_websocket && (xorshift_next(&poll_rng) % 100) > 0) {
        resp.status = 200;
        resp.upgrade_websocket = 1;
    }

    for (uint i = 0; i < xorshift_next(&poll_rng) % 3; ++i) {
        random_api_call(&poll_rng);
    }

    return resp;
}

void ws_open_callback( ulong ws_conn_id, void * ctx ) {
    (void) ws_conn_id;
    (void) ctx;

    for (uint i = 0; i < xorshift_next(&poll_rng) % 3; ++i) {
        random_api_call(&poll_rng);
    }
}

void ws_close_callback( ulong ws_conn_id, int reason, void * ctx ) {
    (void) ws_conn_id;
    (void) reason;
    (void) ctx;

    for (uint i = 0; i < xorshift_next(&poll_rng) % 3; ++i) {
        random_api_call(&poll_rng);
    }
}

void ws_message_callback( ulong ws_conn_id, uchar const * data, ulong data_len, void * ctx ) {
    (void) ws_conn_id;
    (void) data;
    (void) data_len;
    (void) ctx;

    for (uint i = 0; i < xorshift_next(&poll_rng) % 3; ++i) {
        random_api_call(&poll_rng);
    }
}

void close_reset_clients_fd(fd_http_server_t * http) {
  for (ulong i = 0; i < clients_fd_cnt; ++i) {
    if (clients_fd[i] != -1) {
        close(clients_fd[i]);
        clients_fd[i] = -1;
        clients_ws_fd[i] = 0;
    }
  }
  clients_fd_cnt = 0;

  for (ulong conn_idx = 0; conn_idx < (PARAMS.max_connection_cnt + PARAMS.max_ws_connection_cnt); ++conn_idx) {
    if (http->pollfds[ conn_idx ].fd != -1) {
        close(http->pollfds[ conn_idx ].fd);
    }
  }
}

int *reserve_client_fd(void) {
    if (clients_fd_cnt >= (FD_HTTP_SERVER_GUI_MAX_CONNS * 2)) {
        return NULL;
    }
    return &clients_fd[clients_fd_cnt++];
}

int build_http_header(struct Unstructured *u, char *buf, int max_len, int *use_web_socket) {
    if (max_len <= 0) return 0;

    int used = 0;

    switch (rand_uchar(u) % 5) {
        // Content-type
        case 0:
        {
            const char *CONTENT_TYPES[] = {"text/plain", "text/html", "application/json", "application/xml", "application/x-www-form-urlencoded", "multipart/form-data", "application/octet-stream", "image/png", "image/jpeg", "audio/mpeg", "video/mp4", "application/pdf"};
            const char *CHARSET = "; charset=UTF-8";
            const char *content_type = CONTENT_TYPES[rand_uchar(u) % 12];
            if (rand_uchar(u) % 2 == 0) {
                used = snprintf(buf, (size_t) max_len, "Content-Type: %s\r\n", content_type);
            } else {
                used = snprintf(buf, (size_t)max_len, "Content-Type: %s%s\r\n", content_type, CHARSET);
            }
        }
        break;
        // Accept-encoding
        case 1:
        {
            const char *ACCEPT_ENCODINGS[] = {"gzip", "compress", "deflate", "br", "identity", "*"};
            char accept_encoding[64];
            memset(accept_encoding, 0, 64);
            char *cur_encoding_pos = &accept_encoding[0];
            int rem = 64;

            for (int i = 0; i < (1 + (rand_uchar(u) % 6)); ++i) {
                int size = snprintf(cur_encoding_pos, (size_t) rem, "%s, ", ACCEPT_ENCODINGS[rand_uchar(u) % 6]);
                cur_encoding_pos += size;
                rem -= size;
            }

            accept_encoding[strlen(accept_encoding)-2] = 0; // remove ", "

            used = snprintf(buf, (size_t)max_len, "Accept-Encoding: %s\r\n", accept_encoding);
        }
        break;
        // websocket
        case 2:
        {
            used = snprintf(buf, (size_t)max_len, "Upgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n");
            *use_web_socket = 1;
        }
        break;
    }

    if (used >= max_len) {
        buf[0] = 0;
        used = 0;
    }

    return used;
}

void build_http_req(struct Unstructured *u, uchar *buf, int *len, int *use_websocket) {
    int max_size = *len;
    int size = 0;
    memset((char *)buf, 0, (size_t)*len);

    const char *METHODS[] = {"GET", "POST", "OPTIONS"};
    const char *method = METHODS[rand_uchar(u) % 3];
    int is_post = strlen(method) == 4 && strcmp(method, "POST") == 0 ? 1 : 0;
    const char *uri = "/home";

    const char *version = "HTTP/1.1";

    char headers[256];
    memset(headers, 0, 256);
    uint n_headers = 0;
    char *cur_header_pos = &headers[0];
    int rem = 256;
    if (is_post) {
        int used = snprintf(cur_header_pos, (size_t) rem, "Content-Length: 4\r\n");
        if (used >= rem) return;
        cur_header_pos += used;
        rem -= used;
        n_headers++;
    }

    while (n_headers < (rand_uint(u) % 32)) {
        int used = build_http_header(u, cur_header_pos, rem, use_websocket);
        cur_header_pos += used;
        rem -= used;
        n_headers++;
    }

    size = (uchar) snprintf((char *)buf, (size_t) max_size, "%s %s %s\r\n%s\r\n", method, uri, version, headers);
    if (size >= max_size) return;

    if (is_post) {
        int _size = snprintf((char *)buf + size, (size_t) (max_size-size), "body");
        if (_size <= max_size-size) return;
        size += _size;
    }

    *len = size;
}

void build_ws_req(struct Unstructured *u, uchar *buf, int *len) {
    uchar *cur_pos = buf;

    const uchar OPCODES[] = {0x0, 0x1, 0x2, 0x8, 0x9, 0xA};
    uchar opcode = OPCODES[rand_uchar(u) % 6] & 0x0F;
    *cur_pos = opcode;
    if (rand_uchar(u) % 2 == 0) {
        *cur_pos |= (1 << 7);
    }

    ++cur_pos;

    uint payload_len = (uchar) rand_uint(u);
    if (opcode == 0x8 || opcode == 0x9 || opcode == 0xA || *len < 140) {
        payload_len %= 126;
    } else {
        payload_len %= 256;
    }

    if (payload_len < 126) {
        *cur_pos = (uchar) payload_len;
    } else if (rand_uchar(u) % 2 == 0) {
        *cur_pos = 126;
    } else {
        *cur_pos = 127;
    }

    int payload_len_choice = *cur_pos;

    *cur_pos |= (1 << 7);

    ++cur_pos;
    if (payload_len_choice == 126) {
        *(ushort *)cur_pos = (ushort) payload_len;
        cur_pos += sizeof(ushort);
    } else if (payload_len_choice == 127) {
        *(ulong *)cur_pos = (ulong) payload_len;
        cur_pos += sizeof(ulong);
    }

    *(ulong *)cur_pos = 0;
    cur_pos += sizeof(ulong);

    for (uint i = 0; i < payload_len; ++i) {
        cur_pos[i] = rand_uchar(u);
    }

    *len = (int) (cur_pos - buf);
}

static ulong stem_iters = 0;
static int stop = 0;
void* stem_thread(void* arg) {
    (void) arg;
    stem_iters = 0;

    while (1) {
        for (uint i = 0; i < xorshift_next(&poll_rng) % 3; ++i) {
            random_api_call(&poll_rng);
        }

        fd_http_server_poll(http_server, 0);

        for (uint i = 0; i < xorshift_next(&poll_rng) % 3; ++i) {
            random_api_call(&poll_rng);
        }

        ++stem_iters;

        if (stop) break;
        sched_yield();
    }
    return NULL;
}

enum Action {
    HttpOpen = 0,
    Close,
    Send,
    ActionEnd,
};

void do_action(struct Unstructured *u) {
    switch(rand_uchar(u) % ActionEnd) {
        case HttpOpen:
        {
            int *client_fd = reserve_client_fd();
            if (!client_fd) return;

            struct sockaddr_in server_addr;
            *client_fd = socket(AF_INET, SOCK_STREAM, 0);

            memset(&server_addr, 0, sizeof(server_addr));
            server_addr.sin_family = AF_INET;
            server_addr.sin_port = htons(port);

            if (inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr) != 1) {
                close(*client_fd);
                *client_fd = -1;
                clients_fd_cnt--;
                return;
            }

            struct sockaddr sa;
            memcpy(&sa, &server_addr, sizeof(struct sockaddr));

            if (connect(*client_fd, &sa, sizeof(server_addr)) < 0) {
                close(*client_fd);
                *client_fd = -1;
                clients_fd_cnt--;
            }
        }
        break;
        case Close:
        {
            if (clients_fd_cnt > 0) {
                uchar pos = rand_uchar(u) % ((uchar) clients_fd_cnt);
                if (clients_fd[pos] != -1) {
                    close(clients_fd[pos]);
                    clients_fd[pos] = -1;
                    clients_ws_fd[pos] = 0;
                }
            }
        }
        break;
        case Send:
        {
            if (clients_fd_cnt > 0) {
                int len = 1024;
                uchar buf[1024];
                int use_websocket = 0;
                uchar pos = rand_uchar(u) % ((uchar) clients_fd_cnt);

                if (clients_fd[pos] != -1 && clients_ws_fd[pos] == 0) {
                    build_http_req(u, buf, &len, &use_websocket);
                    if (rand_uchar(u) % 5 == 0) {
                        LLVMFuzzerMutate(buf, (ulong)len, (ulong)len);
                    }
                    send(clients_fd[pos], buf, (size_t)len, MSG_NOSIGNAL);
                    if (use_websocket) {
                        clients_ws_fd[pos] = 1;
                    }
                }

                else if (clients_fd[pos] != -1 && clients_ws_fd[pos] == 1) {
                    build_ws_req(u, buf, &len);

                    // add up to 2 messages
                    for (ulong i = 0; i < rand_uchar(u) % 3 && len < 1024; ++i) {
                        int len2 = 1024 - len;
                        build_ws_req(u, buf + len, &len2);
                        len += len2;
                    }

                    if (rand_uchar(u) % 5 == 0) {
                        LLVMFuzzerMutate(buf, (ulong)len, (ulong)len);
                    }

                    send(clients_fd[pos], buf, (size_t)len, MSG_NOSIGNAL);
                }
            }
        }
        break;
    }
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {

  if (size >= sizeof(int)) {
    struct Unstructured u = {
        .data = data,
        .size = size,
        .used = 0
    };
    pthread_t thread;
    uint32_t ip_as_int;
    inet_pton(AF_INET, "0.0.0.0", &ip_as_int);

    srand( rand_uint(&u));

    void * shmem = aligned_alloc( fd_http_server_align(), fd_http_server_footprint( PARAMS ) );
    assert( shmem );

    fd_http_server_callbacks_t gui_callbacks = {
        .open = open_callback,
        .close = close_callback,
        .request = request_callback,
        .ws_open = ws_open_callback,
        .ws_close = ws_close_callback,
        .ws_message = ws_message_callback,
    };

    http_server = fd_http_server_join( fd_http_server_new( shmem, PARAMS, gui_callbacks, NULL ) );
    http_server = fd_http_server_listen( http_server, ip_as_int, 0 );

    union sockaddr_pun {
        struct sockaddr_in addr_in;
        struct sockaddr    sa;
    };

    union sockaddr_pun addr_pun;
    memset(&addr_pun, 0, sizeof(addr_pun));

    socklen_t addr_len = sizeof(addr_pun);

    if (getsockname(http_server->socket_fd, &addr_pun.sa, &addr_len) == -1) {
        printf( "bind failed (%i-%s)", errno, strerror( errno ) );
        abort();
    }

    port = ntohs(addr_pun.addr_in.sin_port);

    xorshift_init(&poll_rng, (uint32_t) rand_uint(&u));

    stop = 0;
    pthread_create(&thread, NULL, stem_thread, NULL);

    uchar n_actions = (uchar) rand_uchar(&u) % 32;
    for (uchar i = 0; i < n_actions; ++i) {
        do_action(&u);

        ulong iters = stem_iters;
        do { sched_yield(); } while (stem_iters < iters + 1);
    }

    stop = 1;
    pthread_join(thread, NULL);

    close_reset_clients_fd(http_server);
    close(fd_http_server_fd(http_server));
    fd_http_server_delete(fd_http_server_leave(http_server));
    free( shmem );
  }

  return 0;
}
