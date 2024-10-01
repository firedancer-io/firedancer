#ifndef HEADER_fd_src_ballet_http_fd_http_server_private_h
#define HEADER_fd_src_ballet_http_fd_http_server_private_h

#include "fd_http_server.h"

#define FD_HTTP_SERVER_MAGIC (0xF17EDA2CE50A11D0) /* FIREDANCER HTTP V0 */

#define FD_HTTP_SERVER_CONNECTION_STATE_READING        0
#define FD_HTTP_SERVER_CONNECTION_STATE_WRITING_HEADER 1
#define FD_HTTP_SERVER_CONNECTION_STATE_WRITING_BODY   2

#define FD_HTTP_SERVER_PONG_STATE_NONE    0
#define FD_HTTP_SERVER_PONG_STATE_WAITING 1
#define FD_HTTP_SERVER_PONG_STATE_WRITING 2

#define FD_HTTP_SERVER_SEND_FRAME_STATE_HEADER 0
#define FD_HTTP_SERVER_SEND_FRAME_STATE_DATA   1

struct fd_http_server_connection {
  int          state;

  int          upgrade_websocket;
  ulong        request_bytes_len;
  char const * sec_websocket_key;

  char * request_bytes;
  ulong  request_bytes_read;

  fd_http_server_response_t response;
  ulong response_bytes_written;

  /* The treap fields */
  ushort left;
  ushort right;
  ushort parent;
  ushort prio;
  ushort prev;
  ushort next;

  /* The memory for the request is placed at the end of the struct here...
  char request[ ]; */
};

struct fd_http_server_ws_frame {
  ulong off;
  ulong len;
};

typedef struct fd_http_server_ws_frame fd_http_server_ws_frame_t;

struct fd_http_server_ws_connection {
  int   pong_state;
  ulong pong_data_len;
  uchar pong_data[ 125 ];
  ulong pong_bytes_written;

  int     recv_started_msg;
  ulong   recv_bytes_parsed;
  ulong   recv_bytes_read;
  uchar * recv_bytes;

  int                         send_frame_state;
  ulong                       send_frame_bytes_written;
  ulong                       send_frame_cnt;
  ulong                       send_frame_idx;
  fd_http_server_ws_frame_t * send_frames;

  /* The treap fields */
  ushort left;
  ushort right;
  ushort parent;
  ushort prio;
  ushort prev;
  ushort next;
};

struct fd_http_server_hcache_private {
  int   err; /* If there has been an error while printing */
  ulong off; /* Offset into the staging buffer */
  ulong len; /* Length of the staging buffer */
};

struct __attribute__((aligned(FD_HTTP_SERVER_ALIGN))) fd_http_server_private {

  int   socket_fd;

  uchar * oring;
  ulong   oring_sz;

  int   stage_err;
  ulong stage_off;
  ulong stage_len;

  ulong max_conns;
  ulong max_ws_conns;
  ulong max_request_len;
  ulong max_ws_recv_frame_len;
  ulong max_ws_send_frame_cnt;

  ulong evict_conn_id;
  ulong evict_ws_conn_id;

  void * callback_ctx;
  fd_http_server_callbacks_t callbacks;

  ulong magic;      /* ==FD_HTTP_SERVER_MAGIC */


  struct fd_http_server_connection *    conns;
  struct fd_http_server_ws_connection * ws_conns;
  struct pollfd *                       pollfds;

  void * conn_treap;
  void * ws_conn_treap;

  /* The memory for conns and pollfds is placed at the end of the struct
     here...

  struct fd_http_server_connection    conns[ ];
  struct fd_http_server_ws_connection ws_conns[ ];
  struct pollfd                       pollfds[ ]; */
};

#endif /* HEADER_fd_src_ballet_http_fd_http_server_private_h */
