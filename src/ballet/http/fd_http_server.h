#ifndef HEADER_fd_src_ballet_http_fd_http_server_h
#define HEADER_fd_src_ballet_http_fd_http_server_h

#include "../fd_ballet_base.h"

#define FD_HTTP_SERVER_ALIGN     (128UL)

#define FD_HTTP_SERVER_MAGIC (0xF17EDA2CE50A11D0) /* FIREDANCER HTTP V0 */

#define FD_HTTP_SERVER_CONNECTION_CLOSE_OK                         (  0)
#define FD_HTTP_SERVER_CONNECTION_CLOSE_EVICTED                    ( -1)
#define FD_HTTP_SERVER_CONNECTION_CLOSE_EXPECTED_EOF               ( -2)
#define FD_HTTP_SERVER_CONNECTION_CLOSE_PEER_RESET                 ( -3)
#define FD_HTTP_SERVER_CONNECTION_CLOSE_LARGE_REQUEST              ( -4)
#define FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST                ( -5)
#define FD_HTTP_SERVER_CONNECTION_CLOSE_UNKNOWN_METHOD             ( -6)
#define FD_HTTP_SERVER_CONNECTION_CLOSE_PATH_TOO_LONG              ( -7)
#define FD_HTTP_SERVER_CONNECTION_CLOSE_WS_BAD_KEY                 ( -8)
#define FD_HTTP_SERVER_CONNECTION_CLOSE_WS_UNEXPECTED_VERSION      ( -9)
#define FD_HTTP_SERVER_CONNECTION_CLOSE_WS_MISSING_KEY_HEADER      (-10)
#define FD_HTTP_SERVER_CONNECTION_CLOSE_WS_MISSING_VERSION_HEADER  (-11)
#define FD_HTTP_SERVER_CONNECTION_CLOSE_WS_BAD_MASK                (-12)
#define FD_HTTP_SERVER_CONNECTION_CLOSE_WS_UNKNOWN_OPCODE          (-13)
#define FD_HTTP_SERVER_CONNECTION_CLOSE_WS_OVERSIZE_FRAME          (-14)
#define FD_HTTP_SERVER_CONNECTION_CLOSE_WS_CLIENT_TOO_SLOW         (-15)
#define FD_HTTP_SERVER_CONNECTION_CLOSE_WS_MISSING_UPGRADE         (-16)
#define FD_HTTP_SERVER_CONNECTION_CLOSE_WS_EXPECTED_CONT_OPCODE    (-17)
#define FD_HTTP_SERVER_CONNECTION_CLOSE_WS_EXPECTED_TEXT_OPCODE    (-18)
#define FD_HTTP_SERVER_CONNECTION_CLOSE_WS_CONTROL_FRAME_TOO_LARGE (-29)

/* Given a FD_HTTP_SERVER_CONNECTION_CLOSE_* reason code, a reason that
   a HTTP connection a client was closed, produce a human readable
   string describing the reason. */

FD_FN_CONST char const *
fd_http_server_connection_close_reason_str( int reason );

/* A response issued by the server handler function to an HTTP request.
   The handler assures that the lifetime of the response buffer will
   exceed that of the request.  The response buffer is owned by the
   server and should not be modified or freed until the handler gets a
   close event.

   status is an HTTP status code.  The response is the body of the HTTP
   response to send.  If status is not 200, the response body is ignored
   and the server will send an empty response.

   If upgrade_websocket is true, the connection will be upgraded to a
   websocket, after which the handler will begin receiving websocket
   frames. */

struct fd_http_server_response {
  ulong status;              /* Status code of the HTTP response */
  int   upgrade_websocket;   /* 1 if we should send a websocket upgrade response */

  char const * content_type; /* Content type to set in the HTTP response */

  uchar const * body;        /* Response body to send, only sent if status is 200 */
  ulong         body_len;    /* Length of the response body */
};

typedef struct fd_http_server_response fd_http_server_response_t;

struct fd_http_server_callbacks {
  /* Handle an incoming HTTP request.  The connection ID is a unique
     identifier for the lifetime of the connection, and will be provided
     to close to indicate that the connection is closed.
     
     Path is the full HTTP path of the request, for example
     "/img/monkeys/gorilla.jpg", and ctx is the context pointer provided
     to fd_http_server_new. */

  fd_http_server_response_t ( * request    )( ulong connection_id, char const * path, void * ctx );

  /* Close an HTTP request.  This is called back once all the data has
     been sent to the HTTP client, or an error condition occurs. */

  void                      ( * close      )( ulong connection_id, int reason, void * ctx );

  void                      ( * ws_open    )( ulong connection_id, void * ctx );
  void                      ( * ws_close   )( ulong connection_id, int reason, void * ctx );
  void                      ( * ws_message )( ulong connection_id, uchar const * data, ulong data_len, void * ctx );
};

typedef struct fd_http_server_callbacks fd_http_server_callbacks_t;

#define FD_HTTP_SERVER_CONNECTION_STATE_READING        0
#define FD_HTTP_SERVER_CONNECTION_STATE_WRITING_HEADER 1
#define FD_HTTP_SERVER_CONNECTION_STATE_WRITING_BODY   2

struct fd_http_server_connection {
  int    state;

  int          upgrade_websocket;
  ulong        request_bytes_len;
  char const * sec_websocket_key;

  char * request_bytes;
  ulong  request_bytes_read;

  fd_http_server_response_t response;
  ulong  response_bytes_written;

  /* The memory for the request is placed at the end of the struct here...
  char request[ ]; */
};

struct fd_http_server_ws_frame {
  uchar const * data;
  ulong         data_len;
};

typedef struct fd_http_server_ws_frame fd_http_server_ws_frame_t;

#define FD_HTTP_SERVER_PONG_STATE_NONE    0
#define FD_HTTP_SERVER_PONG_STATE_WAITING 1
#define FD_HTTP_SERVER_PONG_STATE_WRITING 2

#define FD_HTTP_SERVER_SEND_FRAME_STATE_HEADER 0
#define FD_HTTP_SERVER_SEND_FRAME_STATE_DATA   1

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
};

struct __attribute__((aligned(FD_HTTP_SERVER_ALIGN))) fd_http_server_private {

  int   socket_fd;

  ulong max_conns;
  ulong max_ws_conns;
  ulong max_request_len;
  ulong max_ws_recv_frame_len;
  ulong max_ws_send_frame_cnt;

  ulong conn_id;
  ulong ws_conn_id;

  void * callback_ctx;
  fd_http_server_callbacks_t callbacks;

  ulong magic;      /* ==FD_HTTP_SERVER_MAGIC */

  struct fd_http_server_connection *    conns;
  struct fd_http_server_ws_connection * ws_conns;
  struct pollfd *                       pollfds;

  /* The memory for conns and pollfds is placed at the end of the struct
     here...

  struct fd_http_server_connection    conns[ ];
  struct fd_http_server_ws_connection ws_conns[ ];
  struct pollfd                       pollfds[ ]; */
};

typedef struct fd_http_server_private fd_http_server_t;

FD_PROTOTYPES_BEGIN

/* fd_http_server_{align,footprint} give the needed alignment and
   footprint of a memory region suitable to hold an http server.

   fd_http_server_new formats memory region with suitable alignment and
   footprint suitable for holding a http server state.  Assumes shmem
   points on the caller to the first byte of the memory region owned by
   the caller to use.  Returns shmem on success and NULL on failure
   (logs details).  The memory region will be owned by the state on
   successful return.  The caller is not joined on return.

   fd_http_server_join joins the caller to a http server state. Assumes
   shhttp points to the first byte of the memory region holding the
   state.  Returns a local handle to the join on success (this is
   not necessarily a simple cast of the address) and NULL on failure
   (logs details).

   fd_http_server_leave leaves the caller's current local join to a http
   server state.  Returns a pointer to the memory region holding the
   state on success (this is not necessarily a simple cast of the
   address) and NULL on failure (logs details).  The caller is not
   joined on successful return.

   fd_http_server_delete unformats a memory region that holds a http
   server state.  Assumes shhttp points on the caller to the first
   byte of the memory region holding the state and that nobody is
   joined.  Returns a pointer to the memory region on success and NULL
   on failure (logs details).  The caller has ownership of the memory
   region on successful return. */

FD_FN_CONST ulong
fd_http_server_align( void );

FD_FN_CONST ulong
fd_http_server_footprint( ulong max_connection_cnt,
                          ulong max_ws_connection_cnt,
                          ulong max_request_len,
                          ulong max_ws_recv_frame_len,
                          ulong max_ws_send_frame_cnt );

void *
fd_http_server_new( void *                     shmem,
                    ulong                      max_connection_cnt,    /* Maximum number of concurrent HTTP/1.1 connections open.  Connections are not persistent and will be closed after one request is served. */
                    ulong                      max_ws_connection_cnt, /* Maximum number of concurrent websocket connections open. */
                    ulong                      max_request_len,       /* Maximum total length of an HTTP request, including the terminating \r\n\r\n. */
                    ulong                      max_ws_recv_frame_len, /* Maximum size of an incoming websocket frame from the client.  Must be >= max_request_len. */
                    ulong                      max_ws_send_frame_cnt, /* Maximum number of outgoing websocket frames that can be queued before the client is disconnected. */
                    fd_http_server_callbacks_t callbacks,
                    void *                     callback_ctx );

fd_http_server_t *
fd_http_server_join( void * shhttp );

void *
fd_http_server_leave( fd_http_server_t * http );

void *
fd_http_server_delete( void * shhttp );

fd_http_server_t *
fd_http_server_listen( fd_http_server_t * http,
                       ushort             port );

void
fd_http_server_ws_send( fd_http_server_t * http,
                        ulong              conn_id,
                        uchar const *      data,
                        ulong              data_len );

void
fd_http_server_ws_broadcast( fd_http_server_t * http,
                             uchar const *      data,
                             ulong              data_len );

void
fd_http_server_poll( fd_http_server_t * http );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_http_fd_http_server_h */
