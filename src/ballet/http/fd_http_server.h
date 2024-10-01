#ifndef HEADER_fd_src_ballet_http_fd_http_server_h
#define HEADER_fd_src_ballet_http_fd_http_server_h

/* An fd_http_server is a WebSocket capable HTTP server designed to
   stream output messages quickly to many connected clients, where each
   output message can go to many (and in some cases all) clients.

   The primary use case is for serving ongoing RPC data to RPC
   subscribers, but it also serves a WebSocket stream for browser
   clients to show the GUI.
   
   The server does not allocate and has a built in allocation strategy
   and memory region for outgoing messages which the caller should use.
   HTTP repsonse bodies and WebSocket frames are placed into an outgoing
   ring buffer, wrapping around when reaching the end, and the server
   will automatically evict slow clients that do not read their messages
   in time and would be overwriten when the buffer has wrapped fully
   around.
   
   Using the outgoing ring has two steps,

     (1) Stage data into the ring with fd_http_server_printf and
         fd_http_server_memcpy functions.
     (2) Send the staged data to clients with fd_http_server_send and
         fd_http_server_oring_broadcast.

   The server is designed to be used in a single threaded event loop and
   run within a tile.  The caller should call fd_http_server_poll as
   frequently as possible to service connections and make forward
   progress. */

#include "../fd_ballet_base.h"

#define FD_HTTP_SERVER_ALIGN       (128UL)

#define FD_HTTP_SERVER_METHOD_GET     (0)
#define FD_HTTP_SERVER_METHOD_POST    (1)
#define FD_HTTP_SERVER_METHOD_OPTIONS (2)

#define FD_HTTP_SERVER_CONNECTION_CLOSE_OK                           ( -1)
#define FD_HTTP_SERVER_CONNECTION_CLOSE_EVICTED                      ( -2)
#define FD_HTTP_SERVER_CONNECTION_CLOSE_TOO_SLOW                     ( -3)
#define FD_HTTP_SERVER_CONNECTION_CLOSE_EXPECTED_EOF                 ( -4)
#define FD_HTTP_SERVER_CONNECTION_CLOSE_PEER_RESET                   ( -5)
#define FD_HTTP_SERVER_CONNECTION_CLOSE_LARGE_REQUEST                ( -6)
#define FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST                  ( -7)
#define FD_HTTP_SERVER_CONNECTION_CLOSE_MISSING_CONENT_LENGTH_HEADER ( -8)
#define FD_HTTP_SERVER_CONNECTION_CLOSE_UNKNOWN_METHOD               ( -9)
#define FD_HTTP_SERVER_CONNECTION_CLOSE_PATH_TOO_LONG                (-10)
#define FD_HTTP_SERVER_CONNECTION_CLOSE_WS_BAD_KEY                   (-11)
#define FD_HTTP_SERVER_CONNECTION_CLOSE_WS_UNEXPECTED_VERSION        (-12)
#define FD_HTTP_SERVER_CONNECTION_CLOSE_WS_MISSING_KEY_HEADER        (-13)
#define FD_HTTP_SERVER_CONNECTION_CLOSE_WS_MISSING_VERSION_HEADER    (-14)
#define FD_HTTP_SERVER_CONNECTION_CLOSE_WS_BAD_MASK                  (-15)
#define FD_HTTP_SERVER_CONNECTION_CLOSE_WS_UNKNOWN_OPCODE            (-16)
#define FD_HTTP_SERVER_CONNECTION_CLOSE_WS_OVERSIZE_FRAME            (-17)
#define FD_HTTP_SERVER_CONNECTION_CLOSE_WS_CLIENT_TOO_SLOW           (-18)
#define FD_HTTP_SERVER_CONNECTION_CLOSE_WS_MISSING_UPGRADE           (-19)
#define FD_HTTP_SERVER_CONNECTION_CLOSE_WS_EXPECTED_CONT_OPCODE      (-20)
#define FD_HTTP_SERVER_CONNECTION_CLOSE_WS_EXPECTED_TEXT_OPCODE      (-21)
#define FD_HTTP_SERVER_CONNECTION_CLOSE_WS_CONTROL_FRAME_TOO_LARGE   (-22)

/* Given a FD_HTTP_SERVER_CONNECTION_CLOSE_* reason code, a reason that
   a HTTP connection a client was closed, produce a human readable
   string describing the reason. */

FD_FN_CONST char const *
fd_http_server_connection_close_reason_str( int reason );

/* Given a FD_HTTP_SERVER_METHOD_* code, produce the string for that
   method. */

FD_FN_CONST char const *
fd_http_server_method_str( uchar method );

/* Parameters needed for constructing an HTTP server.  */

struct fd_http_server_params {
  ulong max_connection_cnt;    /* Maximum number of concurrent HTTP/1.1 connections open.  Connections are not persistent and will be closed after one request is served */
  ulong max_ws_connection_cnt; /* Maximum number of concurrent websocket connections open */
  ulong max_request_len;       /* Maximum total length of an HTTP request, including the terminating \r\n\r\n and any body in the case of a POST */
  ulong max_ws_recv_frame_len; /* Maximum size of an incoming websocket frame from the client.  Must be >= max_request_len */
  ulong max_ws_send_frame_cnt; /* Maximum number of outgoing websocket frames that can be queued before the client is disconnected */
  ulong outgoing_buffer_sz;    /* Size of the outgoing data ring, which is used to stage outgoing HTTP response bodies and WebSocket frames */
};

typedef struct fd_http_server_params fd_http_server_params_t;

struct fd_http_server_request {
  ulong        connection_id; /* Unique identifier for the connection.  In [0, max_connection_cnt).  The connection ID is a unique identifier for the lifetime of the connection, and will be
                                 provided to close to indicate that the connection is closed.  After a connection is closed the ID may be recycled */

  uchar        method;        /* One of FD_HTTP_SERVER_METHOD_* indicating what the method of the request is */
  char const * path;          /* The NUL termoinated path component of the request.  Not sanitized and may contain arbitrary content.  Path is the full HTTP path of the request, for example
                                 "/img/monkeys/gorilla.jpg" */

  void *       ctx;           /* The user provided context pointer passed when constructing the HTTP server */

  struct {
    char const * content_type;      /* The NUL terminated value of the Content-Type header of the request.  Not sanitized and may contain arbitrary content.  May be NULL if the header was not present */
    char const * accept_encoding;   /* The NUL terminated value of the Accept-Encoding header of the request.  Not sanitized and may contain arbitrary content.  May be NULL if the header was not present */
    int          upgrade_websocket; /* True if the client has provided an `Upgrade: websocket` header, valid `Sec-WebSocket-Key` and supported `Sec-Websocket-Version`, indicating that the
                                       responder should upgrade the connection to a WebSocket by setting `upgrade_websocket` to 1 in the response */
  } headers;

  union {
    struct {
      uchar const * body;     /* The body of the HTTP request.  The body is byte data, might have internal NUL characters, and may not be NUL terminated */
      ulong         body_len; /* The length of the body of the HTTP request */
    } post;
  };
};

typedef struct fd_http_server_request fd_http_server_request_t;

/* A response issued by the server handler function to an HTTP request.

   The handler should typically create response bodies via. the HTTP
   server functions like fd_http_server_printf.  This allows the server
   to manage buffer lifetimes and ensure high performance.  If using
   the server buffers, the handler should not set a static_body or
   static_body_len, and should instead use fd_http_server_stage_body
   to snap off the staging buffer contents into the body.

   In certain cases, it is desirable to send static content where the
   lifetime of the buffer is known to outlive the HTTP server.  In
   that case, you can set body_static to non-NULL and body_len_static
   to the length of the body payload, and the server will send this
   data instead of the staged data instead.

   status is an HTTP status code.  If status is not 200, the response
   body is ignored and the server will send an empty response.

   If upgrade_websocket is true, the connection will be upgraded to a
   websocket, after which the handler will begin receiving websocket
   frames. */

struct fd_http_server_response {
  ulong status;                  /* Status code of the HTTP response */
  int   upgrade_websocket;       /* 1 if we should send a websocket upgrade response */

  char const * content_type;     /* Content-Type to set in the HTTP response */
  char const * cache_control;    /* Cache-Control to set in the HTTP response */
  char const * content_encoding; /* Content-Encoding to set in the HTTP response */

  char const * access_control_allow_origin;
  char const * access_control_allow_methods;
  char const * access_control_allow_headers;
  ulong        access_control_max_age;

  uchar const * static_body;     /* Response body to send.  Lifetime of response data must outlive the entire HTTP server. */
  ulong         static_body_len; /* Length of the response body */

  ulong _body_off;               /* Internal use only.  Offset into the outgoing buffer where the body starts */
  ulong _body_len;               /* Internal use only.  Length of the body in the outgoing buffer */
};

typedef struct fd_http_server_response fd_http_server_response_t;

struct fd_http_server_callbacks {
  /* Handle an incoming HTTP request.  The callback must be provided
     and is assumed to be non-NULL.  request is a representation of
     the incoming HTTP request.  The callback should return a response
     which will be sent to the client. */

  fd_http_server_response_t ( * request     )( fd_http_server_request_t const * request );

  /* Called when a regular HTTP connection is established.  Called
     immediately after the connection is accepted.  sockfd is the file
     descriptor of the socket.  ctx is the user provided context pointer
     provided when constructing the HTTP server.  The open callback can
     be NULL in which case the callback will not be invoked. */

  void                      ( * open        )( ulong conn_id, int sockfd, void * ctx );

  /* Close an HTTP request.  This is called back once all the data has
     been sent to the HTTP client, or an error condition occurs, or the
     caller force closes the connection by calling close.  If a
     connection is upgraded to a WebSocket connection, a close event is
     first sent once the HTTP upgrade response is sent, before a ws_open
     event is sent.  Close is not called when a WebSocket connection is
     closed, instead ws_close is called.  reason is one of
     FD_HTTP_SERVER_CONNECTION_CLOSE_* indicating why the connection is
     being closed.  ctx is the user provided context pointer provided
     when constructing the HTTP server.  The close callback can be NULL
     in which case the callback will not be invoked. */

  void                      ( * close       )( ulong conn_id, int reason, void * ctx );

  /* Called when a WebSocket is opened.  ws_conn_id in [0,
     max_ws_connection_cnt).  Connection IDs are recycled as WebSocket
     connections are closed.  Connection IDs overlap with regular
     (non-WebSocket) connection IDs, but are in a distinct namespace,
     and WebSocket connection 0 is different from regular connection 0.
     ctx is the user provided context pointer provided when constructing
     the HTTP server. */

  void                      ( * ws_open     )( ulong ws_conn_id, void * ctx );

  /* Called when a WebSocket message is received on the connection.
     data is the message data, and data_len is the length of the message
     data.  ctx is the user provided context pointer provided when
     constructing the HTTP server.  The data provided is valid only
     until the callback returns, and the buffer will be recycled again
     immediately.  data_len is in [0, max_ws_recv_frame_len). */

  void                      ( * ws_message  )( ulong ws_conn_id, uchar const * data, ulong data_len, void * ctx );

  /* Called when a WebSocket connection is closed.  reason is one of
     FD_HTTP_SERVER_CONNECTION_CLOSE_* indicating why the connection was
     closed.  ctx is the user provided context pointer provided when
     constructing the HTTP server.  Typical reasons for closing the
     WebSocket include the peer disconnecting or timing out, or being
     evicted to make space for a new incoming connection.  Also called
     back when the user of the API forcibly closes a connection by
     calling ws_close. */

  void                      ( * ws_close    )( ulong ws_conn_id, int reason, void * ctx );
};

typedef struct fd_http_server_callbacks fd_http_server_callbacks_t;

struct fd_http_server_private;
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
fd_http_server_footprint( fd_http_server_params_t params );

void *
fd_http_server_new( void *                     shmem,
                    fd_http_server_params_t    params,
                    fd_http_server_callbacks_t callbacks,
                    void *                     callback_ctx );

fd_http_server_t *
fd_http_server_join( void * shhttp );

void *
fd_http_server_leave( fd_http_server_t * http );

void *
fd_http_server_delete( void * shhttp );

/* fd_http_server_fd returns the file descriptor of the server.  The
   file descriptor is used to poll for incoming connections and data
   on the server. */

int
fd_http_server_fd( fd_http_server_t * http );

fd_http_server_t *
fd_http_server_listen( fd_http_server_t * http,
                       ushort             port );

/* Close an active connection.  The connection ID must be an open
   open connection in [0, max_connection_cnt).  The connection will
   be forcibly (ungracefully) terminated.  The connection ID is released
   and should not be used again, as it may be recycled for a future
   connection.  If a close callback has been provided to the http
   server, it will be invoked with the reason provided. */

void
fd_http_server_close( fd_http_server_t * http,
                      ulong              conn_id,
                      int                reason );

/* Close an active WebSocket conection.  The connection ID must be an
   open WebSocket connection ID in [0, max_ws_connection_cnt).  The
   connection will be forcibly (ungracefully) terminated.  The
   connection ID is released and should not be used again, as it may be
   recycled for a future WebSocket connection.  If a ws_close callback
   has been provided to the http server, it will be invoked with the
   reason provided. */

void
fd_http_server_ws_close( fd_http_server_t * http,
                         ulong              ws_conn_id,
                         int                reason );

/* fd_http_server_printf appends the rendered format string fmt into the
   staging area of the outgoing ring buffer.  Assumes http is a current
   local join.

   If appending to the ring buffer causes it to wrap around and
   overwrite existing data from a prior message, any connections which
   are still using data from the prior message will be evicted, as they
   cannot keep up.

   Once the full message has been appended into the outgoing ring buffer,
   the staged contents can be sent to all connected WebSocket clients of
   the HTTP server using fd_http_server_broadcast.  This will end the
   current staged message so future prints go into a new message.

   Printing is not error-free, it is assumed that the format string is
   valid but the entire outgoing buffer may not be large enough to hold
   the printed string.  In that case, the staging buffer is marked as
   being in an error state internally.  The next call to send or
   broadcast will fail, returning the error, and the error state will be
   cleared. */

void
fd_http_server_printf( fd_http_server_t * http,
                       char const *       fmt,
                       ... );

/* fd_http_server_memcpy appends the data provided to the end of the
   staging area of the outgoing ring buffer.  Assumes http is a current
   local join.

   If appending to the ring buffer causes it to wrap around and
   overwrite existing data from a prior message, any connections which
   are still using data from the prior message will be evicted, as they
   cannot keep up.

   Once the full message has been appended into the outgoing ring buffer,
   the staged contents can be sent to all connected WebSocket clients of
   the HTTP server using fd_http_server_broadcast.  This will end the
   current staged message so future prints go into a new message.

   Printing is not error-free, it is assumed that the format string is
   valid but the entire outgoing buffer may not be large enough to hold
   the printed string.  In that case, the staging buffer is marked as
   being in an error state internally.  The next call to send or
   broadcast will fail, returning the error, and the error state will be
   cleared. */

void
fd_http_server_memcpy( fd_http_server_t * http,
                       uchar const *      data,
                       ulong              data_len );

/* fd_http_server_unstage unstages any data written into the staging
   buffer, clearing its contents.  It does not advance the ring buffer
   usage, and no clients will be evicted. */

void
fd_http_server_unstage( fd_http_server_t * http );

/* fd_http_server_stage_body marks the current contents of the staging
   buffer as the body of the response.  The response is then ready to be
   sent to the client.  Returns 0 on success and -1 on failure if the
   ring buffer is in an error state, and then clears the error state. */

int
fd_http_server_stage_body( fd_http_server_t *          http,
                              fd_http_server_response_t * response );

/* Send the contents of the staging buffer as a a WebSocket message to a
   single client.  The staging buffer is then cleared.  Returns -1 on
   failure if the ring buffer is an error state, and then clears the
   error state.

   The contents are marked as needing to be sent to the client, but this
   does not block or wait for them to send, which happens async as the
   client is able to read.  If the client reads too slow, and the
   staging buffer wraps around and is eventually overwritten by another
   printer, this client will be force disconnected as being too slow. */

int
fd_http_server_ws_send( fd_http_server_t * http,
                        ulong              ws_conn_id ); /* An existing, open connection.  In [0, max_ws_connection_cnt) */

/* Broadcast the contents of the staging buffer as a WebSocket message
   to all connected clients.  The staging buffer is then cleared.
   Returns -1 on failure if the ring buffer is an error state, and then
   clears the error state.

   The contents are marked as needing to be sent to the client, but this
   does not block or wait for them to send, which happens async as the
   client is able to read.  If the client reads too slow, and the
   staging buffer wraps around and is eventually overwritten by another
   printer, this client will be force disconnected as being too slow. */

int
fd_http_server_ws_broadcast( fd_http_server_t * http );

/* fd_http_server_poll needs to be continuously called in a spin loop to
   drive the HTTP server forward. */

void
fd_http_server_poll( fd_http_server_t * http );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_http_fd_http_server_h */
