#include <openssl/sha.h>

#pragma GCC diagnostic ignored "-Wstringop-overflow"
#pragma GCC diagnostic ignored "-Wrestrict"

#define BAD_REQUEST_PAGE                                                \
  "<html>\n"                                                            \
  "<head>\n"                                                            \
  "<title>fd_rpcserver</title>\n"                                       \
  "</head>\n"                                                           \
  "<body>\n"                                                            \
  "Bad Request\n"                                                       \
  "</body>\n"                                                           \
  "</html>\n"
#define UPGRADE_REQUIRED_PAGE                                           \
  "<html>\n"                                                            \
  "<head>\n"                                                            \
  "<title>fd_rpcserver</title>\n"                                       \
  "</head>\n"                                                           \
  "<body>\n"                                                            \
  "Upgrade required\n"                                                  \
  "</body>\n"                                                           \
  "</html>\n"

#define WS_SEC_WEBSOCKET_VERSION "13"
#define WS_UPGRADE_VALUE "websocket"
#define WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define WS_GUID_LEN 36
#define WS_KEY_LEN 24
#define WS_KEY_GUID_LEN ((WS_KEY_LEN) + (WS_GUID_LEN))
#define WS_FIN 128
#define WS_OPCODE_TEXT_FRAME 1
#define WS_OPCODE_CLOSE_FRAME 8
#define WS_OPCODE_PING_FRAME 9
#define WS_OPCODE_PONG_FRAME 10
#define SHA1HashSize 20

static enum MHD_Result
is_websocket_request (struct MHD_Connection *con, const char *upg_header,
                      const char *con_header)
{

  (void) con;  /* Unused. Silent compiler warning. */

  return ((upg_header != NULL) && (con_header != NULL)
          && (0 == strcmp (upg_header, WS_UPGRADE_VALUE))
          && (NULL != strstr (con_header, "Upgrade")))
         ? MHD_YES
         : MHD_NO;
}

static void do_nothing(void * arg) { (void)arg; }

static enum MHD_Result
send_bad_request (struct MHD_Connection *con)
{
  struct MHD_Response *res;
  enum MHD_Result ret;

  res = MHD_create_response_from_buffer_with_free_callback (strlen (BAD_REQUEST_PAGE), (void *) BAD_REQUEST_PAGE, do_nothing);
  ret = MHD_queue_response (con, MHD_HTTP_BAD_REQUEST, res);
  MHD_destroy_response (res);
  return ret;
}

static enum MHD_Result
send_upgrade_required (struct MHD_Connection *con)
{
  struct MHD_Response *res;
  enum MHD_Result ret;

  res = MHD_create_response_from_buffer_with_free_callback (strlen (UPGRADE_REQUIRED_PAGE), (void *) UPGRADE_REQUIRED_PAGE, do_nothing);
  if (MHD_YES !=
      MHD_add_response_header (res, MHD_HTTP_HEADER_SEC_WEBSOCKET_VERSION,
                               WS_SEC_WEBSOCKET_VERSION))
  {
    MHD_destroy_response (res);
    return MHD_NO;
  }
  ret = MHD_queue_response (con, MHD_HTTP_UPGRADE_REQUIRED, res);
  MHD_destroy_response (res);
  return ret;
}

static enum MHD_Result
ws_get_accept_value (const char *key, char * val)
{
  SHA_CTX ctx;
  unsigned char hash[SHA1HashSize];

  if ( (NULL == key) || (WS_KEY_LEN != strlen (key)))
  {
    return MHD_NO;
  }
  char str[WS_KEY_LEN + WS_GUID_LEN + 1];
  strncpy (str, key, (WS_KEY_LEN + 1));
  strncpy (str + WS_KEY_LEN, WS_GUID, WS_GUID_LEN + 1);
  SHA1_Init (&ctx);
  SHA1_Update (&ctx, (const unsigned char *) str, WS_KEY_GUID_LEN);
  if (!SHA1_Final (hash, &ctx))
  {
    return MHD_NO;
  }
  ulong len = fd_base64_encode(val, hash, SHA1HashSize);
  val[len] = '\0';
  return MHD_YES;
}

static void
make_blocking (MHD_socket fd)
{
#if defined(MHD_POSIX_SOCKETS)
  int flags;

  flags = fcntl (fd, F_GETFL);
  if (-1 == flags)
    abort ();
  if ((flags & ~O_NONBLOCK) != flags)
    if (-1 == fcntl (fd, F_SETFL, flags & ~O_NONBLOCK))
      abort ();
#elif defined(MHD_WINSOCK_SOCKETS)
  unsigned long flags = 0;

  if (0 != ioctlsocket (fd, (int) FIONBIO, &flags))
    abort ();
#endif /* MHD_WINSOCK_SOCKETS */
}

static size_t
send_all (MHD_socket sock, const unsigned char *buf, size_t len)
{
  ssize_t ret;
  size_t off;

  for (off = 0; off < len; off += (size_t) ret)
  {
#if ! defined(_WIN32) || defined(__CYGWIN__)
    ret = send (sock, (const void *) &buf[off], len - off, 0);
#else  /* Native W32 */
    ret = send (sock, (const void *) &buf[off], (int) (len - off), 0);
#endif /* Native W32 */
    if (0 > ret)
    {
      if (EAGAIN == errno)
      {
        ret = 0;
        continue;
      }
      break;
    }
    if (0 == ret)
    {
      break;
    }
  }
  return off;
}

static ssize_t
ws_send_frame (MHD_socket sock, const uchar type, const char *msg, size_t length)
{
  unsigned char *response;
  unsigned char frame[10];
  unsigned char idx_first_rdata;
  unsigned char buf[1<<13];

  frame[0] = (WS_FIN | type);
  if (length <= 125)
  {
    frame[1] = length & 0x7F;
    idx_first_rdata = 2;
  }
  else if (0xFFFF < length)
  {
    frame[1] = 127;
    frame[2] = (unsigned char) ((length >> 56) & 0xFF);
    frame[3] = (unsigned char) ((length >> 48) & 0xFF);
    frame[4] = (unsigned char) ((length >> 40) & 0xFF);
    frame[5] = (unsigned char) ((length >> 32) & 0xFF);
    frame[6] = (unsigned char) ((length >> 24) & 0xFF);
    frame[7] = (unsigned char) ((length >> 16) & 0xFF);
    frame[8] = (unsigned char) ((length >> 8) & 0xFF);
    frame[9] = (unsigned char) (length & 0xFF);
    idx_first_rdata = 10;
  }
  else
  {
    frame[1] = 126;
    frame[2] = (length >> 8) & 0xFF;
    frame[3] = length & 0xFF;
    idx_first_rdata = 4;
  }
  if( idx_first_rdata + length <= sizeof( buf ) )
    response = buf;
  else
    response = malloc (idx_first_rdata + length);
  if (NULL == response)
  {
    return -1;
  }
  memcpy(response, frame, idx_first_rdata);
  memcpy(response + idx_first_rdata, msg, length);
  size_t output = send_all (sock, response, idx_first_rdata + length);
  if( response != buf ) free (response);
  return (ssize_t) output;
}

#define WS_MAX_HDR_SIZE 10U

static ssize_t
ws_send_frame_prepend_hdr(MHD_socket sock, const uchar type, char * msg, size_t length)
{
  uchar * frame;
  size_t tot_length;
  if (length <= 125)
  {
    frame = (uchar*)msg - 2;
    frame[0] = (WS_FIN | type);
    frame[1] = length & 0x7F;
    tot_length = length + 2;
  }
  else if (0xFFFF < length)
  {
    frame = (uchar*)msg - 10;
    frame[0] = (WS_FIN | type);
    frame[1] = 127;
    frame[2] = (unsigned char) ((length >> 56) & 0xFF);
    frame[3] = (unsigned char) ((length >> 48) & 0xFF);
    frame[4] = (unsigned char) ((length >> 40) & 0xFF);
    frame[5] = (unsigned char) ((length >> 32) & 0xFF);
    frame[6] = (unsigned char) ((length >> 24) & 0xFF);
    frame[7] = (unsigned char) ((length >> 16) & 0xFF);
    frame[8] = (unsigned char) ((length >> 8) & 0xFF);
    frame[9] = (unsigned char) (length & 0xFF);
    tot_length = length + 10;
  }
  else
  {
    frame = (uchar*)msg - 4;
    frame[0] = (WS_FIN | type);
    frame[1] = 126;
    frame[2] = (length >> 8) & 0xFF;
    frame[3] = length & 0xFF;
    tot_length = length + 4;
  }
  return (ssize_t) send_all (sock, frame, tot_length);
}

static unsigned char *
ws_receive_frame (unsigned char *frame, ssize_t *length, int *type)
{
  unsigned char masks[4];
  unsigned char mask;
  unsigned char *msg;
  unsigned char flength;
  unsigned char idx_first_mask;
  unsigned char idx_first_data;
  size_t data_length;
  int i;
  int j;

  msg = NULL;
  *type = frame[0] & 0x0F;
  if (frame[0] == (WS_FIN | WS_OPCODE_TEXT_FRAME) ||
      frame[0] == (WS_FIN | WS_OPCODE_PING_FRAME))
  {
    idx_first_mask = 2;
    mask = frame[1];
    flength = mask & 0x7F;
    if (flength == 126)
    {
      idx_first_mask = 4;
    }
    else if (flength == 127)
    {
      idx_first_mask = 10;
    }
    idx_first_data = (unsigned char) (idx_first_mask + 4);
    data_length = (size_t) *length - idx_first_data;
    masks[0] = frame[idx_first_mask + 0];
    masks[1] = frame[idx_first_mask + 1];
    masks[2] = frame[idx_first_mask + 2];
    masks[3] = frame[idx_first_mask + 3];
    msg = malloc (data_length + 1);
    if (NULL != msg)
    {
      for (i = idx_first_data, j = 0; i < *length; i++, j++)
      {
        msg[j] = frame[i] ^ masks[j % 4];
      }
      *length = (ssize_t) data_length;
      msg[j] = '\0';
    }
  }
  return msg;
}

static void
epoll_selected( struct epoll_event * event ) {
  fd_websocket_ctx_t * ws = event->data.ptr;
  struct MHD_UpgradeResponseHandle *urh = ws->urh;
  unsigned char buf[2048];

  do {
    ssize_t got = recv (ws->sock, (void *) buf, sizeof (buf), 0);
    if (0 >= got) {
      break;
    }
    int type = -1;
    char * msg = (char *)ws_receive_frame (buf, &got, &type);
    if (type == WS_OPCODE_TEXT_FRAME) {
      if (NULL == msg) {
        break;
      }
      if( !fd_webserver_ws_request( ws, msg, (ulong)got ) ) {
        free( msg );
        break;
      }
      free( msg );
      /* Happy path */
      return;
    } else if (type == WS_OPCODE_CLOSE_FRAME) {
      break;
    } else if (type == WS_OPCODE_PING_FRAME) {
      ws_send_frame(ws->sock, WS_OPCODE_PONG_FRAME, msg, (ulong)got);
      free( msg );
      return;
    }
    /* Unknown type */
  } while (0);

  fd_webserver_ws_closed(ws, ws->ws->cb_arg);
  epoll_ctl(ws->ws->ws_epoll_fd, EPOLL_CTL_DEL, ws->sock, NULL);
  MHD_upgrade_action (urh, MHD_UPGRADE_ACTION_CLOSE);
  free (ws);
}

static void
uh_cb (void *cls, struct MHD_Connection *con, void *req_cls,
       const char *extra_in, size_t extra_in_size, MHD_socket sock,
       struct MHD_UpgradeResponseHandle *urh)
{
  fd_webserver_t * ws = (fd_webserver_t *)cls;

  (void) con;            /* Unused. Silent compiler warning. */
  (void) req_cls;        /* Unused. Silent compiler warning. */
  (void) extra_in;       /* Unused. Silent compiler warning. */
  (void) extra_in_size;  /* Unused. Silent compiler warning. */

  fd_websocket_ctx_t * wsd = malloc (sizeof (fd_websocket_ctx_t));
  memset (wsd, 0, sizeof (fd_websocket_ctx_t));
  wsd->sock = sock;
  wsd->urh = urh;
  wsd->ws = ws;

  make_blocking (sock);

  struct epoll_event event;
  event.events = EPOLLIN;
  event.data.ptr = wsd;
  if (epoll_ctl(ws->ws_epoll_fd, EPOLL_CTL_ADD, sock, &event)) {
    FD_LOG_ERR(("epoll_ctl failed: %s", strerror(errno) ));
  }
}

static enum MHD_Result
ahc_cb (void *cls, struct MHD_Connection *con, const char *url,
        const char *method, const char *version, const char *upload_data,
        size_t *upload_data_size, void **req_cls)
{
  struct MHD_Response *res;
  const char *upg_header;
  const char *con_header;
  const char *ws_version_header;
  const char *ws_key_header;
  enum MHD_Result ret;
  size_t key_size;

  fd_webserver_t * ws = (fd_webserver_t *)cls;

  (void) url;               /* Unused. Silent compiler warning. */
  (void) upload_data;       /* Unused. Silent compiler warning. */
  (void) upload_data_size;  /* Unused. Silent compiler warning. */

  if (NULL == *req_cls)
  {
    *req_cls = (void *) 1;
    return MHD_YES;
  }
  *req_cls = NULL;
  upg_header = MHD_lookup_connection_value (con, MHD_HEADER_KIND,
                                            MHD_HTTP_HEADER_UPGRADE);
  con_header = MHD_lookup_connection_value (con, MHD_HEADER_KIND,
                                            MHD_HTTP_HEADER_CONNECTION);
  if (MHD_NO == is_websocket_request (con, upg_header, con_header))
  {
    return send_bad_request (con);
  }
  if ((0 != strcmp (method, MHD_HTTP_METHOD_GET))
      || (0 != strcmp (version, MHD_HTTP_VERSION_1_1)))
  {
    return send_bad_request (con);
  }
  ws_version_header =
    MHD_lookup_connection_value (con, MHD_HEADER_KIND,
                                 MHD_HTTP_HEADER_SEC_WEBSOCKET_VERSION);
  if ((NULL == ws_version_header)
      || (0 != strcmp (ws_version_header, WS_SEC_WEBSOCKET_VERSION)))
  {
    return send_upgrade_required (con);
  }
  ret = MHD_lookup_connection_value_n (con, MHD_HEADER_KIND,
                                       MHD_HTTP_HEADER_SEC_WEBSOCKET_KEY,
                                       strlen (MHD_HTTP_HEADER_SEC_WEBSOCKET_KEY),
                                       &ws_key_header, &key_size);
  if ((MHD_NO == ret) || (key_size != WS_KEY_LEN))
  {
    return send_bad_request (con);
  }
  char ws_ac_value[2*SHA1HashSize+1];
  ret = ws_get_accept_value (ws_key_header, ws_ac_value);
  if (MHD_NO == ret)
  {
    return ret;
  }
  res = MHD_create_response_for_upgrade (&uh_cb, ws);
  if (MHD_YES !=
      MHD_add_response_header (res, MHD_HTTP_HEADER_SEC_WEBSOCKET_ACCEPT,
                               ws_ac_value))
  {
    MHD_destroy_response (res);
    return MHD_NO;
  }
  if (MHD_YES !=
      MHD_add_response_header (res, MHD_HTTP_HEADER_UPGRADE, WS_UPGRADE_VALUE))
  {
    MHD_destroy_response (res);
    return MHD_NO;
  }
  ret = MHD_queue_response (con, MHD_HTTP_SWITCHING_PROTOCOLS, res);
  MHD_destroy_response (res);
  return ret;
}
