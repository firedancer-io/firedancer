#include "../../util/fd_util.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <microhttpd.h>
#include "fd_methods.h"
#include "fd_webserver.h"

/**
 * Number of threads to run in the thread pool.
 */
#define NUMBER_OF_THREADS 10

// Read the next json lexical token and report any error to the client
#define NEXT_TOKEN                                                      \
  do {                                                                  \
    prevpos = lex->pos;                                                 \
    token = json_lex_next_token(lex);                                   \
    if (token == JSON_TOKEN_ERROR) {                                    \
      fd_web_replier_error(replier, json_lex_get_text(lex, NULL));        \
      CLEANUP                                                           \
      return 0;                                                         \
    }                                                                   \
  } while (0)

// Report a json parsing syntax error
#define SYNTAX_ERROR(format, ...)                                       \
  do {                                                                  \
    snprintf(message, sizeof(message), format, __VA_ARGS__);            \
    fd_web_replier_error(replier, message);                               \
    CLEANUP                                                             \
    return 0;                                                           \
  } while (0)

#define CLEANUP ;

// Parse a generic json value. The values argument is used for storing
// leaf values for later access. path describes the path through the
// json syntax tree to this value.
int json_parse_params_value(struct fd_web_replier* replier, json_lex_state_t* lex, struct json_values* values, struct json_path* path) {
  ulong prevpos;
  long token;
  char message[128];

  // Prepare to update the path to include a new element
  if (path->len == JSON_MAX_PATH)
    SYNTAX_ERROR("json value is too nested at position %lu", lex->pos);
  uint* path_last = &path->elems[path->len ++];

  NEXT_TOKEN;
  switch (token) {
  case JSON_TOKEN_LBRACE: // Start a new json object
    do {
      NEXT_TOKEN;
      if (token == JSON_TOKEN_RBRACE)
        break;
      if (token != JSON_TOKEN_STRING)
        SYNTAX_ERROR("expected string key at position %lu", prevpos);
      // Translate the key string to a known keyword ID. We only allow
      // a predetermined set of keys.
      ulong key_sz;
      const char* key = json_lex_get_text(lex, &key_sz);
      long keyid = fd_webserver_json_keyword(key, key_sz);
      if (keyid == KEYW_UNKNOWN)
        SYNTAX_ERROR("unrecognized string key at position %lu", prevpos);
      // Append to the path
      *path_last = ((JSON_TOKEN_LBRACE<<16) | (uint)keyid);

      NEXT_TOKEN;
      if (token != JSON_TOKEN_COLON)
        SYNTAX_ERROR("expected colon at position %lu", prevpos);

      // Recursively parse the inner value
      if (!json_parse_params_value(replier, lex, values, path))
        return 0;

      NEXT_TOKEN;
      if (token == JSON_TOKEN_RBRACE)
        break;
      if (token != JSON_TOKEN_COMMA)
        SYNTAX_ERROR("expected comma at position %lu", prevpos);
    } while(1);
    break;

  case JSON_TOKEN_LBRACKET: { // Start an array
    uint i = 0;
    do {
      // Append to the path
      *path_last = ((JSON_TOKEN_LBRACKET<<16) | i);
      // Recursively parse the array element
      if (!json_parse_params_value(replier, lex, values, path))
        return 0;

      NEXT_TOKEN;
      if (token == JSON_TOKEN_RBRACKET)
        break;
      if (token != JSON_TOKEN_COMMA)
        SYNTAX_ERROR("expected comma at position %lu", prevpos);

      ++i;
    } while(1);
    break;
  }

  case JSON_TOKEN_STRING: {
    // Append to the path
    *path_last = (JSON_TOKEN_STRING<<16);
    // Store the leaf value in values, indexed by the current path
    ulong str_sz;
    const char* str = json_lex_get_text(lex, &str_sz);
    json_add_value(values, path, str, str_sz);
    break;
  }

  case JSON_TOKEN_INTEGER: {
    // Append to the path
    *path_last = (JSON_TOKEN_INTEGER<<16);
    // Store the leaf value in values, indexed by the current path
    long val = fd_quickstring_as_int(&lex->last_str);
    json_add_value(values, path, &val, sizeof(val));
    break;
  }

  case JSON_TOKEN_FLOAT: {
    // Append to the path
    *path_last = (JSON_TOKEN_FLOAT<<16);
    // Store the leaf value in values, indexed by the current path
    double val = fd_quickstring_as_float(&lex->last_str);
    json_add_value(values, path, &val, sizeof(val));
    break;
  }

  case JSON_TOKEN_BOOL:
    // Append to the path
    *path_last = (JSON_TOKEN_BOOL<<16);
    // Store the leaf value in values, indexed by the current path
    json_add_value(values, path, &lex->last_bool, sizeof(lex->last_bool));
    break;

  case JSON_TOKEN_NULL:
    // Append to the path
    *path_last = (JSON_TOKEN_NULL<<16);
    // Store the leaf value in values, indexed by the current path
    json_add_value(values, path, NULL, 0);
    break;

  default:
    SYNTAX_ERROR("expected parameter value at position %lu", prevpos);
  }

  path->len --;
  return 1;
}

#undef CLEANUP

// Parse the top level json request object
int json_parse_root(struct fd_web_replier* replier, json_lex_state_t* lex) {
  struct json_values values;
  json_values_new(&values);
  // Make sure we cleanup the values regardless of what path is taken
#define CLEANUP json_values_delete(&values);

  struct json_path path;
  path.len = 0;
  if (!json_parse_params_value(replier, lex, &values, &path)) {
    CLEANUP;
    return 0;
  }
  json_values_printout(&values);
  if (!fd_webserver_method_generic(replier, &values)) {
    CLEANUP;
    return 0;
  }

  CLEANUP;
#undef CLEANUP

  return 1;
}

struct fd_web_replier {
  const char* upload_data;
  size_t upload_data_size;
  unsigned int status_code;
  struct MHD_Response* response;
  char* temp;
  ulong temp_sz;
  ulong temp_alloc;
  char  temp_firstbuf[1024];
};

struct fd_web_replier* fd_web_replier_new() {
  struct fd_web_replier* r = (struct fd_web_replier*)malloc(sizeof(struct fd_web_replier));
  r->upload_data = NULL;
  r->upload_data_size = 0;
  r->status_code = MHD_HTTP_OK;
  r->response = NULL;
  r->temp = r->temp_firstbuf;
  r->temp_sz = 0;
  r->temp_alloc = sizeof(r->temp_firstbuf);
  return r;
}

void fd_web_replier_delete(struct fd_web_replier* r) {
  if (r->response != NULL)
    MHD_destroy_response(r->response);
  for (void* t = r->temp; t != r->temp_firstbuf; ) {
    void* next = *((void**)t);
    free(t);
    t = next;
  }
  free(r);
}

char* fd_web_replier_temp_alloc(struct fd_web_replier* r, ulong sz) {
  // Get the new temp size
  ulong new_sz = r->temp_sz + sz;
  // Make sure there is enough room
  if (new_sz > r->temp_alloc) {
    // Add a new allocation to the linked list
    ulong ta = (sz + (1lu<<14)) & ~((1lu<<13)-1);
    void* t = malloc(ta);
    *((void**)t) = r->temp;
    r->temp = t;
    r->temp_sz = sizeof(void*);
    r->temp_alloc = ta;
    new_sz = r->temp_sz + sz;
  }
  char* res = r->temp + r->temp_sz;
  r->temp_sz = new_sz;
  return res;
}

char* fd_web_replier_temp_copy(struct fd_web_replier* r, const char* text, ulong sz) {
  char* res = fd_web_replier_temp_alloc(r, sz);
  fd_memcpy(res, text, sz);
  return res;
}

void fd_web_replier_reply(struct fd_web_replier* replier, const char* out, uint out_sz) {
  replier->status_code = MHD_HTTP_OK;
  if (replier->response != NULL)
    MHD_destroy_response(replier->response);
  replier->response = MHD_create_response_from_buffer(out_sz, (void*)out, MHD_RESPMEM_PERSISTENT);
}

void fd_web_replier_reply_iov(struct fd_web_replier* replier, const struct fd_iovec* vec, uint nvec) {
  replier->status_code = MHD_HTTP_BAD_REQUEST;
  if (replier->response != NULL)
    MHD_destroy_response(replier->response);
  replier->response = MHD_create_response_from_iovec((struct MHD_IoVec*)vec, nvec, NULL, NULL);
}

static const char b58digits_ordered[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

char* fd_web_replier_encode_base58(struct fd_web_replier* replier, const void* data, ulong data_sz, ulong* out_sz) {
  /* Prevent explosive growth in computation */
  if (data_sz > 256)
    return NULL;

  const uchar* bin = (const uchar*)data;
  ulong carry;
  ulong i, j, high, zcount = 0;
  ulong size;

  while (zcount < data_sz && !bin[zcount])
    ++zcount;

  size = (data_sz - zcount) * 138 / 100 + 1;
  uchar buf[size];
  fd_memset(buf, 0, size);

  for (i = zcount, high = size - 1; i < data_sz; ++i, high = j) {
    for (carry = bin[i], j = size - 1; (j > high) || carry; --j) {
      carry += 256UL * (ulong)buf[j];
      buf[j] = (uchar)(carry % 58);
      carry /= 58UL;
      if (!j) {
        // Otherwise j wraps to maxint which is > high
        break;
      }
    }
  }

  for (j = 0; j < size && !buf[j]; ++j) ;

  *out_sz = zcount + size - j;
  char* b58 = fd_web_replier_temp_alloc(replier, *out_sz);

  if (zcount)
    fd_memset(b58, '1', zcount);
  for (i = zcount; j < size; ++i, ++j)
    b58[i] = b58digits_ordered[buf[j]];
  return b58;
}

static char base64_encoding_table[] = {
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
  'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
  'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
  'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
  'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
  'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
  'w', 'x', 'y', 'z', '0', '1', '2', '3',
  '4', '5', '6', '7', '8', '9', '+', '/'
};

char* fd_web_replier_encode_base64(struct fd_web_replier* replier, const void* data, ulong sz, ulong* out_sz) {
  *out_sz = 4 * ((sz + 2) / 3);
  char* out_data = fd_web_replier_temp_alloc(replier, *out_sz);
  for (ulong i = 0, j = 0; i < sz; ) {
    switch (sz - i) {
    default: { /* 3 and above */
      uint octet_a = ((uchar*)data)[i++];
      uint octet_b = ((uchar*)data)[i++];
      uint octet_c = ((uchar*)data)[i++];
      uint triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;
      out_data[j++] = base64_encoding_table[(triple >> 3 * 6) & 0x3F];
      out_data[j++] = base64_encoding_table[(triple >> 2 * 6) & 0x3F];
      out_data[j++] = base64_encoding_table[(triple >> 1 * 6) & 0x3F];
      out_data[j++] = base64_encoding_table[(triple >> 0 * 6) & 0x3F];
      break;
    }
    case 2: {
      uint octet_a = ((uchar*)data)[i++];
      uint octet_b = ((uchar*)data)[i++];
      uint triple = (octet_a << 0x10) + (octet_b << 0x08);
      out_data[j++] = base64_encoding_table[(triple >> 3 * 6) & 0x3F];
      out_data[j++] = base64_encoding_table[(triple >> 2 * 6) & 0x3F];
      out_data[j++] = base64_encoding_table[(triple >> 1 * 6) & 0x3F];
      out_data[j++] = '=';
      break;
    }
    case 1: {
      uint octet_a = ((uchar*)data)[i++];
      uint triple = (octet_a << 0x10);
      out_data[j++] = base64_encoding_table[(triple >> 3 * 6) & 0x3F];
      out_data[j++] = base64_encoding_table[(triple >> 2 * 6) & 0x3F];
      out_data[j++] = '=';
      out_data[j++] = '=';
      break;
    }
    }
  }
  return out_data;
}

void fd_web_replier_error(struct fd_web_replier* replier, const char* text) {
#define CRLF "\r\n"
  static const char* DOC1 =
"<html>" CRLF
"<head>" CRLF
"<title>ERROR</title>" CRLF
"</head>" CRLF
"<body>" CRLF
"<p><em>";
  static const char* DOC2 =
"</em></p>" CRLF
"<p>Request: <pre>";
  static const char* DOC3 =
"</pre></p>" CRLF
"</body>" CRLF
"</html>";

  struct MHD_IoVec iov[5];
  iov[0].iov_base = (void*)DOC1;
  iov[0].iov_len = strlen(DOC1);
  iov[1].iov_base = fd_web_replier_temp_copy(replier, text, strlen(text));
  iov[1].iov_len = strlen(text);
  iov[2].iov_base = (void*)DOC2;
  iov[2].iov_len = strlen(DOC2);
  iov[3].iov_base = fd_web_replier_temp_copy(replier, replier->upload_data, replier->upload_data_size);
  iov[3].iov_len = replier->upload_data_size;
  iov[4].iov_base = (void*)DOC3;
  iov[4].iov_len = strlen(DOC3);

  replier->status_code = MHD_HTTP_BAD_REQUEST;
  if (replier->response != NULL)
    MHD_destroy_response(replier->response);
  replier->response = MHD_create_response_from_iovec(iov, 5, NULL, NULL);
}

/**
 * Signature of the callback used by MHD to notify the
 * application about completed requests.
 *
 * @param cls client-defined closure
 * @param connection connection handle
 * @param con_cls value as set by the last call to
 *        the MHD_AccessHandlerCallback
 * @param toe reason for request termination
 * @see MHD_OPTION_NOTIFY_COMPLETED
 */
static void completed_cb(void* cls,
                         struct MHD_Connection* connection,
                         void** con_cls,
                         enum MHD_RequestTerminationCode toe)
{
  (void) cls;         /* Unused. Silent compiler warning. */
  (void) connection;  /* Unused. Silent compiler warning. */
  (void) toe;         /* Unused. Silent compiler warning. */

  if (*con_cls != NULL) {
    fd_web_replier_delete((struct fd_web_replier*) (*con_cls));
    *con_cls = NULL;
  }
}

/**
 * Main MHD callback for handling requests.
 *
 * @param cls argument given together with the function
 *        pointer when the handler was registered with MHD
 * @param connection handle identifying the incoming connection
 * @param url the requested url
 * @param method the HTTP method used ("GET", "PUT", etc.)
 * @param version the HTTP version string (i.e. "HTTP/1.1")
 * @param upload_data the data being uploaded (excluding HEADERS,
 *        for a POST that fits into memory and that is encoded
 *        with a supported encoding, the POST data will NOT be
 *        given in upload_data and is instead available as
 *        part of MHD_get_connection_values; very large POST
 *        data *will* be made available incrementally in
 *        upload_data)
 * @param upload_data_size set initially to the size of the
 *        upload_data provided; the method must update this
 *        value to the number of bytes NOT processed;
 * @param ptr pointer that the callback can set to some
 *        address and that will be preserved by MHD for future
 *        calls for this request; since the access handler may
 *        be called many times (i.e., for a PUT/POST operation
 *        with plenty of upload data) this allows the application
 *        to easily associate some request-specific state.
 *        If necessary, this state can be cleaned up in the
 *        global "MHD_RequestCompleted" callback (which
 *        can be set with the MHD_OPTION_NOTIFY_COMPLETED).
 *        Initially, <tt>*con_cls</tt> will be NULL.
 * @return MHS_YES if the connection was handled successfully,
 *         MHS_NO if the socket must be closed due to a serious
 *         error while handling the request
 */
static enum MHD_Result handler(void* cls,
                               struct MHD_Connection* connection,
                               const char* url,
                               const char* method,
                               const char* version,
                               const char* upload_data,
                               size_t* upload_data_size,
                               void** con_cls)
{
  (void) url;               /* Unused. Silent compiler warning. */
  (void) version;           /* Unused. Silent compiler warning. */

  if (0 != strcmp (method, "POST"))
    return MHD_NO;              /* unexpected method */

  // fd_webserver_t * ws = (fd_webserver_t *)cls;
  (void)cls;
  struct fd_web_replier* replier;
  if (*con_cls == NULL)
    *con_cls = replier = fd_web_replier_new();
  else
    replier = (struct fd_web_replier*) (*con_cls);

  size_t sz = *upload_data_size;
  if (sz) {
    replier->upload_data = upload_data;
    replier->upload_data_size = sz;
    json_lex_state_t lex;
    json_lex_state_new(&lex, upload_data, sz);
    json_parse_root(replier, &lex);
    json_lex_state_delete(&lex);
    *upload_data_size = 0;
  }

  // Check if we are done with the request. This is clunky as hell,
  // but I didn't design the API.
  if (!sz && replier->upload_data_size) {
    if (replier->response != NULL)
      return MHD_queue_response (connection, replier->status_code, replier->response);
    return MHD_NO;
  }
  return MHD_YES;
}

int fd_webserver_start(uint portno, fd_webserver_t * ws) {
  ws->daemon = MHD_start_daemon(
    MHD_USE_INTERNAL_POLLING_THREAD
      | MHD_USE_SUPPRESS_DATE_NO_CLOCK
      | MHD_USE_EPOLL | MHD_USE_TURBO,
    (ushort) portno,
    NULL, NULL, &handler, ws,
    MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int) 120,
    MHD_OPTION_THREAD_POOL_SIZE, (unsigned int) NUMBER_OF_THREADS,
    MHD_OPTION_NOTIFY_COMPLETED, &completed_cb, ws,
    MHD_OPTION_CONNECTION_LIMIT, (unsigned int) 1000,
    MHD_OPTION_END);
  if (ws->daemon == NULL)
    return -1;
  return 0;
}

int fd_webserver_stop(fd_webserver_t * ws) {
  MHD_stop_daemon(ws->daemon);
  return 0;
}

// Generic reply sender. Eventually this should be removed when all
// the methods send real replies.
void fd_webserver_reply_ok(struct fd_web_replier* replier) {
  static const char* DOC=
"<html>" CRLF
"<head>" CRLF
"<title>OK</title>" CRLF
"</head>" CRLF
"<body>" CRLF
"</body>" CRLF
"</html>";
  fd_web_replier_reply(replier, DOC, (uint)strlen(DOC));
}
