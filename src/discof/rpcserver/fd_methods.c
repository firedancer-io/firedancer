#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "fd_methods.h"
#include "fd_webserver.h"
#include "../../util/fd_util.h"

// Read the next json lexical token and report any error to the client
#define NEXT_TOKEN                                                      \
  do {                                                                  \
    prevpos = lex->pos;                                                 \
    prevtoken = lex->last_tok;                                          \
    token = json_lex_next_token(lex);                                   \
    if (token == JSON_TOKEN_ERROR) return 0;                            \
  } while (0)

#define UNNEXT_TOKEN                                                    \
  lex->pos = prevpos;                                                   \
  lex->last_tok = prevtoken;

// Report a json parsing syntax error
#define SYNTAX_ERROR(format, ...)                                       \
  do {                                                                  \
    json_lex_sprintf(lex, format, __VA_ARGS__);                         \
    return 0;                                                           \
  } while (0)

// Parse a generic json value. The values argument is used for storing
// leaf values for later access. path describes the path through the
// json syntax tree to this value.
int
json_values_parse(json_lex_state_t* lex, struct json_values* values, struct json_path* path) {
  ulong prevpos;
  long token;
  long prevtoken;

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
      if (!json_values_parse(lex, values, path))
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
      if (!json_values_parse(lex, values, path))
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
    long val = json_lex_as_int(lex);
    json_add_value(values, path, &val, sizeof(val));
    break;
  }

  case JSON_TOKEN_FLOAT: {
    // Append to the path
    *path_last = (JSON_TOKEN_FLOAT<<16);
    // Store the leaf value in values, indexed by the current path
    double val = json_lex_as_float(lex);
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

  case JSON_TOKEN_RBRACKET:
    if (prevtoken == JSON_TOKEN_LBRACKET) {
      /* Empty array */
      UNNEXT_TOKEN;
      break;
    }
    SYNTAX_ERROR("unexpected ']' at position %lu", prevpos);
    break;

  case JSON_TOKEN_RBRACE:
    if (prevtoken == JSON_TOKEN_LBRACE) {
      /* Empty object */
      UNNEXT_TOKEN;
      break;
    }
    SYNTAX_ERROR("unexpected '}' at position %lu", prevpos);
    break;

  default:
    SYNTAX_ERROR("expected json value at position %lu", prevpos);
  }

  path->len --;
  return 1;
}

// Initialize a json_values
void json_values_new(struct json_values* values) {
  values->num_values = 0;
  values->buf = values->buf_init;
  values->buf_sz = 0;
  values->buf_alloc = sizeof(values->buf_init);
}

// Destroy a json_values
void json_values_delete(struct json_values* values) {
  (void)values;
}

// Add a parsed value to a json_values
void json_add_value(struct json_values* values, struct json_path* path, const void* data, ulong data_sz) {
  if (values->num_values == JSON_MAX_PATHS) {
    // Ignore when we have too many values. In the actual requests
    // that we expect to handle, the number of values is modest.
    return;
  }

  // Get the new buffer size after we add the new data (plus null terminator)
  ulong new_buf_sz = values->buf_sz + data_sz + 1;
  new_buf_sz = ((new_buf_sz + 7UL) & ~7UL); // 8-byte align
  if (new_buf_sz > values->buf_alloc) {
    // Grow the allocation
    do {
      values->buf_alloc <<= 1;
    } while (new_buf_sz > values->buf_alloc);
    char* newbuf = (char*)fd_scratch_alloc(1, values->buf_alloc);
    fd_memcpy(newbuf, values->buf, values->buf_sz);
    values->buf = newbuf;
  }

  // Add a new value to the table
  uint i = values->num_values++;
  struct json_path* path2 = &values->values[i].path;
  uint len = path2->len = path->len;
  for (uint j = 0; j < len; ++j)
    path2->elems[j] = path->elems[j];
  // Copy out the data
  ulong off = values->values[i].data_offset = values->buf_sz;
  values->values[i].data_sz = data_sz;
  fd_memcpy(values->buf + off, data, data_sz);
  values->buf[off + data_sz] = '\0';
  values->buf_sz = new_buf_sz;
}

// Retrieve a value at a given path. A NULL is returned if the path
// isn't found
const void* json_get_value(struct json_values* values, const uint* path_elems, uint path_sz, ulong* data_sz) {
  // Loop through the values
  for (uint i = 0; i < values->num_values; ++i) {
    // Compare paths
    struct json_path* path = &values->values[i].path;
    if (path->len == path_sz) {
      for (uint j = 0; ; ++j) {
        if (j == path_sz) {
          *data_sz = values->values[i].data_sz;
          return values->buf + values->values[i].data_offset;
        }
        if (path->elems[j] != path_elems[j])
          break;
      }
    }
  }
  // Not found
  *data_sz = 0;
  return NULL;
}

const void* json_get_value_multi(struct json_values* values, const uint* path_elems, uint path_sz, ulong* data_sz, uint * pos) {
  // Loop through the values
  for (uint i = *pos; i < values->num_values; ++i) {
    // Compare paths
    struct json_path* path = &values->values[i].path;
    if (path->len == path_sz) {
      for (uint j = 0; ; ++j) {
        if (j == path_sz) {
          *data_sz = values->values[i].data_sz;
          *pos = j+1;
          return values->buf + values->values[i].data_offset;
        }
        if (path->elems[j] != path_elems[j])
          break;
      }
    }
  }
  // Not found
  *data_sz = 0;
  *pos = values->num_values;
  return NULL;
}

// Dump the values and paths to stdout
void json_values_printout(struct json_values* values) {
  for (uint i = 0; i < values->num_values; ++i) {
    struct json_path* path = &values->values[i].path;
    const char* data = values->buf + values->values[i].data_offset;
    ulong data_sz = values->values[i].data_sz;
    for (uint j = 0; j < path->len; ++j) {
      uint e = path->elems[j];
      switch (e >> 16U) {
      case JSON_TOKEN_LBRACE:
        printf(" (object|%s)", un_fd_webserver_json_keyword(e & 0xffffUL));
        break;
      case JSON_TOKEN_LBRACKET:
        printf(" (array|%lu)", e & 0xffffUL);
        break;
      case JSON_TOKEN_STRING:
        printf(" STRING \"");
        fwrite(data, 1, data_sz, stdout);
        printf("\"");
        break;
      case JSON_TOKEN_INTEGER:
        assert(data_sz == sizeof(long));
        printf(" INT %ld", *(long*)data);
        break;
      case JSON_TOKEN_FLOAT:
        assert(data_sz == sizeof(double));
        printf(" FLOAT %g", *(double*)data);
        break;
      case JSON_TOKEN_BOOL:
        assert(data_sz == sizeof(int));
        printf(" BOOL %d", *(int*)data);
        break;
      case JSON_TOKEN_NULL:
        printf(" NULL");
        break;
      }
    }
    printf("\n");
  }
}
