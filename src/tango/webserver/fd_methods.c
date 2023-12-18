#include <stdio.h>
#include <malloc.h>
#include <assert.h>
#include "fd_methods.h"
#include "fd_webserver.h"
#include "../../util/fd_util.h"

// Initialize a json_values
void json_values_new(struct json_values* values) {
  values->num_values = 0;
  values->buf = values->buf_init;
  values->buf_sz = 0;
  values->buf_alloc = sizeof(values->buf_init);
}

// Destroy a json_values
void json_values_delete(struct json_values* values) {
  if (values->buf != values->buf_init)
    free(values->buf);
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
    char* newbuf = (char*)malloc(values->buf_alloc);
    fd_memcpy(newbuf, values->buf, values->buf_sz);
    if (values->buf != values->buf_init)
      free(values->buf);
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
