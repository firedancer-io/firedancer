#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include "../../util/fd_util.h"
#include "fd_quickstring.h"

// Initialize the string
void fd_quickstring_new(fd_quickstring_t* str) {
  str->str = str->str_firstbuf;
  str->str_sz = 0;
  str->str_alloc = sizeof(str->str_firstbuf);
  str->str_firstbuf[0] = '\0';
}

// Clean up the string
void fd_quickstring_delete(fd_quickstring_t* str) {
  if (str->str != str->str_firstbuf)
    free(str->str);
}

// Reset the string to zero length
void fd_quickstring_clear(fd_quickstring_t* str) {
  str->str_sz = 0;
  str->str[0] = '\0';
}

// Get the string text and size
const char* fd_quickstring_get(fd_quickstring_t* str, ulong* sz) {
  if (sz != NULL)
    *sz = str->str_sz;
  return str->str;
}

// Resize the string, leaving the content uninitialized. Previous
// string value is lost.
void fd_quickstring_set_size(fd_quickstring_t* str, ulong sz) {
  // Include null terminator
  ulong real_sz = sz+1;
  if (real_sz > str->str_alloc) {
    if (str->str != str->str_firstbuf)
      free(str->str);
    do {
      str->str_alloc <<= 1;
    } while (real_sz > str->str_alloc);
    str->str = (char*)malloc(str->str_alloc);
  }
  str->str_sz = sz;
}

// Set the string to given text and size
void fd_quickstring_set(fd_quickstring_t* str, const char* text, ulong text_sz) {
  fd_quickstring_set_size(str, text_sz);
  fd_memcpy(str->str, text, text_sz);
  str->str[text_sz] = '\0';
}

// Convert the string to an integer (assuming decimal representation)
long fd_quickstring_as_int(fd_quickstring_t* str) {
  // Gangster conversion of decimal text to int
  const char* i = str->str;
  const char* i_end = i + str->str_sz;
  int isneg = 0;
  if (i < i_end && *i == '-') {
    isneg = 1;
    i++;
  }
  long n = 0;
  while (i < i_end)
    n = n*10 + (*(i++) - '0');
  return (isneg ? -n : n);
}

// Convert the string to a float
double fd_quickstring_as_float(fd_quickstring_t* str) {
  return strtod(str->str, NULL);
}

// Formatted print function. The result is stored in the string. If
// there isn't enough allocated space, the output is truncated.
void fd_quickstring_sprintf(fd_quickstring_t* str, const char* format, ...) {
  va_list ap;
  va_start(ap, format);
  int r = vsnprintf(str->str, str->str_alloc, format, ap);
  va_end(ap);
  if (r >= 0)
    str->str_sz = (ulong)r;
  else {
    str->str_sz = 0;
    str->str[0] = '\0';
  }
}

// Reserve space at the end of the string for additional text. The
// pointer to the new space is returned (e.g. for memcpy).
char* fd_quickstring_append_prepare(fd_quickstring_t* str, ulong sz) {
  // Get the new string size
  ulong new_sz = str->str_sz + sz;
  // Make sure there is enough room, including a null terminator
  if (new_sz + 1 > str->str_alloc) {
    // Grow the allocation
    do {
      str->str_alloc <<= 1;
    } while (new_sz + 1 > str->str_alloc);
    char* oldstr = str->str;
    str->str = (char*)malloc(str->str_alloc);
    // Copy the old content to the new space
    fd_memcpy(str->str, oldstr, str->str_sz);
    if (oldstr != str->str_firstbuf)
      free(oldstr);
  }
  // Stick on a null terminator
  char* res = str->str + str->str_sz;
  res[sz] = '\0';
  str->str_sz = new_sz;
  return res;
}

// Append a unicode character to the string. The character is
// converted to UTF-8 encoding.
void fd_quickstring_append_char(fd_quickstring_t* str, uint ch) {
  // Encode in UTF-8 
  if (ch < 0x80) {
    char* dest = fd_quickstring_append_prepare(str, 1);
    *dest =     (char)ch;
  } else if (ch < 0x800) {
    char* dest = fd_quickstring_append_prepare(str, 2);
    *(dest++) = (char)((ch>>6) | 0xC0);
    *dest =     (char)((ch & 0x3F) | 0x80);
  } else if (ch < 0x10000) {
    char* dest = fd_quickstring_append_prepare(str, 3);
    *(dest++) = (char)((ch>>12) | 0xE0);
    *(dest++) = (char)(((ch>>6) & 0x3F) | 0x80);
    *dest =     (char)((ch & 0x3F) | 0x80);
  } else if (ch < 0x110000) {
    char* dest = fd_quickstring_append_prepare(str, 4);
    *(dest++) = (char)((ch>>18) | 0xF0);
    *(dest++) = (char)(((ch>>12) & 0x3F) | 0x80);
    *(dest++) = (char)(((ch>>6) & 0x3F) | 0x80);
    *dest =     (char)((ch & 0x3F) | 0x80);
  }
}
