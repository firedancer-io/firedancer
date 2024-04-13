// Simple implementation of a character string

struct fd_quickstring {
    char* str;
    ulong str_sz;
    ulong str_alloc;
    char  str_firstbuf[512];
};
typedef struct fd_quickstring fd_quickstring_t;

// Initialize the string
void fd_quickstring_new(fd_quickstring_t* str);

// Clean up the string
void fd_quickstring_delete(fd_quickstring_t* str);

// Reset the string to zero length
void fd_quickstring_clear(fd_quickstring_t* str);

// Get the string text and size
const char* fd_quickstring_get(fd_quickstring_t* str, ulong* sz);

// Set the string to given text and size
void fd_quickstring_set(fd_quickstring_t* str, const char* text, ulong text_sz);

// Convert the string to an integer (assuming decimal representation)
long fd_quickstring_as_int(fd_quickstring_t* str);

// Convert the string to a float
double fd_quickstring_as_float(fd_quickstring_t* str);

// Formatted print function. The result is stored in the string. If
// there isn't enough allocated space, the output is truncated.
void fd_quickstring_sprintf(fd_quickstring_t* str, const char* format, ...)
  __attribute__ ((format (printf, 2, 3)));

// Reserve space at the end of the string for additional text. The
// pointer to the new space is returned (e.g. for memcpy).
char* fd_quickstring_append_prepare(fd_quickstring_t* str, ulong sz);

// Append a unicode character to the string. The character is
// converted to UTF-8 encoding.
void fd_quickstring_append_char(fd_quickstring_t* str, uint ch);
