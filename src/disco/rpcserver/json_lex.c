#include "json_lex.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

static char* json_lex_append_prepare(json_lex_state_t* lex, ulong sz);
static void json_lex_append_char(json_lex_state_t* lex, uint ch);

void json_lex_state_new(struct json_lex_state* state,
                        const char* json,
                        ulong json_sz) {
  state->json = json;
  state->json_sz = json_sz;
  state->pos = 0;
  state->last_tok = JSON_TOKEN_ERROR;
  state->last_bool = 0;
  state->last_str = state->last_str_firstbuf;
  state->last_str_sz = 0;
  state->last_str_alloc = sizeof(state->last_str_firstbuf);
  state->last_str_firstbuf[0] = '\0';
}

void json_lex_state_delete(struct json_lex_state* state) {
  (void)state;
}

// Parse a numeric constant
static long json_lex_parse_number(struct json_lex_state* state, const char* start_pos) {
  // Scan to the end of the number
  const char* pos = start_pos;
  const char* const end_pos = state->json + state->json_sz;
  if (pos < end_pos && *pos == '-')
    pos++;
  while (pos < end_pos && (uchar)(*pos - '0') <= (uchar)9)
    pos++;
  int isfloat = 0;
  if (pos < end_pos && *pos == '.') {
    isfloat = 1;
    pos++;
    while (pos < end_pos && (uchar)(*pos - '0') <= (uchar)9)
      pos++;
  }
  if (pos < end_pos && (*pos == 'e' || *pos == 'E')) {
    isfloat = 1;
    pos++;
    if (pos < end_pos && (*pos == '+' || *pos == '-'))
      pos++;
    while (pos < end_pos && (uchar)(*pos - '0') <= (uchar)9)
      pos++;
  }

  // Numbers must end on whitespace or punctuation
  if (pos < end_pos) {
    switch (*pos) {
    case ' ': case '\t': case '\r': case '\n':
    case '[': case ']':  case '{':  case '}':
    case ',': case ':':
      break;
    default:
      state->pos = (ulong)(start_pos - state->json);
      json_lex_sprintf(state, "malformed number at position %lu in json", state->pos);
      return JSON_TOKEN_ERROR;
    }
  }

  // Store the number in string form
  ulong text_sz = (ulong)(pos - start_pos);
  if( text_sz >= state->last_str_alloc ) {
    state->pos = (ulong)(start_pos - state->json);
    json_lex_sprintf(state, "malformed number at position %lu in json", state->pos);
    return JSON_TOKEN_ERROR;
  }
  fd_memcpy(state->last_str, start_pos, text_sz);
  state->last_str[text_sz] = '\0';
  state->last_str_sz = text_sz;
  state->pos = (ulong)(pos - state->json);
  return (isfloat ? JSON_TOKEN_FLOAT : JSON_TOKEN_INTEGER);
}

// Validate a segment of UTF-8 encoded test. If an error is found, a
// pointer to it is returned. A NULL is returned if there is no error.
static const char* json_lex_validate_encoding(const char* t, const char* t_end) {
  /****
Code Points		First Byte	Second Byte	Third Byte	Fourth Byte
U+0020..U+007F		20..7F
U+0080..U+07FF		C2..DF		80..BF
U+0800..U+0FFF		E0		A0..BF		80..BF
U+1000..U+CFFF		E1..EC		80..BF		80..BF
U+D000..U+D7FF		ED		80..9F		80..BF
U+E000..U+FFFF		EE..EF		80..BF		80..BF
U+10000..U+3FFFF	F0		90..BF		80..BF		80..BF
U+40000..U+FFFFF	F1..F3		80..BF		80..BF		80..BF
U+100000..U+10FFFF	F4		80..8F		80..BF		80..BF
Also, '"' and '\' are not allowed.
  ****/
  // Fast case lookup table based on the leading byte
  static const uchar case_table[0x100] = {
    0 /* 00 */, 0 /* 01 */, 0 /* 02 */, 0 /* 03 */, 0 /* 04 */, 0 /* 05 */, 0 /* 06 */, 0 /* 07 */,
    0 /* 08 */, 1 /* 09 */, 1 /* 0a */, 0 /* 0b */, 1 /* 0c */, 0 /* 0d */, 0 /* 0e */, 0 /* 0f */,
    0 /* 10 */, 0 /* 11 */, 0 /* 12 */, 0 /* 13 */, 0 /* 14 */, 0 /* 15 */, 0 /* 16 */, 0 /* 17 */,
    0 /* 18 */, 0 /* 19 */, 0 /* 1a */, 0 /* 1b */, 0 /* 1c */, 0 /* 1d */, 0 /* 1e */, 0 /* 1f */,
    1 /* 20 */, 1 /* 21 */, 0 /* 22 */, 1 /* 23 */, 1 /* 24 */, 1 /* 25 */, 1 /* 26 */, 1 /* 27 */,
    1 /* 28 */, 1 /* 29 */, 1 /* 2a */, 1 /* 2b */, 1 /* 2c */, 1 /* 2d */, 1 /* 2e */, 1 /* 2f */,
    1 /* 30 */, 1 /* 31 */, 1 /* 32 */, 1 /* 33 */, 1 /* 34 */, 1 /* 35 */, 1 /* 36 */, 1 /* 37 */,
    1 /* 38 */, 1 /* 39 */, 1 /* 3a */, 1 /* 3b */, 1 /* 3c */, 1 /* 3d */, 1 /* 3e */, 1 /* 3f */,
    1 /* 40 */, 1 /* 41 */, 1 /* 42 */, 1 /* 43 */, 1 /* 44 */, 1 /* 45 */, 1 /* 46 */, 1 /* 47 */,
    1 /* 48 */, 1 /* 49 */, 1 /* 4a */, 1 /* 4b */, 1 /* 4c */, 1 /* 4d */, 1 /* 4e */, 1 /* 4f */,
    1 /* 50 */, 1 /* 51 */, 1 /* 52 */, 1 /* 53 */, 1 /* 54 */, 1 /* 55 */, 1 /* 56 */, 1 /* 57 */,
    1 /* 58 */, 1 /* 59 */, 1 /* 5a */, 1 /* 5b */, 0 /* 5c */, 1 /* 5d */, 1 /* 5e */, 1 /* 5f */,
    1 /* 60 */, 1 /* 61 */, 1 /* 62 */, 1 /* 63 */, 1 /* 64 */, 1 /* 65 */, 1 /* 66 */, 1 /* 67 */,
    1 /* 68 */, 1 /* 69 */, 1 /* 6a */, 1 /* 6b */, 1 /* 6c */, 1 /* 6d */, 1 /* 6e */, 1 /* 6f */,
    1 /* 70 */, 1 /* 71 */, 1 /* 72 */, 1 /* 73 */, 1 /* 74 */, 1 /* 75 */, 1 /* 76 */, 1 /* 77 */,
    1 /* 78 */, 1 /* 79 */, 1 /* 7a */, 1 /* 7b */, 1 /* 7c */, 1 /* 7d */, 1 /* 7e */, 1 /* 7f */,
    0 /* 80 */, 0 /* 81 */, 0 /* 82 */, 0 /* 83 */, 0 /* 84 */, 0 /* 85 */, 0 /* 86 */, 0 /* 87 */,
    0 /* 88 */, 0 /* 89 */, 0 /* 8a */, 0 /* 8b */, 0 /* 8c */, 0 /* 8d */, 0 /* 8e */, 0 /* 8f */,
    0 /* 90 */, 0 /* 91 */, 0 /* 92 */, 0 /* 93 */, 0 /* 94 */, 0 /* 95 */, 0 /* 96 */, 0 /* 97 */,
    0 /* 98 */, 0 /* 99 */, 0 /* 9a */, 0 /* 9b */, 0 /* 9c */, 0 /* 9d */, 0 /* 9e */, 0 /* 9f */,
    0 /* a0 */, 0 /* a1 */, 0 /* a2 */, 0 /* a3 */, 0 /* a4 */, 0 /* a5 */, 0 /* a6 */, 0 /* a7 */,
    0 /* a8 */, 0 /* a9 */, 0 /* aa */, 0 /* ab */, 0 /* ac */, 0 /* ad */, 0 /* ae */, 0 /* af */,
    0 /* b0 */, 0 /* b1 */, 0 /* b2 */, 0 /* b3 */, 0 /* b4 */, 0 /* b5 */, 0 /* b6 */, 0 /* b7 */,
    0 /* b8 */, 0 /* b9 */, 0 /* ba */, 0 /* bb */, 0 /* bc */, 0 /* bd */, 0 /* be */, 0 /* bf */,
    0 /* c0 */, 0 /* c1 */, 2 /* c2 */, 2 /* c3 */, 2 /* c4 */, 2 /* c5 */, 2 /* c6 */, 2 /* c7 */,
    2 /* c8 */, 2 /* c9 */, 2 /* ca */, 2 /* cb */, 2 /* cc */, 2 /* cd */, 2 /* ce */, 2 /* cf */,
    2 /* d0 */, 2 /* d1 */, 2 /* d2 */, 2 /* d3 */, 2 /* d4 */, 2 /* d5 */, 2 /* d6 */, 2 /* d7 */,
    2 /* d8 */, 2 /* d9 */, 2 /* da */, 2 /* db */, 2 /* dc */, 2 /* dd */, 2 /* de */, 2 /* df */,
    3 /* e0 */, 4 /* e1 */, 4 /* e2 */, 4 /* e3 */, 4 /* e4 */, 4 /* e5 */, 4 /* e6 */, 4 /* e7 */,
    4 /* e8 */, 4 /* e9 */, 4 /* ea */, 4 /* eb */, 4 /* ec */, 5 /* ed */, 6 /* ee */, 6 /* ef */,
    7 /* f0 */, 8 /* f1 */, 8 /* f2 */, 8 /* f3 */, 9 /* f4 */, 0 /* f5 */, 0 /* f6 */, 0 /* f7 */,
    0 /* f8 */, 0 /* f9 */, 0 /* fa */, 0 /* fb */, 0 /* fc */, 0 /* fd */, 0 /* fe */, 0 /* ff */
  };
  while (t < t_end) {
    switch (case_table[(uchar)t[0]]) {
    case 0: // error
      return t;
    case 1: // 20..7F
      ++t;
      break;
    case 2: // C2..DF
      // Determine if a character is in a range
#define MATCH(_ch_, _low_, _high_) ((uchar)_ch_ - (uchar)_low_ <= (uchar)(_high_ - _low_))
      if (!(t+2 <= t_end && MATCH(t[1], 0x80, 0xBF)))
        return t;
      t += 2;
      break;
    case 3: // E0
      if (!(t+3 <= t_end && MATCH(t[1], 0xA0, 0xBF) && MATCH(t[2], 0x80, 0xBF)))
        return t;
      t += 3;
      break;
    case 4: // E1..EC
      if (!(t+3 <= t_end && MATCH(t[1], 0x80, 0xBF) && MATCH(t[2], 0x80, 0xBF)))
        return t;
      t += 3;
      break;
    case 5: // ED
      if (!(t+3 <= t_end && MATCH(t[1], 0x80, 0x9F) && MATCH(t[2], 0x80, 0xBF)))
        return t;
      t += 3;
      break;
    case 6: // EE..EF
      if (!(t+3 <= t_end && MATCH(t[1], 0x80, 0xBF) && MATCH(t[2], 0x80, 0xBF)))
        return t;
      t += 3;
      break;
    case 7: // F0
      if (!(t+4 <= t_end && MATCH(t[1], 0x90, 0xBF) && MATCH(t[2], 0x80, 0xBF) && MATCH(t[3], 0x80, 0xBF)))
        return t;
      t += 4;
      break;
    case 8: // F1..F3
      if (!(t+4 <= t_end && MATCH(t[1], 0x80, 0xBF) && MATCH(t[2], 0x80, 0xBF) && MATCH(t[3], 0x80, 0xBF)))
        return t;
      t += 4;
      break;
    case 9: // F4
      if (!(t+4 <= t_end && MATCH(t[1], 0x80, 0x8F) && MATCH(t[2], 0x80, 0xBF) && MATCH(t[3], 0x80, 0xBF)))
        return t;
      t += 4;
      break;
    }
#undef MATCH
  }
  return NULL;
}

// Parse a json string. All characters are decoded to pure UTF-8
static long json_lex_parse_string(struct json_lex_state* state, const char* start_pos) {
  state->last_str_sz = 0;
  state->last_str[0] = '\0';
  const char* pos = start_pos + 1; // Skip leading quote
  const char* const end_pos = state->json + state->json_sz;
  // Loop over all characters
  while (pos < end_pos) {
    if (*pos == '"') {
      state->pos = (ulong)(pos + 1 - state->json);
      return JSON_TOKEN_STRING;
    }

    if (*pos != '\\') {
      // A segment of simple text without escapes
      const char* s = pos;
      do {
        pos++;
      } while (pos < end_pos && *pos != '"' && *pos != '\\');
      // Make sure the text is correctly encoded
      const char* err_pos = json_lex_validate_encoding(s, pos);
      if (err_pos) {
        // Report the error
        state->pos = (ulong)(start_pos - state->json);
        json_lex_sprintf(state, "invalid character literal at position %ld in json", err_pos - state->json);
        return JSON_TOKEN_ERROR;
      }
      // Just copy out the text
      fd_memcpy(json_lex_append_prepare(state, (ulong)(pos - s)), s, (ulong)(pos - s));
      continue; // break out of switch and continue outer loop
    }

    // Process an escape
    if (pos + 2 > end_pos)
      break;
    uint ch;
    switch (pos[1]) {
      // Simple escapes
    case '"':  ch = 0x22; pos += 2; break;
    case '\\': ch = 0x5C; pos += 2; break;
    case '/':  ch = 0x2F; pos += 2; break;
    case 'b':  ch = 0x8;  pos += 2; break;
    case 'f':  ch = 0xC;  pos += 2; break;
    case 'n':  ch = 0xA;  pos += 2; break;
    case 'r':  ch = 0xD;  pos += 2; break;
    case 't':  ch = 0x9;  pos += 2; break;

    case 'u': // Hexadecimal escape
      if (pos + 6 <= end_pos) {
        ch = 0;
        unsigned i;
        for (i = 2; i < 6; ++i) {
          char j = pos[i];
          if ((uchar)(j - '0') <= (uchar)9)
            ch = (ch<<4) + (uchar)(j - '0');
          else if ((uchar)(j - 'a') <= (uchar)5)
            ch = (ch<<4) + (uchar)(j - ('a' - 10));
          else if ((uchar)(j - 'A') <= (uchar)5)
            ch = (ch<<4) + (uchar)(j - ('A' - 10));
          else
            break;
        }
        // See if the loop succeeded
        if (i == 6) {
          pos += 6;
          break; // Fall out of switch to append_char
        }
      }
      // Fall through to error case
      __attribute__((fallthrough));
    default:
      state->pos = (ulong)(start_pos - state->json);
      json_lex_sprintf(state, "invalid character literal at position %ld in json", pos - state->json);
      return JSON_TOKEN_ERROR;
    }
    // Append the escaped character
    json_lex_append_char(state, ch);

  }
  // We were looking for a closing quote
  state->pos = (ulong)(start_pos - state->json);
  json_lex_sprintf(state, "unterminated string starting at position %lu in json", state->pos);
  return JSON_TOKEN_ERROR;
}

// Report a lexical error
static long json_lex_error(struct json_lex_state* state, const char* pos) {
  state->pos = (ulong)(pos - state->json);
  json_lex_sprintf(state, "lexical error at position %lu in json", state->pos);
  return JSON_TOKEN_ERROR;
}

// Scan the next lexical token
long json_lex_next_token(struct json_lex_state* state) {
  const char* pos = state->json + state->pos;
  const char* end_pos = state->json + state->json_sz;
  while (pos < end_pos) {
    switch (*pos) {
      // Whitespace
    case ' ': case '\t': case '\r': case '\n':
      ++pos;
      continue;

      // Single character cases
    case '[':
      state->pos = (ulong)(pos + 1 - state->json);
      return state->last_tok = JSON_TOKEN_LBRACKET;
    case ']':
      state->pos = (ulong)(pos + 1 - state->json);
      return state->last_tok = JSON_TOKEN_RBRACKET;
    case '{':
      state->pos = (ulong)(pos + 1 - state->json);
      return state->last_tok = JSON_TOKEN_LBRACE;
    case '}':
      state->pos = (ulong)(pos + 1 - state->json);
      return state->last_tok = JSON_TOKEN_RBRACE;
    case ',':
      state->pos = (ulong)(pos + 1 - state->json);
      return state->last_tok = JSON_TOKEN_COMMA;
    case ':':
      state->pos = (ulong)(pos + 1 - state->json);
      return state->last_tok = JSON_TOKEN_COLON;

    case 'n': // null
      if (pos + 4 <= end_pos && pos[1] == 'u' && pos[2] == 'l' && pos[3] == 'l') {
        state->pos = (ulong)(pos + 4 - state->json);
        return state->last_tok = JSON_TOKEN_NULL;
      }
      return state->last_tok = json_lex_error(state, pos);

    case 't': // true
      if (pos + 4 <= end_pos && pos[1] == 'r' && pos[2] == 'u' && pos[3] == 'e') {
        state->pos = (ulong)(pos + 4 - state->json);
        state->last_bool = 1;
        return state->last_tok = JSON_TOKEN_BOOL;
      }
      return state->last_tok = json_lex_error(state, pos);

    case 'f': // false
      if (pos + 5 <= end_pos && pos[1] == 'a' && pos[2] == 'l' && pos[3] == 's' && pos[4] == 'e') {
        state->pos = (ulong)(pos + 5 - state->json);
        state->last_bool = 0;
        return state->last_tok = JSON_TOKEN_BOOL;
      }
      return state->last_tok = json_lex_error(state, pos);

      // number
    case '-': case '0': case '1': case '2': case '3': case '4': case '5':
    case '6': case '7': case '8': case '9':
      return state->last_tok = json_lex_parse_number(state, pos);

    case '"': // string
      return state->last_tok = json_lex_parse_string(state, pos);

    default: // Any other character
      return state->last_tok = json_lex_error(state, pos);
    }
  }
  state->pos = (ulong)(pos - state->json);
  return state->last_tok = JSON_TOKEN_END;
}

const char* json_lex_get_text(json_lex_state_t* state, ulong* sz) {
  if (sz != NULL)
    *sz = state->last_str_sz;
  return state->last_str;
}

// Convert the string to an integer (assuming decimal representation)
long json_lex_as_int(json_lex_state_t* lex) {
  // Gangster conversion of decimal text to int
  const char* i = lex->last_str;
  const char* i_end = i + lex->last_str_sz;
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
double json_lex_as_float(json_lex_state_t* lex) {
  return strtod(lex->last_str, NULL);
}

// Reserve space at the end of the string for additional text. The
// pointer to the new space is returned (e.g. for memcpy).
static char* json_lex_append_prepare(json_lex_state_t* lex, ulong sz) {
  // Get the new string size
  ulong new_sz = lex->last_str_sz + sz;
  // Make sure there is enough room, including a null terminator
  if (new_sz + 1 > lex->last_str_alloc) {
    // Grow the allocation
    do {
      lex->last_str_alloc <<= 1;
    } while (new_sz + 1 > lex->last_str_alloc);
    char* oldstr = lex->last_str;
    lex->last_str = (char*)fd_scratch_alloc(1, lex->last_str_alloc);
    // Copy the old content to the new space
    fd_memcpy(lex->last_str, oldstr, lex->last_str_sz);
  }
  // Stick on a null terminator
  char* res = lex->last_str + lex->last_str_sz;
  res[sz] = '\0';
  lex->last_str_sz = new_sz;
  return res;
}

// Append a unicode character to the string. The character is
// converted to UTF-8 encoding.
static void json_lex_append_char(json_lex_state_t* lex, uint ch) {
  // Encode in UTF-8
  if (ch < 0x80) {
    char* dest = json_lex_append_prepare(lex, 1);
    *dest =     (char)ch;
  } else if (ch < 0x800) {
    char* dest = json_lex_append_prepare(lex, 2);
    *(dest++) = (char)((ch>>6) | 0xC0);
    *dest =     (char)((ch & 0x3F) | 0x80);
  } else if (ch < 0x10000) {
    char* dest = json_lex_append_prepare(lex, 3);
    *(dest++) = (char)((ch>>12) | 0xE0);
    *(dest++) = (char)(((ch>>6) & 0x3F) | 0x80);
    *dest =     (char)((ch & 0x3F) | 0x80);
  } else if (ch < 0x110000) {
    char* dest = json_lex_append_prepare(lex, 4);
    *(dest++) = (char)((ch>>18) | 0xF0);
    *(dest++) = (char)(((ch>>12) & 0x3F) | 0x80);
    *(dest++) = (char)(((ch>>6) & 0x3F) | 0x80);
    *dest =     (char)((ch & 0x3F) | 0x80);
  }
}

// Replaces the string with the result of a formatted printf.
void json_lex_sprintf(json_lex_state_t* lex, const char* format, ...) {
  va_list ap;
  va_start(ap, format);
  int r = vsnprintf(lex->last_str, lex->last_str_alloc, format, ap);
  va_end(ap);
  if (r >= 0) {
    if ((ulong)r >= lex->last_str_alloc) {
      /* Try again with more space */
      do {
        lex->last_str_alloc <<= 1;
      } while ((ulong)r + 1U > lex->last_str_alloc);
      lex->last_str = (char*)fd_scratch_alloc(1, lex->last_str_alloc);
      va_list ap;
      va_start(ap, format);
      r = vsnprintf(lex->last_str, lex->last_str_alloc, format, ap);
      va_end(ap);
    }
    lex->last_str_sz = (ulong)r;
  } else {
    lex->last_str_sz = 0;
    lex->last_str[0] = '\0';
  }
}
