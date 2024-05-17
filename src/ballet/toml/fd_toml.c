#define _DEFAULT_SOURCE
#include "fd_toml.h"
#include "../../util/fd_util.h"
#include <ctype.h>
#include <time.h>

/* Implementation note:

   The lexer/parser of fd_toml.c is a simpler backtracking recursive
   descent parser.  A minimal amount of lookahead tuning is implemented;
   mostly just fast failure paths.  Obvious performance wins are
   possible by adding more speculative lookaheads that lead the CPU down
   "happy paths" such as long strings of ASCII.

   The indexer into fd_pod blindly inserts using fd_pod_insert, which
   may not be the most efficient allocation strategy. */

/* FD_TOML_PATH_MAX is the max supported pod path length. */

#define FD_TOML_PATH_MAX (512UL)

/* fd_toml_cur_t is a cursor object.  It is safe to copy this object via
   assignment to implement backtracking. */

struct fd_toml_cur {
  ulong        lineno;
  char const * data;
};

typedef struct fd_toml_cur fd_toml_cur_t;

/* fd_toml_parser_t is the internal parser state.  It implements the
   lexer/parser itself, logic to unescape and buffer, and logic to
   compose the data into an fd_pod_t. */

struct fd_toml_parser {
  fd_toml_cur_t c;
  char const *  data_end;     /* points one past EOF */
  long          error;        /* hint: fatal pod error occurred */
  uchar *       pod;          /* pod provided by user */

  /* The current buffered string (either for both keys and values) */

  uchar *       scratch;      /* base of scratch buf */
  uchar *       scratch_cur;  /* next free byte in scratch buf */
  uchar *       scratch_end;  /* points one past scratch buf */

  /* Buffered keys */

  uint          key_len;
  char          key[ FD_TOML_PATH_MAX ];  /* cstr */
};

typedef struct fd_toml_parser fd_toml_parser_t;

/* Accumulate and insert data into fd_pod *****************************/

static void
fd_toml_str_init( fd_toml_parser_t * parser ) {
  parser->scratch_cur = parser->scratch;
}

static int
fd_toml_str_append( fd_toml_parser_t * parser,
                    void const *       data,
                    ulong              sz ) {

  if( FD_UNLIKELY( parser->scratch_cur + sz >= parser->scratch_end ) ) {
    parser->error = FD_TOML_ERR_SCRATCH;
    return 0;
  }

  fd_memcpy( parser->scratch_cur, data, sz );
  parser->scratch_cur += sz;
  return 1;
}

static int
fd_toml_str_append_byte( fd_toml_parser_t * parser,
                         int                c ) {

  if( FD_UNLIKELY( parser->scratch_cur >= parser->scratch_end ) ) {
    parser->error = FD_TOML_ERR_SCRATCH;
    return 0;
  }

  parser->scratch_cur[0] = (uchar)c;
  parser->scratch_cur++;
  return 1;
}

/* fd_toml_str_append_utf8 appends the UTF-8 encoding of the given
   Unicode code point (<=UINT_MAX).  If rune is not a valid code point,
   writes the replacement code point instead. */

static int
fd_toml_str_append_utf8( fd_toml_parser_t * parser,
                         long               rune ) {

  if( FD_UNLIKELY( parser->scratch_cur + 4 >= parser->scratch_end ) ) {
    parser->error = FD_TOML_ERR_SCRATCH;
    return 0;
  }

  parser->scratch_cur = (uchar *)fd_cstr_append_utf8( (char *)parser->scratch_cur, (uint)rune );
  return 1;
}

/* Backtracking recursive-descent parser ******************************/

/* fd_toml_advance advances the parser cursor by 'n' chars.  Counts line
   numbers while advancing.  If you now for sure that the next 'n' chars
   don't contain any new lines, use fd_toml_advance_inline instead. */

static void /* consider aggressive inline */
fd_toml_advance( fd_toml_parser_t * parser,
                 ulong              n ) {

  char const * p    = parser->c.data;
  char const * next = p + n;
  if( FD_UNLIKELY( next > parser->data_end ) ) {
    FD_LOG_CRIT(( "fd_toml_advance out of bounds" ));
  }

  /* consider unroll */
  ulong lines = 0UL;
  for( ; p < next; p++ ) {
    if( *p == '\n' ) lines++;
  }

  parser->c.lineno += lines;
  parser->c.data    = next;
}

static inline void
fd_toml_advance_inline( fd_toml_parser_t * parser,
                        ulong              n ) {
  parser->c.data += n;
}

static int
fd_toml_upsert_empty_pod( fd_toml_parser_t * parser ) {
  if( !fd_pod_query_subpod( parser->pod, parser->key ) ) {
    uchar   subpod_mem[ FD_POD_FOOTPRINT_MIN ];
    uchar * subpod = fd_pod_join( fd_pod_new( subpod_mem, FD_POD_FOOTPRINT_MIN ) );
    if( FD_UNLIKELY( !fd_pod_insert( parser->pod, parser->key, FD_POD_VAL_TYPE_SUBPOD, FD_POD_FOOTPRINT_MIN, subpod ) ) ) {
      parser->error = FD_TOML_ERR_POD;
      return 0;
    }
    fd_pod_delete( fd_pod_leave( subpod ) );
  }
  return 1;
}

/* fd_toml_avail returns the number of bytes available for parsing. */

FD_FN_PURE static inline ulong
fd_toml_avail( fd_toml_parser_t const * parser ) {
  if( FD_UNLIKELY( parser->c.data > parser->data_end ) ) {
    FD_LOG_CRIT(( "Parse cursor is out of bounds" ));
  }
  return (ulong)parser->data_end - (ulong)parser->c.data;
}

#define SUB_PARSE( fn_call )                          \
  __extension__ ({                                    \
    fd_toml_cur_t const _macro_backtrack = parser->c; \
    int ret = fn_call;                                \
    if( FD_UNLIKELY( !ret ) ) {                       \
      parser->c = _macro_backtrack;                   \
    }                                                 \
    ret;                                              \
  })

#define EXPECT_CHAR(_c)                                      \
  do {                                                       \
    if( FD_UNLIKELY( !fd_toml_avail( parser )  ) ) return 0; \
    if( FD_UNLIKELY( parser->c.data[0] != (_c) ) ) return 0; \
    fd_toml_advance_inline( parser, 1UL );                   \
  } while(0);

/* Begin fd_toml_parse_{...} functions.  All these functions attempt
   take a single argument, the parser.  Each function attempts to match
   a token and returns 1 on success.  If the token was not matched,
   returns 0.  On success, the cursor is advanced to one past the read
   token.  On failure, the cursor may arbitrarily advance within bounds.
   Parsers can gracefully recover from failure (backtrack) by restoring
   the fd_toml_cur_t object to its original state. */

static int fd_toml_parse_keyval( fd_toml_parser_t * parser );
static int fd_toml_parse_val   ( fd_toml_parser_t * parser );

/* ws = *wschar
   wschar =  %x20  ; Space
   wschar =/ %x09  ; Horizontal tab */

static int
fd_toml_parse_ws( fd_toml_parser_t * parser ) {

  while( fd_toml_avail( parser ) ) {
    char c = parser->c.data[0];
    if( c != ' ' && c != '\t' ) break;
    fd_toml_advance_inline( parser, 1UL );
  }

  return 1;
}

/* comment-start-symbol = %x23
   non-ascii = %x80-D7FF / %xE000-10FFFF
   non-eol = %x09 / %x20-7F / non-ascii

   comment = comment-start-symbol *non-eol */

static int
fd_toml_parse_comment( fd_toml_parser_t * parser ) {
  if( FD_UNLIKELY( !fd_toml_avail( parser ) ) ) return 0;
  if( FD_UNLIKELY( parser->c.data[0] != '#' ) ) return 0;
  fd_toml_advance_inline( parser, 1UL );

  while( fd_toml_avail( parser ) ) {
    uint c = (uchar)parser->c.data[0];
    if( FD_LIKELY( (c==0x09) |
                   (c>=0x20 && c<0x7F) |
                   (c>=0x80) ) ) {
      fd_toml_advance_inline( parser, 1UL );
    } else {
      break;
    }
  }

  return 1;
}

/* quotation-mark = %x22 */

static int
fd_toml_parse_quotation_mark( fd_toml_parser_t * parser ) {
  if( FD_UNLIKELY( !fd_toml_avail( parser ) ) ) return 0;
  if( FD_UNLIKELY( parser->c.data[0] != '"' ) ) return 0;
  fd_toml_advance_inline( parser, 1UL );
  return 1;
}

/* basic-unescaped = wschar / %x21 / %x23-5B / %x5D-7E / non-ascii */

static int
fd_toml_parse_basic_unescaped( fd_toml_parser_t * parser ) {

  if( FD_UNLIKELY( !fd_toml_avail( parser ) ) ) return 0;

  int c = (uchar)parser->c.data[0];
  if( FD_LIKELY( (c==' ') | (c=='\t') |
                 (c==0x21)            |
                 (c>=0x23 && c<=0x5B)  |
                 (c>=0x5D && c<=0x7E)  |
                 (c>=0x80) ) ) { /* ok */ }
  else {
    return 0;
  }

  fd_toml_str_append_byte( parser, (uchar)c );
  fd_toml_advance( parser, 1UL );
  return 1;
}

/* fd_toml_xdigit converts a char to a hex digit.  Assumes that the
   char matches [0-9a-fA-F] */

FD_FN_CONST static inline uint
fd_toml_xdigit( int c ) {
  c = tolower( c );
  c = fd_int_if( c>'9', c-'a'+10, c-'0' );
  return (uint)c;
}

/* escaped = escape escape-seq-char
   escape = %x5C                   ; \
   escape-seq-char =  %x22         ; "    quotation mark  U+0022
   escape-seq-char =/ %x5C         ; \    reverse solidus U+005C
   escape-seq-char =/ %x62         ; b    backspace       U+0008
   escape-seq-char =/ %x66         ; f    form feed       U+000C
   escape-seq-char =/ %x6E         ; n    line feed       U+000A
   escape-seq-char =/ %x72         ; r    carriage return U+000D
   escape-seq-char =/ %x74         ; t    tab             U+0009
   escape-seq-char =/ %x75 4HEXDIG ; uXXXX                U+XXXX
   escape-seq-char =/ %x55 8HEXDIG ; UXXXXXXXX            U+XXXXXXXX */

static int
fd_toml_parse_escaped( fd_toml_parser_t * parser ) {

  if( FD_UNLIKELY( fd_toml_avail( parser ) < 2UL ) ) return 0;
  if( FD_UNLIKELY( parser->c.data[0] != '\\'     ) ) return 0;
  int kind = parser->c.data[1];
  fd_toml_advance_inline( parser, 2UL );

  int valid = 1;
  uint rune;
  switch( kind ) {
  case 'b':
    fd_toml_str_append_byte( parser, '\b' );
    return 1;
  case 'f':
    fd_toml_str_append_byte( parser, '\f' );
    return 1;
  case 'n':
    fd_toml_str_append_byte( parser, '\n' );
    return 1;
  case 'r':
    fd_toml_str_append_byte( parser, '\r' );
    return 1;
  case 't':
    fd_toml_str_append_byte( parser, '\t' );
    return 1;
  case '"':
  case '\\':
    fd_toml_str_append_byte( parser, kind );
    return 1;
  case 'u':
    if( FD_UNLIKELY( fd_toml_avail( parser ) < 4UL ) ) return 0;
    for( ulong j=0; j<4; j++ ) valid &= ( !!isxdigit( parser->c.data[j] ) );
    if( FD_UNLIKELY( !valid ) ) return 0;
    rune  = ( fd_toml_xdigit( parser->c.data[0] )<<12 );
    rune |= ( fd_toml_xdigit( parser->c.data[1] )<< 8 );
    rune |= ( fd_toml_xdigit( parser->c.data[2] )<< 4 );
    rune |= ( fd_toml_xdigit( parser->c.data[3] )     );
    if( FD_UNLIKELY( !fd_toml_str_append_utf8( parser, rune ) ) ) return 0;
    fd_toml_advance_inline( parser, 4UL );
    return 1;
  case 'U':
    if( FD_UNLIKELY( fd_toml_avail( parser ) < 8UL ) ) return 0;
    for( ulong j=0; j<8; j++ ) valid &= ( !!isxdigit( parser->c.data[j] ) );
    if( FD_UNLIKELY( !valid ) ) return 0;
    rune  = ( fd_toml_xdigit( parser->c.data[0] )<<28 );
    rune |= ( fd_toml_xdigit( parser->c.data[1] )<<24 );
    rune |= ( fd_toml_xdigit( parser->c.data[2] )<<20 );
    rune |= ( fd_toml_xdigit( parser->c.data[3] )<<16 );
    rune |= ( fd_toml_xdigit( parser->c.data[4] )<<12 );
    rune |= ( fd_toml_xdigit( parser->c.data[5] )<< 8 );
    rune |= ( fd_toml_xdigit( parser->c.data[6] )<< 4 );
    rune |= ( fd_toml_xdigit( parser->c.data[7] )     );
    if( FD_UNLIKELY( !fd_toml_str_append_utf8( parser, rune ) ) ) return 0;
    fd_toml_advance_inline( parser, 8UL );
    return 1;
  default:
    return 0;
  }
}

/* basic-char = basic-unescaped / escaped */

static int
fd_toml_parse_basic_char( fd_toml_parser_t * parser ) {
  if( FD_LIKELY( SUB_PARSE( fd_toml_parse_basic_unescaped( parser ) ) ) ) return 1;
  if( FD_LIKELY( SUB_PARSE( fd_toml_parse_escaped        ( parser ) ) ) ) return 1;
  return 0;
}

/* basic-string = quotation-mark *basic-char quotation-mark */

static int
fd_toml_parse_basic_string( fd_toml_parser_t * parser ) {
  if( FD_UNLIKELY( !SUB_PARSE( fd_toml_parse_quotation_mark( parser ) ) ) ) return 0;
  fd_toml_str_init( parser );
  while( SUB_PARSE( fd_toml_parse_basic_char( parser ) ) ) {}
  if( FD_UNLIKELY( !SUB_PARSE( fd_toml_parse_quotation_mark( parser ) ) ) ) return 0;
  return 1;
}

/* apostrophe = %x27 ; ' apostrophe */

static int
fd_toml_parse_apostrophe( fd_toml_parser_t * parser ) {
  if( FD_UNLIKELY( !fd_toml_avail( parser )  ) ) return 0;
  if( FD_UNLIKELY( parser->c.data[0] != '\'' ) ) return 0;
  fd_toml_advance_inline( parser, 1UL );
  return 1;
}

/* literal-char = %x09 / %x20-26 / %x28-7E / non-ascii */

static int
fd_toml_parse_literal_char( fd_toml_parser_t * parser ) {

  if( FD_UNLIKELY( !fd_toml_avail( parser ) ) ) return 0;

  int c = (uchar)parser->c.data[0];
  if( FD_LIKELY( (c==0x09) |
                 (c>=0x20 && c<=0x26) |
                 (c>=0x28 && c<=0x7E) |
                 (c>=0x80) ) ) { /* ok */ }
  else {
    return 0;
  }

  fd_toml_str_append_byte( parser, c );
  fd_toml_advance( parser, 1UL );
  return 1;
}

/* literal-string = apostrophe *literal-char apostrophe */

static int
fd_toml_parse_literal_string( fd_toml_parser_t * parser ) {
  if( FD_UNLIKELY( !SUB_PARSE( fd_toml_parse_apostrophe( parser ) ) ) ) return 0;
  fd_toml_str_init( parser );
  while( SUB_PARSE( fd_toml_parse_literal_char( parser ) ) ) {}
  if( FD_UNLIKELY( !SUB_PARSE( fd_toml_parse_apostrophe( parser ) ) ) ) return 0;
  return 1;
}

/* quoted-key = basic-string / literal-string */

static int
fd_toml_parse_quoted_key( fd_toml_parser_t * parser ) {
  if( FD_LIKELY( SUB_PARSE( fd_toml_parse_basic_string  ( parser ) ) ) ) return 1;
  if( FD_LIKELY( SUB_PARSE( fd_toml_parse_literal_string( parser ) ) ) ) return 1;
  return 0;
}

/* unquoted-key = 1*( ALPHA / DIGIT / %x2D / %x5F ) ; A-Z / a-z / 0-9 / - / _ */

static int
fd_toml_is_unquoted_key_char( int c ) {
  return (c>='A' && c<='Z') |
         (c>='a' && c<='z') |
         (c>='0' && c<='9') |
         (c=='-') |
         (c=='_');
}

static int
fd_toml_parse_unquoted_key( fd_toml_parser_t * parser ) {
  if( FD_UNLIKELY( !fd_toml_avail( parser )           ) ) return 0;
  int c = (uchar)parser->c.data[0];
  if( FD_UNLIKELY( !fd_toml_is_unquoted_key_char( c ) ) ) return 0;
  fd_toml_str_init( parser );

  fd_toml_str_append_byte( parser, c );
  fd_toml_advance_inline( parser, 1UL );

  while( fd_toml_avail( parser ) ) {
    c = (uchar)parser->c.data[0];
    if( FD_LIKELY( fd_toml_is_unquoted_key_char( c ) ) ) {
      fd_toml_str_append_byte( parser, c );
      fd_toml_advance_inline( parser, 1UL );
    } else {
      break;
    }
  }
  return 1;
}

/* simple-key = quoted-key / unquoted-key */

static int
fd_toml_parse_simple_key( fd_toml_parser_t * parser ) {
  if( FD_LIKELY( SUB_PARSE( fd_toml_parse_quoted_key  ( parser ) ) ) ) goto add;
  if( FD_LIKELY( SUB_PARSE( fd_toml_parse_unquoted_key( parser ) ) ) ) goto add;
  return 0;

add:
  do {
    uint  old_key_len = parser->key_len;
    ulong suffix_len  = (ulong)parser->scratch_cur - (ulong)parser->scratch;
    ulong key_len     = (ulong)old_key_len + suffix_len + 1;
    if( FD_UNLIKELY( key_len > sizeof(parser->key)  ) ) {
      FD_LOG_WARNING(( "oversz key: \"%.*s%.*s\"",
                      (int)old_key_len, parser->key,
                      (int)suffix_len,  parser->scratch ));
      parser->error = FD_TOML_ERR_KEY;
      return 0;
    }

    char * key_cur = fd_cstr_init( parser->key + old_key_len );
    key_cur = fd_cstr_append_text( key_cur, (char const *)parser->scratch, suffix_len );
    fd_cstr_fini( key_cur );
    parser->key_len = (uint)( key_cur - parser->key );
    return 1;
  } while(0);
}

/* dot-sep = ws %x2E ws  ; . Period */

static int
fd_toml_parse_dot_sep( fd_toml_parser_t * parser ) {
  fd_toml_parse_ws( parser );
  EXPECT_CHAR( '.' );
  fd_toml_parse_ws( parser );
  return 1;
}

/* dotted-key = simple-key 1*( dot-sep simple-key ) */

static int
fd_toml_parse_dotted_key( fd_toml_parser_t * parser ) {
  if( FD_UNLIKELY( !SUB_PARSE( fd_toml_parse_simple_key( parser ) ) ) ) return 0;
  while( fd_toml_avail( parser ) ) {
    if( FD_UNLIKELY( !SUB_PARSE( fd_toml_parse_dot_sep( parser ) ) ) ) break;

    /* Add trailing dot */
    if( parser->key_len + 2 > sizeof(parser->key) ) {
      parser->error = FD_TOML_ERR_KEY;
      return 0;
    }
    parser->key[ parser->key_len++ ] = '.';
    parser->key[ parser->key_len   ] = '\x00';

    if( FD_UNLIKELY( !SUB_PARSE( fd_toml_parse_simple_key( parser ) ) ) ) return 0;
  }
  return 1;
}

/* key = simple-key / dotted-key

   Doing simple-key *( dot-sep simple-key ) instead to simplify code */

static int
fd_toml_parse_key( fd_toml_parser_t * parser ) {
  return fd_toml_parse_dotted_key( parser );
}

/* keyval-sep = ws %x3D ws */

static int
fd_toml_parse_keyval_sep( fd_toml_parser_t * parser ) {
  fd_toml_parse_ws( parser );
  if( FD_UNLIKELY( !fd_toml_avail( parser ) ) ) return 0;
  if( FD_UNLIKELY( parser->c.data[0] != '=' ) ) return 0;
  fd_toml_advance_inline( parser, 1UL );
  fd_toml_parse_ws( parser );
  return 1;
}

/* ml-basic-string-delim = 3quotation-mark */

static int
fd_toml_parse_ml_basic_string_delim( fd_toml_parser_t * parser ) {
  if( FD_UNLIKELY( parser->c.data + 3 > parser->data_end ) ) return 0;
  if( FD_UNLIKELY( ( parser->c.data[0] != '"' ) |
                   ( parser->c.data[1] != '"' ) |
                   ( parser->c.data[2] != '"' ) ) ) return 0;
  fd_toml_advance_inline( parser, 3UL );
  return 1;
}

/* mlb-unescaped = wschar / %x21 / %x23-5B / %x5D-7E / non-ascii */

static int
fd_toml_parse_mlb_unescaped( fd_toml_parser_t * parser ) {
  return fd_toml_parse_basic_unescaped( parser );
}

/* mlb-escaped-nl = escape ws newline *( wschar / newline ) */

static int
fd_toml_parse_mlb_escaped_nl( fd_toml_parser_t * parser ) {
  if( FD_UNLIKELY( fd_toml_avail( parser ) < 2UL ) ) return 0;
  if( FD_UNLIKELY( parser->c.data[0] != '\\'     ) ) return 0;
  fd_toml_advance_inline( parser, 1UL );
  SUB_PARSE( fd_toml_parse_ws( parser ) );
  if( FD_UNLIKELY( !fd_toml_avail( parser )      ) ) return 0;
  if( FD_UNLIKELY( parser->c.data[0] != '\n'     ) ) return 0;
  while( fd_toml_avail( parser ) ) {
    int c = (uchar)parser->c.data[0];
    if( (c==' ') | (c=='\t') | (c=='\n') ) {
      fd_toml_advance( parser, 1UL );
    } else {
      break;
    }
  }
  return 1;
}

/* mlb-content = mlb-char / newline / mlb-escaped-nl
   mlb-char = mlb-unescaped / escaped */

static int
fd_toml_parse_mlb_content( fd_toml_parser_t * parser ) {
  if( FD_UNLIKELY( !fd_toml_avail( parser ) ) ) return 0;
  if( FD_LIKELY( SUB_PARSE( fd_toml_parse_mlb_unescaped( parser ) ) ) ) return 1;
  if( FD_LIKELY( SUB_PARSE( fd_toml_parse_escaped      ( parser ) ) ) ) return 1;
  if( FD_LIKELY( parser->c.data[0] == '\n' ) ) {
    fd_toml_str_append_byte( parser, '\n' );
    fd_toml_advance( parser, 1UL );
    return 1;
  }
  if( FD_LIKELY( SUB_PARSE( fd_toml_parse_mlb_escaped_nl( parser ) ) ) ) return 1;
  return 0;
}

/* mlb-quotes = 1*2quotation-mark
   Note: This is used to allow normal quotes (", "") inside a multiline
         basic comment (""") */

static int
fd_toml_parse_mlb_quotes( fd_toml_parser_t * parser ) {

  /* Count number of quotes */
  char const * begin = parser->c.data;
  ulong quote_cnt = 0UL;
  while( fd_toml_avail( parser ) && parser->c.data[0] == '"' ) {
    fd_toml_advance_inline( parser, 1UL );
    quote_cnt++;
  }

  if( !quote_cnt || quote_cnt > 5 ) return 0;
  if( quote_cnt < 3 ) {
    fd_toml_str_append( parser, begin, quote_cnt );
    return 1;
  }
  if( quote_cnt==3 ) return 0;

  /* Backtrack by 3 quotes, as those might be the multiline */
  parser->c.data -= 3;
  quote_cnt      -= 3;
  fd_toml_str_append( parser, begin, quote_cnt );
  return 1;
}

/* ml-basic-body = *mlb-content *( mlb-quotes 1*mlb-content ) [ mlb-quotes ] */

static int
fd_toml_parse_ml_basic_body( fd_toml_parser_t * parser ) {
  while( SUB_PARSE( fd_toml_parse_mlb_content( parser ) ) ) {}
  for(;;) {
    if( FD_UNLIKELY( !SUB_PARSE( fd_toml_parse_mlb_quotes ( parser ) ) ) ) break;
    if( FD_UNLIKELY( !SUB_PARSE( fd_toml_parse_mlb_content( parser ) ) ) ) break;
    while( SUB_PARSE( fd_toml_parse_mlb_content( parser ) ) ) {}
  }
  SUB_PARSE( fd_toml_parse_mlb_quotes( parser ) );
  return 1;
}

/* ml-basic-string = ml-basic-string-delim [ newline ] ml-basic-body ml-basic-string-delim */

static int
fd_toml_parse_ml_basic_string( fd_toml_parser_t * parser ) {
  if( FD_UNLIKELY( !SUB_PARSE( fd_toml_parse_ml_basic_string_delim( parser ) ) ) ) return 0;
  if( FD_UNLIKELY( !fd_toml_avail( parser ) ) )                                    return 0;
  if( parser->c.data[0] == '\n' ) {
    fd_toml_advance( parser, 1UL );
  }
  fd_toml_str_init( parser );
  if( FD_UNLIKELY( !SUB_PARSE( fd_toml_parse_ml_basic_body        ( parser ) ) ) ) return 0;
  if( FD_UNLIKELY( !SUB_PARSE( fd_toml_parse_ml_basic_string_delim( parser ) ) ) ) return 0;
  return 1;
}

/* mll-quotes = 1*2apostrophe
   Note: This is used to allow normal quotes (', '') inside a multiline
         literal comment (''') */

static int
fd_toml_parse_mll_quotes( fd_toml_parser_t * parser ) {

  /* Count number of quotes */
  char const * begin = parser->c.data;
  ulong quote_cnt = 0UL;
  while( fd_toml_avail( parser ) && parser->c.data[0] == '\'' ) {
    fd_toml_advance_inline( parser, 1UL );
    quote_cnt++;
  }

  if( !quote_cnt || quote_cnt > 5 ) return 0;
  if( quote_cnt < 3 ) {
    fd_toml_str_append( parser, begin, quote_cnt );
    return 1;
  }
  if( quote_cnt==3 ) return 0;

  /* Backtrack by 3 quotes, as those might be the multiline */
  parser->c.data -= 3;
  quote_cnt      -= 3;
  fd_toml_str_append( parser, begin, quote_cnt );
  return 1;
}

/* mll-content = mll-char / newline
   mll-char = %x09 / %x20-26 / %x28-7E / non-ascii */

static int
fd_toml_parse_mll_content( fd_toml_parser_t * parser ) {
  if( FD_UNLIKELY( !fd_toml_avail( parser ) ) ) return 0;

  int c = (uchar)parser->c.data[0];
  if( FD_LIKELY( (c==0x09) |
                 (c>=0x20 && c<=0x26) |
                 (c>=0x28 && c<=0x7E) |
                 (c>=0x80) |
                 (c=='\n') ) ) {
    /* ok */
  } else {
    return 0;
  }
  if( FD_UNLIKELY( !fd_toml_str_append_byte( parser, c ) ) ) return 0;

  fd_toml_advance( parser, 1UL );
  return 1;
}

/* ml-literal-body = *mll-content *( mll-quotes 1*mll-content ) [ mll-quotes ] */

static int
fd_toml_parse_ml_literal_body( fd_toml_parser_t * parser ) {
  while( SUB_PARSE( fd_toml_parse_mll_content( parser ) ) ) {}
  for(;;) {
    if( FD_UNLIKELY( !SUB_PARSE( fd_toml_parse_mll_quotes ( parser ) ) ) ) break;
    if( FD_UNLIKELY( !SUB_PARSE( fd_toml_parse_mll_content( parser ) ) ) ) break;
    while( SUB_PARSE( fd_toml_parse_mll_content( parser ) ) ) {}
  }
  SUB_PARSE( fd_toml_parse_mll_quotes( parser ) );
  return 1;
}

/* ml-literal-string-delim = 3apostrophe */

static int
fd_toml_parse_ml_literal_string_delim( fd_toml_parser_t * parser ) {
  if( FD_UNLIKELY( parser->c.data + 3 > parser->data_end ) ) return 0;
  if( FD_UNLIKELY( ( parser->c.data[0] != '\'' ) |
                   ( parser->c.data[1] != '\'' ) |
                   ( parser->c.data[2] != '\'' ) ) ) return 0;
  fd_toml_advance_inline( parser, 3UL );
  return 1;
}

/* ml-literal-string = ml-literal-string-delim [ newline ] ml-literal-body
                       ml-literal-string-delim */

static int
fd_toml_parse_ml_literal_string( fd_toml_parser_t * parser ) {
  if( FD_UNLIKELY( !SUB_PARSE( fd_toml_parse_ml_literal_string_delim( parser ) ) ) ) return 0;
  if( FD_UNLIKELY( !fd_toml_avail( parser ) ) )                                      return 0;
    if( parser->c.data[0] == '\n' ) {
    fd_toml_advance( parser, 1UL );
  }
  fd_toml_str_init( parser );
  if( FD_UNLIKELY( !SUB_PARSE( fd_toml_parse_ml_literal_body        ( parser ) ) ) ) return 0;
  if( FD_UNLIKELY( !SUB_PARSE( fd_toml_parse_ml_literal_string_delim( parser ) ) ) ) return 0;
  return 1;
}

/* string = ml-basic-string / basic-string / ml-literal-string / literal-string */

static int
fd_toml_parse_string( fd_toml_parser_t * parser ) {
  if( FD_LIKELY( SUB_PARSE( fd_toml_parse_ml_basic_string  ( parser ) ) ) ) goto add;
  if( FD_LIKELY( SUB_PARSE( fd_toml_parse_basic_string     ( parser ) ) ) ) goto add;
  if( FD_LIKELY( SUB_PARSE( fd_toml_parse_ml_literal_string( parser ) ) ) ) goto add;
  if( FD_LIKELY( SUB_PARSE( fd_toml_parse_literal_string   ( parser ) ) ) ) goto add;
  return 0;
add:
  if( FD_UNLIKELY( !fd_toml_str_append_byte( parser, 0 ) ) ) return 0;
  if( FD_UNLIKELY( !fd_pod_insert(
      parser->pod, parser->key, FD_POD_VAL_TYPE_CSTR,
      (ulong)parser->scratch_cur - (ulong)parser->scratch,
      (char *)parser->scratch ) ) ) {
    parser->error = FD_TOML_ERR_POD;
    return 0;
  }
  return 1;
}

/* boolean = true / false */

static int
fd_toml_parse_boolean( fd_toml_parser_t * parser ) {
  int boolv = 0;
  if( parser->c.data + 4 > parser->data_end ) return 0;
  if( 0==memcmp( parser->c.data, "true", 4 ) ) {
    fd_toml_advance_inline( parser, 4 );
    boolv = 1;
    goto add;
  }
  if( parser->c.data + 5 > parser->data_end ) return 0;
  if( 0==memcmp( parser->c.data, "false", 5 ) ) {
    fd_toml_advance_inline( parser, 5 );
    boolv = 0;
    goto add;
  }
  return 0;
add:
  if( FD_UNLIKELY( !fd_pod_insert_int( parser->pod, parser->key, boolv ) ) ) {
    parser->error = FD_TOML_ERR_POD;
    return 0;
  }
  return 1;
}

/* ws-comment-newline = *( wschar / [ comment ] newline ) */

static int
fd_toml_parse_ws_comment_newline_inner( fd_toml_parser_t * parser ) {
  if( FD_UNLIKELY( !fd_toml_avail( parser ) ) ) return 0;
  int c = (uchar)parser->c.data[0];
  if( FD_UNLIKELY( c == ' ' || c == '\t' ) ) {
    fd_toml_advance_inline( parser, 1UL );
    return 1;
  }
  SUB_PARSE( fd_toml_parse_comment( parser ) );
  if( FD_UNLIKELY( !fd_toml_avail( parser )  ) ) return 0;
  if( FD_UNLIKELY( parser->c.data[0] != '\n' ) ) return 0;
  fd_toml_advance( parser, 1UL );
  return 1;
}

static int
fd_toml_parse_ws_comment_newline( fd_toml_parser_t * parser ) {
  while( SUB_PARSE( fd_toml_parse_ws_comment_newline_inner( parser ) ) ) {}
  return 1;
}

/* array-values =  ws-comment-newline val ws-comment-newline array-sep array-values
   array-values =/ ws-comment-newline val ws-comment-newline [ array-sep ] */

static int
fd_toml_parse_array_values( fd_toml_parser_t * parser ) {

  uint   old_len     = parser->key_len;
  char * suffix_cstr = parser->key + parser->key_len;
  if( FD_UNLIKELY( suffix_cstr + 22 > parser->key + sizeof(parser->key) ) ) {
    /* array index might be OOB (see python3 -c 'print(len(str(1<<64)))') */
    parser->error = FD_TOML_ERR_KEY;
    return 0;
  }

  /* Unrolled tail recursion with backtracking */

  fd_toml_cur_t backtrack = parser->c;
  for( ulong j=0;; j++ ) {
    char * child_key = fd_cstr_append_char( suffix_cstr, '.' );
           child_key = fd_cstr_append_ulong_as_text( child_key, 0, 0, j, fd_ulong_base10_dig_cnt( j ) );
    fd_cstr_fini( child_key );
    parser->key_len = (uint)( child_key - parser->key );

    fd_toml_parse_ws_comment_newline( parser );
    if( FD_UNLIKELY( !fd_toml_parse_val( parser ) ) ) {
      parser->c = backtrack;
      break;
    }

    FD_LOG_DEBUG(( "Added key %s", parser->key ));

    fd_toml_parse_ws_comment_newline( parser );

    backtrack = parser->c;
    if( fd_toml_avail( parser ) && parser->c.data[0] == ',' ) {
      fd_toml_advance_inline( parser, 1UL );
    } else {
      break;
    }
    backtrack = parser->c;
  }

  /* Undo array index */

  fd_cstr_fini( suffix_cstr );
  parser->key_len = old_len;
  return 1;
}

/* array = array-open [ array-values ] ws-comment-newline array-close

   array-open =  %x5B ; [
   array-close = %x5D ; ] */

static int
fd_toml_parse_array( fd_toml_parser_t * parser ) {
  uint key_len = parser->key_len;

  EXPECT_CHAR( '[' );
  fd_toml_upsert_empty_pod( parser );
  SUB_PARSE( fd_toml_parse_array_values      ( parser ) );
  SUB_PARSE( fd_toml_parse_ws_comment_newline( parser ) );
  EXPECT_CHAR( ']' );

  parser->key_len        = key_len;
  parser->key[ key_len ] = 0;

  return 1;
}

/* inline-table-sep   = ws %x2C ws  ; , Comma */

static int
fd_toml_parse_inline_table_sep( fd_toml_parser_t * parser ) {
  fd_toml_parse_ws( parser );
  if( FD_UNLIKELY( !fd_toml_avail( parser ) ) ) return 0;
  if( FD_UNLIKELY( parser->c.data[0] != ',' ) ) return 0;
  fd_toml_advance_inline( parser, 1UL );
  fd_toml_parse_ws( parser );
  return 1;
}

/* inline-table-keyvals = keyval [ inline-table-sep inline-table-keyvals ] */

static int
fd_toml_parse_inline_table_keyvals( fd_toml_parser_t * parser ) {

  /* Unrolled tail recursion with backtracking */

  if( !fd_toml_parse_keyval( parser ) ) return 0;
  fd_toml_cur_t backtrack = parser->c;
  for(;;) {
    if( !fd_toml_parse_inline_table_sep( parser ) ) {
      parser->c = backtrack;
      break;
    }
    if( !fd_toml_parse_keyval( parser ) ) return 0;
    backtrack = parser->c;
  }

  return 1;
}

/* inline-table = inline-table-open [ inline-table-keyvals ] inline-table-close

   inline-table-open  = %x7B ws ; {
   inline-table-close = ws %x7D ; } */

static int
fd_toml_parse_inline_table( fd_toml_parser_t * parser ) {

  EXPECT_CHAR( '{' );
  fd_toml_parse_ws( parser );

  uint old_key_len = parser->key_len;
  if( parser->key_len + 2 > sizeof(parser->key) ) {
    parser->error = FD_TOML_ERR_KEY;
    return 0;
  }

  parser->key[ parser->key_len   ] = '\x00';
  fd_toml_upsert_empty_pod( parser );

  parser->key[ parser->key_len++ ] = '.';
  parser->key[ parser->key_len   ] = '\x00';

  while( SUB_PARSE( fd_toml_parse_inline_table_keyvals( parser ) ) ) {}

  fd_toml_parse_ws( parser );
  EXPECT_CHAR( '}' );

  parser->key_len            = old_key_len;
  parser->key[ old_key_len ] = '\x00';
  return 1;
}

/* dec-int = [ minus / plus ] unsigned-dec-int
   unsigned-dec-int = DIGIT / digit1-9 1*( DIGIT / underscore DIGIT ) */

struct fd_toml_dec {
  ulong res;
  uint  len;
  uchar neg : 1;
};

typedef struct fd_toml_dec fd_toml_dec_t;

/* zero-prefixable-int = DIGIT *( DIGIT / underscore DIGIT )

   fd_toml_parse_zero_prefixable_int parses [0-9](_[0-9]|[0-9])*
   Assumes the first digit has been validated prior to call. */

static int
fd_toml_parse_zero_prefixable_int( fd_toml_parser_t * parser,
                                   fd_toml_dec_t *    dec ) {

  uint  len;
  ulong digits = 0UL;
  int allow_underscore = 0;
  for( len=0;; len++ ) {
    if( FD_UNLIKELY( allow_underscore && parser->c.data[0] == '_' ) ) {
      allow_underscore = 0;
      fd_toml_advance_inline( parser, 1UL );
      if( FD_UNLIKELY( !fd_toml_avail( parser )      ) ) return 0;
      if( FD_UNLIKELY( !isdigit( parser->c.data[0] ) ) ) return 0;
    } else {
      int digit = (uchar)parser->c.data[0];
      digits = digits * 10UL + (ulong)( digit - '0' );
      fd_toml_advance_inline( parser, 1UL );
      if( !fd_toml_avail( parser ) ) break;
      if( !isdigit( parser->c.data[0] ) && parser->c.data[0] != '_' ) break;
      allow_underscore = 1;
    }
  }

  dec->res = digits;
  dec->len = len;
  return 1;
}

static int
fd_toml_parse_dec_int_( fd_toml_parser_t * parser,
                        fd_toml_dec_t *    dec ) {
  if( FD_UNLIKELY( !fd_toml_avail( parser ) ) ) return 0;
  int c = (uchar)parser->c.data[0];

  int neg = 0;
  switch( c ) {
  case '-':
    neg = 1;
    __attribute__((fallthrough));
  case '+':
    fd_toml_advance_inline( parser, 1UL );
    break;
  }

  /* TODO OVERFLOW DETECTION */

  if( FD_UNLIKELY( !fd_toml_avail( parser ) ) ) return 0;
  int first_digit = (uchar)parser->c.data[0];
  if( first_digit == '0' ) {
    dec->res = 0UL;
    dec->neg = 0;
    fd_toml_advance_inline( parser, 1UL );
    return 1;
  }

  if( FD_UNLIKELY( first_digit<='0' || first_digit>'9' ) ) return 0;

  dec->neg = !!neg;
  return fd_toml_parse_zero_prefixable_int( parser, dec );
}

static int
fd_toml_parse_dec_int( fd_toml_parser_t * parser ) {
  fd_toml_dec_t dec = {0};
  if( FD_UNLIKELY( !fd_toml_parse_dec_int_( parser, &dec ) ) ) return 0;
  long val = (long)dec.res;
       val = fd_long_if( dec.neg, -val, val );
  if( FD_UNLIKELY( !fd_pod_insert_ulong( parser->pod, parser->key, (ulong)val ) ) ) {
    parser->error = FD_TOML_ERR_POD;
    return 0;
  }
  return 1;
}

/* hex-int = hex-prefix HEXDIG *( HEXDIG / underscore HEXDIG ) */

static int
fd_toml_parse_hex_int( fd_toml_parser_t * parser ) {
  if( FD_UNLIKELY( fd_toml_avail( parser ) < 3    ) ) return 0;
  if( FD_UNLIKELY( parser->c.data[0] != '0'       ) ) return 0;
  if( FD_UNLIKELY( parser->c.data[1] != 'x'       ) ) return 0;
  if( FD_UNLIKELY( !isxdigit( parser->c.data[2] ) ) ) return 0;  /* at least one digit */
  fd_toml_advance_inline( parser, 2UL );

  /* TODO OVERFLOW DETECTION */

  ulong res = 0UL;
  int allow_underscore = 0;
  for(;;) {
    int digit = (uchar)parser->c.data[0];
    if( FD_UNLIKELY( allow_underscore && digit == '_' ) ) {
      allow_underscore = 0;
      fd_toml_advance_inline( parser, 1UL );
      if( FD_UNLIKELY( !fd_toml_avail( parser )       ) ) return 0;
      if( FD_UNLIKELY( !isxdigit( parser->c.data[0] ) ) ) return 0;
    } else {
      if( !isxdigit( digit ) ) break;
      res <<= 4;
      res  |= fd_toml_xdigit( digit );
      fd_toml_advance_inline( parser, 1UL );
      if( !fd_toml_avail( parser ) ) break;
      allow_underscore = 1;
    }
  }

  if( FD_UNLIKELY( !fd_pod_insert_ulong( parser->pod, parser->key, res ) ) ) {
    parser->error = FD_TOML_ERR_POD;
    return 0;
  }

  return 1;
}

/* oct-int = oct-prefix digit0-7 *( digit0-7 / underscore digit0-7 ) */

static inline int
fd_toml_is_odigit( int c ) {
  return c>='0' && c<'8';
}

static int
fd_toml_parse_oct_int( fd_toml_parser_t * parser ) {
  if( FD_UNLIKELY( fd_toml_avail( parser ) < 3             ) ) return 0;
  if( FD_UNLIKELY( parser->c.data[0] != '0'                ) ) return 0;
  if( FD_UNLIKELY( parser->c.data[1] != 'o'                ) ) return 0;
  if( FD_UNLIKELY( !fd_toml_is_odigit( parser->c.data[2] ) ) ) return 0;  /* at least one digit */
  fd_toml_advance_inline( parser, 2UL );

  /* TODO OVERFLOW DETECTION */

  ulong res = 0UL;
  int allow_underscore = 0;
  for(;;) {
    int digit = (uchar)parser->c.data[0];
    if( allow_underscore && digit == '_' ) {
      allow_underscore = 0;
      fd_toml_advance_inline( parser, 1UL );
      if( FD_UNLIKELY( !fd_toml_avail( parser )                ) ) return 0;
      if( FD_UNLIKELY( !fd_toml_is_odigit( parser->c.data[0] ) ) ) return 0;
    } else {
      if( !fd_toml_is_odigit( digit ) ) break;
      res <<= 3;
      res  |= (ulong)( digit - '0' );
      fd_toml_advance_inline( parser, 1UL );
      if( !fd_toml_avail( parser ) ) break;
      allow_underscore = 1;
    }
  }

  if( FD_UNLIKELY( !fd_pod_insert_ulong( parser->pod, parser->key, res ) ) ) {
    parser->error = FD_TOML_ERR_POD;
    return 0;
  }

  return 1;
}

/* bin-int = bin-prefix digit0-1 *( digit0-1 / underscore digit0-1 ) */

static inline int
fd_toml_is_bdigit( int c ) {
  return c=='0' || c=='1';
}

static int
fd_toml_parse_bin_int( fd_toml_parser_t * parser ) {
  if( FD_UNLIKELY( fd_toml_avail( parser ) < 3             ) ) return 0;
  if( FD_UNLIKELY( parser->c.data[0] != '0'                ) ) return 0;
  if( FD_UNLIKELY( parser->c.data[1] != 'b'                ) ) return 0;
  if( FD_UNLIKELY( !fd_toml_is_bdigit( parser->c.data[2] ) ) ) return 0;  /* at least one digit */
  fd_toml_advance_inline( parser, 2UL );

  /* TODO OVERFLOW DETECTION */

  ulong res = 0UL;
  int allow_underscore = 0;
  for(;;) {
    int digit = (uchar)parser->c.data[0];
    if( FD_UNLIKELY( allow_underscore && digit == '_' ) ) {
      allow_underscore = 0;
      fd_toml_advance_inline( parser, 1UL );
      if( FD_UNLIKELY( !fd_toml_avail( parser )                ) ) return 0;
      if( FD_UNLIKELY( !fd_toml_is_bdigit( parser->c.data[0] ) ) ) return 0;
    } else {
      if( !fd_toml_is_bdigit( digit ) ) break;
      res <<= 1;
      res  |= (ulong)( digit - '0' );
      fd_toml_advance_inline( parser, 1UL );
      if( !fd_toml_avail( parser ) ) break;
      allow_underscore = 1;
    }
  }

  if( FD_UNLIKELY( !fd_pod_insert_ulong( parser->pod, parser->key, res ) ) ) {
    parser->error = FD_TOML_ERR_POD;
    return 0;
  }

  return 1;
}

/* integer = dec-int / hex-int / oct-int / bin-int */

static int
fd_toml_parse_integer( fd_toml_parser_t * parser ) {
  if( SUB_PARSE( fd_toml_parse_hex_int( parser ) ) ) return 1;
  if( SUB_PARSE( fd_toml_parse_oct_int( parser ) ) ) return 1;
  if( SUB_PARSE( fd_toml_parse_bin_int( parser ) ) ) return 1;
  if( SUB_PARSE( fd_toml_parse_dec_int( parser ) ) ) return 1;
  return 0;
}

/* exp = "e" float-exp-part
   float-exp-part = [ minus / plus ] zero-prefixable-int */

static int
fd_toml_parse_exp( fd_toml_parser_t * parser,
                   fd_toml_dec_t *    exp ) {
  if( FD_UNLIKELY( fd_toml_avail( parser ) < 2 ) ) return 0;
  switch( parser->c.data[0] ) {
    case 'e': case 'E': break;
    default:            return 0;
  }
  fd_toml_advance_inline( parser, 1UL );

  switch( parser->c.data[0] ) {
  case '-':
    exp->neg = 1;
    __attribute__((fallthrough));
  case '+':
    fd_toml_advance_inline( parser, 1UL );
    if( FD_UNLIKELY( !fd_toml_avail( parser ) ) ) return 0;
    break;
  }

  int first_digit = (uchar)parser->c.data[0];
  if( FD_UNLIKELY( first_digit<'0' || first_digit>'9'                ) ) return 0;
  if( FD_UNLIKELY( !fd_toml_parse_zero_prefixable_int( parser, exp ) ) ) return 0;
  return 1;
}

/* frac = decimal-point zero-prefixable-int
   decimal-point = %x2E */

static int
fd_toml_parse_frac( fd_toml_parser_t * parser,
                    fd_toml_dec_t *    frac ) {
  if( FD_UNLIKELY( fd_toml_avail( parser ) < 2                        ) ) return 0;
  if( FD_UNLIKELY( parser->c.data[0] != '.'                           ) ) return 0;
  fd_toml_advance_inline( parser, 1UL );

  int first_digit = (uchar)parser->c.data[0];
  if( FD_UNLIKELY( first_digit<'0' || first_digit>'9'                 ) ) return 0;
  if( FD_UNLIKELY( !fd_toml_parse_zero_prefixable_int( parser, frac ) ) ) return 0;
  return 1;
}

/* float = float-int-part ( exp / frac [ exp ] )
   float-int-part = dec-int */

static int
fd_toml_parse_float_normal( fd_toml_parser_t * parser,
                            double *           pres ) {

  fd_toml_dec_t stem = {0};
  if( FD_UNLIKELY( !fd_toml_parse_dec_int_( parser, &stem ) ) ) return 0;
  if( FD_UNLIKELY( !fd_toml_avail( parser )                 ) ) return 0;
  double res = (double)stem.res;

  int ok = 0;
  fd_toml_dec_t frac_dec = {0};
  if( SUB_PARSE( fd_toml_parse_frac( parser, &frac_dec ) ) ) {
    double frac = (double)frac_dec.res;
    while( frac_dec.len-- ) frac /= 10.0;  /* use pow? */
    res += frac;
    ok   = 1;
  }

  fd_toml_dec_t exp_dec = {0};
  if( !SUB_PARSE( fd_toml_parse_exp( parser, &exp_dec ) ) ) {
    if( FD_LIKELY( ok ) ) {
      *pres = res;
      return 1;
    }
    return 0;
  }

  double exp = pow( exp_dec.neg ? 0.1 : 10.0, (double)exp_dec.res );
  res *= exp;

  *pres = res;
  return 1;
}

/* special-float = [ minus / plus ] ( inf / nan )
   inf = %x69.6e.66  ; inf
   nan = %x6e.61.6e  ; nan */

static int
fd_float_parse_float_special( fd_toml_parser_t * parser,
                              double *           pres ) {
  if( FD_UNLIKELY( fd_toml_avail( parser ) < 3 ) ) return 0;
  int c       = (uchar)parser->c.data[0];
  double base = 1.0;

  switch( c ) {
  case '-':
    base = -1.0L;
    __attribute__((fallthrough));
  case '+':
    fd_toml_advance_inline( parser, 1UL );
    if( FD_UNLIKELY( fd_toml_avail( parser ) < 3 ) ) return 0;
    break;
  }

  char const * str = parser->c.data;
  fd_toml_advance_inline( parser, 3UL );

  if( 0==memcmp( str, "inf", 3 ) ) {
    FD_LOG_WARNING(( "float infinity is unsupported" ));
    *pres = base * DBL_MAX;
    return 1;
  }

  if( 0==memcmp( str, "nan", 3 ) ) {
    FD_LOG_WARNING(( "float nan is unsupported" ));
    *pres = base * 0.0;
    return 1;
  }

  return 0;
}

/* float = float-int-part ( exp / frac [ exp ] )
   float =/ special-float */

static int
fd_toml_parse_float( fd_toml_parser_t * parser ) {

  double res;
  if( SUB_PARSE( fd_toml_parse_float_normal( parser, &res ) ) ) {
    goto parsed;
  }
  if( SUB_PARSE( fd_float_parse_float_special( parser, &res ) ) ) {
    goto parsed;
  }
  return 0;

parsed:
  if( FD_UNLIKELY( !fd_pod_insert_double( parser->pod, parser->key, res ) ) ) {
    parser->error = FD_TOML_ERR_POD;
    return 0;
  }
  return 1;
}

/* full-date      = date-fullyear "-" date-month "-" date-mday
   date-fullyear  = 4DIGIT
   date-month     = 2DIGIT  ; 01-12
   date-mday      = 2DIGIT  ; 01-28, 01-29, 01-30, 01-31 based on month/year */

static int
fd_toml_parse_full_date( fd_toml_parser_t * parser,
                         struct tm *        time ) {
  if( FD_UNLIKELY( fd_toml_avail( parser ) < 10 ) ) return 0;

  if( ( !isdigit( parser->c.data[0] ) )      |
      ( !isdigit( parser->c.data[1] ) )      |
      ( !isdigit( parser->c.data[2] ) )      |
      ( !isdigit( parser->c.data[3] ) )      |
                ( parser->c.data[4] != '-' ) |
      ( !isdigit( parser->c.data[5] ) )      |
      ( !isdigit( parser->c.data[6] ) )      |
                ( parser->c.data[7] != '-' ) |
      ( !isdigit( parser->c.data[8] ) ) |
      ( !isdigit( parser->c.data[9] ) ) ) {
    return 0;
  }

  char cstr[ 11 ];
  memcpy( cstr, parser->c.data, 10 );
  cstr[10] = '\x00';
  fd_toml_advance_inline( parser, 10UL );

  if( FD_UNLIKELY( !strptime( cstr, "%Y-%m-%d", time ) ) ) {
    FD_LOG_WARNING(( "invalid date format" ));
    return 0;
  }
  return 1;
}

/* time-delim = "T" / %x20 ; T, t, or space */

static int
fd_toml_parse_time_delim( fd_toml_parser_t * parser ) {
  if( FD_UNLIKELY( !fd_toml_avail( parser ) ) ) return 0;
  switch( parser->c.data[0] ) {
  case 'T': case 't': case ' ': break;
  default:                      return 0;
  }
  fd_toml_advance_inline( parser, 1UL );
  return 1;
}

/* time-secfrac = "." 1*DIGIT */

static int
fd_toml_parse_time_secfrac( fd_toml_parser_t * parser,
                            ulong *            pnanos ) {
  if( fd_toml_avail( parser ) < 2                  ) return 0;
  if( parser->c.data[0] != '.'                     ) return 0;
  if( FD_UNLIKELY( !isdigit( parser->c.data[1] ) ) ) return 0;
  fd_toml_advance_inline( parser, 1UL );

  ulong secfrac = 0UL;
  ulong len     = 0UL;
  do {
    int digit = (uchar)parser->c.data[0];
    secfrac = secfrac * 10UL + (ulong)( digit - '0' );
    fd_toml_advance_inline( parser, 1UL );
    len++;
  } while( fd_toml_avail( parser ) && isdigit( parser->c.data[0] ) );
  if( FD_UNLIKELY( len > 9 ) ) {
    FD_LOG_WARNING(( "invalid time fraction format" ));
    return 0;
  }

  while( len++ < 9 ) secfrac *= 10UL;
  *pnanos = secfrac;
  return 1;
}

/* partial-time = time-hour ":" time-minute ":" time-second [ time-secfrac ]
   time-hour      = 2DIGIT  ; 00-23
   time-minute    = 2DIGIT  ; 00-59
   time-second    = 2DIGIT  ; 00-58, 00-59, 00-60 based on leap second rules */

static int
fd_toml_parse_partial_time( fd_toml_parser_t * parser,
                            ulong *            pnanos ) {

  if( FD_UNLIKELY( fd_toml_avail( parser ) < 8 ) ) return 0;
  if( ( !isdigit( parser->c.data[0] ) )      |
      ( !isdigit( parser->c.data[1] ) )      |
                ( parser->c.data[2] != ':' ) |
      ( !isdigit( parser->c.data[3] ) )      |
      ( !isdigit( parser->c.data[4] ) )      |
                ( parser->c.data[5] != ':' ) |
      ( !isdigit( parser->c.data[6] ) )      |
      ( !isdigit( parser->c.data[7] ) ) ) {
    return 0;
  }

  char cstr[ 9 ];
  memcpy( cstr, parser->c.data, 8 );
  cstr[8] = '\x00';
  fd_toml_advance_inline( parser, 8UL );

  struct tm time[1];
  if( FD_UNLIKELY( !strptime( cstr, "%H:%M:%S", time ) ) ) {
    FD_LOG_WARNING(( "invalid time format" ));
    return 0;
  }

  ulong res = 0UL;
        res += (ulong)time->tm_hour * 3600UL;
        res += (ulong)time->tm_min  *   60UL;
        res += (ulong)time->tm_sec;
        res *= (ulong)1e9;
  ulong ns_frac;
  if( SUB_PARSE( fd_toml_parse_time_secfrac( parser, &ns_frac ) ) ) {
    res += ns_frac;
  }
  *pnanos = res;
  return 1;
}

/* time-numoffset = ( "+" / "-" ) time-hour ":" time-minute */

static int
fd_toml_parse_time_numoffset( fd_toml_parser_t * parser,
                              long *             psec ) {
  if( FD_UNLIKELY( !fd_toml_avail( parser ) ) ) return 0;

  int neg = 0;
  switch( parser->c.data[0] ) {
  case '+': neg = 0; break;
  case '-': neg = 1; break;
  default: return 0;
  }
  fd_toml_advance_inline( parser, 1UL );

  if( FD_UNLIKELY( fd_toml_avail( parser ) < 5   ) ) return 0;
  if( ( !isdigit( parser->c.data[0] ) ) |
      ( !isdigit( parser->c.data[1] ) ) |
                ( parser->c.data[2] != ':' ) |
      ( !isdigit( parser->c.data[3] ) ) |
      ( !isdigit( parser->c.data[4] ) ) ) {
    FD_LOG_WARNING(( "invalid time offset format" ));
    return 0;
  }

  char cstr[ 6 ];
  memcpy( cstr, parser->c.data, 5 );
  cstr[5] = '\x00';
  fd_toml_advance_inline( parser, 5UL );

  struct tm time;
  if( FD_UNLIKELY( !strptime( cstr, "%H:%M", &time ) ) ) {
    FD_LOG_WARNING(( "invalid time offset format" ));
    return 0;
  }
  long abs_sec = (long)time.tm_hour * 3600L + (long)time.tm_min * 60L;
  *psec = neg ? -abs_sec : abs_sec;
  return 1;
}

/* time-offset = "Z" / time-numoffset */

static int
fd_toml_parse_time_offset( fd_toml_parser_t * parser,
                           long *             psec ) {
  if( FD_UNLIKELY( !fd_toml_avail( parser ) ) ) return 0;

  switch( parser->c.data[0] ) {
  case 'Z': case 'z':
    *psec = 0;
    fd_toml_advance_inline( parser, 1UL );
    return 1;
  }

  return fd_toml_parse_time_numoffset( parser, psec );
}

/* full-time = partial-time time-offset */

static int
fd_toml_parse_full_time( fd_toml_parser_t * parser,
                         ulong *            pnanos ) {
  long off_sec = 0;
  if( FD_UNLIKELY( !fd_toml_parse_partial_time( parser, pnanos   ) ) ) return 0;
  if( FD_UNLIKELY( !fd_toml_parse_time_offset ( parser, &off_sec ) ) ) return 0;
  *pnanos += (ulong)off_sec;
  return 1;
}

/* offset-date-time = full-date time-delim full-time */

static int
fd_toml_parse_offset_date_time( fd_toml_parser_t * parser,
                                ulong *            pnanos ) {
  struct tm date = {0};

  if( FD_UNLIKELY( !fd_toml_parse_full_date ( parser, &date  ) ) ) return 0;
  if( FD_UNLIKELY( !fd_toml_parse_time_delim( parser         ) ) ) return 0;
  if( FD_UNLIKELY( !fd_toml_parse_full_time ( parser, pnanos ) ) ) return 0;

  *pnanos += (ulong)timegm( &date ) * (ulong)1e9;
  return 1;
}

/* local-date-time = full-date time-delim partial-time */

static int
fd_toml_parse_local_date_time( fd_toml_parser_t * parser,
                               ulong *            pnanos ) {

  struct tm date = {0};
  if( FD_UNLIKELY( !fd_toml_parse_full_date   ( parser, &date  ) ) ) return 0;
  if( FD_UNLIKELY( !fd_toml_parse_time_delim  ( parser         ) ) ) return 0;
  if( FD_UNLIKELY( !fd_toml_parse_partial_time( parser, pnanos ) ) ) return 0;

  *pnanos = (ulong)mktime( &date ) * (ulong)1e9;
  return 1;
}

/* local-date = full-date */

static int
fd_toml_parse_local_date( fd_toml_parser_t * parser,
                          ulong *            pnanos ) {
  struct tm date = {0};
  if( FD_UNLIKELY( !fd_toml_parse_full_date( parser, &date ) ) ) return 0;
  *pnanos = (ulong)mktime( &date ) * (ulong)1e9;
  return 1;
}

/* local-time = partial-time */

static int
fd_toml_parse_local_time( fd_toml_parser_t * parser,
                          ulong *            pnanos ) {
  return fd_toml_parse_partial_time( parser, pnanos );
}

/* date-time = offset-date-time / local-date-time / local-date / local-time */

static int
fd_toml_parse_date_time( fd_toml_parser_t * parser ) {
  ulong unix_nanos;
  if( SUB_PARSE( fd_toml_parse_offset_date_time( parser, &unix_nanos ) ) ) goto add;
  if( SUB_PARSE( fd_toml_parse_local_date_time ( parser, &unix_nanos ) ) ) goto add;
  if( SUB_PARSE( fd_toml_parse_local_date      ( parser, &unix_nanos ) ) ) goto add;
  if( SUB_PARSE( fd_toml_parse_local_time      ( parser, &unix_nanos ) ) ) goto add;
  return 0;
add:
  if( FD_UNLIKELY( !fd_pod_insert_ulong( parser->pod, parser->key, unix_nanos ) ) ) {
    parser->error = FD_TOML_ERR_POD;
    return 0;
  }
  return 1;
}

/* val = string / boolean / array / inline-table / date-time / float / integer */

static int
fd_toml_parse_val( fd_toml_parser_t * parser ) {
  /* consider consider some lookahead for better performance */
  if( SUB_PARSE( fd_toml_parse_string      ( parser ) ) ) return 1;
  if( SUB_PARSE( fd_toml_parse_boolean     ( parser ) ) ) return 1;
  if( SUB_PARSE( fd_toml_parse_array       ( parser ) ) ) return 1;
  if( SUB_PARSE( fd_toml_parse_inline_table( parser ) ) ) return 1;
  if( SUB_PARSE( fd_toml_parse_date_time   ( parser ) ) ) return 1;
  /* NOTE: float and integer have a common dec-int prefix -- dedup for better performance */
  if( SUB_PARSE( fd_toml_parse_float       ( parser ) ) ) return 1;
  if( SUB_PARSE( fd_toml_parse_integer     ( parser ) ) ) return 1;
  return 0;
}

/* keyval = key keyval-sep val */

static int
fd_toml_parse_keyval( fd_toml_parser_t * parser ) {
  uint old_key_len = parser->key_len;
  if( FD_UNLIKELY( !SUB_PARSE( fd_toml_parse_key( parser ) ) ) ) return 0;

  if( FD_UNLIKELY( fd_pod_query( parser->pod, parser->key, NULL )==FD_POD_SUCCESS ) ) {
    FD_LOG_WARNING(( "Duplicate key: \"%s\"", parser->key ));
    parser->error = FD_TOML_ERR_DUP;
    return 0;
  }

  if( FD_UNLIKELY( !SUB_PARSE( fd_toml_parse_keyval_sep( parser ) ) ) ) return 0;
  if( FD_UNLIKELY( !SUB_PARSE( fd_toml_parse_val       ( parser ) ) ) ) return 0;

  FD_LOG_DEBUG(( "Added key %s", parser->key ));
  parser->key[ old_key_len ] = 0;
  parser->key_len            = old_key_len;
  return 1;
}

/* std-table = std-table-open key std-table-close

   std-table-open  = %x5B ws     ; [ Left square bracket
   std-table-close = ws %x5D     ; ] Right square bracket */

static int
fd_toml_parse_std_table( fd_toml_parser_t * parser ) {
  EXPECT_CHAR( '[' );
  fd_toml_parse_ws( parser );

  parser->key[ parser->key_len = 0 ] = 0;
  if( FD_UNLIKELY( !fd_toml_parse_key( parser ) ) ) return 0;
  // FIXME: consider blocking duplicate tables?
  //if( FD_UNLIKELY( fd_pod_query( parser->pod, parser->key, NULL )==FD_POD_SUCCESS ) ) {
  //  FD_LOG_WARNING(( "Duplicate table: \"%s\"", parser->key ));
  //  parser->error = FD_TOML_ERR_DUP;
  //  return 0;
  //}
  FD_LOG_DEBUG(( "Added table %.*s", parser->key_len, parser->key ));

  fd_toml_parse_ws( parser );
  EXPECT_CHAR( ']' );
  return 1;
}

/* array-table = array-table = array-table-open key array-table-close

   array-table-open  = %x5B.5B ws  ; [[ Double left square bracket
   array-table-close = ws %x5D.5D  ; ]] Double right square bracket */

static int
fd_toml_parse_array_table( fd_toml_parser_t * parser ) {
  if( fd_toml_avail( parser ) < 2UL ) return 0;
  if( ( parser->c.data[0] != '[' ) |
      ( parser->c.data[1] != '[' ) ) return 0;
  fd_toml_advance_inline( parser, 2UL );

  fd_toml_parse_ws( parser );

  /* Set parser->key to path to array */

  parser->key[ parser->key_len = 0 ] = 0;
  if( FD_UNLIKELY( !SUB_PARSE( fd_toml_parse_key( parser ) ) ) ) return 0;

  /* Count number of predecessors */

  ulong idx = 0UL;
  uchar const * subpod = fd_pod_query_subpod( parser->pod, parser->key );
  if( subpod ) {
    idx = fd_pod_cnt( subpod );
  }

  /* Append array index to path */

  char * key_c = parser->key + parser->key_len;
  if( FD_UNLIKELY( key_c + 22 > parser->key + sizeof(parser->key) ) ) {
    /* array index might be OOB (see python3 -c 'print(len(str(1<<64)))') */
    parser->error = FD_TOML_ERR_KEY;
    return 0;
  }
  key_c = fd_cstr_append_char( key_c, '.' );
  key_c = fd_cstr_append_ulong_as_text( key_c, 0, 0, idx, fd_ulong_base10_dig_cnt( idx ) );
  fd_cstr_fini( key_c );
  parser->key_len = (uint)( key_c - parser->key );

  FD_LOG_DEBUG(( "Added array table %.*s", parser->key_len, parser->key ));

  /* Continue parsing */

  fd_toml_parse_ws( parser );

  if( FD_UNLIKELY( fd_toml_avail( parser ) < 2UL ) ) return 0;
  if( FD_UNLIKELY( ( parser->c.data[0] != ']' ) |
                   ( parser->c.data[1] != ']' ) ) ) return 0;
  fd_toml_advance_inline( parser, 2UL );
  return 1;
}

/* table = std-table / array-table */

static int
fd_toml_parse_table( fd_toml_parser_t * parser ) {
  if( SUB_PARSE( fd_toml_parse_array_table( parser ) ) ) goto add;
  if( SUB_PARSE( fd_toml_parse_std_table  ( parser ) ) ) goto add;
  return 0;
add:
  fd_toml_upsert_empty_pod( parser );
  /* Add trailing dot */
  if( parser->key_len + 2 > sizeof(parser->key) ) {
    parser->error = FD_TOML_ERR_KEY;
    return 0;
  }
  parser->key[ parser->key_len++ ] = '.';
  parser->key[ parser->key_len   ] = '\x00';
  return 1;
}

/* expression =  ws [ comment ]
   expression =/ ws keyval ws [ comment ]
   expression =/ ws table ws [ comment ] */

static int
fd_toml_parse_expression( fd_toml_parser_t * parser ) {

  fd_toml_parse_ws( parser );

  if( FD_LIKELY( SUB_PARSE( fd_toml_parse_keyval( parser ) ) ) ) {
    fd_toml_parse_ws( parser );
  }
  else if( FD_LIKELY( SUB_PARSE( fd_toml_parse_table( parser ) ) ) ) {
    fd_toml_parse_ws( parser );
  }

  SUB_PARSE( fd_toml_parse_comment( parser ) );
  return 1;
}

/* toml = expression *( newline expression ) */

static int
fd_toml_parse_toml( fd_toml_parser_t * parser ) {

  if( FD_UNLIKELY( !fd_toml_parse_expression( parser ) ) ) return 0;

  for(;;) {
    if( FD_UNLIKELY( parser->error             ) ) break;
    if( FD_UNLIKELY( !fd_toml_avail( parser )  ) ) break;
    if( FD_UNLIKELY( parser->c.data[0] != '\n' ) ) break;
    fd_toml_advance( parser, 1UL );
    if( FD_UNLIKELY( !fd_toml_parse_expression( parser ) ) ) return 0;
  }

  return 1;
}

long
fd_toml_parse( void const * toml,
               ulong        toml_sz,
               uchar *      pod,
               uchar *      scratch,
               ulong        scratch_sz ) {

  if( FD_UNLIKELY( !toml_sz    ) ) return FD_TOML_SUCCESS;
  if( FD_UNLIKELY( !scratch_sz ) ) {
    FD_LOG_WARNING(( "zero scratch_sz" ));
    return FD_TOML_ERR_SCRATCH;
  }

  fd_toml_parser_t parser[1] = {{
    .c = {
      .data   = toml,
      .lineno = 1UL,
    },
    .data_end    = (char const *)toml + toml_sz,
    .pod         = pod,
    .scratch     = scratch,
    .scratch_cur = scratch,
    .scratch_end = scratch + scratch_sz
  }};

  int ok = fd_toml_parse_toml( parser );
  if( FD_UNLIKELY( (!ok) | (fd_toml_avail( parser ) > 0) ) ) {
    /* Parse failed */
    return fd_long_if( !!parser->error, parser->error, fd_long_max( 1L, (long)parser->c.lineno ) );
  }

  return FD_TOML_SUCCESS;
}
