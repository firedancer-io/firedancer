#define _DEFAULT_SOURCE
#include "fd_toml.h"
#include "../../util/fd_util.h"
#include <ctype.h>
#include <math.h>

/* Implementation note:

   The lexer/parser of fd_toml.c is a simpler backtracking recursive
   descent parser.  A minimal amount of lookahead tuning is implemented;
   mostly just fast failure paths.  Obvious performance wins are
   possible by adding more speculative lookaheads that lead the CPU down
   "happy paths" such as long strings of ASCII.

   Strings are decoded in place.  While a string is being parsed, the
   parser keeps a write cursor w in addition to the read cursor r.
   Every string rule consumes at least as many bytes at r as it writes
   at w (escape sequences only ever shrink), so start<=w<=r holds at all
   times and bytes at or after r are never modified.  The terminating
   NUL is written at w after the closing delimiter has been consumed,
   which means it always lands on an already consumed byte.  Mutation
   only starts after an opening quote has been consumed, and every
   alternative that could run after a failed string rule rejects on the
   first byte of the value, so a failed alternative can never change the
   outcome of a later successful one. */

#define FD_TOML_KEY_SEG_MAX (32UL)

/* fd_toml_cur_t is a cursor object.  It is safe to copy this object via
   assignment to implement backtracking. */

struct fd_toml_cur {
  ulong  lineno;
  char * data;
};

typedef struct fd_toml_cur fd_toml_cur_t;

/* fd_toml_parser_t is the internal parser state. */

struct fd_toml_parser {
  fd_toml_cur_t c;
  char *        data_end;     /* points one past EOF */
  char *        base;
  int           error;        /* hint: fatal error occurred */

  /* The string currently being decoded */

  char *        w;            /* write cursor */
  char *        str_start;    /* first content byte */
  uint          str_off;      /* last completed string */
  uint          str_len;

  /* Node storage */

  fd_toml_node_t * node;
  uint             node_cnt;
  uint             node_max;

  uint          table;        /* node index that keyvals are added to */

  /* Key segments of the key being parsed */

  uint          key_off[ FD_TOML_KEY_SEG_MAX ];
  uint          key_len[ FD_TOML_KEY_SEG_MAX ];
  uint          key_cnt;

  /* Slot that the next value node is attached to */

  uint          val_parent;
  uint          val_key_off;
  uint          val_key_len;
  uint          val_line;
};

typedef struct fd_toml_parser fd_toml_parser_t;

/* Node tree construction ********************************************/

static fd_toml_node_t *
fd_toml_node_alloc( fd_toml_parser_t * parser,
                    uint               parent,
                    uint               type,
                    uint               key_off,
                    uint               key_len,
                    uint               line ) {
  if( FD_UNLIKELY( parser->node_cnt>=parser->node_max ) ) {
    parser->error = FD_TOML_ERR_NODE;
    return NULL;
  }
  uint idx = parser->node_cnt++;
  fd_toml_node_t * node = parser->node + idx;
  *node = (fd_toml_node_t) {
    .type         = (ushort)type,
    .line         = line,
    .key_off      = key_off,
    .key_len      = key_len,
    .parent       = parent,
    .next_sibling = FD_TOML_IDX_NULL,
    .first_child  = FD_TOML_IDX_NULL,
    .last_child   = FD_TOML_IDX_NULL,
  };
  if( FD_LIKELY( parent!=FD_TOML_IDX_NULL ) ) {
    fd_toml_node_t * p = parser->node + parent;
    if( p->last_child==FD_TOML_IDX_NULL ) p->first_child = idx;
    else parser->node[ p->last_child ].next_sibling = idx;
    p->last_child = idx;
  }
  return node;
}

static fd_toml_node_t *
fd_toml_node_find( fd_toml_parser_t * parser,
                   uint               parent,
                   uint               key_off,
                   uint               key_len ) {
  char const * key = parser->base + key_off;
  for( uint idx=parser->node[ parent ].first_child; idx!=FD_TOML_IDX_NULL; idx=parser->node[ idx ].next_sibling ) {
    fd_toml_node_t * n = parser->node + idx;
    if( n->key_len==key_len && 0==memcmp( parser->base + n->key_off, key, key_len ) ) return n;
  }
  return NULL;
}

/* fd_toml_emit allocates the value node for the pending slot. */

static fd_toml_node_t *
fd_toml_emit( fd_toml_parser_t * parser,
              uint               type ) {
  return fd_toml_node_alloc( parser, parser->val_parent, type, parser->val_key_off, parser->val_key_len, parser->val_line );
}

static void
fd_toml_dup_warn( fd_toml_parser_t * parser,
                  uint               key_off,
                  uint               key_len ) {
  FD_LOG_WARNING(( "TOML parse error: duplicate key: \"%.*s\"", (int)key_len, parser->base + key_off ));
  parser->error = FD_TOML_ERR_DUP;
}

/* fd_toml_table_walk descends from node idx through key segments
   [seg_lo,seg_hi), creating tables as needed.  An array table
   resolves to its last element.  Returns the final table index or
   FD_TOML_IDX_NULL on error. */

static uint
fd_toml_table_walk( fd_toml_parser_t * parser,
                    uint               idx,
                    ulong              seg_lo,
                    ulong              seg_hi ) {
  for( ulong j=seg_lo; j<seg_hi; j++ ) {
    uint key_off = parser->key_off[ j ];
    uint key_len = parser->key_len[ j ];
    fd_toml_node_t * n = fd_toml_node_find( parser, idx, key_off, key_len );
    if( !n ) {
      n = fd_toml_node_alloc( parser, idx, FD_TOML_NODE_TABLE, key_off, key_len, (uint)parser->c.lineno );
      if( FD_UNLIKELY( !n ) ) return FD_TOML_IDX_NULL;
    } else if( n->type==FD_TOML_NODE_ARRAY && n->last_child!=FD_TOML_IDX_NULL &&
               parser->node[ n->last_child ].type==FD_TOML_NODE_TABLE ) {
      n = parser->node + n->last_child;
    } else if( n->type!=FD_TOML_NODE_TABLE ) {
      fd_toml_dup_warn( parser, key_off, key_len );
      return FD_TOML_IDX_NULL;
    }
    idx = (uint)( n - parser->node );
  }
  return idx;
}

/* String decoding ***************************************************/

static inline void
fd_toml_str_init( fd_toml_parser_t * parser ) {
  parser->w         = parser->c.data;
  parser->str_start = parser->c.data;
}

static inline void
fd_toml_str_append_byte( fd_toml_parser_t * parser,
                         int                c ) {
  *(parser->w++) = (char)c;
}

static inline void
fd_toml_str_append( fd_toml_parser_t * parser,
                    char const *       data,
                    ulong              sz ) {
  for( ulong j=0UL; j<sz; j++ ) fd_toml_str_append_byte( parser, data[j] );
}

/* fd_toml_str_append_utf8 appends the UTF-8 encoding of the given
   Unicode code point.  If rune is not a valid code point, writes the
   replacement code point instead. */

static inline void
fd_toml_str_append_utf8( fd_toml_parser_t * parser,
                         long               rune ) {
  parser->w = fd_cstr_append_utf8( parser->w, (uint)rune );
}

/* fd_toml_str_fini terminates the decoded string.  Must be called
   after the closing delimiter was consumed. */

static inline void
fd_toml_str_fini( fd_toml_parser_t * parser ) {
  parser->str_off = (uint)( parser->str_start - parser->base );
  parser->str_len = (uint)( parser->w - parser->str_start );
  *parser->w = '\0';
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
  parser->c.data   += n;
}

static inline void
fd_toml_advance_inline( fd_toml_parser_t * parser,
                        ulong              n ) {
  parser->c.data += n;
}

/* fd_toml_avail returns the number of bytes available for parsing. */

static inline ulong
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
    if( !ret ) {                                      \
      if( parser->error ) return 0;                   \
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
    for( ulong j=0; j<4; j++ ) valid &= fd_isxdigit( parser->c.data[j] );
    if( FD_UNLIKELY( !valid ) ) return 0;
    rune  = ( fd_toml_xdigit( parser->c.data[0] )<<12 );
    rune |= ( fd_toml_xdigit( parser->c.data[1] )<< 8 );
    rune |= ( fd_toml_xdigit( parser->c.data[2] )<< 4 );
    rune |= ( fd_toml_xdigit( parser->c.data[3] )     );
    fd_toml_advance_inline( parser, 4UL );
    fd_toml_str_append_utf8( parser, rune );
    return 1;
  case 'U':
    if( FD_UNLIKELY( fd_toml_avail( parser ) < 8UL ) ) return 0;
    for( ulong j=0; j<8; j++ ) valid &= fd_isxdigit( parser->c.data[j] );
    if( FD_UNLIKELY( !valid ) ) return 0;
    rune  = ( fd_toml_xdigit( parser->c.data[0] )<<28 );
    rune |= ( fd_toml_xdigit( parser->c.data[1] )<<24 );
    rune |= ( fd_toml_xdigit( parser->c.data[2] )<<20 );
    rune |= ( fd_toml_xdigit( parser->c.data[3] )<<16 );
    rune |= ( fd_toml_xdigit( parser->c.data[4] )<<12 );
    rune |= ( fd_toml_xdigit( parser->c.data[5] )<< 8 );
    rune |= ( fd_toml_xdigit( parser->c.data[6] )<< 4 );
    rune |= ( fd_toml_xdigit( parser->c.data[7] )     );
    fd_toml_advance_inline( parser, 8UL );
    fd_toml_str_append_utf8( parser, rune );
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
  fd_toml_str_fini( parser );
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
  fd_toml_str_fini( parser );
  return 1;
}

/* quoted-key = basic-string / literal-string */

static int
fd_toml_parse_quoted_key( fd_toml_parser_t * parser ) {
  if( FD_LIKELY( SUB_PARSE( fd_toml_parse_basic_string  ( parser ) ) ) ) return 1;
  if( FD_LIKELY( SUB_PARSE( fd_toml_parse_literal_string( parser ) ) ) ) return 1;
  return 0;
}

/* unquoted-key = 1*( ALPHA / DIGIT / %x2D / %x5F ) ; A-Z / a-z / 0-9 / - / _

   Unquoted keys are referenced in place and never modified: the byte
   following the key is still needed by the parser. */

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
  char const * start = parser->c.data;
  fd_toml_advance_inline( parser, 1UL );

  while( fd_toml_avail( parser ) ) {
    c = (uchar)parser->c.data[0];
    if( FD_LIKELY( fd_toml_is_unquoted_key_char( c ) ) ) {
      fd_toml_advance_inline( parser, 1UL );
    } else {
      break;
    }
  }

  parser->str_off = (uint)( start - parser->base );
  parser->str_len = (uint)( parser->c.data - start );
  return 1;
}

/* simple-key = quoted-key / unquoted-key */

static int
fd_toml_parse_simple_key( fd_toml_parser_t * parser ) {
  if( FD_LIKELY( SUB_PARSE( fd_toml_parse_quoted_key  ( parser ) ) ) ) goto add;
  if( FD_LIKELY( SUB_PARSE( fd_toml_parse_unquoted_key( parser ) ) ) ) goto add;
  return 0;

add:
  if( FD_UNLIKELY( parser->key_cnt>=FD_TOML_KEY_SEG_MAX ) ) {
    FD_LOG_WARNING(( "TOML parse error: key has too many segments (max %lu)", FD_TOML_KEY_SEG_MAX ));
    parser->error = FD_TOML_ERR_PARSE;
    return 0;
  }
  parser->key_off[ parser->key_cnt ] = parser->str_off;
  parser->key_len[ parser->key_cnt ] = parser->str_len;
  parser->key_cnt++;
  return 1;
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
  parser->key_cnt = 0U;
  if( FD_UNLIKELY( !SUB_PARSE( fd_toml_parse_simple_key( parser ) ) ) ) return 0;
  while( fd_toml_avail( parser ) ) {
    if( FD_UNLIKELY( !SUB_PARSE( fd_toml_parse_dot_sep( parser ) ) ) ) break;
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
  fd_toml_str_fini( parser );
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
  fd_toml_str_append_byte( parser, c );

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
  fd_toml_str_fini( parser );
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
  do {
    fd_toml_node_t * node = fd_toml_emit( parser, FD_TOML_NODE_STRING );
    if( FD_UNLIKELY( !node ) ) return 0;
    node->str.off = parser->str_off;
    node->str.len = parser->str_len;
    return 1;
  } while(0);
}

/* boolean = true / false */

static int
fd_toml_parse_boolean( fd_toml_parser_t * parser ) {
  int boolv = 0;
  if( parser->c.data + 4 > parser->data_end ) return 0;
  if( 0==memcmp( parser->c.data, "true", 4 ) ) {
    fd_toml_advance_inline( parser, 4 );
    boolv = 1;
  } else if( parser->c.data + 5 <= parser->data_end &&
             0==memcmp( parser->c.data, "false", 5 ) ) {
    fd_toml_advance_inline( parser, 5 );
    boolv = 0;
  } else {
    return 0;
  }

  fd_toml_node_t * node = fd_toml_emit( parser, FD_TOML_NODE_BOOL );
  if( FD_UNLIKELY( !node ) ) return 0;
  node->b = boolv;
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
fd_toml_parse_array_values( fd_toml_parser_t * parser,
                            uint               array ) {

  /* Unrolled tail recursion with backtracking */

  fd_toml_cur_t backtrack = parser->c;
  for(;;) {
    fd_toml_parse_ws_comment_newline( parser );

    parser->val_parent  = array;
    parser->val_key_off = 0U;
    parser->val_key_len = 0U;
    parser->val_line    = (uint)parser->c.lineno;

    if( FD_UNLIKELY( !fd_toml_parse_val( parser ) ) ) {
      parser->c = backtrack;
      break;
    }

    fd_toml_parse_ws_comment_newline( parser );

    backtrack = parser->c;
    if( fd_toml_avail( parser ) && parser->c.data[0] == ',' ) {
      fd_toml_advance_inline( parser, 1UL );
    } else {
      break;
    }
    backtrack = parser->c;
  }

  return 1;
}

/* array = array-open [ array-values ] ws-comment-newline array-close

   array-open =  %x5B ; [
   array-close = %x5D ; ] */

static int
fd_toml_parse_array( fd_toml_parser_t * parser ) {
  EXPECT_CHAR( '[' );
  fd_toml_node_t * node = fd_toml_emit( parser, FD_TOML_NODE_ARRAY );
  if( FD_UNLIKELY( !node ) ) return 0;
  uint array = (uint)( node - parser->node );
  SUB_PARSE( fd_toml_parse_array_values      ( parser, array ) );
  SUB_PARSE( fd_toml_parse_ws_comment_newline( parser ) );
  EXPECT_CHAR( ']' );
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

  fd_toml_node_t * node = fd_toml_emit( parser, FD_TOML_NODE_TABLE );
  if( FD_UNLIKELY( !node ) ) return 0;

  uint old_table = parser->table;
  parser->table = (uint)( node - parser->node );

  while( SUB_PARSE( fd_toml_parse_inline_table_keyvals( parser ) ) ) {}

  fd_toml_parse_ws( parser );
  EXPECT_CHAR( '}' );

  parser->table = old_table;
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

  uint  len    = 0U;
  ulong digits = 0UL;
  int allow_underscore = 0;
  for(;;) {
    if( FD_UNLIKELY( allow_underscore && parser->c.data[0] == '_' ) ) {
      allow_underscore = 0;
      fd_toml_advance_inline( parser, 1UL );
      if( FD_UNLIKELY( !fd_toml_avail( parser )         ) ) return 0;
      if( FD_UNLIKELY( !fd_isdigit( parser->c.data[0] ) ) ) return 0;
    } else {
      int digit = (uchar)parser->c.data[0];
      if( FD_UNLIKELY(
          __builtin_umull_overflow( digits, 10, &digits ) ||
          __builtin_uaddl_overflow( digits, (ulong)( digit - '0' ), &digits ) ) ) {
        parser->error = FD_TOML_ERR_RANGE;
        return 0;
      }
      len++;
      fd_toml_advance_inline( parser, 1UL );
      if( !fd_toml_avail( parser ) ) break;
      if( !fd_isdigit( parser->c.data[0] ) && parser->c.data[0] != '_' ) break;
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

  if( FD_UNLIKELY( !fd_toml_avail( parser ) ) ) return 0;
  int first_digit = (uchar)parser->c.data[0];
  if( first_digit == '0' ) {
    dec->res = 0UL;
    dec->neg = !!neg;
    fd_toml_advance_inline( parser, 1UL );
    return 1;
  }

  if( FD_UNLIKELY( first_digit<='0' || first_digit>'9' ) ) return 0;

  dec->neg = !!neg;
  return fd_toml_parse_zero_prefixable_int( parser, dec );
}

static int
fd_toml_emit_int( fd_toml_parser_t * parser,
                  long               val ) {
  fd_toml_node_t * node = fd_toml_emit( parser, FD_TOML_NODE_INT );
  if( FD_UNLIKELY( !node ) ) return 0;
  node->i = val;
  return 1;
}

static int
fd_toml_parse_dec_int( fd_toml_parser_t * parser ) {
  fd_toml_dec_t dec = {0};
  if( FD_UNLIKELY( !fd_toml_parse_dec_int_( parser, &dec ) ) ) return 0;
  long val = (long)dec.res;
       val = fd_long_if( dec.neg, -val, val );
  return fd_toml_emit_int( parser, val );
}

/* hex-int = hex-prefix HEXDIG *( HEXDIG / underscore HEXDIG ) */

static int
fd_toml_parse_hex_int( fd_toml_parser_t * parser ) {
  if( FD_UNLIKELY( fd_toml_avail( parser ) < 3       ) ) return 0;
  if( FD_UNLIKELY( parser->c.data[0] != '0'          ) ) return 0;
  if( FD_UNLIKELY( parser->c.data[1] != 'x'          ) ) return 0;
  if( FD_UNLIKELY( !fd_isxdigit( parser->c.data[2] ) ) ) return 0;  /* at least one digit */
  fd_toml_advance_inline( parser, 2UL );

  ulong res = 0UL;
  int allow_underscore = 0;
  for(;;) {
    int digit = (uchar)parser->c.data[0];
    if( FD_UNLIKELY( allow_underscore && digit == '_' ) ) {
      allow_underscore = 0;
      fd_toml_advance_inline( parser, 1UL );
      if( FD_UNLIKELY( !fd_toml_avail( parser )          ) ) return 0;
      if( FD_UNLIKELY( !fd_isxdigit( parser->c.data[0] ) ) ) return 0;
    } else {
      if( !fd_isxdigit( digit ) ) break;
      if( FD_UNLIKELY( res>>60 ) ) {
        parser->error = FD_TOML_ERR_RANGE;
        return 0;
      }
      res <<= 4;
      res  |= fd_toml_xdigit( digit );
      fd_toml_advance_inline( parser, 1UL );
      if( !fd_toml_avail( parser ) ) break;
      allow_underscore = 1;
    }
  }

  return fd_toml_emit_int( parser, (long)res );
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
      if( FD_UNLIKELY( res>>61 ) ) {
        parser->error = FD_TOML_ERR_RANGE;
        return 0;
      }
      res <<= 3;
      res  |= (ulong)( digit - '0' );
      fd_toml_advance_inline( parser, 1UL );
      if( !fd_toml_avail( parser ) ) break;
      allow_underscore = 1;
    }
  }

  return fd_toml_emit_int( parser, (long)res );
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
      if( FD_UNLIKELY( res>>63 ) ) {
        parser->error = FD_TOML_ERR_RANGE;
        return 0;
      }
      res <<= 1;
      res  |= (ulong)( digit - '0' );
      fd_toml_advance_inline( parser, 1UL );
      if( !fd_toml_avail( parser ) ) break;
      allow_underscore = 1;
    }
  }

  return fd_toml_emit_int( parser, (long)res );
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
fd_toml_parse_float_normal( fd_toml_parser_t * parser ) {

  fd_toml_dec_t stem = {0};
  if( FD_UNLIKELY( !fd_toml_parse_dec_int_( parser, &stem ) ) ) return 0;
  if( FD_UNLIKELY( !fd_toml_avail( parser )                 ) ) return 0;
  double res = (double)stem.res;

  int ok = 0;
  fd_toml_dec_t frac_dec = {0};
  if( SUB_PARSE( fd_toml_parse_frac( parser, &frac_dec ) ) ) {
    double frac = (double)frac_dec.res;
    while( frac_dec.len-- ) frac /= 10.0;
    res += frac;
    ok   = 1;
  }

  fd_toml_dec_t exp_dec = {0};
  if( !SUB_PARSE( fd_toml_parse_exp( parser, &exp_dec ) ) ) {
    if( FD_LIKELY( ok ) ) goto parsed;
    return 0;
  }

  res *= pow( exp_dec.neg ? 0.1 : 10.0, (double)exp_dec.res );

parsed:
  if( stem.neg ) res = -res;
  do {
    fd_toml_node_t * node = fd_toml_emit( parser, FD_TOML_NODE_FLOAT );
    if( FD_UNLIKELY( !node ) ) return 0;
    node->f = res;
    return 1;
  } while(0);
}

/* special-float = [ minus / plus ] ( inf / nan )
   inf = %x69.6e.66  ; inf
   nan = %x6e.61.6e  ; nan */

static int
fd_float_parse_float_special( fd_toml_parser_t * parser ) {
  if( FD_UNLIKELY( fd_toml_avail( parser ) < 3 ) ) return 0;
  int c = (uchar)parser->c.data[0];

  switch( c ) {
  case '-': case '+':
    fd_toml_advance_inline( parser, 1UL );
    if( FD_UNLIKELY( fd_toml_avail( parser ) < 3 ) ) return 0;
    break;
  }

  char const * str = parser->c.data;
  fd_toml_advance_inline( parser, 3UL );

  if( 0==strncasecmp( str, "inf", 3 ) ) {
    FD_LOG_WARNING(( "TOML parse error: float infinity is unsupported" ));
    parser->error = FD_TOML_ERR_RANGE;
    return 0;
  }

  if( 0==strncasecmp( str, "nan", 3 ) ) {
    FD_LOG_WARNING(( "TOML parse error: float NaN is unsupported" ));
    parser->error = FD_TOML_ERR_RANGE;
    return 1;
  }

  return 0;
}

/* float = float-int-part ( exp / frac [ exp ] )
   float =/ special-float */

static int
fd_toml_parse_float( fd_toml_parser_t * parser ) {
  if( SUB_PARSE( fd_toml_parse_float_normal  ( parser ) ) ) return 1;
  if( SUB_PARSE( fd_float_parse_float_special( parser ) ) ) return 1;
  return 0;
}

/* val = string / boolean / array / inline-table / float / integer */

static int
fd_toml_parse_val( fd_toml_parser_t * parser ) {
  /* consider some lookahead for better performance */
  if( SUB_PARSE( fd_toml_parse_string      ( parser ) ) ) return 1;
  if( SUB_PARSE( fd_toml_parse_boolean     ( parser ) ) ) return 1;
  if( SUB_PARSE( fd_toml_parse_array       ( parser ) ) ) return 1;
  if( SUB_PARSE( fd_toml_parse_inline_table( parser ) ) ) return 1;
  // if( SUB_PARSE( fd_toml_parse_date_time   ( parser ) ) ) return 1; /* not supported */
  /* NOTE: float and integer have a common dec-int prefix -- dedup for better performance */
  if( SUB_PARSE( fd_toml_parse_float       ( parser ) ) ) return 1;
  if( SUB_PARSE( fd_toml_parse_integer     ( parser ) ) ) return 1;
  return 0;
}

/* keyval = key keyval-sep val */

static int
fd_toml_parse_keyval( fd_toml_parser_t * parser ) {
  if( FD_UNLIKELY( !SUB_PARSE( fd_toml_parse_key( parser ) ) ) ) return 0;

  ulong last = parser->key_cnt-1UL;
  uint parent = fd_toml_table_walk( parser, parser->table, 0UL, last );
  if( FD_UNLIKELY( parent==FD_TOML_IDX_NULL ) ) return 0;

  uint key_off = parser->key_off[ last ];
  uint key_len = parser->key_len[ last ];
  if( FD_UNLIKELY( fd_toml_node_find( parser, parent, key_off, key_len ) ) ) {
    fd_toml_dup_warn( parser, key_off, key_len );
    return 0;
  }

  parser->val_parent  = parent;
  parser->val_key_off = key_off;
  parser->val_key_len = key_len;
  parser->val_line    = (uint)parser->c.lineno;

  if( FD_UNLIKELY( !SUB_PARSE( fd_toml_parse_keyval_sep( parser ) ) ) ) return 0;
  if( FD_UNLIKELY( !SUB_PARSE( fd_toml_parse_val       ( parser ) ) ) ) return 0;
  return 1;
}

/* std-table = std-table-open key std-table-close

   std-table-open  = %x5B ws     ; [ Left square bracket
   std-table-close = ws %x5D     ; ] Right square bracket */

static int
fd_toml_parse_std_table( fd_toml_parser_t * parser ) {
  EXPECT_CHAR( '[' );
  fd_toml_parse_ws( parser );

  if( FD_UNLIKELY( !fd_toml_parse_key( parser ) ) ) return 0;

  fd_toml_parse_ws( parser );
  EXPECT_CHAR( ']' );

  uint table = fd_toml_table_walk( parser, 0U, 0UL, parser->key_cnt );
  if( FD_UNLIKELY( table==FD_TOML_IDX_NULL ) ) return 0;
  parser->table = table;
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

  if( FD_UNLIKELY( !SUB_PARSE( fd_toml_parse_key( parser ) ) ) ) return 0;

  fd_toml_parse_ws( parser );

  if( FD_UNLIKELY( fd_toml_avail( parser ) < 2UL ) ) return 0;
  if( FD_UNLIKELY( ( parser->c.data[0] != ']' ) |
                   ( parser->c.data[1] != ']' ) ) ) return 0;
  fd_toml_advance_inline( parser, 2UL );

  ulong last = parser->key_cnt-1UL;
  uint parent = fd_toml_table_walk( parser, 0U, 0UL, last );
  if( FD_UNLIKELY( parent==FD_TOML_IDX_NULL ) ) return 0;

  uint key_off = parser->key_off[ last ];
  uint key_len = parser->key_len[ last ];
  fd_toml_node_t * array = fd_toml_node_find( parser, parent, key_off, key_len );
  if( !array ) {
    array = fd_toml_node_alloc( parser, parent, FD_TOML_NODE_ARRAY, key_off, key_len, (uint)parser->c.lineno );
    if( FD_UNLIKELY( !array ) ) return 0;
  } else if( FD_UNLIKELY( array->type!=FD_TOML_NODE_ARRAY ) ) {
    fd_toml_dup_warn( parser, key_off, key_len );
    return 0;
  }

  fd_toml_node_t * table = fd_toml_node_alloc( parser, (uint)( array - parser->node ), FD_TOML_NODE_TABLE, 0U, 0U, (uint)parser->c.lineno );
  if( FD_UNLIKELY( !table ) ) return 0;
  parser->table = (uint)( table - parser->node );
  return 1;
}

/* table = std-table / array-table */

static int
fd_toml_parse_table( fd_toml_parser_t * parser ) {
  if( SUB_PARSE( fd_toml_parse_array_table( parser ) ) ) return 1;
  if( SUB_PARSE( fd_toml_parse_std_table  ( parser ) ) ) return 1;
  return 0;
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

int
fd_toml_parse( fd_toml_doc_t *      doc,
               char *               toml,
               ulong                toml_sz,
               fd_toml_node_t *     nodes,
               ulong                node_max,
               fd_toml_err_info_t * opt_err ) {

  static fd_toml_err_info_t _dummy_err[1];
  if( !opt_err ) opt_err = _dummy_err;
  opt_err->line = 0UL;

  *doc = (fd_toml_doc_t) {
    .base     = toml,
    .base_sz  = toml_sz,
    .node     = nodes,
    .node_cnt = 0UL,
    .node_max = node_max,
  };

  if( FD_UNLIKELY( !node_max || node_max>UINT_MAX ) ) {
    FD_LOG_WARNING(( "invalid node_max %lu", node_max ));
    return FD_TOML_ERR_NODE;
  }

  fd_toml_parser_t parser[1] = {{
    .c = {
      .data   = toml,
      .lineno = 1UL,
    },
    .data_end = toml + toml_sz,
    .base     = toml,
    .node     = nodes,
    .node_max = (uint)node_max,
    .table    = 0U,
  }};

  fd_toml_node_alloc( parser, FD_TOML_IDX_NULL, FD_TOML_NODE_TABLE, 0U, 0U, 1U );

  int ok = 1;
  if( FD_LIKELY( toml_sz ) ) ok = fd_toml_parse_toml( parser );
  opt_err->line = parser->c.lineno;
  doc->node_cnt = parser->node_cnt;

  if( FD_UNLIKELY( (!ok) | (fd_toml_avail( parser ) > 0) ) ) {
    return fd_int_if( !!parser->error, parser->error, FD_TOML_ERR_PARSE );
  }

  return FD_TOML_SUCCESS;
}

/* Query API ***********************************************************/

fd_toml_node_t *
fd_toml_child( fd_toml_doc_t const *  doc,
               fd_toml_node_t const * parent,
               char const *           key,
               ulong                  key_len ) {
  for( fd_toml_node_t * n=fd_toml_child_first( doc, parent ); n; n=fd_toml_child_next( doc, n ) ) {
    if( n->key_len==key_len && 0==memcmp( doc->base + n->key_off, key, key_len ) ) return n;
  }
  return NULL;
}

fd_toml_node_t *
fd_toml_get( fd_toml_doc_t const *  doc,
             fd_toml_node_t const * parent,
             char const *           path ) {
  fd_toml_node_t * node = parent ? (fd_toml_node_t *)parent : fd_toml_root( doc );
  while( *path ) {
    char const * dot = strchr( path, '.' );
    ulong seg_len = dot ? (ulong)( dot - path ) : strlen( path );
    node = fd_toml_child( doc, node, path, seg_len );
    if( !node ) return NULL;
    path += seg_len;
    if( *path=='.' ) path++;
  }
  return node;
}

fd_toml_node_t *
fd_toml_find_leftover( fd_toml_doc_t const * doc,
                       fd_toml_node_t *      node ) {
  if( node->consumed ) return NULL;
  switch( node->type ) {
  case FD_TOML_NODE_TABLE:
    for( fd_toml_node_t * n=fd_toml_child_first( doc, node ); n; n=fd_toml_child_next( doc, n ) ) {
      fd_toml_node_t * left = fd_toml_find_leftover( doc, n );
      if( left ) return left;
    }
    return NULL;
  case FD_TOML_NODE_ARRAY:
    if( node->first_child==FD_TOML_IDX_NULL ) return node;
    for( fd_toml_node_t * n=fd_toml_child_first( doc, node ); n; n=fd_toml_child_next( doc, n ) ) {
      fd_toml_node_t * left = fd_toml_find_leftover( doc, n );
      if( left ) return left;
    }
    return NULL;
  default:
    return node;
  }
}

/* fd_toml_path_append copies up to sz bytes of text to p, truncating
   at end. */

static char *
fd_toml_path_append( char *       p,
                     char const * end,
                     char const * text,
                     ulong        sz ) {
  sz = fd_ulong_min( sz, (ulong)( end-p ) );
  return fd_cstr_append_text( p, text, sz );
}

static char *
fd_toml_node_path_( fd_toml_doc_t const *  doc,
                    fd_toml_node_t const * node,
                    char *                 p,
                    char const *           end ) {
  if( node->parent==FD_TOML_IDX_NULL ) return p;
  fd_toml_node_t const * parent = doc->node + node->parent;
  p = fd_toml_node_path_( doc, parent, p, end );
  if( parent->type==FD_TOML_NODE_ARRAY ) {
    ulong idx = 0UL;
    for( fd_toml_node_t const * n=fd_toml_child_first( doc, parent ); n && n!=node; n=fd_toml_child_next( doc, n ) ) idx++;
    char idx_cstr[ 21 ];
    fd_cstr_fini( fd_cstr_append_ulong_as_text( idx_cstr, 0, 0, idx, fd_ulong_base10_dig_cnt( idx ) ) );
    p = fd_toml_path_append( p, end, "[", 1UL );
    p = fd_toml_path_append( p, end, idx_cstr, strlen( idx_cstr ) );
    p = fd_toml_path_append( p, end, "]", 1UL );
  } else {
    if( parent->parent!=FD_TOML_IDX_NULL ) p = fd_toml_path_append( p, end, ".", 1UL );
    p = fd_toml_path_append( p, end, doc->base + node->key_off, node->key_len );
  }
  return p;
}

ulong
fd_toml_node_path( fd_toml_doc_t const *  doc,
                   fd_toml_node_t const * node,
                   char *                 buf,
                   ulong                  buf_sz ) {
  if( FD_UNLIKELY( !buf_sz ) ) return 0UL;
  char * end = buf + buf_sz - 1UL;
  char * p   = fd_toml_node_path_( doc, node, buf, end );
  *p = '\0';
  return (ulong)( p - buf );
}

FD_FN_CONST char const *
fd_toml_strerror( int err ) {
  switch( err ) {
  case FD_TOML_SUCCESS:   return "success";
  case FD_TOML_ERR_NODE:  return "out of nodes";
  case FD_TOML_ERR_DUP:   return "duplicate key";
  case FD_TOML_ERR_RANGE: return "integer overflow";
  case FD_TOML_ERR_PARSE: return "parse failure";
  default:                return "unknown error";
  }
}
