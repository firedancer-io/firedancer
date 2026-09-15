#ifndef HEADER_fd_src_ballet_toml_fd_toml_h
#define HEADER_fd_src_ballet_toml_fd_toml_h

/* fd_toml.h provides APIs for parsing TOML config files.

   Grammar: https://github.com/toml-lang/toml/blob/1.0.0/toml.abnf */

#include "../../util/fd_util_base.h"

/* Error codes */

#define FD_TOML_SUCCESS   ( 0)  /* ok */
#define FD_TOML_ERR_NODE  (-1)  /* ran out of nodes */
#define FD_TOML_ERR_DUP   (-4)  /* duplicate key */
#define FD_TOML_ERR_RANGE (-5)  /* overflow */
#define FD_TOML_ERR_PARSE (-6)  /* parse fail */

/* Node types */

#define FD_TOML_NODE_TABLE  (1)
#define FD_TOML_NODE_ARRAY  (2)
#define FD_TOML_NODE_STRING (3)
#define FD_TOML_NODE_INT    (4)
#define FD_TOML_NODE_FLOAT  (5)
#define FD_TOML_NODE_BOOL   (6)

#define FD_TOML_IDX_NULL (UINT_MAX)

/* fd_toml_node_t is one entry of the parsed document tree.  All string
   data (keys and values) lives in the caller's TOML buffer.  Keys are
   not NUL terminated.  String values are NUL terminated (the parser
   writes the terminator in place). */

struct __attribute__((aligned(8))) fd_toml_node {
  ushort type;         /* FD_TOML_NODE_* */
  ushort consumed;     /* set by fd_toml_node_consume */
  uint   line;         /* 1-indexed line number of the key */
  uint   key_off;      /* key segment at base+key_off, key_len bytes */
  uint   key_len;      /* 0 for the root and for array elements */
  uint   parent;       /* FD_TOML_IDX_NULL for the root */
  uint   next_sibling;
  uint   first_child;  /* TABLE and ARRAY only */
  uint   last_child;
  union {
    struct { uint off; uint len; } str; /* STRING: cstr at base+off */
    long   i;                           /* INT */
    double f;                           /* FLOAT */
    int    b;                           /* BOOL */
  };
};

typedef struct fd_toml_node fd_toml_node_t;

/* fd_toml_doc_t describes a parsed document.  node[0] is the root
   table. */

struct fd_toml_doc {
  char *           base;
  ulong            base_sz;
  fd_toml_node_t * node;
  ulong            node_cnt;
  ulong            node_max;
};

typedef struct fd_toml_doc fd_toml_doc_t;

/* fd_toml_err_info_t contains information about a TOML parse failure.  */

struct fd_toml_err_info {
  ulong line; /* 1-indexed line number */
};

typedef struct fd_toml_err_info fd_toml_err_info_t;

FD_PROTOTYPES_BEGIN

/* fd_toml_parse deserializes a TOML document into a node tree.  toml
   points to the first byte of the TOML, toml_sz is its byte length.
   The buffer is MUTATED: escape sequences are decoded in place and
   string values are NUL terminated in place.  Nodes are written to
   [nodes,nodes+node_max), node_max>=1.  On success returns
   FD_TOML_SUCCESS and initializes *doc.  On failure returns
   FD_TOML_ERR_*; *doc then describes the partial tree.  If
   opt_err!=NULL, initializes *opt_err with error information (even if
   the return code was success).

   All node pointers and strings alias the toml buffer, which must stay
   valid and unmodified for as long as the doc is used.

   Note that toml is not interpreted as a cstr -- No terminating zero is
   fine and so are stray zeros in the middle of the file.

   fd_toml_parse is not hardened against untrusted input. fd_toml_parse
   is not optimized for performance.

   Mapping:

    TOML type      | Example     | node type
    ---------------|-------------|--------------------------------------
     table         | [key]       | TABLE
     array table   | [[key]]     | ARRAY of TABLE
     inline table  | x={a=1,b=2} | TABLE
     inline array  | x=[1,2]     | ARRAY
     bool          | true        | BOOL
     integer       | -3          | INT
     float         | 3e-3        | FLOAT
     string        | 'hello'     | STRING

   Despite the name, TOML is neither "obvious" nor "minimal".  fd_toml
   thus only supports a subset of the 'spec' and ignores some horrors.
   Known errata:

   - fd_toml allows duplicate tables whereas TOML has various
     complicated rules that forbid such.

   - Missing validation for out-of-bounds Unicode escapes

   - Missing support for CRLF

   - Infinite and NaN floats are rejected.

   - Missing support for date-time values. */

int
fd_toml_parse( fd_toml_doc_t *      doc,
               char *               toml,
               ulong                toml_sz,
               fd_toml_node_t *     nodes,
               ulong                node_max,
               fd_toml_err_info_t * opt_err );

/* Query API.  All functions take a doc produced by fd_toml_parse. */

/* fd_toml_root returns the root table. */

static inline fd_toml_node_t *
fd_toml_root( fd_toml_doc_t const * doc ) {
  return doc->node;
}

/* fd_toml_child returns the child of parent (a TABLE) whose key is
   [key,key+key_len), or NULL if there is none. */

fd_toml_node_t *
fd_toml_child( fd_toml_doc_t const *  doc,
               fd_toml_node_t const * parent,
               char const *           key,
               ulong                  key_len );

/* fd_toml_get looks up a dotted path ("a.b.c") of unquoted key segments
   starting at parent (NULL for the root).  Returns NULL if any segment
   is missing. */

fd_toml_node_t *
fd_toml_get( fd_toml_doc_t const *  doc,
             fd_toml_node_t const * parent,
             char const *           path );

/* fd_toml_child_{first,next} iterate over the children of a TABLE or
   ARRAY in document order.  Return NULL at the end. */

static inline fd_toml_node_t *
fd_toml_child_first( fd_toml_doc_t const *  doc,
                     fd_toml_node_t const * node ) {
  return node->first_child==FD_TOML_IDX_NULL ? NULL : doc->node + node->first_child;
}

static inline fd_toml_node_t *
fd_toml_child_next( fd_toml_doc_t const *  doc,
                    fd_toml_node_t const * node ) {
  return node->next_sibling==FD_TOML_IDX_NULL ? NULL : doc->node + node->next_sibling;
}

/* fd_toml_node_key returns a pointer to the node's key segment.  The
   key is NOT NUL terminated; its length is stored to *opt_len. */

static inline char const *
fd_toml_node_key( fd_toml_doc_t const *  doc,
                  fd_toml_node_t const * node,
                  ulong *                opt_len ) {
  if( opt_len ) *opt_len = node->key_len;
  return doc->base + node->key_off;
}

/* fd_toml_node_str returns the NUL terminated string value of a STRING
   node. */

static inline char const *
fd_toml_node_str( fd_toml_doc_t const *  doc,
                  fd_toml_node_t const * node ) {
  return doc->base + node->str.off;
}

/* fd_toml_node_consume marks a node as handled by the caller.  A
   consumed TABLE or ARRAY covers all its descendants. */

static inline void
fd_toml_node_consume( fd_toml_node_t * node ) {
  node->consumed = 1;
}

/* fd_toml_find_leftover returns the first node under node (inclusive)
   that was not consumed: an unconsumed leaf, or an unconsumed ARRAY
   without children.  Returns NULL if everything was consumed. */

fd_toml_node_t *
fd_toml_find_leftover( fd_toml_doc_t const * doc,
                       fd_toml_node_t *      node );

/* fd_toml_node_path renders the dotted path of node ("a.b[2].c") as a
   cstr into buf.  Truncates if buf_sz is too small.  Returns the
   number of chars written excluding the NUL. */

ulong
fd_toml_node_path( fd_toml_doc_t const *  doc,
                   fd_toml_node_t const * node,
                   char *                 buf,
                   ulong                  buf_sz );

/* fd_toml_strerror returns a human-readable error string with static
   storage describing the given FD_TOML_ERR_* code.  Works for negative
   return values in fd_toml_parse. */

FD_FN_CONST char const *
fd_toml_strerror( int err );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_toml_fd_toml_h */
