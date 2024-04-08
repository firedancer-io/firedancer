#include "fd_pod.h"

/* FD_POD_PATH_SPLIT splits the path into a leading key prefix and a
   suffix.  On return, prefix_len is the number of bytes in a strlen
   sense of the leading key prefix.  If delim is '.', suffix points to
   the first byte of the path suffix.  If delim is '\0', the path is
   just a single key with no suffix and suffix should be ignored.  This
   macro is not robust. */

#define FD_POD_PATH_SPLIT( path, prefix_len, delim, suffix ) do { \
    suffix = path;                                                \
    for(;;) {                                                     \
      delim = suffix[0];                                          \
      if( FD_UNLIKELY( (delim=='.') | (!delim) ) ) break;         \
      suffix++;                                                   \
    }                                                             \
    prefix_len = (ulong)(suffix - path);                          \
    suffix++;                                                     \
  } while(0)

/* FD_POD_FOR_ALL_BEGIN / FD_POD_FOR_ALL_END iterates over all key-val
   pairs in a pod.  Each iteration:

     uchar * pair     points to the first byte of the encoded key-val pair
     uchar * next     points to the one after the last byte of the encoded key-val pair
     ulong   ksz      is the SVW encoded width of the key_sz field
     ulong   key_sz   is the strlen(key)+1 of the key
     char  * key      is points to the first byte of the key cstr
     int     val_type is the type of val associated with this key (FD_POD_VAL_TYPE_*)
     ulong   vsz      is the SVW encoded width of the val_sz field
     ulong   val_sz   is the number of bytes in the encoded value
     void  * val      points to the first byte of the encoded val

   The actual iteration process does not depend on these values.
   (E.g. caller can mangle these without impact the iteration.)

   There are also variables:
     ulong _csz    is the SWV encoded width of the pod header variables
     ulong _used   is the number of bytes used in the pod
     ulong _cursor is the next byte to process in the iteration
     ulong _stop   is one after the last byte to process in the iteration

   This macro is not robust. */

#define FD_POD_FOR_ALL_BEGIN( pod, pair, next, ksz, key_sz, key, val_type, vsz, val_sz, val ) \
  do {                                                                                        \
    ulong   _csz    = fd_ulong_svw_dec_sz( pod );                                             \
    ulong   _used   = fd_ulong_svw_dec_fixed( pod + _csz, _csz );                             \
    uchar * _cursor = (uchar *)(pod + _csz*3UL);                                              \
    uchar * _stop   = (uchar *)(pod + _used);                                                 \
    while( _cursor<_stop ) {                                                                  \
      pair     = _cursor;                                                   (void)pair;       \
      ksz      = fd_ulong_svw_dec_sz( _cursor );                                              \
      key_sz   = fd_ulong_svw_dec_fixed( _cursor, ksz ); _cursor += ksz;                      \
      key      = (char *)_cursor;                        _cursor += key_sz; (void)key;        \
      val_type = (int)_cursor[0];                        _cursor += 1;      (void)val_type;   \
      vsz      = fd_ulong_svw_dec_sz( _cursor );                                              \
      val_sz   = fd_ulong_svw_dec_fixed( _cursor, vsz ); _cursor += vsz;                      \
      val      = (void *)_cursor;                        _cursor += val_sz; (void)val;        \
      next     = _cursor;                                                   (void)next;       \

#define FD_POD_FOR_ALL_END \
    }                      \
  } while(0)

fd_pod_info_t *
fd_pod_list( uchar const   * FD_RESTRICT pod,
             fd_pod_info_t * FD_RESTRICT info ) {
  if( FD_UNLIKELY( !pod ) ) return NULL;

  ulong idx = 0UL;

  uchar const * pair; uchar const * next;
  ulong ksz; ulong key_sz; char const * key; int val_type;
  ulong vsz; ulong val_sz; void const * val;
  FD_POD_FOR_ALL_BEGIN( pod, pair, next, ksz, key_sz, key, val_type, vsz, val_sz, val ) {

    info[idx].key_sz   = key_sz;
    info[idx].key      = key;
    info[idx].val_type = val_type;
    info[idx].val_sz   = val_sz;
    info[idx].val      = val;
    info[idx].parent   = NULL;
    idx++;

  } FD_POD_FOR_ALL_END;

  return info;
}

ulong
fd_pod_cnt_subpod( uchar const * FD_RESTRICT pod ) {
  if( FD_UNLIKELY( !pod ) ) return 0UL;

  ulong cnt = 0UL;

  uchar const * pair; uchar const * next;
  ulong ksz; ulong key_sz; char const * key; int val_type;
  ulong vsz; ulong val_sz; void const * val;
  FD_POD_FOR_ALL_BEGIN( pod, pair, next, ksz, key_sz, key, val_type, vsz, val_sz, val ) {
    cnt += (ulong)(val_type==FD_POD_VAL_TYPE_SUBPOD);
  } FD_POD_FOR_ALL_END;

  return cnt;
}

ulong
fd_pod_cnt_recursive( uchar const * FD_RESTRICT pod ) {
  if( FD_UNLIKELY( !pod ) ) return 0UL;

  ulong cnt = 0UL;

  uchar const * pair; uchar const * next;
  ulong ksz; ulong key_sz; char const * key; int val_type;
  ulong vsz; ulong val_sz; void const * val;
  FD_POD_FOR_ALL_BEGIN( pod, pair, next, ksz, key_sz, key, val_type, vsz, val_sz, val ) {
    cnt++;
    if( val_type==FD_POD_VAL_TYPE_SUBPOD ) cnt += fd_pod_cnt_recursive( (uchar *)val );
  } FD_POD_FOR_ALL_END;

  return cnt;
}

static fd_pod_info_t *
fd_pod_list_recursive_node( fd_pod_info_t * FD_RESTRICT parent,
                            uchar const   * FD_RESTRICT pod,
                            fd_pod_info_t * FD_RESTRICT info ) {

  uchar const * pair; uchar const * next;
  ulong ksz; ulong key_sz; char const * key; int val_type;
  ulong vsz; ulong val_sz; void const * val;
  FD_POD_FOR_ALL_BEGIN( pod, pair, next, ksz, key_sz, key, val_type, vsz, val_sz, val ) {

    info->key_sz   = key_sz;
    info->key      = key;
    info->val_type = val_type;
    info->val_sz   = val_sz;
    info->val      = val;
    info->parent   = parent;
    info++;

    if( val_type==FD_POD_VAL_TYPE_SUBPOD ) info = fd_pod_list_recursive_node( info-1, (uchar *)val, info );

  } FD_POD_FOR_ALL_END;

  return info;
}

fd_pod_info_t *
fd_pod_list_recursive( uchar const   * FD_RESTRICT pod,
                       fd_pod_info_t * FD_RESTRICT info ) {
  if( FD_UNLIKELY( !pod ) ) return info;
  fd_pod_list_recursive_node( NULL, pod, info );
  return info;
}

int
fd_pod_query( uchar const   * FD_RESTRICT pod,
              char const    * FD_RESTRICT path,
              fd_pod_info_t * FD_RESTRICT opt_info ) {
  if( FD_UNLIKELY( (!pod) | (!path) ) ) return FD_POD_ERR_INVAL;

  ulong prefix_len; char delim; char const * suffix;
  FD_POD_PATH_SPLIT( path, prefix_len, delim, suffix );

  uchar const * pair; uchar const * next;
  ulong ksz; ulong key_sz; char const * key; int val_type;
  ulong vsz; ulong val_sz; void const * val;
  FD_POD_FOR_ALL_BEGIN( pod, pair, next, ksz, key_sz, key, val_type, vsz, val_sz, val ) {

    if( ((key_sz-1UL)==prefix_len) && !memcmp( key, path, prefix_len ) ) { /* Found leading key in pod */

      if( !delim ) { /* Path was a single key, return it */

        if( opt_info ) {
          opt_info->key_sz   = key_sz;
          opt_info->key      = key;
          opt_info->val_type = val_type;
          opt_info->val_sz   = val_sz;
          opt_info->val      = val;
          opt_info->parent   = NULL;
        }
        return FD_POD_SUCCESS;

      } else { /* Path had a suffix.  Recurse into the subpod */

        if( FD_UNLIKELY( val_type!=FD_POD_VAL_TYPE_SUBPOD ) ) return FD_POD_ERR_TYPE;
        return fd_pod_query( (uchar const *)val, suffix, opt_info );

      }
    }

  } FD_POD_FOR_ALL_END;

  return FD_POD_ERR_RESOLVE;
}

char const *
fd_pod_strerror( int err ) {
  switch( err ) {
  case FD_POD_SUCCESS:     return "success";
  case FD_POD_ERR_INVAL:   return "bad input args";
  case FD_POD_ERR_TYPE:    return "path contained an unexpected type key";
  case FD_POD_ERR_RESOLVE: return "path did not resolve to a key";
  case FD_POD_ERR_FULL:    return "pod too full";
  default: break;
  }
  return "unknown";
}

ulong
fd_pod_resize( uchar * pod,
               ulong   new_max ) {
  if( FD_UNLIKELY( !pod ) ) return 0UL;

  ulong csz    = fd_ulong_svw_dec_sz( pod );
//ulong max    = fd_ulong_svw_dec_fixed( pod,           csz );
  ulong used   = fd_ulong_svw_dec_fixed( pod + csz,     csz ); if( FD_UNLIKELY( used>new_max ) ) return 0UL;
  ulong cnt    = fd_ulong_svw_dec_fixed( pod + csz*2UL, csz );
  ulong bdy_sz = used - csz*3UL;

  ulong new_csz;
  ulong new_used;
  for(;;) {
    new_csz    = fd_ulong_svw_enc_sz( new_max );
    new_used   = new_csz*3UL + bdy_sz;
    if( FD_LIKELY( new_used<=new_max ) ) break;
    /* Resized header was too large ... try a smaller new_max */
    new_max--;
  }

  memmove( pod + new_csz*3UL, pod + csz*3UL, bdy_sz );
  fd_ulong_svw_enc_fixed( pod,               new_csz, new_max  );
  fd_ulong_svw_enc_fixed( pod + new_csz,     new_csz, new_used );
  fd_ulong_svw_enc_fixed( pod + new_csz*2UL, new_csz, cnt      );
  return new_max;
}

ulong
fd_pod_compact( uchar * pod,
                int     full ) {
  if( FD_UNLIKELY( !pod ) ) return 0UL;

  /* Compact the body */

  ulong   csz = fd_ulong_svw_dec_sz( pod );
  ulong   max = fd_ulong_svw_dec_fixed( pod,           csz );
  ulong   cnt = fd_ulong_svw_dec_fixed( pod + csz*2UL, csz );
  uchar * bdy = pod + csz*3UL;

  uchar * pair; uchar * next = bdy;
  ulong ksz; ulong key_sz; char const * key; int val_type;
  ulong vsz; ulong val_sz; void * val;
  FD_POD_FOR_ALL_BEGIN( pod, pair, next, ksz, key_sz, key, val_type, vsz, val_sz, val ) {

    /* Compact the pair */

    ulong new_key_sz = strlen( key ) + 1UL; /* <=key_sz */
    ulong new_ksz    = fd_ulong_svw_enc_sz( new_key_sz );

    ulong new_val_sz;
    if( val_type==FD_POD_VAL_TYPE_SUBPOD ) {
      uchar * subpod = (uchar *)val;
      fd_pod_compact( subpod, 1 /*full*/ ); /* Yes, do not pass through the user provided value of full */
      new_val_sz = fd_pod_max( subpod ); /* ==fd_pod_used at this point */
    } else if( val_type==FD_POD_VAL_TYPE_CSTR ) {
      new_val_sz = val_sz ? (strlen( (char *)val )+1UL) : 0UL;
    } else {
      new_val_sz = val_sz;
    }
    /* Note: new_val_sz<=val_sz */
    ulong new_vsz = fd_ulong_svw_enc_sz( new_val_sz );

    uchar * new_cursor = pair;
    fd_ulong_svw_enc_fixed( new_cursor, new_ksz, new_key_sz ); new_cursor += new_ksz;
    memmove( new_cursor, key, new_key_sz );                    new_cursor += new_key_sz;
    new_cursor[0] = (uchar)val_type;                           new_cursor += 1;
    fd_ulong_svw_enc_fixed( new_cursor, new_vsz, new_val_sz ); new_cursor += new_vsz;
    memmove( new_cursor, val, new_val_sz );                    new_cursor += new_val_sz;

    /* Compact the trailing space */

    ulong rem = (ulong)(_stop-next);
    memmove( new_cursor, next, rem );

    /* Update the iterator internals */

    next    = new_cursor;
    _cursor = new_cursor;
    _stop   = new_cursor + rem;
    _used   = (ulong)(_stop - pod);
  } FD_POD_FOR_ALL_END;

  ulong new_bdy_sz = (ulong)(next - bdy);

  /* Compact the header and (if full) trailing padding */

  ulong new_csz;
  ulong new_max;
  ulong new_used;

  if( !full ) {
    new_csz  = fd_ulong_svw_enc_sz( max ); /* <=csz */
    new_max  = max;
    new_used = new_csz*3UL + new_bdy_sz;
  } else {
    new_csz = 1UL;
    for(;;) {
      /**/  new_max  = new_csz*3UL + new_bdy_sz;
      ulong test_csz = fd_ulong_svw_enc_sz( new_max );
      if( FD_LIKELY( test_csz==new_csz ) ) break;
      new_csz = test_csz;
    }
    new_used = new_max;
  }

  memmove( pod + new_csz*3UL, bdy, new_bdy_sz );
  fd_ulong_svw_enc_fixed( pod,               new_csz, new_max  );
  fd_ulong_svw_enc_fixed( pod + new_csz,     new_csz, new_used );
  fd_ulong_svw_enc_fixed( pod + new_csz*2UL, new_csz, cnt      );

  return new_max;
}

int
fd_cstr_to_pod_val_type( char const * cstr ) {
  if( FD_UNLIKELY( !cstr ) ) return FD_POD_ERR_INVAL;
  if( !fd_cstr_casecmp( cstr, "subpod"  ) ) return FD_POD_VAL_TYPE_SUBPOD;
  if( !fd_cstr_casecmp( cstr, "buf"     ) ) return FD_POD_VAL_TYPE_BUF;
  if( !fd_cstr_casecmp( cstr, "cstr"    ) ) return FD_POD_VAL_TYPE_CSTR;
  if( !fd_cstr_casecmp( cstr, "char"    ) ) return FD_POD_VAL_TYPE_CHAR;
  if( !fd_cstr_casecmp( cstr, "schar"   ) ) return FD_POD_VAL_TYPE_SCHAR;
  if( !fd_cstr_casecmp( cstr, "short"   ) ) return FD_POD_VAL_TYPE_SHORT;
  if( !fd_cstr_casecmp( cstr, "int"     ) ) return FD_POD_VAL_TYPE_INT;
  if( !fd_cstr_casecmp( cstr, "long"    ) ) return FD_POD_VAL_TYPE_LONG;
  if( !fd_cstr_casecmp( cstr, "int128"  ) ) return FD_POD_VAL_TYPE_INT128;
  if( !fd_cstr_casecmp( cstr, "uchar"   ) ) return FD_POD_VAL_TYPE_UCHAR;
  if( !fd_cstr_casecmp( cstr, "ushort"  ) ) return FD_POD_VAL_TYPE_USHORT;
  if( !fd_cstr_casecmp( cstr, "uint"    ) ) return FD_POD_VAL_TYPE_UINT;
  if( !fd_cstr_casecmp( cstr, "ulong"   ) ) return FD_POD_VAL_TYPE_ULONG;
  if( !fd_cstr_casecmp( cstr, "uint128" ) ) return FD_POD_VAL_TYPE_UINT128;
  if( !fd_cstr_casecmp( cstr, "float"   ) ) return FD_POD_VAL_TYPE_FLOAT;
  if( !fd_cstr_casecmp( cstr, "double"  ) ) return FD_POD_VAL_TYPE_DOUBLE;
  /* FIXME: ADD FD_CSTR_NCASECMP */
  if( !strncmp( cstr, "user", 4UL ) || !strncmp( cstr, "USER", 4UL ) || !strncmp( cstr, "User", 4UL ) ) {
    int val_type = fd_cstr_to_int( cstr+4UL );
    if( FD_LIKELY( ((0<=val_type) & (val_type<=255)) ) ) return val_type;
  }
  return FD_POD_ERR_INVAL;
}

char *
fd_pod_val_type_to_cstr( int    val_type,
                         char * cstr ) {
  if( FD_UNLIKELY( !cstr ) ) return NULL;
  switch( val_type ) {
  case FD_POD_VAL_TYPE_SUBPOD:  return strcpy( cstr, "subpod"  );
  case FD_POD_VAL_TYPE_BUF:     return strcpy( cstr, "buf"     );
  case FD_POD_VAL_TYPE_CSTR:    return strcpy( cstr, "cstr"    );
  case FD_POD_VAL_TYPE_CHAR:    return strcpy( cstr, "char"    );
  case FD_POD_VAL_TYPE_SCHAR:   return strcpy( cstr, "schar"   );
  case FD_POD_VAL_TYPE_SHORT:   return strcpy( cstr, "short"   );
  case FD_POD_VAL_TYPE_INT:     return strcpy( cstr, "int"     );
  case FD_POD_VAL_TYPE_LONG:    return strcpy( cstr, "long"    );
  case FD_POD_VAL_TYPE_INT128:  return strcpy( cstr, "int128"  );
  case FD_POD_VAL_TYPE_UCHAR:   return strcpy( cstr, "uchar"   );
  case FD_POD_VAL_TYPE_USHORT:  return strcpy( cstr, "ushort"  );
  case FD_POD_VAL_TYPE_UINT:    return strcpy( cstr, "uint"    );
  case FD_POD_VAL_TYPE_ULONG:   return strcpy( cstr, "ulong"   );
  case FD_POD_VAL_TYPE_UINT128: return strcpy( cstr, "uint128" );
  case FD_POD_VAL_TYPE_FLOAT:   return strcpy( cstr, "float"   );
  case FD_POD_VAL_TYPE_DOUBLE:  return strcpy( cstr, "double"  );
  default: break;
  }
  if( FD_UNLIKELY( !((0<=val_type) & (val_type<=255)) ) ) return NULL;
  return fd_cstr_printf( cstr, FD_POD_VAL_TYPE_CSTR_MAX, NULL, "user%i", val_type );
}

/* fd_pod_subpod_grow increases the amount of space for key-val pairs
   in the deepest nested subpod on the subpod path by needed bytes.
   This operation can impact the location of items all the subpods along
   the path.  On success, returns FD_POD_SUCCESS.  On failure, returns
   FD_POD_ERR* */

struct fd_pod_subpod_path;
typedef struct fd_pod_subpod_path fd_pod_subpod_path_t;

struct fd_pod_subpod_path {
  uchar *                pod;    /* Points to the subpod val of subpod key-val pair */
  fd_pod_subpod_path_t * parent; /* Points to the subpod that contains the subpod (NULL if this subpod is in the root pod) */
};

static int
fd_pod_subpod_grow( fd_pod_subpod_path_t * node,
                    ulong                  needed ) { /* How much more space is needed for key-val pairs (i.e. in the body) */
  if( FD_UNLIKELY( !needed ) ) return FD_POD_SUCCESS; /* Don't need anything */

  fd_pod_subpod_path_t * parent = node->parent;
  if( FD_UNLIKELY( !parent ) ) return FD_POD_ERR_FULL; /* Can't grow the root pod */

  /* Compute how much larger the parent's val footprint needs to be,
     accounting for the possibility that this pod's header might need to
     expand and/or the parent's val_sz encoding might also need to
     expand. */

  uchar * pod = node->pod;

  ulong vsz    = fd_ulong_svw_dec_tail_sz( pod );
  ulong val_sz = fd_ulong_svw_dec_fixed( pod - vsz, vsz );

  ulong csz    = fd_ulong_svw_dec_sz( pod );
  ulong max    = fd_ulong_svw_dec_fixed( pod,           csz ); /* <=val_sz */
  ulong used   = fd_ulong_svw_dec_fixed( pod + csz,     csz );
  ulong cnt    = fd_ulong_svw_dec_fixed( pod + csz*2UL, csz );
  ulong bdy_sz = used - csz*3UL;

  ulong new_bdy_max = max + needed - csz*3UL;
  ulong new_csz     = csz;
  ulong new_max;
  for(;;) {
    new_max = new_csz*3UL + new_bdy_max;
    ulong test_csz = fd_ulong_svw_enc_sz( new_max );
    if( FD_LIKELY( test_csz==new_csz ) ) break;
    new_csz = test_csz;
  }
  ulong new_used = new_csz*3UL + bdy_sz;

  if( new_max<=val_sz ) { /* Can grow this pod without touching our parent */

    /* Repack the pod */

    uchar * cursor = pod + new_max;

    cursor -= new_bdy_max; memmove( cursor, pod + 3UL*csz, bdy_sz );
    cursor -= new_csz;     fd_ulong_svw_enc_fixed( cursor, new_csz, cnt      );
    cursor -= new_csz;     fd_ulong_svw_enc_fixed( cursor, new_csz, new_used );
    cursor -= new_csz;     fd_ulong_svw_enc_fixed( cursor, new_csz, new_max  );

    return FD_POD_SUCCESS;
  }

  /* fd_ulong_max below is to eliminate a very rare edge cases at a
     minuscule temporary cost in packing efficiency (compact can handle
     it).  The edge case is the ideal new_val_footprint is at most the
     current val_footprint but the current val_sz can't be encoded in
     the ideal new_val_footprint.  In this case, we'd need to repack the
     rest of the pod to use a smaller val sz but we don't have enough
     info to do that here (which would actually be correcting for a
     previous packing inefficiency).  We avoid the edge case by not
     letting new_vsz be less than vsz (such that the current val_sz is
     always encodable in the new format).  In short, this defers cleanup
     of the preexisting packing inefficiency to compact and does not
     make it worse. */

  ulong new_vsz = fd_ulong_max( fd_ulong_svw_enc_sz( new_max ), vsz );

  ulong     val_footprint = vsz     + val_sz;
  ulong new_val_footprint = new_vsz + new_max;
  if( new_val_footprint<=val_footprint ) { /* Can grow this pod without growing our parent but have to recode val_sz */

    /* Repack the pod */

    uchar * cursor = pod - vsz + new_val_footprint;

    cursor -= new_bdy_max; memmove( cursor, pod + 3UL*csz, bdy_sz );
    cursor -= new_csz;     fd_ulong_svw_enc_fixed( cursor, new_csz, cnt      );
    cursor -= new_csz;     fd_ulong_svw_enc_fixed( cursor, new_csz, new_used );
    cursor -= new_csz;     fd_ulong_svw_enc_fixed( cursor, new_csz, new_max  );
    cursor -= new_vsz;     fd_ulong_svw_enc_fixed( cursor, new_vsz, val_sz   );

    return FD_POD_SUCCESS;
  }

  /* Have to repack the parent to grow this pod */

  uchar * parent_pod    = parent->pod;
  ulong   parent_csz    = fd_ulong_svw_dec_sz( parent_pod );
  ulong   parent_max    = fd_ulong_svw_dec_fixed( parent_pod,              parent_csz );
  ulong   parent_used   = fd_ulong_svw_dec_fixed( parent_pod + parent_csz, parent_csz );
  ulong   parent_avail  = parent_max - parent_used;
  ulong   parent_needed = new_val_footprint - val_footprint;
  if( parent_avail < parent_needed ) { /* Need to grow the parent (and maybe their parent and ...) to grow this pod */

    int err = fd_pod_subpod_grow( parent, parent_needed-parent_avail );
    if( FD_UNLIKELY( err ) ) return err;

    /* Determine where the parent and this pod ended up after growth */

    ulong pod_off = (ulong)(pod - parent_pod) - parent_csz*3UL; /* Original offset pod relative to the parent body */

    parent_pod   = parent->pod;
    parent_csz   = fd_ulong_svw_dec_sz( parent_pod );
  //parent_max   = fd_ulong_svw_dec_fixed( parent_pod,              parent_csz );
    parent_used  = fd_ulong_svw_dec_fixed( parent_pod + parent_csz, parent_csz );
  //parent_avail = parent_max - parent_used;

    pod = parent_pod + parent_csz*3UL + pod_off;
  }

  /* At this point, our parent has enough room to accommodate growing
     this pod.  Repack the parent pod and grow this pod. */

  uchar * parent_next = pod         + max;
  uchar * parent_stop = parent_pod  + parent_used;
  uchar * cursor      = parent_stop + parent_needed;
  ulong   rem         = (ulong)(parent_stop - parent_next);

  cursor -= rem;         memmove( cursor, parent_next, rem );
  cursor -= new_bdy_max; memmove( cursor, pod + csz*3UL, bdy_sz );
  cursor -= new_csz;     fd_ulong_svw_enc_fixed( cursor, new_csz, cnt      );
  cursor -= new_csz;     fd_ulong_svw_enc_fixed( cursor, new_csz, new_used );
  cursor -= new_csz;     fd_ulong_svw_enc_fixed( cursor, new_csz, new_max  ); node->pod = cursor;
  cursor -= new_vsz;     fd_ulong_svw_enc_fixed( cursor, new_vsz, new_max  );

  fd_ulong_svw_enc_fixed( parent_pod + parent_csz, parent_csz, parent_used + parent_needed );

  return FD_POD_SUCCESS;
}

static uchar *
fd_pod_private_alloc_node( fd_pod_subpod_path_t * FD_RESTRICT parent,
                           uchar                * FD_RESTRICT pod,
                           char const           * FD_RESTRICT path,
                           int                                new_val_type,
                           ulong                              new_val_sz ) {
  fd_pod_subpod_path_t node[1];
  node->pod    = pod;
  node->parent = parent;

  ulong prefix_len; char delim; char const * suffix;
  FD_POD_PATH_SPLIT( path, prefix_len, delim, suffix );

  uchar * pair; uchar * next;
  ulong ksz; ulong key_sz; char * key; int val_type;
  ulong vsz; ulong val_sz; void * val;
  FD_POD_FOR_ALL_BEGIN( pod, pair, next, ksz, key_sz, key, val_type, vsz, val_sz, val ) {

    if( ((key_sz-1UL)==prefix_len) && !memcmp( key, path, prefix_len ) ) { /* Found leading key in pod */

      if( !delim ) { /* Path was a single key.  Fail as key already in pod. */

        return NULL;

      } else { /* Path had a suffix.  Recurse into the subpod */

        if( FD_UNLIKELY( val_type!=FD_POD_VAL_TYPE_SUBPOD ) ) return NULL;
        return fd_pod_private_alloc_node( node, (uchar *)val, suffix, new_val_type, new_val_sz );

      }
    }
  } FD_POD_FOR_ALL_END;

  /* Leading key not found in pod. */

  /* Extract the pod header */

  ulong csz   = fd_ulong_svw_dec_sz( pod );
  ulong max   = fd_ulong_svw_dec_fixed( pod,       csz );
  ulong used  = fd_ulong_svw_dec_fixed( pod + csz, csz );
  ulong avail = max - used;

  if( delim ) { /* Path had a suffix. */

    /* Compute the amount of space needed in this pod to hold the
       subpod.  FIXME: IDEALLY WE'D DO A "DRESS REHEARSAL" TO FIGURE OUT
       TIGHTLY THE MAX AMOUNT FOR THE REST OF THE ALLOC AND SAVE TIME
       FROM HAVING TO GROW PODS REPEATEDLY FOR A DEEPLY NESTED PATH.
       THIS WOULD ALSO PREVENT ANY MODIFICATIONS BEING MADE TO THE POD
       UNLESS THE ALLOC IS SUCCESSFUL (AS IT IS, THIS MIGHT LEAVE SOME
       PATH THAT TERMINATES ON AN EMPTY POD, WHICH IS THEORETICALLY FINE
       BUT POTENTIALLY NOT THE MOST DESIRABLE PRACTICALLY). */

    ulong subpod_max = FD_POD_FOOTPRINT_MIN;

    char const * subpod_key    = path; /* Does not include terminating '\0', potentially has additional keys following. */
    ulong        subpod_key_sz = prefix_len + 1UL;
    ulong        subpod_ksz    = fd_ulong_svw_enc_sz( subpod_key_sz );
    ulong        subpod_val_sz = fd_pod_footprint( subpod_max );
    ulong        subpod_vsz    = fd_ulong_svw_enc_sz( subpod_val_sz );

    ulong needed = subpod_ksz + subpod_key_sz + 1UL /* subpod_val_type */ + subpod_vsz + subpod_val_sz;

    /* Expand the pod if necessary */

    if( needed > avail ) {
      int err = fd_pod_subpod_grow( node, needed-avail );
      if( FD_UNLIKELY( err ) ) return NULL;
      pod   = node->pod;
      csz   = fd_ulong_svw_dec_sz( pod );
    //max   = fd_ulong_svw_dec_fixed( pod,       csz );
      used  = fd_ulong_svw_dec_fixed( pod + csz, csz );
    //avail = max - used;
    }

    /* Insert the subpod */

    uchar * cursor = pod + used;
    fd_ulong_svw_enc_fixed( cursor, subpod_ksz, subpod_key_sz );      cursor += subpod_ksz;
    fd_memcpy( cursor, subpod_key, subpod_key_sz-1UL );
    cursor[subpod_key_sz-1UL] = '\0';                                 cursor += subpod_key_sz; /* Handle terminating '\0' */
    cursor[0                ] = (uchar)FD_POD_VAL_TYPE_SUBPOD;        cursor += 1;
    fd_ulong_svw_enc_fixed( cursor, subpod_vsz, subpod_val_sz );      cursor += subpod_vsz;
    uchar * subpod = fd_pod_join( fd_pod_new( cursor, subpod_max ) ); cursor += subpod_val_sz;

    /* Update the pod header */

    ulong cnt = fd_ulong_svw_dec_fixed( pod + csz*2UL, csz );
    fd_ulong_svw_enc_fixed( pod + csz,     csz, (ulong)(cursor-pod) ); /* used */
    fd_ulong_svw_enc_fixed( pod + csz*2UL, csz, cnt + 1UL );

    /* Recurse into the subpod */

    return fd_pod_private_alloc_node( node, subpod, suffix, new_val_type, new_val_sz );
  }

  /* Path was a single key */

  /* Compute how much space we need in the pod for this val. */

  char const * new_key    = path;
  ulong        new_key_sz = prefix_len + 1UL;
  ulong        new_ksz    = fd_ulong_svw_enc_sz( new_key_sz );
  ulong        new_vsz    = fd_ulong_svw_enc_sz( new_val_sz );

  ulong needed = new_ksz + new_key_sz + 1UL /* new_val_type */ + new_vsz + new_val_sz;

  /* Expand the pod if necessary */

  if( needed > avail ) {
    int err = fd_pod_subpod_grow( node, needed-avail );
    if( FD_UNLIKELY( err ) ) return NULL;
    pod  = node->pod;
    csz  = fd_ulong_svw_dec_sz( pod );
  //max  = fd_ulong_svw_dec_fixed( pod,       csz );
    used = fd_ulong_svw_dec_fixed( pod + csz, csz );
  }

  /* Allocate the val */

  uchar * cursor = pod + used;
  fd_ulong_svw_enc_fixed( cursor, new_ksz, new_key_sz ); cursor += new_ksz;
  fd_memcpy( cursor, new_key, new_key_sz );              cursor += new_key_sz;
  cursor[0] = (uchar)new_val_type;                       cursor += 1;
  fd_ulong_svw_enc_fixed( cursor, new_vsz, new_val_sz ); cursor += new_vsz;
  uchar * new_val = cursor;                              cursor += new_val_sz;

  /* Update the pod header */

  ulong cnt = fd_ulong_svw_dec_fixed( pod + csz*2UL, csz );
  fd_ulong_svw_enc_fixed( pod + csz,     csz, (ulong)(cursor-pod) ); /* used */
  fd_ulong_svw_enc_fixed( pod + csz*2UL, csz, cnt + 1UL );

  return new_val;
}

ulong
fd_pod_alloc( uchar      * FD_RESTRICT pod,
              char const * FD_RESTRICT path,
              int                      val_type,
              ulong                    val_sz ) {
  if( FD_UNLIKELY( (!pod) | (!path) | (!((0<=val_type) & (val_type<=255))) ) ) return 0UL;

  uchar * val = fd_pod_private_alloc_node( NULL, pod, path, val_type, val_sz );
  if( FD_UNLIKELY( !val ) ) {
    fd_pod_compact( pod, 0 /*partial*/ );
    val = fd_pod_private_alloc_node( NULL, pod, path, val_type, val_sz );
    if( FD_UNLIKELY( !val ) ) return 0UL;
  }

  return (ulong)(val-pod);
}

int
fd_pod_remove( uchar      * FD_RESTRICT pod,
               char const * FD_RESTRICT path ) {
  if( FD_UNLIKELY( (!pod) | (!path) ) ) return FD_POD_ERR_INVAL;

  ulong prefix_len; char delim; char const * suffix;
  FD_POD_PATH_SPLIT( path, prefix_len, delim, suffix );

  uchar * pair; uchar * next;
  ulong ksz; ulong key_sz; char const * key; int val_type;
  ulong vsz; ulong val_sz; void * val;
  FD_POD_FOR_ALL_BEGIN( pod, pair, next, ksz, key_sz, key, val_type, vsz, val_sz, val ) {

    if( ((key_sz-1UL)==prefix_len) && !memcmp( key, path, prefix_len ) ) { /* Found leading key in pod */

      if( !delim ) { /* Path was a single key, delete it */

        ulong footprint = (ulong)( next - pair);
        ulong rem       = (ulong)(_stop - next);
        memmove( pair, next, rem );
        ulong cnt = fd_ulong_svw_dec_fixed( pod + _csz*2UL, _csz );
        fd_ulong_svw_enc_fixed( pod + _csz,     _csz, _used - footprint ); /* upd used */
        fd_ulong_svw_enc_fixed( pod + _csz*2UL, _csz, cnt - 1UL         ); /* upd cnt */
        return FD_POD_SUCCESS;

      } else { /* Path had a suffix.  Recurse into the subpod */

        if( FD_UNLIKELY( val_type!=FD_POD_VAL_TYPE_SUBPOD ) ) return FD_POD_ERR_TYPE;
        return fd_pod_remove( (uchar *)val, suffix );

      }
    }

  } FD_POD_FOR_ALL_END;

  return FD_POD_ERR_RESOLVE;
}

#undef FD_POD_FOR_ALL_END
#undef FD_POD_FOR_ALL_BEGIN
#undef FD_POD_PATH_SPLIT

