#include "fd_vinyl.h"

#define PAIR_MAX (4UL)

struct pair {
  int             creating;
  long            acq;
  ulong           ver;
  ulong           val_max;
  fd_vinyl_key_t  key        [ 1 ];
  fd_vinyl_info_t info       [ 1 ];
  fd_vinyl_info_t backup_info[ 1 ];
  uchar           val        [ FD_VINYL_VAL_MAX ];
  uchar           backup_val [ FD_VINYL_VAL_MAX ];
};

typedef struct pair pair_t;

static struct {
  ulong  quota_rem;
  ulong  used;
  pair_t pair[ PAIR_MAX ];
} ref;

static int
req( int                    type,    /* request type */
     ulong                  flags,   /* request flags */
     ulong                  val_max, /* for acquire-with-modify */
     fd_vinyl_key_t const * key,     /* Key for req */
     pair_t **              _pair,   /* Location of pair on successful acquire and/or successful try */
     ulong *                _ver ) { /* Version of pair on try, has try version on test, ignored otherwise */

  switch( type ) {

  case FD_VINYL_REQ_TYPE_ACQUIRE: {
    if( fd_vinyl_req_flag_modify( flags ) && (val_max>FD_VINYL_VAL_MAX) ) return FD_VINYL_ERR_INVAL; /* bad req val_max */
    if( !ref.quota_rem                                                  ) return FD_VINYL_ERR_FULL;  /* client quota exhausted */

    ulong    idx  = 0UL;
    pair_t * pair = NULL;
    for( ; idx<PAIR_MAX; idx++ ) {
      if( ((ref.used >> idx) & 1UL) && fd_vinyl_key_eq( key, ref.pair[ idx ].key ) ) {
        pair = &ref.pair[ idx ];
        break;
      }
    }

    if( pair ) {

      if( !fd_vinyl_req_flag_modify( flags ) ) {

        /* start blocking read of an existing pair */

        if( pair->acq < 0L ) return FD_VINYL_ERR_AGAIN; /* key acquired for modify */

        ulong ref_szc = fd_vinyl_data_szc( (ulong)pair->info->val_sz );
        pair->val_max = fd_vinyl_data_szc_val_max( ref_szc );

        FD_TEST( !pair->creating );
        pair->acq++;
      //pair->ver unchanged

        ref.quota_rem--;

        *_pair = pair;
        return FD_VINYL_SUCCESS;

      }

      /* start modify of an existing pair */

      if( pair->acq                       ) return FD_VINYL_ERR_AGAIN; /* key acquired at least once */
      if( fd_vinyl_req_flag_excl( flags ) ) return FD_VINYL_ERR_INVAL; /* not allowed to modify existing */

      pair->backup_info[0] = pair->info[0];
      if( pair->info->val_sz ) memcpy( pair->backup_val, pair->val, (ulong)pair->info->val_sz );

      if( fd_vinyl_req_flag_ignore( flags ) ) pair->info->val_sz = 0U;

      ulong ref_szc = fd_vinyl_data_szc( fd_ulong_max( val_max, (ulong)pair->info->val_sz ) );
      pair->val_max = fd_vinyl_data_szc_val_max( ref_szc );

      FD_TEST( !pair->creating );
      pair->acq = -1L;
      pair->ver++;

      ref.quota_rem--;

      *_pair = pair;
      return FD_VINYL_SUCCESS;

    }

    /* start creating a pair */

    if( !(fd_vinyl_req_flag_modify( flags ) && fd_vinyl_req_flag_create( flags )) ) return FD_VINYL_ERR_KEY;

    FD_TEST( (ulong)fd_ulong_popcnt( ref.used ) < PAIR_MAX );
    idx = (ulong)fd_ulong_find_lsb( ~ref.used );
    pair = &ref.pair[ idx ];
    ref.used |= (1UL << idx);

    pair->key[0] = key[0];
    memset( pair->info, 0UL, sizeof(fd_vinyl_info_t) );

    ulong ref_szc = fd_vinyl_data_szc( val_max );
    pair->val_max = fd_vinyl_data_szc_val_max( ref_szc );

    pair->creating = 1;
    pair->acq      = -1L;
    pair->ver++;

    ref.quota_rem--;

    *_pair = pair;
    return FD_VINYL_SUCCESS;
  }

  case FD_VINYL_REQ_TYPE_RELEASE: {
    ulong    idx  = 0UL;
    pair_t * pair = NULL;
    for( ; idx<PAIR_MAX; idx++ ) {
      if( ((ref.used >> idx) & 1UL) && fd_vinyl_key_eq( key, ref.pair[ idx ].key ) ) {
        pair = &ref.pair[ idx ];
        break;
      }
    }

    if( !pair      ) return FD_VINYL_ERR_INVAL; /* Key does not exist and is not being created (cannot have been acquired) */
    if( !pair->acq ) return FD_VINYL_ERR_INVAL; /* Key is not acquired */

    if( pair->acq > 0L ) {

      /* finish blocking read */

      if( fd_vinyl_req_flag_modify( flags ) ) FD_LOG_CRIT(( "modify read only" ));

      FD_TEST( !pair->creating );

      pair->acq--;

      ref.quota_rem++;
      return FD_VINYL_SUCCESS;

    }

    if( pair->creating ) {

      if( ((!fd_vinyl_req_flag_modify( flags )) | fd_vinyl_req_flag_erase( flags )) ) {

        /* cancel / erase a create */

        pair->ver++;

        ref.used &= ~(1UL << idx);

        ref.quota_rem++;
        return FD_VINYL_SUCCESS;

      }

      /* finish a create */

      if( (ulong)pair->info->val_sz > pair->val_max ) FD_LOG_CRIT(( "val buffer overrun" ));

      ulong ref_szc = fd_vinyl_data_szc( (ulong)pair->info->val_sz );
      pair->val_max = fd_vinyl_data_szc_val_max( ref_szc );

      pair->creating = 0;
      pair->acq      = 0L;
      pair->ver++;

      ref.quota_rem++;
      return FD_VINYL_SUCCESS;

    }

    if( !fd_vinyl_req_flag_modify( flags ) ) {

      if( !fd_vinyl_req_flag_ignore( flags ) ) {

        /* cancel modify existing (info/val were not clobbered during the modify attempt) */

        pair->acq = 0L;
        pair->ver--;

        ref.quota_rem++;
        return FD_VINYL_SUCCESS;

      }

      /* cancel modify existing (info/val were potentially clobbered during the modify attempt) */

      pair->info[0] = pair->backup_info[0];
      if( pair->backup_info->val_sz ) memcpy( pair->val, pair->backup_val, (ulong)pair->backup_info->val_sz );

      ulong ref_szc = fd_vinyl_data_szc( (ulong)pair->info->val_sz );
      pair->val_max = fd_vinyl_data_szc_val_max( ref_szc );

      pair->acq = 0L;
      pair->ver++;

      ref.quota_rem++;
      return FD_VINYL_SUCCESS;

    }

    if( fd_vinyl_req_flag_erase( flags ) ) {

      /* erase existing */

      pair->ver++;

      ref.used &= ~(1UL<<idx);
      ref.quota_rem++;
      return FD_VINYL_SUCCESS;

    }

    /* finish modify existing */

    if( (ulong)pair->info->val_sz > pair->val_max ) FD_LOG_CRIT(( "val buffer overrun" ));

    ulong ref_szc = fd_vinyl_data_szc( (ulong)pair->info->val_sz );
    pair->val_max = fd_vinyl_data_szc_val_max( ref_szc );

    pair->acq = 0L;
    pair->ver++;

    ref.quota_rem++;
    return FD_VINYL_SUCCESS;
  }

  case FD_VINYL_REQ_TYPE_ERASE: {
    ulong    idx  = 0UL;
    pair_t * pair = NULL;
    for( ; idx<PAIR_MAX; idx++ ) {
      if( ((ref.used >> idx) & 1UL) && fd_vinyl_key_eq( key, ref.pair[ idx ].key ) ) {
        pair = &ref.pair[ idx ];
        break;
      }
    }

    if( !pair     ) return FD_VINYL_ERR_KEY;   /* Key does not exist */
    if( pair->acq ) return FD_VINYL_ERR_AGAIN; /* Key acquired at least once */

    pair->ver++;

    ref.used &= ~(1UL<<idx);
    return FD_VINYL_SUCCESS;
  }

  case FD_VINYL_REQ_TYPE_MOVE: {
    fd_vinyl_key_t const * src_key = key;
    fd_vinyl_key_t const * dst_key = (fd_vinyl_key_t *)_pair;

    if( fd_vinyl_key_eq( src_key, dst_key ) ) return FD_VINYL_SUCCESS; /* Input and output keys are the same is a no-op */

    /* Lookup pair dst_key.  Fail with AGAIN if pair dst_key exists and
       is currently acquired. */

    ulong    dst_idx  = 0UL;
    pair_t * dst_pair = NULL;
    for( ; dst_idx<PAIR_MAX; dst_idx++ ) {
      if( ((ref.used >> dst_idx) & 1UL) && fd_vinyl_key_eq( dst_key, ref.pair[ dst_idx ].key ) ) {
        dst_pair = &ref.pair[ dst_idx ];
        break;
      }
    }

    if( dst_pair && dst_pair->acq ) return FD_VINYL_ERR_AGAIN;

    /* Lookup pair src_key.  If it doesn't exist, fail with KEY.  If it
       is acquired, fail with AGAIN. */

    ulong    src_idx  = 0UL;
    pair_t * src_pair = NULL;
    for( ; src_idx<PAIR_MAX; src_idx++ ) {
      if( ((ref.used >> src_idx) & 1UL) && fd_vinyl_key_eq( src_key, ref.pair[ src_idx ].key ) ) {
        src_pair = &ref.pair[ src_idx ];
        break;
      }
    }

    if( !src_pair     ) return FD_VINYL_ERR_KEY;
    if( src_pair->acq ) return FD_VINYL_ERR_AGAIN;

    /* At this point:
      - pair dst_key may or may not exist.  If it exists it is not
        acquired.
      - pair src_key exists and is not acquired.
      Thus we are clear to move.  Erase pair dst_key if it exists.  Then
      rename pair src_key to pair dst_key. */

    if( dst_pair ) {
      dst_pair->ver++;
      ref.used &= ~(1UL<<dst_idx);
    }

    src_pair->key[0] = dst_key[0];
    src_pair->ver++;

    return FD_VINYL_SUCCESS;
  }

  case FD_VINYL_REQ_TYPE_FETCH: {
    return FD_VINYL_SUCCESS;
  }

  case FD_VINYL_REQ_TYPE_FLUSH: {
    return FD_VINYL_SUCCESS;
  }

  case FD_VINYL_REQ_TYPE_TRY: {
    ulong    idx  = 0UL;
    pair_t * pair = NULL;
    for( ; idx<PAIR_MAX; idx++ ) {
      if( ((ref.used >> idx) & 1UL) && fd_vinyl_key_eq( key, ref.pair[ idx ].key ) ) {
        pair = &ref.pair[ idx ];
        break;
      }
    }

    if( !pair        ) return FD_VINYL_ERR_KEY;   /* Key does not exist */
    if( pair->acq<0L ) return FD_VINYL_ERR_AGAIN; /* Key acquired-for-modify */

    *_pair = pair;
    *_ver  = pair->ver;

    return FD_VINYL_SUCCESS;
  }

  case FD_VINYL_REQ_TYPE_TEST: {

    if( (*_pair)->ver != (*_ver) ) return FD_VINYL_ERR_CORRUPT; /* Key modified during the try */

    return FD_VINYL_SUCCESS;
  }

  default:
    break;
  }

  return FD_VINYL_ERR_INVAL;
}

static int
fd_vinyl_tile( int     argc,
               char ** argv ) {
  (void)argc;
  fd_vinyl_exec( (fd_vinyl_t *)argv );
  return 0;
}

static void
client_tile( ulong            iter_max,
             fd_cnc_t *       cnc,
             ulong            link_id,
             fd_vinyl_rq_t *  rq,
             fd_vinyl_cq_t *  cq,
             fd_wksp_t *      wksp,
             void *           _scratch ) {
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  uchar * top = (uchar *)_scratch;

  fd_vinyl_key_t *  _key       = (fd_vinyl_key_t *) top; top += sizeof(fd_vinyl_key_t)*PAIR_MAX;
  ulong *           _try_gaddr = (ulong *)          top; top += sizeof(ulong)*2UL     *PAIR_MAX;

  fd_vinyl_comp_t * comp      = (fd_vinyl_comp_t *)top; top += sizeof(fd_vinyl_comp_t);
  ulong *           val_gaddr = (ulong *)          top; top += sizeof(ulong);
  schar *           err       = (schar *)          top; top += sizeof(schar);

  ulong comp_gaddr      = fd_wksp_gaddr( wksp, comp      );
  ulong val_gaddr_gaddr = fd_wksp_gaddr( wksp, val_gaddr );
  ulong err_gaddr       = fd_wksp_gaddr( wksp, err       );

  ulong cq_seq = fd_vinyl_cq_seq( cq );

# define WAIT do {                                                   \
    if( oob ) {                                                      \
      while( !FD_VOLATILE_CONST( comp->seq ) ) FD_SPIN_PAUSE();      \
      FD_TEST( comp->seq==1UL );                                     \
    } else {                                                         \
      while( fd_vinyl_cq_recv( cq, cq_seq, comp ) ) FD_SPIN_PAUSE(); \
      FD_TEST( comp->seq==cq_seq );                                  \
      cq_seq++;                                                      \
    }                                                                \
    FD_TEST( comp->req_id ==req_id  );                               \
    FD_TEST( comp->link_id==link_id );                               \
  } while(0)

  ulong val_max_bad = FD_VINYL_VAL_MAX+1UL;

  long     acq         [ PAIR_MAX ]; for( ulong idx=0UL; idx<PAIR_MAX; idx++ ) acq         [idx] = 0L;
  ulong    acq_gaddr   [ PAIR_MAX ]; for( ulong idx=0UL; idx<PAIR_MAX; idx++ ) acq_gaddr   [idx] = 0UL;
  int      acq_modified[ PAIR_MAX ]; for( ulong idx=0UL; idx<PAIR_MAX; idx++ ) acq_modified[idx] = 0;

  int      try_live    [ PAIR_MAX ]; for( ulong idx=0UL; idx<PAIR_MAX; idx++ ) try_live    [idx] = 0;
  pair_t * try_pair    [ PAIR_MAX ]; for( ulong idx=0UL; idx<PAIR_MAX; idx++ ) try_pair    [idx] = NULL;
  ulong    try_ver     [ PAIR_MAX ]; for( ulong idx=0UL; idx<PAIR_MAX; idx++ ) try_ver     [idx] = 0UL;

  fd_vinyl_key_init( _key+0, "test",   5UL );
  fd_vinyl_key_init( _key+1, "foo",    4UL );
  fd_vinyl_key_init( _key+2, "bar",    4UL );
  fd_vinyl_key_init( _key+3, "foobar", 7UL );

  ulong diag_rem = 0UL;
  for( ulong iter_idx=0UL; iter_idx<iter_max; iter_idx++ ) {
    if( !diag_rem ) {
      FD_LOG_NOTICE(( "On iteration %lu of %lu", iter_idx, iter_max ));
      diag_rem = 1000000UL;
    }
    diag_rem--;

    ulong req_id = fd_rng_ulong( rng );

    ulong r = fd_rng_ulong( rng );

    ulong src_idx =      (r &  3UL);                                r >>=  2;
    ulong dst_idx =      (r &  3UL);                                r >>=  2;
    int   op      = (int)(r & 63UL);                                r >>=  6;
    int   by_key  = (int)(r &  1UL);                                r >>=  1;
    int   do_mod  = (int)(r &  1UL);                                r >>=  1;
    ulong oob     = (int)(r &  1UL) ? comp_gaddr : 0UL;             r >>=  1;
    ulong flags   = (r & 255UL);                                    r >>=  8;
    ulong val_max = (r & (ulong)UINT_MAX) % (FD_VINYL_VAL_MAX+1UL); r >>= 32;
    int   pat     = (int)(r & 255UL);                               r >>=  8;

    fd_vinyl_key_t * src_key         = _key       +     src_idx;
    fd_vinyl_key_t * dst_key         = _key       +     dst_idx;
    ulong *          try_gaddr       = _try_gaddr + 2UL*src_idx;

    ulong src_key_gaddr   = fd_wksp_gaddr( wksp, src_key   );
    ulong dst_key_gaddr   = fd_wksp_gaddr( wksp, dst_key   );
    ulong try_gaddr_gaddr = fd_wksp_gaddr( wksp, try_gaddr );

    comp->seq = 0UL;

    switch( op ) {

    case 0: /* mismatched link id (dropped and ticks the DROP_LINK counter) */
      fd_vinyl_rq_send( rq, req_id, ~link_id, FD_VINYL_REQ_TYPE_ACQUIRE, flags, 1UL, val_max,
                        src_key_gaddr, val_gaddr_gaddr, err_gaddr, oob );
      break;

    case 1: /* unmappable oob completion (dropped and ticks the DROP_COMP counter) */
      fd_vinyl_rq_send( rq, req_id, link_id, FD_VINYL_REQ_TYPE_ACQUIRE, flags, 1UL, val_max,
                        src_key_gaddr, val_gaddr_gaddr, err_gaddr, ULONG_MAX );
      break;

    case 2: /* bad request type */
      fd_vinyl_rq_send( rq, req_id, link_id, -1, flags, 1UL, val_max,
                        src_key_gaddr, val_gaddr_gaddr, err_gaddr, oob ); WAIT;
      FD_TEST( comp->err      ==FD_VINYL_ERR_INVAL ); FD_TEST( comp->batch_cnt==(ushort)1             );
      FD_TEST( comp->fail_cnt ==(ushort)0          ); FD_TEST( comp->quota_rem==(ushort)ref.quota_rem );
      break;

    /* acquire tests */

    case 3: /* acquire with unmappable key */
      fd_vinyl_rq_send( rq, req_id, link_id, FD_VINYL_REQ_TYPE_ACQUIRE, flags, 1UL, val_max,
                        0UL, val_gaddr_gaddr, err_gaddr, oob ); WAIT;
      FD_TEST( comp->err      ==FD_VINYL_ERR_INVAL ); FD_TEST( comp->batch_cnt==(ushort)1             );
      FD_TEST( comp->fail_cnt ==(ushort)0          ); FD_TEST( comp->quota_rem==(ushort)ref.quota_rem );
      break;

    case 4: /* acquire with unmappable val */
      fd_vinyl_rq_send( rq, req_id, link_id, FD_VINYL_REQ_TYPE_ACQUIRE, flags, 1UL, val_max,
                        src_key_gaddr, 0UL, err_gaddr, oob ); WAIT;
      FD_TEST( comp->err      ==FD_VINYL_ERR_INVAL ); FD_TEST( comp->batch_cnt==(ushort)1             );
      FD_TEST( comp->fail_cnt ==(ushort)0          ); FD_TEST( comp->quota_rem==(ushort)ref.quota_rem );
      break;

    case 5: /* acquire with unmappable err */
      fd_vinyl_rq_send( rq, req_id, link_id, FD_VINYL_REQ_TYPE_ACQUIRE, flags, 1UL, val_max,
                        src_key_gaddr, val_gaddr_gaddr, 0UL, oob ); WAIT;
      FD_TEST( comp->err      ==FD_VINYL_ERR_INVAL ); FD_TEST( comp->batch_cnt==(ushort)1             );
      FD_TEST( comp->fail_cnt ==(ushort)0          ); FD_TEST( comp->quota_rem==(ushort)ref.quota_rem );
      break;

    case 6: /* acquire with bad val_max */
      FD_TEST( req( FD_VINYL_REQ_TYPE_ACQUIRE, flags | FD_VINYL_REQ_FLAG_MODIFY, val_max_bad,
                    src_key, NULL, NULL )==FD_VINYL_ERR_INVAL );
      fd_vinyl_rq_send( rq, req_id, link_id, FD_VINYL_REQ_TYPE_ACQUIRE, flags | FD_VINYL_REQ_FLAG_MODIFY, 1UL, val_max_bad,
                        src_key_gaddr, val_gaddr_gaddr, err_gaddr, oob ); WAIT;
      FD_TEST( comp->err      ==FD_VINYL_ERR_INVAL ); FD_TEST( comp->batch_cnt==(ushort)1             );
      FD_TEST( comp->fail_cnt ==(ushort)0          ); FD_TEST( comp->quota_rem==(ushort)ref.quota_rem );
      break;

    case 7: /* acquire with zero batch */
      fd_vinyl_rq_send( rq, req_id, link_id, FD_VINYL_REQ_TYPE_ACQUIRE, flags, 0UL, val_max,
                        0UL, 0UL, 0UL, oob ); WAIT;
      FD_TEST( comp->err      ==FD_VINYL_SUCCESS  ); FD_TEST( comp->batch_cnt==(ushort)0             );
      FD_TEST( comp->fail_cnt ==(ushort)0         ); FD_TEST( comp->quota_rem==(ushort)ref.quota_rem );
      break;

    case 8: { /* acquire */
      pair_t * pair;
      int ref_err = req( FD_VINYL_REQ_TYPE_ACQUIRE, flags, val_max, src_key, &pair, NULL );
      fd_vinyl_rq_send( rq, req_id, link_id, FD_VINYL_REQ_TYPE_ACQUIRE, flags, 1UL, val_max,
                        src_key_gaddr, val_gaddr_gaddr, err_gaddr, oob ); WAIT;
      if( ref_err==FD_VINYL_ERR_FULL ) {
        FD_TEST( comp->err      ==FD_VINYL_ERR_FULL ); FD_TEST( comp->batch_cnt==(ushort)1             );
        FD_TEST( comp->fail_cnt ==(ushort)0         ); FD_TEST( comp->quota_rem==(ushort)ref.quota_rem );
        break;
      }
      FD_TEST( comp->err      ==FD_VINYL_SUCCESS  ); FD_TEST( comp->batch_cnt==(ushort)1             );
      FD_TEST( comp->fail_cnt ==(ushort)!!ref_err ); FD_TEST( comp->quota_rem==(ushort)ref.quota_rem );
      FD_TEST( err[0]==(schar)ref_err );

      if( !ref_err ) {
        acq_gaddr[ src_idx ] = val_gaddr[0];

        void *            val     = fd_wksp_laddr_fast( wksp, val_gaddr[0] );
        fd_vinyl_info_t * info    = fd_vinyl_data_info( val );
        ulong             val_sz  = (ulong)info->val_sz;
        ulong             val_max = fd_vinyl_data_val_max( val );

        FD_TEST( val_max==pair->val_max );

        FD_TEST( !memcmp( info, pair->info, sizeof(fd_vinyl_info_t) ) );

        if( val_sz ) FD_TEST( !memcmp( val, pair->val, val_sz ) );

        /* FIXME: TEST [VAL_SZ,VAL_MAX) ZPAD? */

        if( fd_vinyl_req_flag_modify( flags ) ) {
          acq         [ src_idx ] = -1L;
          acq_modified[ src_idx ] = fd_vinyl_req_flag_ignore( flags );
          if( do_mod ) {
            val_sz = fd_rng_ulong_roll( rng, val_max + 1UL );
            memset( info,     pat, sizeof(fd_vinyl_info_t) ); memset( pair->info, pat, sizeof(fd_vinyl_info_t) );
            memset( val,      pat, val_sz                  ); memset( pair->val,  pat, val_sz                  );
            info->val_sz = (uint)val_sz;                      pair->info->val_sz = (uint)val_sz;
            acq_modified[ src_idx ] |= 1;
          }
        } else {
          FD_TEST( !memcmp( info, pair->info, sizeof(fd_vinyl_info_t) ) );
          FD_TEST( !memcmp( val,  pair->val,  val_sz                  ) );
          acq         [ src_idx ]++;
          acq_modified[ src_idx ] = 0;
        }
      }
      break;
    }

    /* release tests */

    case 9: /* release with unmappable key */
      fd_vinyl_rq_send( rq, req_id, link_id, FD_VINYL_REQ_TYPE_RELEASE, flags | FD_VINYL_REQ_FLAG_BY_KEY, 1UL, val_max_bad,
                        0UL, val_gaddr_gaddr, err_gaddr, oob ); WAIT;
      FD_TEST( comp->err      ==FD_VINYL_ERR_INVAL ); FD_TEST( comp->batch_cnt==(ushort)1             );
      FD_TEST( comp->fail_cnt ==(ushort)0          ); FD_TEST( comp->quota_rem==(ushort)ref.quota_rem );
      break;

    case 10: /* release with unmappable val */
      fd_vinyl_rq_send( rq, req_id, link_id, FD_VINYL_REQ_TYPE_RELEASE, flags & ~FD_VINYL_REQ_FLAG_BY_KEY, 1UL, val_max_bad,
                        src_key_gaddr, 0UL, err_gaddr, oob ); WAIT;
      FD_TEST( comp->err      ==FD_VINYL_ERR_INVAL ); FD_TEST( comp->batch_cnt==(ushort)1             );
      FD_TEST( comp->fail_cnt ==(ushort)0          ); FD_TEST( comp->quota_rem==(ushort)ref.quota_rem );
      break;

    case 11: /* release with unmappable err */
      fd_vinyl_rq_send( rq, req_id, link_id, FD_VINYL_REQ_TYPE_RELEASE, flags, 1UL, val_max_bad,
                        src_key_gaddr, val_gaddr_gaddr, 0UL, oob ); WAIT;
      FD_TEST( comp->err      ==FD_VINYL_ERR_INVAL ); FD_TEST( comp->batch_cnt==(ushort)1             );
      FD_TEST( comp->fail_cnt ==(ushort)0          ); FD_TEST( comp->quota_rem==(ushort)ref.quota_rem );
      break;

    case 12: /* release with zero batch */
      fd_vinyl_rq_send( rq, req_id, link_id, FD_VINYL_REQ_TYPE_RELEASE, flags, 0UL, val_max_bad,
                        0UL, 0UL, 0UL, oob ); WAIT;
      FD_TEST( comp->err      ==FD_VINYL_SUCCESS   ); FD_TEST( comp->batch_cnt==(ushort)0             );
      FD_TEST( comp->fail_cnt ==(ushort)0          ); FD_TEST( comp->quota_rem==(ushort)ref.quota_rem );
      break;

    case 13: { /* release */
      if( acq[ src_idx ] > 0L ) flags &= ~FD_VINYL_REQ_FLAG_MODIFY; /* can't say modify on an acquire-for-read */
      if( ((acq[ src_idx ] < 0L) & (!fd_vinyl_req_flag_modify( flags )) & acq_modified[ src_idx ]) )
        flags |= FD_VINYL_REQ_FLAG_IGNORE;
      int ref_err = req( FD_VINYL_REQ_TYPE_RELEASE, flags, val_max_bad, src_key, NULL, NULL );
      if( by_key || !acq[ src_idx ] ) {
        fd_vinyl_rq_send( rq, req_id, link_id, FD_VINYL_REQ_TYPE_RELEASE, flags |  FD_VINYL_REQ_FLAG_BY_KEY, 1UL, val_max_bad,
                          src_key_gaddr, 0UL, err_gaddr, oob );
      } else {
        val_gaddr[0] = acq_gaddr[ src_idx ];
        fd_vinyl_rq_send( rq, req_id, link_id, FD_VINYL_REQ_TYPE_RELEASE, flags & ~FD_VINYL_REQ_FLAG_BY_KEY, 1UL, val_max_bad,
                          0UL, val_gaddr_gaddr, err_gaddr, oob );
      }
      WAIT;
      FD_TEST( comp->err      ==FD_VINYL_SUCCESS   ); FD_TEST( comp->batch_cnt==(ushort)1             );
      FD_TEST( comp->fail_cnt ==(ushort)!!ref_err  ); FD_TEST( comp->quota_rem==(ushort)ref.quota_rem );
      FD_TEST( err[0]==(schar)ref_err );
      if( !ref_err ) acq[ src_idx ] = (acq[ src_idx ] > 0L) ? (acq[ src_idx ]-1L) : 0L;
      break;
    }

    /* erase tests */

    case 14: /* erase with unmappable key */
      fd_vinyl_rq_send( rq, req_id, link_id, FD_VINYL_REQ_TYPE_ERASE, flags, 1UL, val_max_bad,
                        0UL, 0UL, err_gaddr, oob ); WAIT;
      FD_TEST( comp->err      ==FD_VINYL_ERR_INVAL ); FD_TEST( comp->batch_cnt==(ushort)1             );
      FD_TEST( comp->fail_cnt ==(ushort)0          ); FD_TEST( comp->quota_rem==(ushort)ref.quota_rem );
      break;

    case 15: /* erase with unmappable err */
      fd_vinyl_rq_send( rq, req_id, link_id, FD_VINYL_REQ_TYPE_ERASE, flags, 1UL, val_max_bad,
                        src_key_gaddr, 0UL, 0UL, oob ); WAIT;
      FD_TEST( comp->err      ==FD_VINYL_ERR_INVAL ); FD_TEST( comp->batch_cnt==(ushort)1             );
      FD_TEST( comp->fail_cnt ==(ushort)0          ); FD_TEST( comp->quota_rem==(ushort)ref.quota_rem );
      break;

    case 16: /* erase with zero batch */
      fd_vinyl_rq_send( rq, req_id, link_id, FD_VINYL_REQ_TYPE_ERASE, flags, 0UL, val_max_bad,
                        src_key_gaddr, 0UL, err_gaddr, oob ); WAIT;
      FD_TEST( comp->err      ==FD_VINYL_SUCCESS   ); FD_TEST( comp->batch_cnt==(ushort)0             );
      FD_TEST( comp->fail_cnt ==(ushort)0          ); FD_TEST( comp->quota_rem==(ushort)ref.quota_rem );
      break;

    case 17: { /* erase */
      int ref_err = req( FD_VINYL_REQ_TYPE_ERASE, flags, val_max_bad, src_key, NULL, NULL );
      fd_vinyl_rq_send( rq, req_id, link_id, FD_VINYL_REQ_TYPE_ERASE, flags, 1UL, val_max_bad,
                        src_key_gaddr, 1UL, err_gaddr, oob ); WAIT;
      FD_TEST( comp->err      ==FD_VINYL_SUCCESS   ); FD_TEST( comp->batch_cnt==(ushort)1             );
      FD_TEST( comp->fail_cnt ==(ushort)!!ref_err  ); FD_TEST( comp->quota_rem==(ushort)ref.quota_rem );
      FD_TEST( err[0]==(schar)ref_err );
      break;
    }

    /* move tests */

    case 18: /* move with unmappable src */
      fd_vinyl_rq_send( rq, req_id, link_id, FD_VINYL_REQ_TYPE_MOVE, flags, 1UL, val_max_bad,
                        0UL, src_key_gaddr, err_gaddr, oob ); WAIT;
      FD_TEST( comp->err      ==FD_VINYL_ERR_INVAL ); FD_TEST( comp->batch_cnt==(ushort)1             );
      FD_TEST( comp->fail_cnt ==(ushort)0          ); FD_TEST( comp->quota_rem==(ushort)ref.quota_rem );
      break;

    case 19: /* move with unmappable dst */
      fd_vinyl_rq_send( rq, req_id, link_id, FD_VINYL_REQ_TYPE_MOVE, flags, 1UL, val_max_bad,
                        src_key_gaddr, 0UL, err_gaddr, oob ); WAIT;
      FD_TEST( comp->err      ==FD_VINYL_ERR_INVAL ); FD_TEST( comp->batch_cnt==(ushort)1             );
      FD_TEST( comp->fail_cnt ==(ushort)0          ); FD_TEST( comp->quota_rem==(ushort)ref.quota_rem );
      break;

    case 20: /* move with unmappable err */
      fd_vinyl_rq_send( rq, req_id, link_id, FD_VINYL_REQ_TYPE_MOVE, flags, 1UL, val_max_bad,
                        src_key_gaddr, dst_key_gaddr, 0UL, oob ); WAIT;
      FD_TEST( comp->err      ==FD_VINYL_ERR_INVAL ); FD_TEST( comp->batch_cnt==(ushort)1             );
      FD_TEST( comp->fail_cnt ==(ushort)0          ); FD_TEST( comp->quota_rem==(ushort)ref.quota_rem );
      break;

    case 21: /* move with zero batch */
      fd_vinyl_rq_send( rq, req_id, link_id, FD_VINYL_REQ_TYPE_MOVE, flags, 0UL, val_max_bad,
                        src_key_gaddr, dst_key_gaddr, err_gaddr, oob ); WAIT;
      FD_TEST( comp->err      ==FD_VINYL_SUCCESS   ); FD_TEST( comp->batch_cnt==(ushort)0             );
      FD_TEST( comp->fail_cnt ==(ushort)0          ); FD_TEST( comp->quota_rem==(ushort)ref.quota_rem );
      break;

    case 22: { /* move */
      int ref_err = req( FD_VINYL_REQ_TYPE_MOVE, flags, val_max_bad, src_key, (pair_t **)dst_key, NULL );
      fd_vinyl_rq_send( rq, req_id, link_id, FD_VINYL_REQ_TYPE_MOVE, flags, 1UL, val_max_bad,
                        src_key_gaddr, dst_key_gaddr, err_gaddr, oob ); WAIT;
      FD_TEST( comp->err      ==FD_VINYL_SUCCESS   ); FD_TEST( comp->batch_cnt==(ushort)1             );
      FD_TEST( comp->fail_cnt ==(ushort)!!ref_err  ); FD_TEST( comp->quota_rem==(ushort)ref.quota_rem );
      FD_TEST( err[0]==(schar)ref_err );
      break;
    }

    /* fetch tests (these are logical no-op / hints and don't generate completions) */

    case 23: /* fetch with unmappable key */
      fd_vinyl_rq_send( rq, req_id, link_id, FD_VINYL_REQ_TYPE_FETCH, flags, 1UL, val_max_bad, 0UL, 0UL, 0UL, oob );
      break;

    case 24: /* fetch with zero batch cnt */
      fd_vinyl_rq_send( rq, req_id, link_id, FD_VINYL_REQ_TYPE_FETCH, flags, 0UL, val_max_bad, 0UL, 0UL, 0UL, oob );
      break;

    case 25: /* fetch */
      FD_TEST( !req( FD_VINYL_REQ_TYPE_FETCH, 0UL, 0UL, src_key, NULL, NULL ) );
      fd_vinyl_rq_send( rq, req_id, link_id, FD_VINYL_REQ_TYPE_FETCH, flags, 1UL, val_max_bad, src_key_gaddr, 0UL, 0UL, oob );
      break;

    /* flush tests (these are logical no-ops / hints and don't generate completions) */

    case 26: /* flush with unmappable key */
      fd_vinyl_rq_send( rq, req_id, link_id, FD_VINYL_REQ_TYPE_FLUSH, flags, 1UL, val_max_bad, 0UL, 0UL, 0UL, oob );
      break;

    case 27: /* flush with zero batch cnt */
      fd_vinyl_rq_send( rq, req_id, link_id, FD_VINYL_REQ_TYPE_FLUSH, flags, 0UL, val_max_bad, 0UL, 0UL, 0UL, oob );
      break;

    case 28: /* flush */
      FD_TEST( !req( FD_VINYL_REQ_TYPE_FLUSH, 0UL, 0UL, src_key, NULL, NULL ) );
      fd_vinyl_rq_send( rq, req_id, link_id, FD_VINYL_REQ_TYPE_FLUSH, flags, 1UL, val_max_bad, src_key_gaddr, 0UL, 0UL, oob );
      break;

    /* try tests */

    case 29: /* try with unmappable key */
      fd_vinyl_rq_send( rq, req_id, link_id, FD_VINYL_REQ_TYPE_TRY, flags, 1UL, val_max_bad,
                        0UL, try_gaddr_gaddr, err_gaddr, oob ); WAIT;
      FD_TEST( comp->err      ==FD_VINYL_ERR_INVAL ); FD_TEST( comp->batch_cnt==(ushort)1             );
      FD_TEST( comp->fail_cnt ==(ushort)0          ); FD_TEST( comp->quota_rem==(ushort)ref.quota_rem );
      break;

    case 30: /* try with unmappable try */
      fd_vinyl_rq_send( rq, req_id, link_id, FD_VINYL_REQ_TYPE_TRY, flags, 1UL, val_max_bad,
                        src_key_gaddr, 0UL, err_gaddr, oob ); WAIT;
      FD_TEST( comp->err      ==FD_VINYL_ERR_INVAL ); FD_TEST( comp->batch_cnt==(ushort)1             );
      FD_TEST( comp->fail_cnt ==(ushort)0          ); FD_TEST( comp->quota_rem==(ushort)ref.quota_rem );
      break;

    case 31: /* try with unmappable err */
      fd_vinyl_rq_send( rq, req_id, link_id, FD_VINYL_REQ_TYPE_TRY, flags, 1UL, val_max_bad,
                        src_key_gaddr, try_gaddr_gaddr, 0UL, oob ); WAIT;
      FD_TEST( comp->err      ==FD_VINYL_ERR_INVAL ); FD_TEST( comp->batch_cnt==(ushort)1             );
      FD_TEST( comp->fail_cnt ==(ushort)0          ); FD_TEST( comp->quota_rem==(ushort)ref.quota_rem );
      break;

    case 32: /* try with zero batch */
      fd_vinyl_rq_send( rq, req_id, link_id, FD_VINYL_REQ_TYPE_TRY, flags, 0UL, val_max_bad,
                        src_key_gaddr, try_gaddr_gaddr, err_gaddr, oob ); WAIT;
      FD_TEST( comp->err      ==FD_VINYL_SUCCESS   ); FD_TEST( comp->batch_cnt==(ushort)0             );
      FD_TEST( comp->fail_cnt ==(ushort)0          ); FD_TEST( comp->quota_rem==(ushort)ref.quota_rem );
      break;

    case 33: { /* try */
      int ref_err = req( FD_VINYL_REQ_TYPE_TRY, flags, val_max_bad, src_key, &try_pair[ src_idx ], &try_ver[ src_idx ] );
      fd_vinyl_rq_send( rq, req_id, link_id, FD_VINYL_REQ_TYPE_TRY, flags, 1UL, val_max_bad,
                        src_key_gaddr, try_gaddr_gaddr, err_gaddr, oob ); WAIT;
      FD_TEST( comp->err      ==FD_VINYL_SUCCESS   ); FD_TEST( comp->batch_cnt==(ushort)1             );
      FD_TEST( comp->fail_cnt ==(ushort)!!ref_err  ); FD_TEST( comp->quota_rem==(ushort)ref.quota_rem );
      FD_TEST( err[0]==(schar)ref_err );
      if( !ref_err ) try_live[ src_idx ] = 1;
      break;
    }

    /* test tests */

    case 34: /* test with unmappable try */
      fd_vinyl_rq_send( rq, req_id, link_id, FD_VINYL_REQ_TYPE_TEST, flags, 1UL, val_max_bad,
                        0UL, 0UL, err_gaddr, oob ); WAIT;
      FD_TEST( comp->err      ==FD_VINYL_ERR_INVAL ); FD_TEST( comp->batch_cnt==(ushort)1             );
      FD_TEST( comp->fail_cnt ==(ushort)0          ); FD_TEST( comp->quota_rem==(ushort)ref.quota_rem );
      break;

    case 35: /* test with unmappable err */
      fd_vinyl_rq_send( rq, req_id, link_id, FD_VINYL_REQ_TYPE_TEST, flags, 1UL, val_max_bad,
                        0UL, try_gaddr_gaddr, 0UL, oob ); WAIT;
      FD_TEST( comp->err      ==FD_VINYL_ERR_INVAL ); FD_TEST( comp->batch_cnt==(ushort)1             );
      FD_TEST( comp->fail_cnt ==(ushort)0          ); FD_TEST( comp->quota_rem==(ushort)ref.quota_rem );
      break;

    case 36: /* test with zero batch */
      fd_vinyl_rq_send( rq, req_id, link_id, FD_VINYL_REQ_TYPE_TEST, flags, 0UL, val_max_bad,
                        0UL, try_gaddr_gaddr, err_gaddr, oob ); WAIT;
      FD_TEST( comp->err      ==FD_VINYL_SUCCESS   ); FD_TEST( comp->batch_cnt==(ushort)0             );
      FD_TEST( comp->fail_cnt ==(ushort)0          ); FD_TEST( comp->quota_rem==(ushort)ref.quota_rem );
      break;

    case 37: { /* test */
      if( !try_live[ src_idx ] ) break;
      void *            try_val    = fd_wksp_laddr_fast( wksp, try_gaddr[0] );
      fd_vinyl_info_t * try_info   = fd_vinyl_data_info( try_val );
      ulong             try_val_sz = fd_ulong_min( (ulong)try_info->val_sz, FD_VINYL_VAL_MAX );
      int try_cmp = (!memcmp( try_info, try_pair[ src_idx ]->info, sizeof(fd_vinyl_info_t) )) &&
                    (!memcmp( try_val,  try_pair[ src_idx ]->val,  try_val_sz              ));
      int ref_err = req( FD_VINYL_REQ_TYPE_TEST, flags, val_max_bad, NULL, &try_pair[ src_idx ], &try_ver[ src_idx ] );
      fd_vinyl_rq_send( rq, req_id, link_id, FD_VINYL_REQ_TYPE_TEST, flags, 1UL, val_max_bad,
                        0UL, try_gaddr_gaddr, err_gaddr, oob ); WAIT;
      try_live[ src_idx ] = 0;
      FD_TEST( comp->err      ==FD_VINYL_SUCCESS   ); FD_TEST( comp->batch_cnt==(ushort)1             );
      /**/                                            FD_TEST( comp->quota_rem==(ushort)ref.quota_rem );
      /* Note that it is possible for a try to work in the ref version
         and fail in the full version (e.g. cache line flushing, val
         resizing in the background, etc). */
      if( ((!ref_err) & (!!err[0])) ) break;
      FD_TEST( comp->fail_cnt ==(ushort)!!ref_err  );
      FD_TEST( (!!err[0]) | try_cmp );
      break;
    }

    case 38: { /* sync */
      FD_TEST( !fd_vinyl_sync( cnc ) );
      break;
    }

    case 39: { /* randomly toggle data compression on and off */
      int new_style = (r & 1UL) ? (ulong)FD_VINYL_BSTREAM_CTL_STYLE_RAW : (ulong)FD_VINYL_BSTREAM_CTL_STYLE_LZ4;
      FD_TEST( !fd_vinyl_set( cnc, FD_VINYL_OPT_STYLE, (ulong)new_style, NULL ) );
      break;
    }

    default: break;
    }
  }

  /* Clean up */

  for( ulong src_idx=0UL; src_idx<PAIR_MAX; src_idx++ ) {
    fd_vinyl_key_t * src_key       = _key + src_idx;
    ulong            src_key_gaddr = fd_wksp_gaddr( wksp, src_key );
    val_gaddr[0] = acq_gaddr[ src_idx ];
    for( long rem=(long)fd_long_abs( acq[ src_idx ] ); rem; rem-- ) {
      ulong req_id = fd_rng_ulong( rng );
      ulong oob    = 0UL;
      int ref_err = req( FD_VINYL_REQ_TYPE_RELEASE, FD_VINYL_REQ_FLAG_IGNORE, val_max_bad, src_key, NULL, NULL );
      FD_TEST( !ref_err );
      fd_vinyl_rq_send( rq, req_id, link_id, FD_VINYL_REQ_TYPE_RELEASE, FD_VINYL_REQ_FLAG_IGNORE, 1UL, val_max_bad,
                        src_key_gaddr, val_gaddr_gaddr, err_gaddr, oob ); WAIT;
      FD_TEST( comp->err      ==FD_VINYL_SUCCESS   ); FD_TEST( comp->batch_cnt==(ushort)1             );
      FD_TEST( comp->fail_cnt ==(ushort)!!ref_err  ); FD_TEST( comp->quota_rem==(ushort)ref.quota_rem );
      FD_TEST( err[0]==(schar)ref_err );
    }

  }

  fd_rng_delete( fd_rng_leave( rng ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  if( FD_UNLIKELY( fd_tile_cnt() < 2UL ) ) FD_LOG_ERR(( "This test requires at least tiles" ));

  char const * _wksp       = fd_env_strip_cmdline_cstr ( &argc, &argv, "--wksp",        NULL,                   NULL );
  char const * _page_sz    = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",     NULL,             "gigantic" );
  ulong        page_cnt    = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",    NULL,                    8UL );
  ulong        near_cpu    = fd_env_strip_cmdline_ulong( &argc, &argv, "--near-cpu",    NULL,        fd_log_cpu_id() );
  ulong        tag         = fd_env_strip_cmdline_ulong( &argc, &argv, "--tag",         NULL,                    1UL );

  ulong        spad_max    = fd_env_strip_cmdline_ulong( &argc, &argv, "--spad-max",    NULL, fd_vinyl_io_spad_est() );
  ulong        dev_sz      = fd_env_strip_cmdline_ulong( &argc, &argv, "--dev-sz",      NULL,              1UL << 30 );
  ulong        io_seed     = fd_env_strip_cmdline_ulong( &argc, &argv, "--io-seed",     NULL,                 1234UL );

  ulong        line_cnt    = fd_env_strip_cmdline_ulong( &argc, &argv, "--line-cnt",    NULL,                    7UL );

  ulong        ele_max     = fd_env_strip_cmdline_ulong( &argc, &argv, "--ele-max",     NULL,                    8UL );
  ulong        lock_cnt    = fd_env_strip_cmdline_ulong( &argc, &argv, "--lock_cnt",    NULL,                    8UL );
  ulong        probe_max   = ele_max;
  ulong        seed        = fd_env_strip_cmdline_ulong( &argc, &argv, "--seed",        NULL,                 5678UL );

  ulong        obj_sz      = fd_env_strip_cmdline_ulong( &argc, &argv, "--obj-sz",      NULL,              6UL << 30 );

  ulong        async_min   = fd_env_strip_cmdline_ulong( &argc, &argv, "--async-min",   NULL,                    5UL );
  ulong        async_max   = fd_env_strip_cmdline_ulong( &argc, &argv, "--async-max",   NULL,          2UL*async_min );
  ulong        part_thresh = fd_env_strip_cmdline_ulong( &argc, &argv, "--part-thresh", NULL,             64UL << 20 );
  ulong        gc_thresh   = fd_env_strip_cmdline_ulong( &argc, &argv, "--gc-thresh",   NULL,            128UL << 20 );
  int          gc_eager    = fd_env_strip_cmdline_int  ( &argc, &argv, "--gc-eager",    NULL,                      2 );
  char const * _style      = fd_env_strip_cmdline_cstr ( &argc, &argv, "--style",       NULL,                  "lz4" );
  int          level       = fd_env_strip_cmdline_int  ( &argc, &argv, "--level",       NULL,                      0 );

  ulong        rq_max      = fd_env_strip_cmdline_ulong( &argc, &argv, "--rq-max",      NULL,                   32UL );
  ulong        cq_max      = fd_env_strip_cmdline_ulong( &argc, &argv, "--cq-max",      NULL,                   32UL );
  ulong        link_id     = fd_env_strip_cmdline_ulong( &argc, &argv, "--link-id",     NULL,                 2345UL );
  ulong        burst_max   = fd_env_strip_cmdline_ulong( &argc, &argv, "--burst-max",   NULL,                    1UL );
  ulong        quota_max   = fd_env_strip_cmdline_ulong( &argc, &argv, "--quota-max",   NULL,                    2UL );
  ulong        scratch_sz  = fd_env_strip_cmdline_ulong( &argc, &argv, "--scratch-sz",  NULL,                 4096UL );

  ulong        iter_max    = fd_env_strip_cmdline_ulong( &argc, &argv, "--iter-max",    NULL,             (ulong)1e7 );

  int style = fd_cstr_to_vinyl_bstream_ctl_style( _style );

  fd_wksp_t * wksp;
  if( _wksp ) {
    FD_LOG_NOTICE(( "Attaching to --wksp %s", _wksp ));
    wksp = fd_wksp_attach( _wksp );
  } else {
    FD_LOG_NOTICE(( "--wksp not specified, using an anonymous local workspace (--page-sz %s --page-cnt %lu --near-cpu %lu)",
                    _page_sz, page_cnt, near_cpu ));
    wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, near_cpu, "wksp", 0UL );
  }
  FD_TEST( wksp );

  FD_LOG_NOTICE(( "Creating vinyl tile" ));

  ulong io_footprint    = fd_vinyl_io_mm_footprint( spad_max );                      FD_TEST( io_footprint    );
  ulong dev_footprint   = fd_ulong_align_dn( dev_sz, FD_VINYL_BSTREAM_BLOCK_SZ );    FD_TEST( dev_footprint   );
  ulong vinyl_footprint = fd_vinyl_footprint();                                      FD_TEST( vinyl_footprint );
  ulong cnc_footprint   = fd_cnc_footprint( FD_VINYL_CNC_APP_SZ );                   FD_TEST( cnc_footprint   );
  ulong meta_footprint  = fd_vinyl_meta_footprint( ele_max, lock_cnt, probe_max );   FD_TEST( meta_footprint  );
  ulong line_footprint  = sizeof(fd_vinyl_line_t) * line_cnt;                        FD_TEST( line_footprint  );
  ulong ele_footprint   = sizeof(fd_vinyl_meta_ele_t) * ele_max;                     FD_TEST( ele_footprint   );
  ulong obj_footprint   = fd_ulong_align_dn( obj_sz, alignof(fd_vinyl_data_obj_t) ); FD_TEST( obj_footprint   );
  ulong rq_footprint    = fd_vinyl_rq_footprint( rq_max );                           FD_TEST( rq_footprint    );
  ulong cq_footprint    = fd_vinyl_cq_footprint( cq_max );                           FD_TEST( cq_footprint    );

  void * _io      = fd_wksp_alloc_laddr( wksp, fd_vinyl_io_mm_align(),       io_footprint,    tag ); FD_TEST( _io      );
  void * _dev     = fd_wksp_alloc_laddr( wksp, FD_VINYL_BSTREAM_BLOCK_SZ,    dev_footprint,   tag ); FD_TEST( _dev     );
  void * _vinyl   = fd_wksp_alloc_laddr( wksp, fd_vinyl_align(),             vinyl_footprint, tag ); FD_TEST( _vinyl   );
  void * _cnc     = fd_wksp_alloc_laddr( wksp, fd_cnc_align(),               cnc_footprint,   tag ); FD_TEST( _cnc     );
  void * _meta    = fd_wksp_alloc_laddr( wksp, fd_vinyl_meta_align(),        meta_footprint,  tag ); FD_TEST( _meta    );
  void * _line    = fd_wksp_alloc_laddr( wksp, alignof(fd_vinyl_line_t),     line_footprint,  tag ); FD_TEST( _line    );
  void * _ele     = fd_wksp_alloc_laddr( wksp, alignof(fd_vinyl_meta_ele_t), ele_footprint,   tag ); FD_TEST( _ele     );
  void * _obj     = fd_wksp_alloc_laddr( wksp, alignof(fd_vinyl_data_obj_t), obj_footprint,   tag ); FD_TEST( _obj     );
  void * _rq      = fd_wksp_alloc_laddr( wksp, fd_vinyl_rq_align(),          rq_footprint,    tag ); FD_TEST( _rq      );
  void * _cq      = fd_wksp_alloc_laddr( wksp, fd_vinyl_cq_align(),          cq_footprint,    tag ); FD_TEST( _cq      );
  void * _scratch = fd_wksp_alloc_laddr( wksp, 4096UL,                       scratch_sz,      tag ); FD_TEST( _scratch );

  fd_vinyl_io_t * io = fd_vinyl_io_mm_init( _io, spad_max, _dev, dev_footprint, 1, "test", 5UL, io_seed ); FD_TEST( io );

  fd_tpool_t * tpool = NULL;

  ulong thread_cnt = fd_tile_cnt();

  if( FD_LIKELY( thread_cnt>1UL ) ) {
    FD_LOG_NOTICE(( "Creating temporary tpool from all %lu tiles for thread paralel init", thread_cnt ));

    static uchar _tpool[ FD_TPOOL_FOOTPRINT( FD_TILE_MAX ) ] __attribute__((aligned(FD_TPOOL_ALIGN)));

    tpool = fd_tpool_init( _tpool, thread_cnt, 0UL ); /* logs details */
    if( FD_UNLIKELY( !tpool ) ) FD_LOG_ERR(( "fd_tpool_init failed" ));

    for( ulong thread_idx=1UL; thread_idx<thread_cnt; thread_idx++ )
      if( FD_UNLIKELY( !fd_tpool_worker_push( tpool, thread_idx ) ) ) FD_LOG_ERR(( "fd_tpool_worker_push failed" ));
  }

  fd_vinyl_t * vinyl = fd_vinyl_init( tpool, 0UL, thread_cnt, level, _vinyl,
                                      _cnc,  cnc_footprint,
                                      _meta, meta_footprint,
                                      _line, line_footprint,
                                      _ele,  ele_footprint,
                                      _obj,  obj_footprint,
                                      io, seed, wksp, async_min, async_max,
                                      part_thresh, gc_thresh, gc_eager, style );

  if( FD_LIKELY( tpool ) ) {
    FD_LOG_NOTICE(( "Destroying temporary tpool" ));
    fd_tpool_fini( tpool ); /* pops all worker threads, logs details */
  }

  FD_TEST( vinyl );
  FD_TEST( fd_vinyl_shcnc      ( vinyl )==_cnc        ); FD_TEST( fd_vinyl_cnc_footprint  ( vinyl )==cnc_footprint  );
  FD_TEST( fd_vinyl_shmeta     ( vinyl )==_meta       ); FD_TEST( fd_vinyl_meta_footprint_( vinyl )==meta_footprint );
  FD_TEST( fd_vinyl_shline     ( vinyl )==_line       ); FD_TEST( fd_vinyl_line_footprint ( vinyl )==line_footprint );
  FD_TEST( fd_vinyl_shele      ( vinyl )==_ele        ); FD_TEST( fd_vinyl_ele_footprint  ( vinyl )==ele_footprint  );
  FD_TEST( fd_vinyl_shobj      ( vinyl )==_obj        ); FD_TEST( fd_vinyl_obj_footprint  ( vinyl )==obj_footprint  );
  FD_TEST( fd_vinyl_io         ( vinyl )==io          );
  FD_TEST( fd_vinyl_seed       ( vinyl )==seed        ); FD_TEST( fd_vinyl_obj_laddr0     ( vinyl )==(void *)wksp   );
  FD_TEST( fd_vinyl_async_min  ( vinyl )==async_min   ); FD_TEST( fd_vinyl_async_max      ( vinyl )==async_max      );
  FD_TEST( fd_vinyl_part_thresh( vinyl )==part_thresh ); FD_TEST( fd_vinyl_gc_thresh      ( vinyl )==gc_thresh      );
  FD_TEST( fd_vinyl_gc_eager   ( vinyl )==gc_eager    ); FD_TEST( fd_vinyl_style          ( vinyl )==style          );

  FD_LOG_NOTICE(( "Booting up vinyl tile" ));

  fd_tile_exec_t * exec = fd_tile_exec_new( 1UL, fd_vinyl_tile, 0, (char **)vinyl ); FD_TEST( exec );

  /* Start client side operations *************************************/

  FD_LOG_NOTICE(( "Creating rq and cq" ));

  fd_vinyl_rq_t * rq = fd_vinyl_rq_join( fd_vinyl_rq_new( _rq, rq_max ) ); FD_TEST( rq );
  fd_vinyl_cq_t * cq = fd_vinyl_cq_join( fd_vinyl_cq_new( _cq, cq_max ) ); FD_TEST( cq );

  FD_LOG_NOTICE(( "Joining vinyl cnc" ));

  fd_cnc_t * cnc = fd_cnc_join( _cnc ); FD_TEST( cnc );

  FD_LOG_NOTICE(( "Waiting for vinyl tile to boot up" ));

  FD_TEST( fd_cnc_wait( cnc, FD_VINYL_CNC_SIGNAL_BOOT, (long)5e9, NULL )==FD_VINYL_CNC_SIGNAL_RUN );

  FD_LOG_NOTICE(( "Testing sync" ));

  FD_TEST( !fd_vinyl_sync( cnc ) );

  FD_LOG_NOTICE(( "Testing get" ));

  ulong old;

  FD_TEST( !fd_vinyl_get( cnc, FD_VINYL_OPT_PART_THRESH, NULL ) );
  FD_TEST( !fd_vinyl_get( cnc, FD_VINYL_OPT_PART_THRESH, &old ) );
  FD_TEST( old==part_thresh );

  FD_TEST( !fd_vinyl_get( cnc, FD_VINYL_OPT_GC_THRESH, NULL ) );
  FD_TEST( !fd_vinyl_get( cnc, FD_VINYL_OPT_GC_THRESH, &old ) );
  FD_TEST( old==gc_thresh );

  FD_TEST( !fd_vinyl_get( cnc, FD_VINYL_OPT_GC_EAGER, NULL ) );
  FD_TEST( !fd_vinyl_get( cnc, FD_VINYL_OPT_GC_EAGER, &old ) );
  FD_TEST( ((int)old)==gc_eager );

  FD_TEST( !fd_vinyl_get( cnc, FD_VINYL_OPT_STYLE, NULL ) );
  FD_TEST( !fd_vinyl_get( cnc, FD_VINYL_OPT_STYLE, &old ) );
  FD_TEST( ((int)old)==style );

  FD_TEST( fd_vinyl_get( cnc, -1, NULL )==FD_VINYL_ERR_INVAL );
  FD_TEST( fd_vinyl_get( cnc, -1, &old )==FD_VINYL_ERR_INVAL );

  FD_LOG_NOTICE(( "Testing set" ));

  FD_TEST( !fd_vinyl_set( cnc, FD_VINYL_OPT_PART_THRESH, part_thresh+1UL, NULL ) );
  FD_TEST( !fd_vinyl_set( cnc, FD_VINYL_OPT_PART_THRESH, part_thresh,     &old ) );
  FD_TEST( old==(part_thresh+1UL) );

  FD_TEST( !fd_vinyl_set( cnc, FD_VINYL_OPT_GC_THRESH, gc_thresh+1UL, NULL ) );
  FD_TEST( !fd_vinyl_set( cnc, FD_VINYL_OPT_GC_THRESH, gc_thresh,     &old ) );
  FD_TEST( old==(gc_thresh+1UL) );

  FD_TEST( !fd_vinyl_set( cnc, FD_VINYL_OPT_GC_EAGER, (ulong)-1,       NULL ) );
  FD_TEST( !fd_vinyl_set( cnc, FD_VINYL_OPT_GC_EAGER, (ulong)gc_eager, &old ) );
  FD_TEST( ((int)old)==-1 );

  FD_TEST( !fd_vinyl_set( cnc, FD_VINYL_OPT_STYLE, (ulong)255,   NULL ) );
  FD_TEST( !fd_vinyl_set( cnc, FD_VINYL_OPT_STYLE, (ulong)style, &old ) );
  FD_TEST( ((int)old)==255 );

  FD_TEST( fd_vinyl_set( cnc, -1, 1234UL, NULL )==FD_VINYL_ERR_INVAL );
  FD_TEST( fd_vinyl_set( cnc, -1, 1234UL, &old )==FD_VINYL_ERR_INVAL );

  FD_LOG_NOTICE(( "Testing client join" ));

  FD_TEST( fd_vinyl_client_join( cnc, NULL, cq,   wksp, link_id, burst_max, quota_max )==FD_VINYL_ERR_INVAL ); /* bad rq */
  FD_TEST( fd_vinyl_client_join( cnc, rq,   NULL, wksp, link_id, burst_max, quota_max )==FD_VINYL_ERR_INVAL ); /* bad cq */
  FD_TEST( fd_vinyl_client_join( cnc, rq,   cq,   NULL, link_id, burst_max, quota_max )==FD_VINYL_ERR_INVAL ); /* bad wksp */
  /* bad link_id tested below */
  FD_TEST( fd_vinyl_client_join( cnc, rq,   cq,   wksp, link_id, ULONG_MAX, quota_max )==FD_VINYL_ERR_FULL  ); /* too large burst */
  FD_TEST( fd_vinyl_client_join( cnc, rq,   cq,   wksp, link_id, burst_max, ULONG_MAX )==FD_VINYL_ERR_FULL  ); /* too large quota */

  FD_TEST( !fd_vinyl_client_join( cnc, rq, cq, wksp, link_id, burst_max, quota_max ) );

  ref.quota_rem = quota_max;

  FD_TEST( fd_vinyl_client_join( cnc, rq, cq, wksp, link_id, burst_max, quota_max )==FD_VINYL_ERR_FULL ); /* already joined */

  FD_LOG_NOTICE(( "Running client tile" ));

  client_tile( iter_max, cnc, link_id, rq, cq, wksp, _scratch );

  FD_LOG_NOTICE(( "Testing client leave" ));

  FD_TEST( !fd_vinyl_client_leave( cnc, link_id ) );

  FD_TEST( fd_vinyl_client_leave( cnc, link_id )==FD_VINYL_ERR_EMPTY ); /* not joined */

  FD_LOG_NOTICE(( "Testing halt" ));

  FD_TEST( !fd_vinyl_halt( cnc ) );

  FD_LOG_NOTICE(( "Leaving vinyl cnc" ));

  FD_TEST( fd_cnc_leave( cnc )==_cnc );

  FD_LOG_NOTICE(( "Destroying rq and cq" ));

  FD_TEST( fd_vinyl_cq_delete( fd_vinyl_cq_leave( cq ) )==_cq );
  FD_TEST( fd_vinyl_rq_delete( fd_vinyl_rq_leave( rq ) )==_rq );

  /* End client side operations ***************************************/

  FD_LOG_NOTICE(( "Cleaning up" ));

  fd_tile_exec_delete( exec, NULL );

  FD_TEST( fd_vinyl_fini( vinyl )==_vinyl );
  FD_TEST( fd_vinyl_io_fini( io )==_io );

  fd_wksp_free_laddr( _scratch );
  fd_wksp_free_laddr( _cq      );
  fd_wksp_free_laddr( _rq      );

  fd_wksp_free_laddr( _obj     );
  fd_wksp_free_laddr( _ele     );
  fd_wksp_free_laddr( _line    );
  fd_wksp_free_laddr( _meta    );
  fd_wksp_free_laddr( _cnc     );
  fd_wksp_free_laddr( _vinyl   );

  fd_wksp_free_laddr( _dev     );
  fd_wksp_free_laddr( _io      );

  if( _wksp ) fd_wksp_detach( wksp );
  else        fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
