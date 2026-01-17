#include "fd_accdb_impl_v0.h"

fd_account_meta_t const fd_accdb_meta_empty = {0};

FD_FN_CONST ulong
fd_accdb_v0_align( void ) {
  return alignof(fd_accdb_v0_t);
}

ulong
fd_accdb_v0_footprint( ulong rec_cnt ) {
  ulong rec_sz;
  if( FD_UNLIKELY( __builtin_umull_overflow( rec_cnt, sizeof(fd_accdb_v0_rec_t), &rec_sz ) ) ) return 0UL;
  ulong sz;
  if( FD_UNLIKELY( __builtin_uaddl_overflow( sizeof(fd_accdb_v0_t), rec_sz, &sz ) ) ) return 0UL;
  return sz;
}

void *
fd_accdb_v0_new( void * shmem,
                 ulong  rec_cnt ) {

  if( FD_UNLIKELY( !fd_accdb_v0_footprint( rec_cnt ) ) ) {
    FD_LOG_WARNING(( "invalid rec_cnt" ));
    return NULL;
  }

  fd_accdb_v0_t * v0 = (fd_accdb_v0_t *)shmem;
  memset( v0, 0, sizeof(fd_accdb_v0_t) );
  v0->rec_cnt = 0UL;
  v0->rec_max = rec_cnt;
  fd_rwlock_new( &v0->lock );

  FD_COMPILER_MFENCE();
  v0->magic = FD_ACCDB_V0_MAGIC;
  FD_COMPILER_MFENCE();

  return v0;
}

fd_accdb_v0_t *
fd_accdb_v0_join( void * mem ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL accdb_v0" ));
    return NULL;
  }
  fd_accdb_v0_t * v0 = (fd_accdb_v0_t *)mem;
  if( FD_UNLIKELY( v0->magic!=FD_ACCDB_V0_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return v0;
}

void *
fd_accdb_v0_leave( fd_accdb_v0_t * v0 ) {
  return v0;
}

void *
fd_accdb_v0_delete( void * mem ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL accdb_v0" ));
    return NULL;
  }
  fd_accdb_v0_t * v0 = (fd_accdb_v0_t *)mem;
  if( FD_UNLIKELY( v0->magic!=FD_ACCDB_V0_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }
  v0->magic = 0UL;

  fd_rwlock_write( &v0->lock );
  for( ulong i=0UL; i<v0->rec_cnt; i++ ) {
    if( FD_UNLIKELY( (!!v0->rec[ i ].writer_cnt) |
                     (!!v0->rec[ i ].reader_cnt) ) ) {
      FD_LOG_CRIT(( "attempted to delete accdb_v0 with active users, aborting" ));
    }
  }
  fd_rwlock_unwrite( &v0->lock );

  memset( v0, 0, fd_accdb_v0_footprint( v0->rec_cnt ) );
  return v0;
}

fd_accdb_user_t *
fd_accdb_user_v0_init( fd_accdb_user_t * accdb_,
                       fd_accdb_v0_t *   v0 ) {

  if( FD_UNLIKELY( !v0 || v0->magic!=FD_ACCDB_V0_MAGIC ) ) {
    FD_LOG_WARNING(( "invalid accdb_v0" ));
    return NULL;
  }

  fd_accdb_user_v0_t * accdb = fd_type_pun( accdb_ );
  memset( accdb, 0, sizeof(fd_accdb_user_v0_t) );
  accdb->base.accdb_type = FD_ACCDB_TYPE_V0;
  accdb->base.vt         = &fd_accdb_user_v0_vt;
  accdb->v0              = v0;
  return accdb_;
}

void
fd_accdb_user_v0_fini( fd_accdb_user_t * accdb ) {
  (void)accdb;
  /* FIXME consider asserting that the v0 reference count is zero */
  return;
}

static long
find_key( fd_accdb_v0_t const * v0,
          void const *          address ) {
  for( ulong i=0UL; i<v0->rec_cnt; i++ ) {
    if( 0==memcmp( &v0->rec[ i ].key, address, sizeof(fd_pubkey_t) ) ) {
      return (long)i;
    }
  }
  return -1L;
}

static void
remove_rec( fd_accdb_v0_t * v0,
            long            idx ) {
  if( v0->rec_cnt ) {
    ulong last_idx = v0->rec_cnt-1UL;
    v0->rec[ idx ] = v0->rec[ last_idx ];
  }
  v0->rec_cnt--;
}

static long
push_rec( fd_accdb_v0_t * v0,
          void const *    address ) {
  if( FD_UNLIKELY( v0->rec_cnt >= v0->rec_max ) ) return -1L;
  long idx = (long)v0->rec_cnt;
  fd_accdb_v0_rec_t * rec = &v0->rec[ idx ];
  memset( rec,       0,       sizeof(fd_accdb_v0_rec_t) );
  memcpy( &rec->key, address, sizeof(fd_pubkey_t)       );
  v0->rec_cnt++;
  return idx;
}

static ulong
fd_accdb_user_v0_batch_max( fd_accdb_user_t * accdb ) {
  (void)accdb;
  return 1UL;
}

fd_accdb_peek_t *
fd_accdb_user_v0_peek( fd_accdb_user_t *         accdb,
                       fd_accdb_peek_t *         peek,
                       fd_funk_txn_xid_t const * xid,
                       void const *              address ) {
  /* No true concurrency, therefore no speculative accesses */
  (void)accdb; (void)peek; (void)xid; (void)address;
  return NULL;
}

static fd_accdb_ro_t *
fd_accdb_user_v0_open_ro( fd_accdb_user_t *         accdb_,
                          fd_accdb_ro_t *           ro,
                          fd_funk_txn_xid_t const * xid,
                          void const *              address ) {
  (void)xid;
  fd_accdb_user_v0_t * accdb = (fd_accdb_user_v0_t *)accdb_;
  fd_accdb_v0_t *      v0    = accdb->v0;

  long idx = find_key( v0, address );
  fd_accdb_ro_t * found = NULL;
  if( idx>=0L ) {
    fd_accdb_v0_rec_t * rec = &v0->rec[ idx ];
    if( FD_UNLIKELY( rec->writer_cnt ) ) {
      FD_BASE58_ENCODE_32_BYTES( address, address_b58 );
      FD_LOG_CRIT(( "accdb_user_v0_open_ro failed: account %s is currently in use", address_b58 ));
    }
    rec->reader_cnt++;

    *ro = (fd_accdb_ro_t) {0};
    FD_STORE( fd_pubkey_t, ro->ref->address, rec->key );
    ro->ref->accdb_type = FD_ACCDB_TYPE_V0;
    ro->ref->ref_type   = FD_ACCDB_REF_RO;
    ro->ref->user_data  = 0UL;
    ro->meta            = &rec->meta;

    accdb->base.ro_active++;
    found = ro;
  }

  return found;
}

void
fd_accdb_user_v0_open_ro_multi( fd_accdb_user_t *         accdb_,
                                fd_accdb_ro_t *           ro,
                                fd_funk_txn_xid_t const * xid,
                                void const *              address,
                                ulong                     cnt ) {
  fd_accdb_user_v0_t * accdb = (fd_accdb_user_v0_t *)accdb_;
  fd_accdb_v0_t *      v0    = accdb->v0;
  fd_rwlock_write( &v0->lock );
  ulong addr_laddr = (ulong)address;
  for( ulong i=0UL; i<cnt; i++ ) {
    void const *    addr_i = (void const *)( (ulong)addr_laddr + i*32UL );
    fd_accdb_ro_t * ro_i   = fd_accdb_user_v0_open_ro( accdb_, &ro[i], xid, addr_i );
    if( !ro_i ) fd_accdb_ro_init_empty( &ro[i], addr_i );
  }
  fd_rwlock_unwrite( &v0->lock );
}

static void
fd_accdb_user_v0_close_ro( fd_accdb_user_t * accdb,
                           fd_accdb_ro_t *   ro ) {
  fd_accdb_user_v0_t * user = (fd_accdb_user_v0_t *)accdb;
  fd_accdb_v0_t *      v0   = user->v0;

  long idx = find_key( v0, ro->ref->address );
  if( FD_UNLIKELY( idx<0L ) ) {
    FD_BASE58_ENCODE_32_BYTES( ro->ref->address, address_b58 );
    FD_LOG_CRIT(( "accdb_user_v0_close_ro failed: account %s not found", address_b58 ));
  }
  fd_accdb_v0_rec_t * rec = &v0->rec[ idx ];

  if( FD_UNLIKELY( !rec->reader_cnt ||
                   !user->base.ro_active ) ) {
    FD_LOG_CRIT(( "accdb_user_v0_close_ro failed: ref count underflow" ));
  }
  rec->reader_cnt--;
  user->base.ro_active--;
}

static fd_accdb_rw_t *
fd_accdb_user_v0_open_rw( fd_accdb_user_t *         accdb_,
                          fd_accdb_rw_t *           rw_,
                          fd_funk_txn_xid_t const * xid,
                          void const *              address,
                          ulong                     data_max,
                          int                       flags ) {
  fd_accdb_user_v0_t * accdb = (fd_accdb_user_v0_t *)accdb_;
  fd_accdb_v0_t *      v0    = accdb->v0;
  (void)xid;

  fd_accdb_rw_t * rw = NULL;

  int const flag_create   = !!( flags & FD_ACCDB_FLAG_CREATE   );
  int const flag_truncate = !!( flags & FD_ACCDB_FLAG_TRUNCATE );
  if( FD_UNLIKELY( flags & ~(FD_ACCDB_FLAG_CREATE|FD_ACCDB_FLAG_TRUNCATE) ) ) {
    FD_LOG_CRIT(( "invalid flags for open_rw: %#02x", (uint)flags ));
  }

  if( FD_UNLIKELY( data_max > FD_RUNTIME_ACC_SZ_MAX ) ) {
    FD_LOG_CRIT(( "invalid data_max %lu", data_max ));
  }

  long idx = find_key( v0, address );
  if( idx<0L ) {
    if( !flag_create ) return NULL;
    idx = push_rec( v0, address );
    if( FD_UNLIKELY( idx<0L ) ) FD_LOG_CRIT(( "accdb_user_v0_open_rw failed: cannot create account, out of memory" ));
  }
  rw = rw_;

  fd_accdb_v0_rec_t * rec = &v0->rec[ idx ];
  if( flag_truncate ) rec->meta.dlen = 0;
  accdb->base.rw_active++;
  rec->writer_cnt = 1;
  rec->reader_cnt = 0;

  *rw = (fd_accdb_rw_t) {0};
  memcpy( rw->ref->address, address, sizeof(fd_pubkey_t) );
  rw->ref->accdb_type = FD_ACCDB_TYPE_V0;
  rw->ref->ref_type   = FD_ACCDB_REF_RW;
  rw->ref->user_data  = 0UL;
  rw->meta            = &rec->meta;

  return rw;
}

void
fd_accdb_user_v0_open_rw_multi( fd_accdb_user_t *         accdb_,
                                fd_accdb_rw_t *           rw,
                                fd_funk_txn_xid_t const * xid,
                                void const *              address,
                                ulong const *             data_max,
                                int                       flags,
                                ulong                     cnt ) {
  fd_accdb_user_v0_t * accdb = (fd_accdb_user_v0_t *)accdb_;
  fd_accdb_v0_t *      v0    = accdb->v0;
  fd_rwlock_write( &v0->lock );
  ulong addr_laddr = (ulong)address;
  for( ulong i=0UL; i<cnt; i++ ) {
    void const *    addr_i = (void const *)( (ulong)addr_laddr + i*32UL );
    ulong           dmax_i = data_max[i];
    fd_accdb_rw_t * rw_i   = fd_accdb_user_v0_open_rw( accdb_, &rw[i], xid, addr_i, dmax_i, flags );
    if( !rw_i ) memset( &rw[i], 0, sizeof(fd_accdb_rw_t) );
  }
  fd_rwlock_unwrite( &v0->lock );
}

static void
fd_accdb_user_v0_close_rw( fd_accdb_user_t * accdb,
                           fd_accdb_rw_t *   rw ) {
  fd_accdb_user_v0_t * user = (fd_accdb_user_v0_t *)accdb;
  fd_accdb_v0_t *      v0   = user->v0;

  long idx = find_key( v0, rw->ref->address );
  if( FD_UNLIKELY( idx<0L ) ) {
    FD_BASE58_ENCODE_32_BYTES( rw->ref->address, address_b58 );
    FD_LOG_CRIT(( "accdb_user_v0_close_rw failed: account %s not found", address_b58 ));
  }
  fd_accdb_v0_rec_t * rec = &v0->rec[ idx ];

  if( FD_UNLIKELY( !rec->writer_cnt ||
                   !user->base.rw_active ||
                   user->base.ro_active ) ) {
    FD_LOG_CRIT(( "accdb_user_v0_close_rw failed: invalid ref count detected" ));
  }
  rec->writer_cnt--;
  user->base.rw_active--;

  if( rec->meta.lamports==0UL ) remove_rec( v0, idx );
}

static void
fd_accdb_user_v0_close_ref( fd_accdb_user_t * accdb,
                            fd_accdb_ref_t *  ref ) {
  if( ref->accdb_type==FD_ACCDB_TYPE_NONE ) return;
  switch( ref->ref_type ) {
  case FD_ACCDB_REF_RO:
    fd_accdb_user_v0_close_ro( accdb, (fd_accdb_ro_t *)ref );
    break;
  case FD_ACCDB_REF_RW:
    fd_accdb_user_v0_close_rw( accdb, (fd_accdb_rw_t *)ref );
    break;
  default:
    FD_LOG_CRIT(( "invalid ref_type %u in fd_accdb_user_v0_close_ref", (uint)ref->ref_type ));
  }
}

void
fd_accdb_user_v0_close_ref_multi( fd_accdb_user_t * accdb_,
                                  fd_accdb_ref_t *  ref,
                                  ulong             cnt ) {
  fd_accdb_user_v0_t * accdb = (fd_accdb_user_v0_t *)accdb_;
  fd_accdb_v0_t *      v0    = accdb->v0;
  fd_rwlock_write( &v0->lock );
  for( ulong i=0UL; i<cnt; i++ ) {
    fd_accdb_ref_t * ref_i = &ref[i];
    fd_accdb_user_v0_close_ref( accdb_, ref_i );
  }
  fd_rwlock_unwrite( &v0->lock );
}

ulong
fd_accdb_user_v0_rw_data_max( fd_accdb_user_t *     accdb,
                              fd_accdb_rw_t const * rw ) {
  (void)accdb;
  if( rw->ref->accdb_type==FD_ACCDB_TYPE_NONE ) {
    return rw->ref->user_data; /* data_max */
  }
  return FD_RUNTIME_ACC_SZ_MAX;
}

void
fd_accdb_user_v0_rw_data_sz_set( fd_accdb_user_t * accdb,
                                 fd_accdb_rw_t *   rw,
                                 ulong             data_sz,
                                 int               flags ) {
  (void)accdb;
  int flag_dontzero = !!( flags & FD_ACCDB_FLAG_DONTZERO );
  if( FD_UNLIKELY( flags & ~(FD_ACCDB_FLAG_DONTZERO) ) ) {
    FD_LOG_CRIT(( "invalid flags for rw_data_sz_set: %#02x", (uint)flags ));
  }

  ulong prev_sz = rw->meta->dlen;
  if( data_sz>prev_sz ) {
    if( FD_UNLIKELY( data_sz>FD_RUNTIME_ACC_SZ_MAX ) ) {
      FD_LOG_CRIT(( "attempted to write %lu bytes into a rec with only %lu bytes of data space",
                    data_sz, FD_RUNTIME_ACC_SZ_MAX ));
    }
    if( !flag_dontzero ) {
      void * tail = (uchar *)fd_accdb_ref_data( rw ) + prev_sz;
      fd_memset( tail, 0, data_sz-prev_sz );
    }
  }
  rw->meta->dlen = (uint)data_sz;
}

fd_accdb_user_vt_t const fd_accdb_user_v0_vt = {
  .fini            = fd_accdb_user_v0_fini,
  .batch_max       = fd_accdb_user_v0_batch_max,
  .peek            = fd_accdb_user_v0_peek,
  .open_ro_multi   = fd_accdb_user_v0_open_ro_multi,
  .open_rw_multi   = fd_accdb_user_v0_open_rw_multi,
  .close_ref_multi = fd_accdb_user_v0_close_ref_multi,
  .rw_data_max     = fd_accdb_user_v0_rw_data_max,
  .rw_data_sz_set  = fd_accdb_user_v0_rw_data_sz_set
};
