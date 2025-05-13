#include "fd_bank_mgr.h"

static inline fd_funk_rec_key_t
fd_bank_mgr_cache_key( ulong entry_id ) {
  fd_funk_rec_key_t id;
  memcpy( id.uc, &entry_id, sizeof(ulong) );
  memset( id.uc + sizeof(ulong), 0, sizeof(fd_funk_rec_key_t) - sizeof(ulong) );

  id.uc[ FD_FUNK_REC_KEY_FOOTPRINT - 1 ] = FD_FUNK_KEY_TYPE_BANK_MGR;

  return id;
}

ulong
fd_bank_mgr_align( void ) {
  return alignof(fd_bank_mgr_t);
}

ulong
fd_bank_mgr_footprint( void ) {
  return sizeof(fd_bank_mgr_t);
}

void *
fd_bank_mgr_new( void * mem ) {
  return mem;
}

fd_bank_mgr_t *
fd_bank_mgr_join( void * mem, fd_funk_t * funk, fd_funk_txn_t * funk_txn ) {

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_bank_mgr_align() ) ) ) {
    FD_LOG_ERR(( "Bank manager mem not aligned" ));
    return NULL;
  }

  fd_bank_mgr_t * bank_mgr = (fd_bank_mgr_t * )mem;

  bank_mgr->funk     = funk;
  bank_mgr->funk_txn = funk_txn;
  memset( &bank_mgr->query, 0, sizeof(fd_funk_rec_query_t) );

  return bank_mgr;
}

#define BANK_MGR_FUNCTION_IMPL(type, name, id, footprint, align)                                   \
type *                                                                                             \
fd_bank_mgr_##name##_query( fd_bank_mgr_t * bank_mgr ) {                                           \
  for(;;) {                                                                                        \
    fd_funk_rec_query_t   query = {0};                                                             \
    fd_funk_rec_key_t     key   = fd_bank_mgr_cache_key( fd_bank_mgr_##name##_id );                \
    fd_funk_rec_t const * rec   = fd_funk_rec_query_try_global( bank_mgr->funk,                    \
                                                                bank_mgr->funk_txn,                \
                                                                &key,                              \
                                                                NULL,                              \
                                                                &query );                          \
    if( FD_UNLIKELY( !rec ) ) {                                                                    \
      return NULL;                                                                                 \
    }                                                                                              \
                                                                                                   \
    if( FD_LIKELY( fd_funk_rec_query_test( &query )==FD_FUNK_SUCCESS ) )                           \
      return (type *)fd_ulong_align_up( (ulong)fd_funk_val( rec, fd_funk_wksp( bank_mgr->funk ) ), \
                                        fd_bank_mgr_##name##_align );                              \
    }                                                                                              \
}                                                                                                  \
                                                                                                   \
type *                                                                                             \
fd_bank_mgr_##name##_modify( fd_bank_mgr_t * bank_mgr ) {                                          \
  fd_funk_rec_key_t     key   = fd_bank_mgr_cache_key( fd_bank_mgr_##name##_id );                  \
  fd_funk_rec_try_clone_safe( bank_mgr->funk,                                                      \
                              bank_mgr->funk_txn,                                                  \
                              &key,                                                                \
                              fd_bank_mgr_##name##_footprint,                                      \
                              fd_bank_mgr_##name##_align );                                        \
  fd_funk_rec_t * mod_rec = fd_funk_rec_modify_try( bank_mgr->funk,                                \
                                                    bank_mgr->funk_txn,                            \
                                                    &key,                                          \
                                                    &bank_mgr->query );                            \
  if( FD_UNLIKELY( !mod_rec ) ) {                                                                  \
    FD_LOG_CRIT(( "Failed to modify bank manager record" ));                                       \
  }                                                                                                \
  return fd_funk_val( mod_rec, fd_funk_wksp( bank_mgr->funk ) );                                   \
}                                                                                                  \
int                                                                                                \
fd_bank_mgr_##name##_save( fd_bank_mgr_t * bank_mgr ) {                                            \
  fd_funk_rec_modify_publish( &bank_mgr->query );                                                  \
  fd_memset( &bank_mgr->query, 0, sizeof(fd_funk_rec_query_t) );                                   \
  return 0;                                                                                        \
}
FD_BANK_MGR_ITER(BANK_MGR_FUNCTION_IMPL)
