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

  bank_mgr->funk      = funk;
  bank_mgr->funk_txn  = funk_txn;
  bank_mgr->is_modify = 0;
  bank_mgr->is_new    = 0;
  memset( &bank_mgr->prepare, 0, sizeof(fd_funk_rec_prepare_t) );
  memset( &bank_mgr->query, 0, sizeof(fd_funk_rec_query_t) );

  return bank_mgr;
}

#define BANK_MGR_FUNCTION_IMPL(type, name, uppername)                                              \
type *                                                                                             \
fd_bank_mgr_##name##_query( fd_bank_mgr_t * bank_mgr ) {                                           \
  for ( ; ; ) {                                                                                    \
    fd_funk_rec_query_t   query = {0};                                                             \
    fd_funk_rec_key_t     key   = fd_bank_mgr_cache_key( FD_BANK_MGR_##uppername##_ID );           \
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
                                        FD_BANK_MGR_##uppername##_ALIGN );                         \
    }                                                                                              \
}                                                                                                  \
                                                                                                   \
type *                                                                                             \
fd_bank_mgr_##name##_modify( fd_bank_mgr_t * bank_mgr ) {                                          \
  fd_funk_rec_query_t   query = {0};                                                               \
  fd_funk_rec_key_t     key   = fd_bank_mgr_cache_key( FD_BANK_MGR_##uppername##_ID );             \
  fd_funk_rec_t const * rec   = fd_funk_rec_query_try( bank_mgr->funk,                             \
                                                       bank_mgr->funk_txn,                         \
                                                       &key,                                       \
                                                       &query );                                   \
  fd_funk_rec_t * mod_rec = NULL;                                                                  \
  if( !!rec ) {                                                                                    \
    /* If rec exists in the current funk txn, modify the current rec */                            \
    memset( &bank_mgr->query, 0, sizeof(fd_funk_rec_query_t) );                                    \
    mod_rec = fd_funk_rec_modify_try( bank_mgr->funk,                                          \
                                          bank_mgr->funk_txn,                                      \
                                          &key,                                                    \
                                          &bank_mgr->query );                                      \
    bank_mgr->is_modify = 1;                                                                       \
    return (type *)fd_ulong_align_up( (ulong)fd_funk_val( rec, fd_funk_wksp( bank_mgr->funk ) ),   \
                                      FD_BANK_MGR_##uppername##_ALIGN );                           \
  }                                                                                                \
  /* Case where the record does not exist in the current funk txn */                               \
  bank_mgr->is_new = 1;                                                                            \
  for( ;; ) {                                                                                      \
    fd_funk_rec_query_t glob_query = {0};                                                          \
    rec = fd_funk_rec_query_try_global( bank_mgr->funk,                                            \
                                        bank_mgr->funk_txn,                                        \
                                        &key,                                                      \
                                        NULL,                                                      \
                                        &glob_query );                                             \
    if( FD_UNLIKELY( !rec ) ) {                                                                    \
      break;                                                                                       \
    }                                                                                              \
    if( FD_LIKELY( fd_funk_rec_query_test( &glob_query )==FD_FUNK_SUCCESS ) ) {                    \
      break;                                                                                       \
    }                                                                                              \
  }                                                                                                \
  /* Prepare a new record to be inserted into the funk txn */                                      \
  mod_rec = fd_funk_rec_prepare( bank_mgr->funk,                                                   \
                                 bank_mgr->funk_txn,                                               \
                                 &key,                                                             \
                                 &bank_mgr->prepare,                                               \
                                 NULL );                                                           \
  int     err      = 0;                                                                            \
  uchar * new_data = fd_funk_val_truncate( mod_rec,                                                \
                                           FD_BANK_MGR_##uppername##_FOOTPRINT,                    \
                                           fd_funk_alloc( bank_mgr->funk ),                        \
                                           fd_funk_wksp( bank_mgr->funk ),                         \
                                           fd_funk_val_min_align(),                                \
                                           &err );                                                 \
  if( FD_UNLIKELY( err ) ) {                                                                       \
    FD_LOG_ERR(( "Could not truncate new data" ));                                                 \
  }                                                                                                \
  uchar * new_data_start = (uchar *)fd_ulong_align_up( (ulong)new_data,                            \
                                                       FD_BANK_MGR_##uppername##_ALIGN );          \
  if( FD_LIKELY( rec ) ) {                                                                         \
    /* Copy over most recent data into the newly created funk rec */                               \
    uchar * old_data       = fd_funk_val( rec, fd_funk_wksp( bank_mgr->funk ) );                   \
    uchar * old_data_start = (uchar *)fd_ulong_align_up( (ulong)old_data,                          \
                                                         FD_BANK_MGR_##uppername##_ALIGN );        \
    fd_memcpy( new_data_start,                                                                     \
               old_data_start,                                                                     \
               FD_BANK_MGR_##uppername##_FOOTPRINT - ((ulong)new_data_start - (ulong)new_data) );  \
  }                                                                                                \
  return (type *)new_data_start;                                                                   \
}                                                                                                  \
int                                                                                                \
fd_bank_mgr_##name##_save( fd_bank_mgr_t * bank_mgr ) {                                            \
  if( FD_UNLIKELY( (bank_mgr->is_modify && bank_mgr->is_new) ||                                    \
                   (!bank_mgr->is_modify && !bank_mgr->is_new) ) ) {                               \
    FD_LOG_ERR(( "Bank manager is_modify and is_new are both %d", bank_mgr->is_modify ));          \
  }                                                                                                \
  if( bank_mgr->is_new ) {                                                                         \
    fd_funk_rec_publish( bank_mgr->funk, &bank_mgr->prepare );                                     \
    bank_mgr->is_new = 0;                                                                          \
    fd_memset( &bank_mgr->prepare, 0, sizeof(fd_funk_rec_prepare_t) );                             \
  } else {                                                                                         \
    fd_funk_rec_modify_publish( &bank_mgr->query );                                                \
    bank_mgr->is_modify = 0;                                                                       \
    fd_memset( &bank_mgr->query, 0, sizeof(fd_funk_rec_query_t) );                                 \
  }                                                                                                \
  return 0;                                                                                        \
}
FD_BANK_MGR_ITER(BANK_MGR_FUNCTION_IMPL)
