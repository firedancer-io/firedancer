#include "fd_accdb_batch.h"
#include "fd_accdb_sync.h"

struct fd_accdb_ro_pipe1 {
  fd_accdb_user_t * accdb;
  fd_accdb_ro_t     ro[1];
  fd_funk_txn_xid_t xid;
  uint ro_borrowed : 1;  /* ro accessible by user */
};

typedef struct fd_accdb_ro_pipe1 fd_accdb_ro_pipe1_t;

FD_STATIC_ASSERT( alignof(fd_accdb_ro_pipe1_t)<=alignof(fd_accdb_ro_pipe_t), layout );
FD_STATIC_ASSERT( sizeof (fd_accdb_ro_pipe1_t)<=sizeof(fd_accdb_ro_pipe_t),  layout );

fd_accdb_ro_pipe_t *
fd_accdb_ro_pipe1_init( fd_accdb_ro_pipe_t *      pipe_,
                        fd_accdb_user_t *         accdb,
                        fd_funk_txn_xid_t const * xid ) {
  fd_accdb_ro_pipe1_t * pipe = (fd_accdb_ro_pipe1_t *)pipe_;
  *pipe = (fd_accdb_ro_pipe1_t) {
    .accdb = accdb,
    .xid   = *xid
  };
  return pipe_;
}

void
fd_accdb_ro_pipe1_fini( fd_accdb_ro_pipe_t * pipe_ ) {
  (void)fd_accdb_ro_pipe1_poll( pipe_ );
  memset( pipe_, 0, sizeof(fd_accdb_ro_pipe1_t) );
}

void
fd_accdb_ro_pipe1_enqueue( fd_accdb_ro_pipe_t * pipe_,
                           void const *         address ) {
  fd_accdb_ro_pipe1_t * pipe = (fd_accdb_ro_pipe1_t *)pipe_;
  if( FD_UNLIKELY( pipe->ro_borrowed ) ) FD_LOG_CRIT(( "ro_pipe_enqueue failed: not ready for new requests (poll() required before next request)" ));
  fd_accdb_ro_t * ro = pipe->ro;
  if( !fd_accdb_open_ro( pipe->accdb, ro, &pipe->xid, address ) ) {
    memset( ro, 0, sizeof(fd_accdb_ro_t) );
    ro->ref->accdb_type = FD_ACCDB_TYPE_NONE;
    memcpy( ro->ref->address, address, 32UL );
    static fd_account_meta_t const fd_account_meta_zero = {0};
    ro->meta = &fd_account_meta_zero;
  }
}

void
fd_accdb_ro_pipe1_flush( fd_accdb_ro_pipe_t * pipe_ ) {
  (void)fd_accdb_ro_pipe1_poll( pipe_ );
}

fd_accdb_ro_t *
fd_accdb_ro_pipe1_poll( fd_accdb_ro_pipe_t * pipe_ ) {
  fd_accdb_ro_pipe1_t * pipe = (fd_accdb_ro_pipe1_t *)pipe_;
  if( !pipe->ro->ref->accdb_type ) return NULL;
  if( pipe->ro_borrowed ) {
    fd_accdb_close_ro( pipe->accdb, pipe->ro );
    pipe->ro_borrowed = 0;
    return NULL;
  }
  pipe->ro_borrowed = 1;
  return pipe->ro;
}
