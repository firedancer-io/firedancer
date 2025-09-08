#ifndef HEADER_fd_src_flamenco_accdb_fd_accdb_async_h
#define HEADER_fd_src_flamenco_accdb_fd_accdb_async_h

/* fd_accdb_async.h provides an asynchronous client API for the
   Firedancer account database. */

/* fd_accdb_qp_t is a 'queue pair' object. */

struct fd_accdb_qp;
typedef struct fd_accdb_qp fd_accdb_qp_t;

struct fd_accdb_wr {

  uint lthash_sub : 1;
  uint lthash_add : 1;

};

FD_PROTOTYPES_BEGIN

/* fd_accdb_req_borrow */

int
fd_accdb_req_borrow( fd_accdb_qp_t * qp );

/* fd_accdb_poll drives I/O and delivers completion events. */

void
fd_accdb_poll( fd_accdb_qp_t *       qp,
               fd_accdb_cb_t const * cb );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_accdb_fd_accdb_async_h */
