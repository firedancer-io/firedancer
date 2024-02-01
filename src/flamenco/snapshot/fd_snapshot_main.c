#define FD_SCRATCH_USE_HANDHOLDING 1
#include "fd_snapshot.h"
#include "../runtime/fd_acc_mgr.h"
#include "../runtime/context/fd_exec_epoch_ctx.h"
#include "../runtime/context/fd_exec_slot_ctx.h"
#include "../../ballet/zstd/fd_zstd.h"
#include "../../flamenco/types/fd_types.h"
#include "../../flamenco/types/fd_types_yaml.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/random.h>

/* TODO Instead of using a streaming pipeline using indirect calls, use
        a tango message-passing architecture instead.  Scales better
        across multiple cores, is more secure, faster, etc... */

/* Byte streaming API *************************************************/

/* Below is an experimental object-oriented API for handling output
   streams of data.  It is dynamically dispatched (C++ style virtual
   function tables) */

struct fd_io_istream_vt {

  /* Virtual version of fd_io_read
     Assumed to be blocking (TODO fix) */

  int
  (* read)( void *  _this,
            void *  _dst,
            ulong   dst_max,
            ulong * _dst_sz );

};

typedef struct fd_io_istream_vt fd_io_istream_vt_t;

struct fd_io_istream_obj {
  void *                     this;
  fd_io_istream_vt_t const * vt;
};

typedef struct fd_io_istream_obj fd_io_istream_obj_t;

static inline int
fd_io_istream_obj_read( fd_io_istream_obj_t * obj,
                        void *                dst,
                        ulong                 dst_max,
                        ulong *               dst_sz ) {
  return obj->vt->read( obj->this, dst, dst_max, dst_sz );
}

/* fd_io_istream_zstd_t implements fd_io_istream_vt_t. */

struct fd_io_istream_zstd {
  fd_zstd_dstream_t * dstream;  /* borrowed for lifetime of self */
  fd_io_istream_obj_t src;

# define FD_IO_ISTREAM_ZSTD_BUFSZ (8192UL)  /* should probably be configurable at runtime */
  uchar   in_buf[ FD_IO_ISTREAM_ZSTD_BUFSZ ];
  uchar * in_cur;  /* in_cur in [in_buf,in_end) */
  uchar * in_end;  /* in_end in [in_buf,in_buf+FD_IO_ISTREAM_ZSTD_BUFSZ) */

  int dirty;
};

typedef struct fd_io_istream_zstd fd_io_istream_zstd_t;

static fd_io_istream_zstd_t *
fd_io_istream_zstd_new( void *              mem,
                        fd_zstd_dstream_t * dstream,
                        fd_io_istream_obj_t src ) {
  fd_io_istream_zstd_t * this = mem;
  *this = (fd_io_istream_zstd_t){
    .dstream = dstream,
    .src     = src,
    .in_cur  = this->in_buf,
    .in_end  = this->in_buf,
    .dirty   = 0
  };
  return this;
}

static void *
fd_io_istream_zstd_delete( fd_io_istream_zstd_t * this ) {
  fd_memset( this, 0, sizeof(fd_io_istream_zstd_t) );
  return (void *)this;
}

static int
fd_io_istream_zstd_read( void *  _this,
                         void *  dst,
                         ulong   dst_max,
                         ulong * dst_sz ) {

  fd_io_istream_zstd_t * restrict this = _this;

  if( (!this->dirty) & (this->in_cur == this->in_end) ) {
    /* needs refill */
    ulong in_sz = 0UL;
    int read_err = fd_io_istream_obj_read( &this->src, this->in_buf, FD_IO_ISTREAM_ZSTD_BUFSZ, &in_sz );
    if( FD_LIKELY( read_err==0 ) ) { /* ok */ }
    else if( read_err<0 ) { /* EOF */ return 0; /* TODO handle unexpected EOF case */ }
    else {
      FD_LOG_DEBUG(( "failed to read from source (%d-%s)", read_err, fd_io_strerror( read_err ) ));
      return read_err;
    }
    this->in_cur = this->in_buf;
    this->in_end = this->in_buf + in_sz;
  }

  uchar * out     = dst;
  uchar * out_end = out + dst_max;
  int zstd_err = fd_zstd_dstream_read( this->dstream, (uchar const **)&this->in_cur, this->in_end, &out, out_end, NULL );
  if( FD_UNLIKELY( zstd_err>0 ) ) {
    FD_LOG_WARNING(( "fd_zstd_dstream_read failed" ));
    /* TODO set out pointers? */
    return EPROTO;
  }
  this->dirty = (out==out_end);

  *dst_sz = (ulong)out - (ulong)dst;
  return 0;
}

static fd_io_istream_vt_t const fd_io_istream_zstd_vt =
  { .read = fd_io_istream_zstd_read };

/* fd_io_istream_file_t implements fd_io_stream_file_t. */

struct fd_io_istream_file {
  int fd;
};

typedef struct fd_io_istream_file fd_io_istream_file_t;

static fd_io_istream_file_t *
fd_io_istream_file_new( void * mem,
                        int    fd ) {
  fd_io_istream_file_t * this = mem;
  *this = (fd_io_istream_file_t){
    .fd = fd  /* borrowed for lifetime */
  };
  return this;
}

static void *
fd_io_istream_file_delete( fd_io_istream_file_t * this ) {
  fd_memset( this, 0, sizeof(fd_io_istream_file_t) );
  return (void *)this;
}

static int
fd_io_istream_file_read( void *  _this,
                         void *  dst,
                         ulong   dst_max,
                         ulong * dst_sz ) {
  fd_io_istream_file_t * this = _this;
  return fd_io_read( this->fd, dst, 1UL, dst_max, dst_sz );
}

static fd_io_istream_vt_t const fd_io_istream_file_vt =
  { .read = fd_io_istream_file_read };

fd_io_istream_obj_t
fd_io_istream_file_virtual( fd_io_istream_file_t * this ) {
  return (fd_io_istream_obj_t){
    .this = this,
    .vt   = &fd_io_istream_file_vt
  };
}

static fd_io_istream_obj_t
fd_io_istream_zstd_virtual( fd_io_istream_zstd_t * this ) {
  return (fd_io_istream_obj_t){
    .this = this,
    .vt   = &fd_io_istream_zstd_vt
  };
}

/* fd_tar_io_reader_t reads a tar from an fd_io_istream_obj_t source. */

struct fd_tar_io_reader {
  fd_tar_reader_t *   reader;  /* borrowed for lifetime */
  fd_io_istream_obj_t src;
};

typedef struct fd_tar_io_reader fd_tar_io_reader_t;

static fd_tar_io_reader_t *
fd_tar_io_reader_new( void *              mem,
                      fd_tar_reader_t *   reader,
                      fd_io_istream_obj_t src ) {

  if( FD_UNLIKELY( !reader ) ) {
    FD_LOG_WARNING(( "NULL reader" ));
    return NULL;
  }
  if( FD_UNLIKELY( !src.vt ) ) {
    FD_LOG_WARNING(( "NULL source" ));
    return NULL;
  }

  fd_tar_io_reader_t * this = mem;
  *this = (fd_tar_io_reader_t){
    .reader = reader,
    .src    = src
  };
  return this;
}

static void *
fd_tar_io_reader_delete( fd_tar_io_reader_t * this ) {
  fd_memset( this, 0, sizeof(fd_tar_io_reader_t) );
  return (void *)this;
}

static int
fd_tar_io_reader_advance( fd_tar_io_reader_t * this ) {

  uchar buf[ 16384 ];
  ulong buf_sz = 0UL;
  int read_err = fd_io_istream_obj_read( &this->src, buf, sizeof(buf), &buf_sz );
  if( FD_LIKELY( read_err==0 ) ) { /* ok */ }
  else if( read_err<0 ) { /* EOF */ return -1; /* TODO handle unexpected EOF case */ }
  else {
    FD_LOG_WARNING(( "snapshot tar stream failed (%d-%s)", read_err, fd_io_strerror( read_err ) ));
    return read_err;
  }

  int tar_err = fd_tar_read( this->reader, buf, buf_sz );
  if( FD_UNLIKELY( tar_err>0 ) ) {
    FD_LOG_WARNING(( "snapshot tar stream failed (%d-%s)", tar_err, fd_io_strerror( tar_err ) ));
    return tar_err;
  }

  return 0;
}

/* Snapshot restore ***************************************************/

#define OSTREAM_BUFSZ (32768UL)

struct fd_snapshot_dumper {
  fd_alloc_t *   alloc;
  fd_funk_t *    funk;
  fd_acc_mgr_t * acc_mgr;

  fd_exec_epoch_ctx_t * epoch_ctx;
  fd_exec_slot_ctx_t *  slot_ctx;

  int                 snapshot_fd;
  fd_zstd_dstream_t * zstd;
  fd_tar_reader_t *   tar;

  fd_io_istream_file_t * vfile;
  fd_io_istream_zstd_t * vzstd;
  fd_tar_io_reader_t *   vtar;

  fd_snapshot_restore_t * restore;

  int                      yaml_fd;

  int                      csv_fd;
  fd_io_buffered_ostream_t csv_out;
  uchar                    csv_buf[ OSTREAM_BUFSZ ];

  int want_manifest;
  int want_accounts;
  int has_fail;
};

typedef struct fd_snapshot_dumper fd_snapshot_dumper_t;

static fd_snapshot_dumper_t *
fd_snapshot_dumper_new( void * mem ) {
  fd_snapshot_dumper_t * dumper = mem;
  *dumper = (fd_snapshot_dumper_t) {
    .snapshot_fd = -1,
    .yaml_fd     = -1,
    .csv_fd      = -1
  };
  return dumper;
}

static void *
fd_snapshot_dumper_delete( fd_snapshot_dumper_t * dumper ) {

  if( dumper->restore ) {
    fd_snapshot_restore_delete( dumper->restore );
    dumper->restore = NULL;
  }

  if( dumper->vtar ) {
    fd_tar_io_reader_delete( dumper->vtar );
    dumper->vtar = NULL;
  }

  if( dumper->vzstd ) {
    fd_io_istream_zstd_delete( dumper->vzstd );
    dumper->vzstd = NULL;
  }

  if( dumper->vfile ) {
    fd_io_istream_file_delete( dumper->vfile );
    dumper->vfile = NULL;
  }

  if( dumper->tar ) {
    fd_tar_reader_delete( dumper->tar );
    dumper->tar = NULL;
  }

  if( dumper->zstd ) {
    fd_zstd_dstream_delete( dumper->zstd );
    dumper->zstd = NULL;
  }

  if( dumper->snapshot_fd>=0 ) {
    if( FD_UNLIKELY( 0!=close( dumper->snapshot_fd ) ) )
      FD_LOG_WARNING(( "close(%d) failed (%d-%s)", dumper->snapshot_fd, errno, fd_io_strerror( errno ) ));
    dumper->snapshot_fd = -1;
  }

  if( dumper->slot_ctx ) {
    fd_exec_slot_ctx_delete( fd_exec_slot_ctx_leave( dumper->slot_ctx ) );
    dumper->slot_ctx = NULL;
  }

  if( dumper->epoch_ctx ) {
    fd_exec_epoch_ctx_delete( fd_exec_epoch_ctx_leave( dumper->epoch_ctx ) );
    dumper->epoch_ctx = NULL;
  }

  if( dumper->acc_mgr ) {
    fd_acc_mgr_delete( dumper->acc_mgr );
    dumper->acc_mgr = NULL;
  }

  if( dumper->funk ) {
    fd_wksp_free_laddr( fd_funk_delete( fd_funk_leave( dumper->funk ) ) );
    dumper->funk = NULL;
  }

  if( dumper->alloc ) {
    fd_wksp_free_laddr( fd_alloc_delete( fd_alloc_leave( dumper->alloc ) ) );
    dumper->alloc = NULL;
  }

  if( dumper->yaml_fd>=0 ) {
    if( FD_UNLIKELY( 0!=close( dumper->yaml_fd ) ) )
      FD_LOG_WARNING(( "close(%d) failed (%d-%s)", dumper->yaml_fd, errno, fd_io_strerror( errno ) ));
    dumper->yaml_fd = -1;
  }

  if( dumper->csv_fd>=0 ) {
    fd_io_buffered_ostream_fini( &dumper->csv_out );
    if( FD_UNLIKELY( 0!=close( dumper->csv_fd ) ) )
      FD_LOG_WARNING(( "close(%d) failed (%d-%s)", dumper->csv_fd, errno, fd_io_strerror( errno ) ));
    dumper->csv_fd = -1;
  }

  fd_memset( dumper, 0, sizeof(fd_snapshot_dumper_t) );
  return dumper;
}

/* fd_snapshot_dumper_on_manifest gets called when the snapshot manifest
   becomes available. */

static void
fd_snapshot_dumper_on_manifest( void *                 _d,
                                fd_solana_manifest_t * manifest ) {

  fd_snapshot_dumper_t * d = _d;
  if( d->yaml_fd<0 ) return;
  d->want_manifest = 0;

  FILE * file = fdopen( d->yaml_fd, "w" );
  if( FD_UNLIKELY( !file ) ) {
    FD_LOG_WARNING(( "fdopen(%d) failed (%d-%s)", d->yaml_fd, errno, fd_io_strerror( errno ) ));
    close( d->yaml_fd );
    d->yaml_fd  = -1;
    d->has_fail = 1;
    return;
  }

  fd_scratch_push();
  fd_flamenco_yaml_t * yaml = fd_flamenco_yaml_init( fd_flamenco_yaml_new( fd_scratch_alloc( fd_flamenco_yaml_align(), fd_flamenco_yaml_footprint() ) ), file );
  fd_solana_manifest_walk( yaml, manifest, fd_flamenco_yaml_walk, NULL, 0U );
  fd_flamenco_yaml_delete( yaml );
  fd_scratch_pop();

  int err = 0;
  if( FD_UNLIKELY( (err = ferror( file )) ) ) {
    FD_LOG_WARNING(( "Error occurred while writing manifest (%d-%s)", err, fd_io_strerror( err ) ));
    d->has_fail = 1;
  }

  fclose( file );
  close( d->yaml_fd );
  d->yaml_fd = -1;
}

/* fd_snapshot_dumper_prepare creates a new funk transaction ready to
   collect any accounts newly inserted by the snapshot loader.  Unlike
   in a real database, these accounts get discarded very frequently
   during unpack. */

static void
fd_snapshot_dumper_prepare( fd_snapshot_dumper_t * d ) {
  fd_exec_slot_ctx_t * slot_ctx = d->slot_ctx;

  fd_funk_txn_xid_t funk_txn_xid = { .ul = { 1UL } };
  fd_funk_txn_t * funk_txn = fd_funk_txn_prepare( d->funk, NULL, &funk_txn_xid, 1 );
  if( FD_UNLIKELY( !funk_txn ) )
    FD_LOG_ERR(( "Failed to create funk txn" ));  /* unreachable, as there will only ever be one live funk txn */

  slot_ctx->funk_txn = funk_txn;
}

/* fd_snapshot_dumper_record processes a newly encountered account
   record. */

union fd_snapshot_csv_rec {
  char line[ 180 ];
  struct __attribute__((packed)) {
    char acct_addr[ FD_BASE58_ENCODED_32_LEN ];
    char comma1;
    char owner_addr[ FD_BASE58_ENCODED_32_LEN ];
    char comma2;
    char hash[ FD_BASE58_ENCODED_32_LEN ];
    char comma3;
    char slot[ 14 ];  /* enough for 10000 years at 400ms slot time */
    char comma4;
    char size[ 8 ];  /* can represent [0,10<<20) */
    char comma5;
    char lamports[ 20 ];  /* can represent [0,1<<64) */
    char newline;
  };
};

typedef union fd_snapshot_csv_rec fd_snapshot_csv_rec_t;

static void
fd_snapshot_dumper_record( fd_snapshot_dumper_t * d,
                           fd_funk_rec_t const *  rec,
                           fd_wksp_t *            wksp ) {

  uchar const *             rec_val = fd_funk_val_const( rec, wksp );
  fd_account_meta_t const * meta    = (fd_account_meta_t const *)rec_val;
  //uchar const *             data    = rec_val + meta->hlen;

  if( d->csv_fd>=0 ) {
    fd_snapshot_csv_rec_t csv_rec;
    fd_memset( &csv_rec, ' ', sizeof(csv_rec) );

    ulong b58sz;
    fd_base58_encode_32( fd_funk_key_to_acc( rec->pair.key )->uc, &b58sz, csv_rec.acct_addr );
    csv_rec.line[ offsetof(fd_snapshot_csv_rec_t,acct_addr)+b58sz ] = ' ';
    csv_rec.comma1 = ',';

    fd_base58_encode_32( meta->info.owner, &b58sz, csv_rec.owner_addr );
    csv_rec.line[ offsetof(fd_snapshot_csv_rec_t,owner_addr)+b58sz ] = ' ';
    csv_rec.comma2 = ',';

    fd_base58_encode_32( meta->hash, &b58sz, csv_rec.hash );
    csv_rec.line[ offsetof(fd_snapshot_csv_rec_t,hash)+b58sz ] = ' ';
    csv_rec.comma3 = ',';

    fd_cstr_append_ulong_as_text( csv_rec.slot, ' ', '\0', meta->dlen, 15 );
    csv_rec.comma4 = ',';

    fd_cstr_append_ulong_as_text( csv_rec.size, ' ', '\0', meta->dlen, 8 );
    csv_rec.comma5 = ',';

    fd_cstr_append_ulong_as_text( csv_rec.lamports, ' ', '\0', meta->info.lamports, 20 );
    csv_rec.newline = '\n';

    fd_io_buffered_ostream_write( &d->csv_out, csv_rec.line, sizeof(csv_rec.line) );
  }
}

/* fd_snapshot_dumper_release visits any newly appeared accounts and
   removes their records from the database. */

static int
fd_snapshot_dumper_release( fd_snapshot_dumper_t * d ) {

  fd_exec_slot_ctx_t * slot_ctx = d->slot_ctx;
  fd_funk_txn_t *      funk_txn = slot_ctx->funk_txn;
  fd_funk_t *          funk     = d->funk;
  fd_wksp_t *          wksp     = fd_funk_wksp( funk );
  fd_funk_rec_t *      rec_map  = fd_funk_rec_map( funk, wksp );

  for( fd_funk_rec_t const * rec = fd_funk_txn_rec_head( funk_txn, rec_map );
                             rec;
                             rec = fd_funk_rec_next( rec, rec_map ) ) {
    if( FD_UNLIKELY( !fd_funk_key_is_acc( rec->pair.key ) ) ) continue;
    fd_snapshot_dumper_record( d, rec, wksp );
  }

  if( FD_UNLIKELY( fd_funk_txn_cancel( funk, funk_txn, 1 )!=1UL ) )
    FD_LOG_ERR(( "Failed to cancel funk txn" ));  /* unreachable */
  slot_ctx->funk_txn = NULL;

  return 0;
}

/* fd_snapshot_dumper_advance polls the tar reader for data and handles
   any newly appeared accounts. */

static int
fd_snapshot_dumper_advance( fd_snapshot_dumper_t * dumper ) {

  fd_tar_io_reader_t * vtar = dumper->vtar;

  fd_snapshot_dumper_prepare( dumper );

  int untar_err = fd_tar_io_reader_advance( vtar );
  if( untar_err==0 ) { /* ok */ }
  else if( untar_err<0 ) { /* EOF */ return -1; }
  else {
    FD_LOG_WARNING(( "Failed to load snapshot (%d-%s)", untar_err, fd_io_strerror( untar_err ) ));
    return untar_err;
  }

  int collect_err = fd_snapshot_dumper_release( dumper );
  if( FD_UNLIKELY( collect_err ) ) return collect_err;

  return 0;
}

/* fd_snapshot_dump_args_t contains the command-line arguments for the
   dump command. */

struct fd_snapshot_dump_args {
  char const * _page_sz;
  ulong        page_cnt;
  ulong        manifest_max;
  ulong        near_cpu;
  ulong        zstd_window_sz;
  char const * snapshot;
  char const * manifest_path;
  char const * csv_path;
  int          csv_hdr;
};

typedef struct fd_snapshot_dump_args fd_snapshot_dump_args_t;

static int
do_dump( fd_snapshot_dumper_t *    d,
         fd_snapshot_dump_args_t * args,
         fd_wksp_t *               wksp ) {

  /* Create a heap */

  ulong const fd_alloc_tag = 41UL;
  d->alloc = fd_alloc_join( fd_alloc_new( fd_wksp_alloc_laddr( wksp, fd_alloc_align(), fd_alloc_footprint(), fd_alloc_tag ), fd_alloc_tag ), 0UL );
  if( FD_UNLIKELY( !d->alloc ) ) { FD_LOG_WARNING(( "fd_alloc_join() failed" )); return EXIT_FAILURE; }

  fd_wksp_usage_t wksp_usage[1] = {0};
  fd_wksp_usage( wksp, NULL, 0UL, wksp_usage );

  int snapshot_fd = open( args->snapshot, O_RDONLY );
  if( FD_UNLIKELY( snapshot_fd<0 ) ) { FD_LOG_WARNING(( "open(%s) failed (%d-%s)", args->snapshot, errno, fd_io_strerror( errno ) )); return EXIT_FAILURE; }

  if( args->csv_path ) {
    d->csv_fd = open( args->csv_path, O_WRONLY|O_CREAT|O_TRUNC, 0644 );
    if( FD_UNLIKELY( d->csv_fd<0 ) ) { FD_LOG_WARNING(( "open(%s) failed (%d-%s)", args->csv_path, errno, fd_io_strerror( errno ) )); return EXIT_FAILURE; }
    fd_io_buffered_ostream_init( &d->csv_out, d->csv_fd, d->csv_buf, OSTREAM_BUFSZ );
  }

  if( args->manifest_path ) {
    d->yaml_fd = open( args->manifest_path, O_WRONLY|O_CREAT|O_TRUNC, 0644 );
    if( FD_UNLIKELY( d->yaml_fd<0 ) ) { FD_LOG_WARNING(( "open(%s) failed (%d-%s)", args->manifest_path, errno, fd_io_strerror( errno ) )); return EXIT_FAILURE; }
  }

  /* Create a high-quality hash seed for fd_funk */

  ulong funk_seed;
  if( FD_UNLIKELY( sizeof(ulong)!=getrandom( &funk_seed, sizeof(ulong), 0 ) ) )
    { FD_LOG_WARNING(( "getrandom() failed (%d-%s)", errno, fd_io_strerror( errno ) )); return EXIT_FAILURE; }

  /* Create a funk database */

  ulong const txn_max =   16UL;  /* we really only need 1 */
  ulong const rec_max = 1024UL;  /* we evict records as we go */

  ulong funk_tag = 42UL;
  d->funk = fd_funk_join( fd_funk_new( fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_footprint(), funk_tag ), funk_tag, funk_seed, txn_max, rec_max ) );
  if( FD_UNLIKELY( !d->funk ) ) { FD_LOG_WARNING(( "Failed to create fd_funk_t" )); return EXIT_FAILURE; }

  /* Create a new processing context */

  d->acc_mgr = fd_acc_mgr_new( fd_scratch_alloc( FD_ACC_MGR_ALIGN, FD_ACC_MGR_FOOTPRINT ), d->funk );
  if( FD_UNLIKELY( !d->acc_mgr ) ) { FD_LOG_WARNING(( "Failed to create fd_acc_mgr_t" )); return EXIT_FAILURE; }

  d->epoch_ctx = fd_exec_epoch_ctx_join( fd_exec_epoch_ctx_new( fd_scratch_alloc( FD_EXEC_EPOCH_CTX_ALIGN, FD_EXEC_EPOCH_CTX_FOOTPRINT ) ) );
  if( FD_UNLIKELY( !d->epoch_ctx ) ) { FD_LOG_WARNING(( "Failed to create fd_exec_epoch_ctx_t" )); return EXIT_FAILURE; }

  d->slot_ctx = fd_exec_slot_ctx_join( fd_exec_slot_ctx_new( fd_scratch_alloc( FD_EXEC_SLOT_CTX_ALIGN, FD_EXEC_SLOT_CTX_FOOTPRINT ) ) );
  if( FD_UNLIKELY( !d->slot_ctx ) ) { FD_LOG_WARNING(( "Failed to create fd_exec_slot_ctx_t" )); return EXIT_FAILURE; }

  d->epoch_ctx->valloc = fd_alloc_virtual( d->alloc );
  d->slot_ctx ->valloc = fd_alloc_virtual( d->alloc );
  d->slot_ctx ->acc_mgr   = d->acc_mgr;
  d->slot_ctx ->epoch_ctx = d->epoch_ctx;

  void * restore_mem = fd_scratch_alloc( fd_snapshot_restore_align(), fd_snapshot_restore_footprint() );
  if( FD_UNLIKELY( !restore_mem ) ) FD_LOG_ERR(( "Failed to allocate restore buffer" ));  /* unreachable */

  /* Set up the snapshot reader */

  uchar * file_buf = fd_scratch_alloc( 1UL, args->manifest_max );
  d->restore = fd_snapshot_restore_new( restore_mem, d->slot_ctx, file_buf, args->manifest_max );
  if( FD_UNLIKELY( !d->restore ) ) { FD_LOG_WARNING(( "Failed to create fd_snapshot_restore_t" )); return EXIT_FAILURE; }
  fd_snapshot_restore_set_cb_manifest( d->restore, fd_snapshot_dumper_on_manifest, d );

  d->tar = fd_tar_reader_new( fd_scratch_alloc( alignof(fd_tar_reader_t), sizeof(fd_tar_reader_t) ), &fd_snapshot_restore_tar_vt, d->restore );
  if( FD_UNLIKELY( !d->tar ) ) { FD_LOG_WARNING(( "Failed to create fd_tar_reader_t" )); return EXIT_FAILURE; }

  uchar * zstd_mem = fd_scratch_alloc( fd_zstd_dstream_align(), fd_zstd_dstream_footprint( args->zstd_window_sz ) );
  d->zstd = fd_zstd_dstream_new( zstd_mem, args->zstd_window_sz );
  if( FD_UNLIKELY( !d->zstd ) ) { FD_LOG_WARNING(( "Failed to create fd_zstd_dstream_t" )); return EXIT_FAILURE; }

  d->vfile = fd_io_istream_file_new( fd_scratch_alloc( alignof(fd_io_istream_file_t), sizeof(fd_io_istream_file_t) ), snapshot_fd );
  if( FD_UNLIKELY( !d->vfile ) ) { FD_LOG_WARNING(( "Failed to create fd_io_istream_file_t" )); return EXIT_FAILURE; }

  d->vzstd = fd_io_istream_zstd_new( fd_scratch_alloc( alignof(fd_io_istream_zstd_t), sizeof(fd_io_istream_zstd_t) ), d->zstd, fd_io_istream_file_virtual( d->vfile ) );
  if( FD_UNLIKELY( !d->vzstd ) ) { FD_LOG_WARNING(( "Failed to create fd_io_istream_zstd_t" )); return EXIT_FAILURE; }

  d->vtar = fd_tar_io_reader_new( fd_scratch_alloc( alignof(fd_tar_io_reader_t), sizeof(fd_tar_io_reader_t) ), d->tar, fd_io_istream_zstd_virtual( d->vzstd ) );
  if( FD_UNLIKELY( !d->vtar ) ) { FD_LOG_WARNING(( "Failed to create fd_tar_io_reader_t" )); return EXIT_FAILURE; }

  d->want_manifest = (!!args->manifest_path);
  d->want_accounts = (!!args->csv_path);

  if( FD_UNLIKELY( (!d->want_manifest) & (!d->want_accounts) ) ) {
    FD_LOG_NOTICE(( "Nothing to do, exiting." ));
    return EXIT_SUCCESS;
  }

  if( (d->csv_fd>=0) & (args->csv_hdr) ) {
    fd_snapshot_csv_rec_t csv_rec;
    memset( &csv_rec, ' ', sizeof(fd_snapshot_csv_rec_t) );
    memcpy( csv_rec.acct_addr,  "address",  strlen( "address"  ) );
    memcpy( csv_rec.owner_addr, "owner",    strlen( "owner"    ) );
    memcpy( csv_rec.hash,       "hash",     strlen( "hash"     ) );
    memcpy( csv_rec.slot,       "slot",     strlen( "slot"     ) );
    memcpy( csv_rec.size,       "size",     strlen( "size"     ) );
    memcpy( csv_rec.lamports,   "lamports", strlen( "lamports" ) );
    csv_rec.comma1  = ',';
    csv_rec.comma2  = ',';
    csv_rec.comma3  = ',';
    csv_rec.comma4  = ',';
    csv_rec.comma5  = ',';
    csv_rec.newline = '\n';

    if( FD_UNLIKELY( write( d->csv_fd, csv_rec.line, sizeof(fd_snapshot_csv_rec_t) )
                     != sizeof(fd_snapshot_csv_rec_t) ) ) {
      FD_LOG_WARNING(( "Failed to write CSV header (%d-%s)", errno, fd_io_strerror( errno ) ));
      d->has_fail = 1;
      return EXIT_FAILURE;
    }
  }

  for(;;) {
    int err = fd_snapshot_dumper_advance( d );
    if( err==0 ) { /* ok */ }
    else if( err<0 ) { /* EOF */ break; }
    else {
      FD_LOG_WARNING(( "Failed to load snapshot" ));
      return EXIT_FAILURE;
    }

    if( FD_UNLIKELY( (!d->want_accounts) & (!d->want_manifest) ) )
      break;
  }

  return d->has_fail ? EXIT_FAILURE : EXIT_SUCCESS;
}

int
cmd_dump( int     argc,
          char ** argv ) {

  fd_snapshot_dump_args_t args[1] = {{0}};
  args->_page_sz       = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",        NULL,      "gigantic" );
  args->page_cnt       = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",       NULL,             8UL );
  args->manifest_max   = fd_env_strip_cmdline_ulong( &argc, &argv, "--manifest-max",   NULL,         1UL<<30 );  /* 1 GiB */
  args->near_cpu       = fd_env_strip_cmdline_ulong( &argc, &argv, "--near-cpu",       NULL, fd_log_cpu_id() );
  args->zstd_window_sz = fd_env_strip_cmdline_ulong( &argc, &argv, "--zstd-window-sz", NULL,      33554432UL );
  args->snapshot       = fd_env_strip_cmdline_cstr ( &argc, &argv, "--snapshot",       NULL,            NULL );
  args->manifest_path  = fd_env_strip_cmdline_cstr ( &argc, &argv, "--manifest",       NULL,            NULL );
  args->csv_path       = fd_env_strip_cmdline_cstr ( &argc, &argv, "--csv",            NULL,            NULL );
  args->csv_hdr        = fd_env_strip_cmdline_int  ( &argc, &argv, "--csv-hdr",        NULL,               1 );

  if( FD_UNLIKELY( argc!=1 ) )
    FD_LOG_ERR(( "Unexpected command-line arguments" ));
  if( FD_UNLIKELY( !args->snapshot ) )
    FD_LOG_ERR(( "Missing --snapshot argument" ));

  FD_LOG_NOTICE(( "Creating workspace (--page-cnt %lu, --page-sz %s)", args->page_cnt, args->_page_sz ));

  /* With workspace */

  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( args->_page_sz ), args->page_cnt, args->near_cpu, "wksp", 0UL );
  if( FD_UNLIKELY( !wksp ) ) FD_LOG_ERR(( "fd_wksp_new_anonymous() failed" ));

  /* With scratch */

  ulong smax = args->manifest_max + args->zstd_window_sz + (1<<29);  /* manifest plus 512 MiB headroom */
  FD_LOG_INFO(( "Using %.2f MiB scratch space", (double)smax/(1<<20) ));
  uchar * smem = fd_wksp_alloc_laddr( wksp, FD_SCRATCH_SMEM_ALIGN, smax, 1UL );
  if( FD_UNLIKELY( !smem ) ) FD_LOG_ERR(( "fd_wksp_alloc_laddr for scratch region of size %lu failed", smax ));
  ulong fmem[16];
  fd_scratch_attach( smem, fmem, smax, 16UL );
  fd_scratch_push();

  /* With dump context */

  fd_snapshot_dumper_t  _dumper[1];
  fd_snapshot_dumper_t * dumper = fd_snapshot_dumper_new( _dumper );

  int rc = do_dump( dumper, args, wksp );
  FD_LOG_INFO(( "Done. Cleaning up." ));

  fd_snapshot_dumper_delete( dumper );

  fd_scratch_pop();
  fd_scratch_detach( NULL );
  fd_wksp_delete_anonymous( wksp );
  return rc;
}

FD_IMPORT_CSTR( _help, "src/flamenco/snapshot/fd_snapshot_help.txt" );

__attribute__((noreturn)) static int
usage( int code ) {
  fwrite( _help, 1, _help_sz, stderr );
  fflush( stderr );
  exit( code );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  if( argc==1 ) return usage(1);
  if( 0==strcmp( argv[1], "help" ) ) return usage(0);
  for( int i=1; i<argc; i++ )
    if( 0==strcmp( argv[i], "--help" ) )
      return usage(0);

  argc--; argv++;
  char const * cmd = argv[0];

  if( 0==strcmp( cmd, "dump" ) ) {
    return cmd_dump( argc, argv );
  } else {
    fprintf( stderr, "Unknown command: %s\n", cmd );
    return usage(1);
  }

  fd_halt();
  return 0;
}
