#ifndef HEADER_fd_src_app_fdctl_run_tiles_h
#define HEADER_fd_src_app_fdctl_run_tiles_h

#include "../../fdctl.h"

#include "../../../../disco/mux/fd_mux.h"
#include "../../../../disco/shred/fd_shredder.h"
#include "../../../../ballet/shred/fd_shred.h"
#include "../../../../ballet/pack/fd_pack.h"

#include <linux/filter.h>

/* fd_shred34 is a collection of up to 34 shreds batched in a way that's
   convenient for use in a dcache and for access from Rust. The limit of
   34 comes so that sizeof( fd_shred34_t ) < USHORT_MAX. */

struct __attribute__((aligned(FD_CHUNK_ALIGN))) fd_shred34 {
  ulong shred_cnt;
  ulong stride;
  ulong offset;
  ulong shred_sz; /* The size of each shred */
  /* For i in [0, shred_cnt), shred i's payload spans bytes
     [i*stride+offset, i*stride+offset+shred_sz ), counting from the
     start of the struct, not this point. */
  union {
    fd_shred_t shred;
    uchar      buffer[ FD_SHRED_MAX_SZ ];
  } pkts[ 34 ];
};
typedef struct fd_shred34 fd_shred34_t;

struct fd_became_leader {
  /* Start time of the slot in nanoseconds. */
  long   slot_start_ns;

  /* An opaque pointer to a Rust Arc<Bank> object, which should only
     be used with fd_ext_* functions to execute transactions or drop
     the bank.  The ownership is complicated, but basically any bank
     tile that receives this frag has a strong refcnt to the bank and
     should release it when done, other tiles should ignore and never
     use the bank. */
  void const * bank;
};
typedef struct fd_became_leader fd_became_leader_t;

struct fd_microblock_trailer {
  /* A *const SanitizedTransation pointer, created by the bank which
     the PoH tile should use to commit the transactions.  This is a
     Rust ABI compatible array of SanitizedTransaction-s.  It is not
     heap allocated and should not be freed.  It lives in workspace
     memory for the bank tile that sent the microblock.  The bank
     tile promises it won't reclaim this memory until the PoH tile
     indicates it's done, by pushing a busy sequence number greater
     or equal to the busy_seq given below. */
  void * abi_txns;

  /* Opaque pointer to Rust Box<LoadAndExecuteOutput> object, created
     by the bank before executing the microblock.  Ownership belongs
     to the PoH tile when it receives the microblock, and it will
     need to be freed. */
  void * load_and_execute_output;

  /* Opaque pointer to Rust Box<PreBalanceInfo> object, created by
     the bank before executing the microblock.  Ownership belongs
     to the PoH tile when it receives the microblock, and it will
     need to be freed. */
  void * pre_balance_info;

  /* The sequence number of the mcache frag that this microblock was
     sent from pack to bank with.  This is the sequence number we
     need to report back in the bank busy fseq to tell the bank that
     the transactions have been committed and the relevant accounts
     can now be reused. */
  ulong  busy_seq;
};
typedef struct fd_microblock_trailer fd_microblock_trailer_t;

typedef struct {
  ulong                         mux_flags;
  ulong                         burst;
  ulong                         rlimit_file_cnt;
  void * (*mux_ctx           )( void * scratch );

  fd_mux_during_housekeeping_fn * mux_during_housekeeping;
  fd_mux_before_credit_fn       * mux_before_credit;
  fd_mux_after_credit_fn        * mux_after_credit;
  fd_mux_before_frag_fn         * mux_before_frag;
  fd_mux_during_frag_fn         * mux_during_frag;
  fd_mux_after_frag_fn          * mux_after_frag;
  fd_mux_metrics_write_fn       * mux_metrics_write;

  long  (*lazy                    )( fd_topo_tile_t * tile );
  ulong (*populate_allowed_seccomp)( void * scratch, ulong out_cnt, struct sock_filter * out );
  ulong (*populate_allowed_fds    )( void * scratch, ulong out_fds_sz, int * out_fds );
  ulong (*loose_footprint         )( fd_topo_tile_t * tile );
  ulong (*scratch_align           )( void );
  ulong (*scratch_footprint       )( fd_topo_tile_t * tile );
  void  (*privileged_init         )( fd_topo_t * topo, fd_topo_tile_t * tile, void * scratch );
  void  (*unprivileged_init       )( fd_topo_t * topo, fd_topo_tile_t * tile, void * scratch );
} fd_tile_config_t;

FD_FN_CONST fd_tile_config_t *
fd_topo_tile_to_config( fd_topo_tile_t * tile );

extern fd_tile_config_t fd_tile_net;
extern fd_tile_config_t fd_tile_netmux;
extern fd_tile_config_t fd_tile_quic;
extern fd_tile_config_t fd_tile_verify;
extern fd_tile_config_t fd_tile_dedup;
extern fd_tile_config_t fd_tile_pack;
extern fd_tile_config_t fd_tile_bank;
extern fd_tile_config_t fd_tile_poh;
extern fd_tile_config_t fd_tile_shred;
extern fd_tile_config_t fd_tile_store;
extern fd_tile_config_t fd_tile_sign;
extern fd_tile_config_t fd_tile_metric;
extern fd_tile_config_t fd_tile_tvu;

void *
fd_wksp_pod_map1( uchar const * pod,
                  char const *  format,
                  ... );

int
fd_tvu_tile( fd_cnc_t *              cnc,
             ulong                   flags,
             ulong                   in_cnt,
             fd_frag_meta_t const ** in_mcache,
             ulong **                in_fseq,
             fd_frag_meta_t *        mcache,
             ulong                   out_cnt,
             ulong **                _out_fseq,
             ulong                   burst,
             ulong                   cr_max,
             long                    lazy,
             fd_rng_t *              rng,
             void *                  scratch,
             void *                  ctx,
             fd_mux_callbacks_t *    callbacks );

#endif /* HEADER_fd_src_app_fdctl_run_tiles_h */
