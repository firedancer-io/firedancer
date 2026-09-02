#include "fd_progcache.h"
#include "fd_progcache_clock.h"
#include "../../util/racesan/fd_racesan_target.h"
#include "../vm/fd_vm.h" /* fd_vm_syscall_register_slot, fd_vm_validate */

/* A free record is always write-locked: pop/push moves the lock between 0xFFFF
   (free) and 1 (read-locked by the acquirer), so a stale speculative reader can
   never lock a free record. */

/* rec_init_inflight turns a write-locked record of class c into an in-flight
   one owned by the caller.  Callers hold the write lock and have the record
   out of the map, so no other thread can observe the intermediate state. */

static fd_progcache_rec_t *
rec_init_inflight( fd_progcache_join_t * join,
                   ulong                 idx,
                   ulong                 c ) {
  fd_progcache_shmem_t * pc  = join->shmem;
  fd_progcache_rec_t *   rec = join->rec.ele + idx;

  /* Two spans so the lock is skipped: the record is write-locked, and a stale
     speculative reader must never see that clear.  state is skipped with it and
     cleared below. */
  memset( rec, 0, offsetof(fd_progcache_rec_t, lock) );
  memset( &rec->txn_idx, 0, sizeof(fd_progcache_rec_t)-offsetof(fd_progcache_rec_t, txn_idx) );
  rec->exists       = 1;
  rec->size_class   = c & 0x7UL; /* c<FD_PROGCACHE_CACHE_CLASS_CNT, checked by callers */
  rec->txn_idx      = UINT_MAX;
  rec->calldests_off = UINT_MAX;

  /* Attach value storage: the record's own arena slot */
  ulong slot_sz   = fd_progcache_cache_slot_sz[ c ];
  rec->data_gaddr = pc->cache.arena_gaddr[ c ] + (ulong)( idx - pc->cache.rec_base[ c ] )*slot_sz;
  rec->data_max   = (uint)slot_sz;

  fd_prog_state_clear( join->rec.ele, idx );
  atomic_store_explicit( &rec->lock.value, (ushort)1, memory_order_release ); /* write-locked -> read-locked by caller */
  return rec;
}

/* free_push returns record idx to class c's free list.  free_pop takes one, or
   returns UINT_MAX when the class is full.  Both are lock-free: the link lives in
   the record being moved, which no other thread can be touching, so there is no
   shared slot to race on, and the version in the top word defeats ABA. */

static void
free_push( fd_progcache_join_t * join,
           ulong                 c,
           ulong                 idx ) {
  fd_progcache_shmem_t * pc  = join->shmem;
  fd_progcache_rec_t *   rec = join->rec.ele + idx;
  for(;;) {
    ulong old_vt  = FD_VOLATILE_CONST( pc->cache.free_top[ c ].ver_top );
    uint  old_top = (uint)( old_vt & (ulong)UINT_MAX );
    uint  old_ver = (uint)( old_vt >> 32 );
    rec->free_next = old_top;
    FD_COMPILER_MFENCE();
    ulong new_vt = ( (ulong)(uint)( old_ver+1U ) << 32 ) | (ulong)(uint)idx;
    if( FD_LIKELY( __atomic_compare_exchange_n( &pc->cache.free_top[ c ].ver_top, &old_vt, new_vt,
                                                0, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED ) ) ) {
      __atomic_fetch_add( &pc->cache.free_cnt[ c ].val, 1UL, __ATOMIC_RELAXED );
      return;
    }
    fd_racesan_hook( "prog_free_push:cas_retry" );
    FD_SPIN_PAUSE();
  }
}

static uint
free_pop( fd_progcache_join_t * join,
          ulong                 c ) {
  fd_progcache_shmem_t * pc = join->shmem;
  for(;;) {
    ulong old_vt  = FD_VOLATILE_CONST( pc->cache.free_top[ c ].ver_top );
    uint  old_top = (uint)( old_vt & (ulong)UINT_MAX );
    if( FD_UNLIKELY( old_top==UINT_MAX ) ) return UINT_MAX; /* class full */
    uint  old_ver = (uint)( old_vt >> 32 );
    uint  next    = FD_VOLATILE_CONST( join->rec.ele[ old_top ].free_next );
    ulong new_vt  = ( (ulong)(uint)( old_ver+1U ) << 32 ) | (ulong)next;
    if( FD_LIKELY( __atomic_compare_exchange_n( &pc->cache.free_top[ c ].ver_top, &old_vt, new_vt,
                                                0, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED ) ) ) {
      __atomic_fetch_sub( &pc->cache.free_cnt[ c ].val, 1UL, __ATOMIC_RELAXED );
      return old_top;
    }
    fd_racesan_hook( "prog_free_pop:cas_retry" );
    FD_SPIN_PAUSE();
  }
}

fd_progcache_rec_t *
fd_progcache_rec_acquire( fd_progcache_join_t * join,
                          ulong                 val_footprint ) {
  ulong c = fd_progcache_cache_class( val_footprint );
  FD_TEST( c<FD_PROGCACHE_CACHE_CLASS_CNT );

  /* Pop a free record from the class fitting val_footprint. */
  uint idx = free_pop( join, c );
  if( FD_UNLIKELY( idx==UINT_MAX ) ) return NULL; /* class full */

  return rec_init_inflight( join, idx, c );
}

fd_progcache_rec_t *
fd_progcache_rec_reinit( fd_progcache_join_t * join,
                         fd_progcache_rec_t *  rec ) {
  return rec_init_inflight( join, (ulong)( rec - join->rec.ele ), rec->size_class );
}

void
fd_progcache_rec_release( fd_progcache_join_t * join,
                          fd_progcache_rec_t *  rec ) {
  ulong idx = (ulong)( rec - join->rec.ele );
  ulong c   = rec->size_class;

  rec->exists     = 0;
  rec->data_gaddr = 0UL;
  rec->data_max   = 0U;
  /* lock stays write-locked (the free-record invariant) */

  fd_prog_state_clear( join->rec.ele, idx );
  free_push( join, c, idx );
}

void
fd_progcache_rec_abandon( fd_progcache_join_t * join,
                          fd_progcache_rec_t *  rec ) {
  /* Never in the map, so no new reader can find it, but a stale reader of a
     previous incarnation may hold a transient tryread: trade our read lock for
     the write lock to drain them. */
  fd_rwlock_unread( &rec->lock );
  while( FD_UNLIKELY( !fd_rwlock_trywrite( &rec->lock ) ) ) FD_SPIN_PAUSE();
  fd_progcache_rec_release( join, rec );
}

FD_FN_PURE ulong
fd_progcache_val_footprint( fd_sbpf_elf_info_t const * elf_info ) {
  int   has_calldests = !fd_sbpf_enable_stricter_elf_headers_enabled( elf_info->sbpf_version );
  ulong pc_max        = fd_ulong_max( 1UL, elf_info->text_cnt );

  /* load_buf_sz is the exact buffer the loader needs (peek-computed):
     text_off+text_sz for strict, the rodata image for lenient-fast, or bin_sz
     for legacy lenient. */
  ulong l = FD_LAYOUT_INIT;
  if( has_calldests ) {
    l = FD_LAYOUT_APPEND( l, fd_sbpf_calldests_align(), fd_sbpf_calldests_footprint( pc_max ) );
  }
  l = FD_LAYOUT_APPEND( l, 8UL, elf_info->load_buf_sz );
  return FD_LAYOUT_FINI( l, fd_progcache_val_align() );
}

/* Program loader wrapper */

fd_progcache_rec_t *
fd_progcache_rec_load( fd_progcache_rec_t *            rec,
                       fd_wksp_t *                     wksp,
                       fd_sbpf_elf_info_t const *      elf_info,
                       fd_sbpf_loader_config_t const * config,
                       ulong                           load_slot,
                       fd_features_t const *           features,
                       void const *                    progdata,
                       ulong                           progdata_sz,
                       void *                          scratch,
                       ulong                           scratch_sz ) {

  /* Format object */

  int has_calldests = !fd_sbpf_enable_stricter_elf_headers_enabled( elf_info->sbpf_version );

  void * val           = fd_wksp_laddr_fast( wksp, rec->data_gaddr );
  void * calldests_mem = NULL;
  void * rodata_mem;
  if( has_calldests ) {
    /* Lenient (v0-v2): [ calldests | rodata ] laid out inside val.  The rodata
       buffer is load_buf_sz (rodata image on the fast path, bin_sz on the
       legacy path); must match fd_progcache_val_footprint. */
    FD_SCRATCH_ALLOC_INIT( l, val );
    calldests_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_sbpf_calldests_align(), fd_sbpf_calldests_footprint( fd_ulong_max( 1UL, elf_info->text_cnt ) ) );
    rodata_mem    = FD_SCRATCH_ALLOC_APPEND( l, 8UL, elf_info->load_buf_sz );
    FD_SCRATCH_ALLOC_FINI( l, fd_progcache_val_align() );
    FD_TEST( _l-(ulong)val == fd_progcache_val_footprint( elf_info ) );
  } else {
    /* Strict (v3+): no calldests, so rodata is just the start of val
       (val is fd_progcache_val_align()-aligned, which is >= 8). */
    rodata_mem = val;
  }

  rec->calldests_off = has_calldests ? (uint)( (ulong)calldests_mem - (ulong)val ) : UINT_MAX;
  rec->rodata_off    = (uint)( (ulong)rodata_mem - (ulong)val );
  rec->entry_pc      = 0;
  rec->rodata_sz     = 0;

  rec->text_cnt      = elf_info->text_cnt;
  rec->text_off      = elf_info->text_off;
  rec->text_sz       = (uint)elf_info->text_sz;
  rec->sbpf_version  = (uchar)elf_info->sbpf_version;

  /* Set up sbpf_loader (redirect writes into progcache_rec object) */

  fd_sbpf_program_t prog[1] = {{
    .info     = *elf_info,
    .rodata   = rodata_mem,
    .text     = (ulong *)((ulong)rodata_mem + elf_info->text_off), /* FIXME: WHAT IF MISALIGNED */
    .entry_pc = ULONG_MAX
  }};
  if( has_calldests && elf_info->text_cnt>0UL ) {
    prog->calldests_shmem = calldests_mem;
    prog->calldests = fd_sbpf_calldests_join( fd_sbpf_calldests_new( calldests_mem, elf_info->text_cnt ) );
  }

  /* Loader requires syscall table */

  fd_sbpf_syscalls_t _syscalls[ FD_SBPF_SYSCALLS_SLOT_CNT ];
  fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_join( fd_sbpf_syscalls_new( _syscalls ) );
  int syscalls_err = fd_vm_syscall_register_slot( syscalls, load_slot, features, /* is_deploy */ 0 );
  if( FD_UNLIKELY( syscalls_err!=FD_VM_SUCCESS ) ) FD_LOG_CRIT(( "fd_vm_syscall_register_slot failed" ));

  /* Run ELF loader.

     Scratch is needed only by the lenient (v0-v2) fallback path, which
     assembles the rodata segment via a scratch buffer.  The lenient fast
     path and strict (v3+) loads write directly into the destination buffer;
     passing NULL both selects the loader's fast/no-scratch path and faults
     loudly if it ever starts relying on scratch. */

  int    use_scratch     = fd_sbpf_loader_is_legacy_lenient( elf_info );
  void * load_scratch    = use_scratch ? scratch    : NULL;
  ulong  load_scratch_sz = use_scratch ? scratch_sz : 0UL;

  if( FD_UNLIKELY( 0!=fd_sbpf_program_load( prog, progdata, progdata_sz, syscalls, config, load_scratch, load_scratch_sz ) ) ) {
    return NULL;
  }

  rec->entry_pc  = (uint)prog->entry_pc;
  rec->rodata_sz = (uint)prog->rodata_sz;

  /* Run bytecode validator */

  fd_vm_t _vm[1];
  fd_vm_t * vm = fd_vm_join( fd_vm_new( _vm ) );
  if( FD_UNLIKELY( !vm ) ) FD_LOG_CRIT(( "fd_vm_new failed" ));
  vm = fd_vm_init( vm,
                   NULL, /* OK since unused in `fd_vm_validate()` */
                   0UL,
                   0UL,
                   prog->rodata,
                   prog->rodata_sz,
                   prog->text,
                   prog->info.text_cnt,
                   prog->info.text_off,
                   prog->info.text_sz,
                   prog->entry_pc,
                   prog->calldests,
                   elf_info->sbpf_version,
                   syscalls,
                   NULL,
                   NULL,
                   NULL,
                   0U,
                   NULL,
                   0,
                   FD_FEATURE_ACTIVE( load_slot, features, account_data_direct_mapping ),
                   FD_FEATURE_ACTIVE( load_slot, features, syscall_parameter_address_restrictions ),
                   FD_FEATURE_ACTIVE( load_slot, features, virtual_address_space_adjustments ),
                   0,
                   0UL );
  if( FD_UNLIKELY( !vm ) ) FD_LOG_CRIT(( "fd_vm_init failed" ));

  if( FD_UNLIKELY( fd_vm_validate( vm )!=FD_VM_SUCCESS ) ) return NULL;

  return rec;
}

fd_progcache_rec_t *
fd_progcache_rec_nx( fd_progcache_rec_t * rec ) {
  rec->data_gaddr    = 0UL;
  rec->data_max      = 0U;
  rec->entry_pc      = 0;
  rec->text_cnt      = 0;
  rec->text_off      = 0;
  rec->text_sz       = 0;
  rec->rodata_sz     = 0;
  rec->calldests_off = UINT_MAX;
  rec->rodata_off    = 0;
  rec->sbpf_version  = 0;
  return rec;
}
