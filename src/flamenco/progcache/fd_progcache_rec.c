#include "fd_progcache.h"
#include "../vm/fd_vm.h" /* fd_vm_syscall_register_slot, fd_vm_validate */
#include "../../util/alloc/fd_alloc.h"

void *
fd_progcache_val_alloc( fd_progcache_rec_t *  rec,
                        fd_progcache_join_t * join,
                        ulong                 val_align,
                        ulong                 val_footprint ) {
  if( rec->data_gaddr ) fd_progcache_val_free( rec, join );
  ulong val_max = 0UL;
  void * mem = fd_alloc_malloc_at_least( join->alloc, val_align, val_footprint, &val_max );
  if( FD_UNLIKELY( !mem ) ) return NULL;
  FD_CRIT( val_max<=UINT_MAX, "massive" ); /* unreachable */
  rec->data_gaddr = fd_wksp_gaddr_fast( join->wksp, mem );
  rec->data_max   = (uint)val_max;
  return mem;
}

void
fd_progcache_val_free( fd_progcache_rec_t *  rec,
                       fd_progcache_join_t * join ) {
  if( !rec->data_gaddr ) return;
  void * mem = fd_wksp_laddr_fast( join->wksp, rec->data_gaddr );

  /* Illegal to call val_free on a spill-allocated buffer */
  FD_TEST( !( (ulong)mem >= (ulong)join->shmem->spill.spad &&
              (ulong)mem <  (ulong)join->shmem->spill.spad+FD_PROGCACHE_SPAD_MAX ) );

  fd_alloc_free( join->alloc, mem );
  rec->data_gaddr = 0UL;
  rec->data_max   = 0U;
  rec->rodata_off = 0U;
  rec->rodata_sz  = 0U;
}

FD_FN_PURE ulong
fd_progcache_val_footprint( fd_sbpf_elf_info_t const * elf_info ) {
  int   has_calldests = !fd_sbpf_enable_stricter_elf_headers_enabled( elf_info->sbpf_version );
  ulong pc_max        = fd_ulong_max( 1UL, elf_info->text_cnt );

  ulong l = FD_LAYOUT_INIT;
  if( has_calldests ) {
    l = FD_LAYOUT_APPEND( l, fd_sbpf_calldests_align(), fd_sbpf_calldests_footprint( pc_max ) );
  }
  l = FD_LAYOUT_APPEND( l, 8UL, elf_info->bin_sz );
  return FD_LAYOUT_FINI( l, fd_progcache_val_align() );
}

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

  void * val = fd_wksp_laddr_fast( wksp, rec->data_gaddr );
  FD_SCRATCH_ALLOC_INIT( l, val );
  void *               calldests_mem = NULL;
  if( has_calldests ) {
    /*               */calldests_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_sbpf_calldests_align(), fd_sbpf_calldests_footprint( fd_ulong_max( 1UL, elf_info->text_cnt ) ) );
  }
  void *               rodata_mem    = FD_SCRATCH_ALLOC_APPEND( l, 8UL, elf_info->bin_sz );
  FD_SCRATCH_ALLOC_FINI( l, fd_progcache_val_align() );
  FD_TEST( _l-(ulong)val == fd_progcache_val_footprint( elf_info ) );

  rec->calldests_off = has_calldests ? (uint)( (ulong)calldests_mem - (ulong)val ) : 0U;
  rec->rodata_off    = (uint)( (ulong)rodata_mem - (ulong)val );
  rec->entry_pc      = 0;
  rec->rodata_sz     = 0;
  rec->executable    = 0;

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

  /* Run ELF loader */

  if( FD_UNLIKELY( 0!=fd_sbpf_program_load( prog, progdata, progdata_sz, syscalls, config, scratch, scratch_sz ) ) ) {
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
                   FD_FEATURE_ACTIVE( load_slot, features, stricter_abi_and_runtime_constraints ),
                   0,
                   0UL );
  if( FD_UNLIKELY( !vm ) ) FD_LOG_CRIT(( "fd_vm_init failed" ));

  if( FD_UNLIKELY( fd_vm_validate( vm )!=FD_VM_SUCCESS ) ) return NULL;

  rec->executable = 1;
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
  rec->calldests_off = 0;
  rec->rodata_off    = 0;
  rec->sbpf_version  = 0;
  rec->executable    = 0;
  rec->invalidate    = 0;
  return rec;
}
