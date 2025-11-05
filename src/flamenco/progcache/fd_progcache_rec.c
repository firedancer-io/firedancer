#include "fd_progcache_rec.h"
#include "../vm/fd_vm.h" /* fd_vm_syscall_register_slot, fd_vm_validate */

fd_progcache_rec_t *
fd_progcache_rec_new( void *                          mem,
                      fd_sbpf_elf_info_t const *      elf_info,
                      fd_sbpf_loader_config_t const * config,
                      ulong                           load_slot,
                      fd_features_t const *           features,
                      void const *                    progdata,
                      ulong                           progdata_sz,
                      void *                          scratch,
                      ulong                           scratch_sz ) {

  /* Format object */

  int   has_calldests = !fd_sbpf_enable_stricter_elf_headers_enabled( elf_info->sbpf_version );

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_progcache_rec_t * rec           = FD_SCRATCH_ALLOC_APPEND( l, fd_progcache_rec_align(),  sizeof(fd_progcache_rec_t) );
  void *               calldests_mem = NULL;
  if( has_calldests ) {
    /*               */calldests_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_sbpf_calldests_align(), fd_sbpf_calldests_footprint( elf_info->text_cnt ) );
  }
  void *               rodata_mem    = FD_SCRATCH_ALLOC_APPEND( l, 8UL,                       elf_info->bin_sz );
  FD_SCRATCH_ALLOC_FINI( l, fd_progcache_rec_align() );
  memset( rec, 0, sizeof(fd_progcache_rec_t) );
  rec->calldests_off = has_calldests ? (uint)( (ulong)calldests_mem - (ulong)mem ) : 0U;
  rec->rodata_off    = (uint)( (ulong)rodata_mem - (ulong)mem );

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
                   0 );
  if( FD_UNLIKELY( !vm ) ) FD_LOG_CRIT(( "fd_vm_init failed" ));

  if( FD_UNLIKELY( fd_vm_validate( vm )!=FD_VM_SUCCESS ) ) return NULL;

  rec->slot       = load_slot;
  rec->executable = 1;
  return rec;
}

fd_progcache_rec_t *
fd_progcache_rec_new_nx( void * mem,
                         ulong  load_slot ) {
  fd_progcache_rec_t * rec = mem;
  memset( rec, 0, sizeof(fd_progcache_rec_t) );
  rec->slot       = load_slot;
  rec->executable = 0;
  return rec;
}
