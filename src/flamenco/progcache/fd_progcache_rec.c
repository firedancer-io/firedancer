#include "fd_progcache_rec.h"
#include "../vm/fd_vm.h" /* fd_vm_syscall_register_slot, fd_vm_validate */

fd_progcache_rec_t *
fd_progcache_rec_new( void *                     mem,
                      fd_sbpf_elf_info_t const * elf_info,
                      ulong                      load_slot,
                      fd_features_t const *      features,
                      void const *               progdata,
                      ulong                      progdata_sz ) {

  /* Format object */

  int   has_calldests = !fd_sbpf_enable_stricter_elf_headers( elf_info->sbpf_version );
  ulong pc_max        = elf_info->rodata_sz/8UL;
  /* FIXME pc_max could be smaller since .text ends before rodata ends */

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_progcache_rec_t * rec           = FD_SCRATCH_ALLOC_APPEND( l, fd_progcache_rec_align(),  sizeof(fd_progcache_rec_t) );
  void *               calldests_mem = NULL;
  if( has_calldests )
    /*               */calldests_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_sbpf_calldests_align(), fd_sbpf_calldests_footprint( pc_max ) );
  void *               rodata_mem    = FD_SCRATCH_ALLOC_APPEND( l, 8UL,                       elf_info->rodata_footprint );
  FD_SCRATCH_ALLOC_FINI( l, fd_progcache_rec_align() );
  memset( rec, 0, sizeof(fd_progcache_rec_t) );
  rec->calldests_off = has_calldests ? (uint)( (ulong)calldests_mem - (ulong)mem ) : 0U;
  rec->rodata_off    = (uint)( (ulong)rodata_mem    - (ulong)mem );

  rec->entry_pc      = elf_info->entry_pc;
  rec->text_cnt      = elf_info->text_cnt;
  rec->text_off      = elf_info->text_off;
  rec->text_sz       = (uint)elf_info->text_sz;
  rec->rodata_sz     = (uint)elf_info->rodata_sz;
  rec->sbpf_version  = (uchar)elf_info->sbpf_version;

  /* Set up sbpf_loader (redirect writes into progcache_rec object) */

  fd_sbpf_program_t prog[1] = {{
    .info      = *elf_info,
    .rodata    = rodata_mem,
    .rodata_sz = elf_info->rodata_sz,
    .text      = (ulong *)((ulong)rodata_mem + elf_info->text_off), /* FIXME: WHAT IF MISALIGNED */
    .text_off  = elf_info->text_off,
    .text_cnt  = elf_info->text_cnt,
    .text_sz   = elf_info->text_sz,
    .entry_pc  = elf_info->entry_pc
  }};
  if( has_calldests ) {
    prog->calldests_shmem = calldests_mem;
    prog->calldests = fd_sbpf_calldests_join( fd_sbpf_calldests_new( calldests_mem, pc_max ) );
  }

  /* Loader requires syscall table */

  fd_sbpf_syscalls_t _syscalls[ FD_SBPF_SYSCALLS_SLOT_CNT ];
  fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_join( fd_sbpf_syscalls_new( _syscalls ) );
  int syscalls_err = fd_vm_syscall_register_slot( syscalls, load_slot, features, /* is_deploy */ 0 );
  if( FD_UNLIKELY( syscalls_err!=FD_VM_SUCCESS ) ) FD_LOG_CRIT(( "fd_vm_syscall_register_slot failed" ));

  /* Run ELF loader */

  fd_sbpf_loader_config_t config = {0};
  if( FD_UNLIKELY( 0!=fd_sbpf_program_load( prog, progdata, progdata_sz, syscalls, &config ) ) ) {\
    return NULL;
  }

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
                   prog->text_cnt,
                   prog->text_off,
                   prog->text_sz,
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
                   FD_FEATURE_ACTIVE( load_slot, features, bpf_account_data_direct_mapping ),
                   0 );
  if( FD_UNLIKELY( !vm ) ) FD_LOG_CRIT(( "fd_vm_init failed" ));

  if( FD_UNLIKELY( fd_vm_validate( vm )!=FD_VM_SUCCESS ) ) return NULL;

  rec->last_slot_verified = load_slot;
  rec->last_slot_modified = 0UL;
  rec->executable         = 1;
  return rec;
}

fd_progcache_rec_t *
fd_progcache_rec_new_nx( void * mem,
                         ulong  load_slot,
                         ulong  modify_slot ) {
  fd_progcache_rec_t * rec = mem;
  memset( rec, 0, sizeof(fd_progcache_rec_t) );
  rec->last_slot_verified = load_slot;
  rec->last_slot_modified = modify_slot;
  rec->executable         = 0;
  return rec;
}
