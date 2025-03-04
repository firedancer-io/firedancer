#include "fd_vm_syscall.h"

#include "../../../ballet/ed25519/fd_curve25519.h"

/* fd_compute_pda derives a PDA given:
   - the vm
   - the program id, which should be provided through either program_id or program_id_vaddr
      - This allows the user to pass in a program ID in either host address space or virtual address space.
      - If both are passed in, the host address space pubkey will be used.
   - the program_id pubkey in virtual address space. if the host address space pubkey is not given then the virtual address will be translated.
   - the seeds array vaddr
   - the seeds array count
   - an optional bump seed
   - out, the address in host address space where the PDA will be written to

If the derived PDA was not a valid ed25519 point, then this function will return FD_VM_SYSCALL_ERR_INVALID_PDA.

The derivation can also fail because of an out-of-bounds memory access, or an invalid seed list.
 */
int
fd_vm_derive_pda( fd_vm_t *           vm,
                  fd_pubkey_t const * program_id,
                  void const * *      seed_haddrs,
                  ulong *             seed_szs,
                  ulong               seeds_cnt,
                  uchar *             bump_seed,
                  fd_pubkey_t *       out ) {

  /* This is a preflight check that is performed in Agave before deriving PDAs but after checking the seeds vaddr.
     Weirdly they do two checks for seeds cnt - one before PDA derivation, and one during. The first check will
     fail the preflight checks, and the second should just continue execution. We can't put this check one level up
     because it's only done after haddr conversion / alignment / size checks, which is done by the above line. We
     also can't rely on just the second check because we need execution to halt.
     https://github.com/anza-xyz/agave/blob/v2.1.0/programs/bpf_loader/src/syscalls/mod.rs#L728-L730 */
  if( FD_UNLIKELY( seeds_cnt>FD_VM_PDA_SEEDS_MAX ) ) {
    FD_VM_ERR_FOR_LOG_SYSCALL( vm, FD_VM_SYSCALL_ERR_BAD_SEEDS );
    return FD_VM_SYSCALL_ERR_BAD_SEEDS;
  }

  /* This check does NOT halt execution within `fd_vm_syscall_sol_try_find_program_address`. This means
     that if the user provides 16 seeds (excluding the bump) in the `try_find_program_address` syscall,
     this same check below will be hit 255 times and deduct that many CUs. Very strange...
     https://github.com/anza-xyz/agave/blob/v2.1.0/sdk/pubkey/src/lib.rs#L725-L727 */
  if( FD_UNLIKELY( seeds_cnt+( !!bump_seed )>FD_VM_PDA_SEEDS_MAX ) ) {
    return FD_VM_SYSCALL_ERR_INVALID_PDA;
  }

  for( ulong i=0UL; i<seeds_cnt; i++ ) {
    /* This is an unconditional check in Agave:
       https://github.com/anza-xyz/agave/blob/v2.1.6/sdk/pubkey/src/lib.rs#L729-L731
     */
    if( FD_UNLIKELY( seed_szs[ i ]>FD_VM_PDA_SEED_MEM_MAX ) ) {
      FD_VM_ERR_FOR_LOG_SYSCALL( vm, FD_VM_SYSCALL_ERR_BAD_SEEDS );
      return FD_VM_SYSCALL_ERR_BAD_SEEDS;
    }
  }

  fd_sha256_init( vm->sha );
  for( ulong i=0UL; i<seeds_cnt; i++ ) {
    ulong seed_sz = seed_szs[ i ];

    /* If the seed length is 0, then we don't need to append anything. solana_bpf_loader_program::syscalls::translate_slice
       returns an empty array in host space when given an empty array, which means this seed will have no affect on the PDA.
       https://github.com/anza-xyz/agave/blob/v2.1.0/programs/bpf_loader/src/syscalls/mod.rs#L737-L742 */
    if( FD_UNLIKELY( !seed_sz ) ) {
      continue;
    }
    void const * seed_haddr = seed_haddrs[ i ];
    fd_sha256_append( vm->sha, seed_haddr, seed_sz );
  }

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/sdk/pubkey/src/lib.rs#L738-L747 */
  if( bump_seed ) {
    fd_sha256_append( vm->sha, bump_seed, 1UL );
  }

  if( FD_LIKELY( program_id )) {
    fd_sha256_append( vm->sha, program_id, FD_PUBKEY_FOOTPRINT );
  } else {
    FD_LOG_ERR(( "No program id passed in" ));
  }

  fd_sha256_append( vm->sha, "ProgramDerivedAddress", 21UL ); /* TODO: use marker constant */

  fd_sha256_fini( vm->sha, out );

  /* A PDA is valid if it is not a valid ed25519 curve point.
     In most cases the user will have derived the PDA off-chain, or the PDA is a known signer. */
  if( FD_UNLIKELY( fd_ed25519_point_validate( out->key ) ) ) {
    return FD_VM_SYSCALL_ERR_INVALID_PDA;
  }

  return FD_VM_SUCCESS;
}

/* fd_vm_translate_and_check_program_address_inputs is responsible for doing
   the preflight checks and translation of the seeds and program id.
   https://github.com/anza-xyz/agave/blob/v2.1.0/programs/bpf_loader/src/syscalls/mod.rs#L719 */

int
fd_vm_translate_and_check_program_address_inputs( fd_vm_t *             vm,
                                                  ulong                 seeds_vaddr,
                                                  ulong                 seeds_cnt,
                                                  ulong                 program_id_vaddr,
                                                  void const * *        out_seed_haddrs,
                                                  ulong *               out_seed_szs,
                                                  fd_pubkey_t const * * out_program_id,
                                                  uchar                 is_syscall ) {

  fd_vm_vec_t const * untranslated_seeds = FD_VM_MEM_SLICE_HADDR_LD( vm, seeds_vaddr, FD_VM_ALIGN_RUST_SLICE_U8_REF,
                                                                     fd_ulong_sat_mul( seeds_cnt, FD_VM_VEC_SIZE ) );

  /* This is a preflight check that is performed in Agave before deriving PDAs but after checking the seeds vaddr.
     When called to help CPI signer translation, this logs an
     instruction error:
     https://github.com/anza-xyz/agave/blob/v2.1.11/programs/bpf_loader/src/syscalls/cpi.rs#L538-L540
     However, when called from a syscall, this logs a syscall error:
     https://github.com/anza-xyz/agave/blob/v2.1.0/programs/bpf_loader/src/syscalls/mod.rs#L728-L730 */
  if( FD_UNLIKELY( seeds_cnt>FD_VM_PDA_SEEDS_MAX ) ) {
    if( is_syscall ) {
      FD_VM_ERR_FOR_LOG_SYSCALL( vm, FD_VM_SYSCALL_ERR_BAD_SEEDS );
      return FD_VM_SYSCALL_ERR_BAD_SEEDS;
    } else {
      FD_VM_ERR_FOR_LOG_INSTR( vm, FD_EXECUTOR_INSTR_ERR_MAX_SEED_LENGTH_EXCEEDED );
      return FD_EXECUTOR_INSTR_ERR_MAX_SEED_LENGTH_EXCEEDED;
    }
  }
  for( ulong i=0UL; i<seeds_cnt; i++ ) {
    ulong seed_sz = untranslated_seeds[i].len;
    /* Another preflight check
       https://github.com/anza-xyz/agave/blob/v2.1.0/programs/bpf_loader/src/syscalls/mod.rs#L734-L736
       When this function is called from syscalls, we would like to
       abort when exceeding SEED_MEM_MAX.
       However, when we reuse this function from CPI for signer
       translation, this check doesn't exist.  Sigh.
       Instead, the check is delayed until deriving PDA.
       https://github.com/anza-xyz/agave/blob/v2.1.6/programs/bpf_loader/src/syscalls/cpi.rs#L543
     */
    if( FD_UNLIKELY( seed_sz>FD_VM_PDA_SEED_MEM_MAX && is_syscall ) ) {
      FD_VM_ERR_FOR_LOG_SYSCALL( vm, FD_VM_SYSCALL_ERR_BAD_SEEDS );
      return FD_VM_SYSCALL_ERR_BAD_SEEDS;
    }
    void const * seed_haddr = FD_VM_MEM_SLICE_HADDR_LD( vm, untranslated_seeds[i].addr, FD_VM_ALIGN_RUST_U8, seed_sz );
    out_seed_haddrs[ i ] = seed_haddr;
    out_seed_szs   [ i ] = seed_sz;
  }

  /* We only want to do this check if the user requires it. */
  if( out_program_id ) {
    *out_program_id = FD_VM_MEM_HADDR_LD( vm, program_id_vaddr, FD_VM_ALIGN_RUST_PUBKEY, FD_PUBKEY_FOOTPRINT );
  }
  return 0;
}

/* fd_vm_syscall_sol_create_program_address is the entrypoint for the sol_create_program_address syscall:
https://github.com/anza-xyz/agave/blob/v2.0.8/programs/bpf_loader/src/syscalls/mod.rs#L729

The main semantic difference between Firedancer's implementation and Solana's is that Solana
translates all the seed pointers before doing any computation, while Firedancer translates
the seed pointers on-demand. This is to avoid an extra memory allocation.

This syscall creates a valid program derived address without searching for a bump seed.
It does this by hashing all the seeds, the program id, and the PDA marker, and then
checking if the resulting hash is a valid ed25519 curve point.

There is roughly a 50% chance of this syscall failing, due to the hash not being
a valid curve point, for any given collection of seeds.

Parameters:
- _vm: a pointer to the VM
- seed_vaddr: the address of the first element of an iovec-like scatter of a seed byte array in VM address space
- seed_cnt: the number of scatter elements
- program_id_vaddr: the address of the program id pubkey in VM address space
- out_vaddr: the address of the memory location where the resulting derived PDA will be written to, in VM address space, if the syscall is successful
- r5: unused
- _ret: a pointer to the return value of the syscall
*/
int
fd_vm_syscall_sol_create_program_address( /**/            void *  _vm,
                                          /**/            ulong   seeds_vaddr,
                                          /**/            ulong   seeds_cnt,
                                          /**/            ulong   program_id_vaddr,
                                          /**/            ulong   out_vaddr,
                                          FD_PARAM_UNUSED ulong   r5,
                                          /**/            ulong * _ret )  {
  fd_vm_t * vm = (fd_vm_t *)_vm;

  uchar * bump_seed = NULL;

  FD_VM_CU_UPDATE( vm, FD_VM_CREATE_PROGRAM_ADDRESS_UNITS );

  void const *        seed_haddrs[ FD_VM_PDA_SEEDS_MAX ];
  ulong               seed_szs   [ FD_VM_PDA_SEEDS_MAX ];
  fd_pubkey_t const * program_id;

  int err = fd_vm_translate_and_check_program_address_inputs( vm,
                                                              seeds_vaddr,
                                                              seeds_cnt,
                                                              program_id_vaddr,
                                                              seed_haddrs,
                                                              seed_szs,
                                                              &program_id,
                                                              1U );
  if( FD_UNLIKELY( err ) ) {
    *_ret = 0UL;
    return err;
  }

  fd_pubkey_t derived[1];
  err = fd_vm_derive_pda( vm, program_id, seed_haddrs, seed_szs, seeds_cnt, bump_seed, derived );
  /* Agave does their translation before the calculation, so if the translation fails we should fail
     the syscall.

     https://github.com/anza-xyz/agave/blob/v2.0.8/programs/bpf_loader/src/syscalls/mod.rs#L744-L750 */
  if ( FD_UNLIKELY( err != FD_VM_SUCCESS ) ) {

    /* Place 1 in r0 and successfully exit if we failed to derive a PDA
      https://github.com/anza-xyz/agave/blob/v2.0.8/programs/bpf_loader/src/syscalls/mod.rs#L753 */
    if ( FD_LIKELY( err == FD_VM_SYSCALL_ERR_INVALID_PDA ) ) {
      *_ret = 1UL;
      return FD_VM_SUCCESS;
    }

    return err;
  }

  fd_pubkey_t * out_haddr = FD_VM_MEM_HADDR_ST( vm, out_vaddr, FD_VM_ALIGN_RUST_U8, FD_PUBKEY_FOOTPRINT );
  memcpy( out_haddr, derived->uc, FD_PUBKEY_FOOTPRINT );

  /* Success */
  *_ret = 0UL;
  return FD_VM_SUCCESS;
}

/* fd_vm_syscall_sol_try_find_program_address is the entrypoint for the sol_try_find_program_address syscall:
https://github.com/anza-xyz/agave/blob/v2.1.1/programs/bpf_loader/src/syscalls/mod.rs#L791

This syscall creates a valid program derived address, searching for a valid ed25519 curve point by
iterating through 255 possible bump seeds.

It does this by hashing all the seeds, the program id, and the PDA marker, and then
checking if the resulting hash is a valid ed25519 curve point.
 */
int
fd_vm_syscall_sol_try_find_program_address( void *  _vm,
                                            ulong   seeds_vaddr,
                                            ulong   seeds_cnt,
                                            ulong   program_id_vaddr,
                                            ulong   out_vaddr,
                                            ulong   out_bump_seed_vaddr,
                                            ulong * _ret ) {
  fd_vm_t * vm = (fd_vm_t *)_vm;

  /* Costs the same as a create_program_address call.. weird but that is the protocol. */
  FD_VM_CU_UPDATE( vm, FD_VM_CREATE_PROGRAM_ADDRESS_UNITS );

  /* Similar to create_program_address but appends a 1 byte nonce that
     decrements from 255 down to 1 until a valid PDA is found.

     TODO: Solana Labs recomputes the SHA hash for each iteration here.  We
     can leverage SHA's streaming properties to precompute all but the last
     two blocks (1 data, 0 or 1 padding). PROBABLY NEED TO ADD CHECKPT / RESTORE
     CALLS TO SHA TO SUPPORT THIS)*/

  uchar bump_seed[1];

  /* First we need to do the preflight checks */
  void const *        seed_haddrs[ FD_VM_PDA_SEEDS_MAX ];
  ulong               seed_szs   [ FD_VM_PDA_SEEDS_MAX ];
  fd_pubkey_t const * program_id;

  int err = fd_vm_translate_and_check_program_address_inputs( vm,
                                                              seeds_vaddr,
                                                              seeds_cnt,
                                                              program_id_vaddr,
                                                              seed_haddrs,
                                                              seed_szs,
                                                              &program_id,
                                                              1U );
  if( FD_UNLIKELY( err ) ) {
    *_ret = 0UL;
    return err;
  }

  for( ulong i=0UL; i<255UL; i++ ) {
    bump_seed[0] = (uchar)(255UL - i);

    fd_pubkey_t derived[1];
    err = fd_vm_derive_pda( vm, program_id, seed_haddrs, seed_szs, seeds_cnt, bump_seed, derived );
    if( FD_LIKELY( err==FD_VM_SUCCESS ) ) {
      /* Stop looking if we have found a valid PDA */
      err = 0;
      fd_pubkey_t * out_haddr = FD_VM_MEM_HADDR_ST_( vm, out_vaddr, FD_VM_ALIGN_RUST_U8, sizeof(fd_pubkey_t), &err );
      if( FD_UNLIKELY( 0 != err ) ) {
        *_ret = 0UL;
        return err;
      }
      uchar * out_bump_seed_haddr = FD_VM_MEM_HADDR_ST_( vm, out_bump_seed_vaddr, FD_VM_ALIGN_RUST_U8, 1UL, &err );
      if( FD_UNLIKELY( 0 != err ) ) {
        *_ret = 0UL;
        return err;
      }

      /* Do the overlap check, which is only included for this syscall */
      FD_VM_MEM_CHECK_NON_OVERLAPPING( vm, (ulong)out_haddr, 32UL, (ulong)out_bump_seed_haddr, 1UL );

      memcpy( out_haddr, derived, sizeof(fd_pubkey_t) );
      *out_bump_seed_haddr = (uchar)*bump_seed;

      *_ret = 0UL;
      return FD_VM_SUCCESS;
    } else if( FD_UNLIKELY( err!=FD_VM_SYSCALL_ERR_INVALID_PDA ) ) {
      return err;
    }

    FD_VM_CU_UPDATE( vm, FD_VM_CREATE_PROGRAM_ADDRESS_UNITS );
  }

  *_ret = 1UL;
  return FD_VM_SUCCESS;
}
