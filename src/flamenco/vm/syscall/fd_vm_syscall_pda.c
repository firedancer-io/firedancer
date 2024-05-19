#include "fd_vm_syscall.h"

#include "../../../ballet/ed25519/fd_curve25519.h"

/* The maximum number of seeds a PDA can have 
   https://github.com/solana-labs/solana/blob/2afde1b028ed4593da5b6c735729d8994c4bfac6/sdk/program/src/pubkey.rs#L21 */
#define FD_VM_PDA_SEEDS_MAX    (16UL)
/* The maximum length of a PDA seed
   https://github.com/solana-labs/solana/blob/2afde1b028ed4593da5b6c735729d8994c4bfac6/sdk/program/src/pubkey.rs#L19 */
#define FD_VM_PDA_SEED_MEM_MAX (32UL)

/* fd_compute_pda derives a PDA given:
   - the vm
   - program_id pubkey in host address space
   - the seeds array vaddr
   - the seeds array count
   - an optional bump seed
   - out, the address in host address space where the PDA will be written to

If the derived PDA was not a valid ed25519 point, then this function will return FD_VM_ERR_INVALID_PDA.

The derivation can also fail because of an out-of-bounds memory access, or an invalid seed list.
 */
int
fd_vm_derive_pda( fd_vm_t *           vm,
                  fd_pubkey_t const * program_id,
                  ulong               seeds_vaddr,
                  ulong               seeds_cnt,
                  uchar *             bump_seed,
                  fd_pubkey_t *       out ) {

  if ( seeds_cnt>FD_VM_PDA_SEEDS_MAX ) {
    return FD_VM_ERR_INVAL;
  }

  /* When seeds_cnt==0 Solana Labs does not verify the pointer. Neither do we. */
  fd_vm_vec_t const * seeds_haddr = FD_VM_MEM_HADDR_LD( vm, seeds_vaddr, FD_VM_VEC_ALIGN, seeds_cnt*FD_VM_VEC_SIZE );

  fd_sha256_init( vm->sha );
  for ( ulong i=0UL; i<seeds_cnt; i++ ) {
    ulong seed_sz = seeds_haddr[i].len;

    if( FD_UNLIKELY( seed_sz>FD_VM_PDA_SEED_MEM_MAX ) ) return FD_VM_ERR_INVAL;

    /* If the seed length is 0, then we don't need to append anything. solana_bpf_loader_program::syscalls::translate_slice
       returns an empty array in host space when given an empty array, which means this seed will have no affect on the PDA. */
    if ( FD_UNLIKELY( seed_sz==0 ) ) continue;

    void const * seed_haddr = FD_VM_MEM_HADDR_LD( vm, seeds_haddr[i].addr, alignof(uchar), seed_sz );
    fd_sha256_append( vm->sha, seed_haddr, seed_sz );
  }

  if( bump_seed ) {
    fd_sha256_append( vm->sha, bump_seed, 1UL );
  }

  fd_sha256_append( vm->sha, program_id, sizeof(fd_pubkey_t) );
  fd_sha256_append( vm->sha, "ProgramDerivedAddress", 21UL ); /* TODO: use marker constant */

  fd_sha256_fini( vm->sha, out );

  /* A PDA is valid if it is not a valid ed25519 curve point.
     In most cases the user will have derived the PDA off-chain, or the PDA is a known signer. */
  if( FD_UNLIKELY( fd_ed25519_point_validate( out->key ) ) ) {
    return FD_VM_ERR_INVALID_PDA;
  }

  return FD_VM_SUCCESS;
}

/* fd_vm_syscall_sol_create_program_address is the entrypoint for the sol_create_program_address syscall:
https://github.com/solana-labs/solana/blob/2afde1b028ed4593da5b6c735729d8994c4bfac6/programs/bpf_loader/src/syscalls/mod.rs#L689

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
- arg4: unused
- _ret: a pointer to the return value of the syscall
*/
int
fd_vm_syscall_sol_create_program_address( /**/            void *  _vm,
                                          /**/            ulong   seeds_vaddr,
                                          /**/            ulong   seeds_cnt,
                                          /**/            ulong   program_id_vaddr,
                                          /**/            ulong   out_vaddr,
                                          FD_PARAM_UNUSED ulong   arg4,
                                          /**/            ulong * _ret )  {
  fd_vm_t * vm = (fd_vm_t *)_vm;

  if ( seeds_cnt == 0 ) return FD_VM_ERR_INVAL;

  ulong r0 = 0UL;

  uchar * bump_seed = NULL;

  FD_VM_CU_UPDATE( vm, FD_VM_CREATE_PROGRAM_ADDRESS_UNITS );

  fd_pubkey_t const * program_id = FD_VM_MEM_HADDR_LD( vm, program_id_vaddr, alignof(uchar), sizeof(fd_pubkey_t) );

  fd_pubkey_t derived[1];
  int err = fd_vm_derive_pda( vm, program_id, seeds_vaddr, seeds_cnt, bump_seed, derived );
  if ( FD_UNLIKELY( err == FD_VM_ERR_INVALID_PDA ) ) {
    /* Place 1 in r0 if the PDA is invalid
       https://github.com/solana-labs/solana/blob/2afde1b028ed4593da5b6c735729d8994c4bfac6/programs/bpf_loader/src/syscalls/mod.rs#L712 */
    r0 = 1UL;
  } else if ( FD_UNLIKELY( err ) ) {
    return err;
  }

  fd_pubkey_t * out_haddr = FD_VM_MEM_HADDR_ST( vm, out_vaddr, alignof(fd_pubkey_t), sizeof(fd_pubkey_t) );
  memcpy( out_haddr, derived->uc, sizeof(fd_pubkey_t) );

  /* Success */
  *_ret = r0;
  return FD_VM_SUCCESS;
}

/* fd_vm_syscall_sol_try_find_program_address is the entrypoint for the sol_try_find_program_address syscall:
https://github.com/solana-labs/solana/blob/2afde1b028ed4593da5b6c735729d8994c4bfac6/programs/bpf_loader/src/syscalls/mod.rs#L727

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

  ulong r0 = 1UL; /* No PDA found */

  uchar bump_seed[1];
  for ( ulong i=0UL; i<256UL; i++ ) {
    bump_seed[0] = (uchar)(255UL - i);

    fd_pubkey_t const * program_id = FD_VM_MEM_HADDR_LD( vm, program_id_vaddr, alignof(fd_pubkey_t), sizeof(fd_pubkey_t) );

    fd_pubkey_t derived[1];
    int err = fd_vm_derive_pda( vm, program_id, seeds_vaddr, seeds_cnt, bump_seed, derived );
    if ( FD_LIKELY( err == FD_VM_SUCCESS ) ) {
      /* Stop looking if we have found a valid PDA */
      r0 = 0UL;
      fd_pubkey_t * out_haddr = FD_VM_MEM_HADDR_ST( vm, out_vaddr, alignof(fd_pubkey_t), sizeof(fd_pubkey_t) );
      uchar * out_bump_seed_haddr = FD_VM_MEM_HADDR_ST( vm, out_bump_seed_vaddr, alignof(uchar), 1UL );
      memcpy( out_haddr, derived, sizeof(fd_pubkey_t) );
      *out_bump_seed_haddr = (uchar)*bump_seed;

      break;
    } else if ( FD_UNLIKELY( err && (err != FD_VM_ERR_INVALID_PDA) ) ) {
      return err;
    }

    /* TODO: can we move this to the top of the loop? */
    FD_VM_CU_UPDATE( vm, FD_VM_CREATE_PROGRAM_ADDRESS_UNITS );

  }

  /* Do the overlap check, which is only included for this syscall */
  /* FIXME: USE IS_NONOVERLAPPING FROM {GET,SET}RETURN? (NOTE THAT
         THIS ASSUMES XLAT REJECTS WRAPPING ADDRESS RANGES). */
  if( (ulong)out_vaddr > (ulong)out_bump_seed_vaddr ) {
    if( !(((ulong)out_vaddr       - (ulong)out_bump_seed_vaddr)>= 1UL) ) return FD_VM_ERR_PERM;
  } else {
    if( !(((ulong)out_bump_seed_vaddr - (ulong)out_vaddr      )>=32UL) ) return FD_VM_ERR_PERM;
  }

  *_ret = r0;
  return FD_VM_SUCCESS;
}
