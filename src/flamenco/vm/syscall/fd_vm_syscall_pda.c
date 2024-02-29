#include "../syscall/fd_vm_syscall.h"

#include "../../../ballet/ed25519/fd_ed25519_ge.h"

/* fd_vm_partial_derive_address does the initial appends to a SHA
   calculation for a program derived account address.  sha is an current
   local join to SHA state object.  program_id_vaddr points to the
   program address in VM address space. seed_vaddr points to the first
   element of an iovec-like scatter of a seed byte array (&[&[u8]]) in
   VM address space.  seed_cnt is the number of scatter elems.  Returns
   sha calculation on success and null on failure.  Reasons for failure
   include out-of-bounds memory access or invalid seed list. */

static fd_sha256_t *
fd_vm_partial_derive_address( fd_vm_exec_context_t * vm,
                              fd_sha256_t *          sha,
                              ulong                  program_id_vaddr,
                              ulong                  seed_vaddr,
                              ulong                  seed_cnt,
                              uchar *                bump_seed ) {
  if( FD_UNLIKELY( seed_cnt>FD_VM_CPI_SEED_MAX ) ) return NULL;

  /* FIXME: WHAT'S THE EXPECTED BEHAVIOR IF SEED_CNT==0 */
  /* FIXME: TYPE CONFUSION BUG */
  ulong seed_sz = seed_cnt*sizeof(fd_vm_rust_vec_t); /* No ovfl as seed_cnt << ULONG_MAX/sizeof at this point */

  /* FIXME: WHICH ALIGNOF FOR PUBKEY?  OTHER CODE USES
     ALIGNOF(FD_PUBKEY_T) (WHICH ALSO IS 1 BUT WE SHOULD BE
     CONSISTENT)*/
  fd_pubkey_t const * program_id_haddr = fd_vm_translate_vm_to_host_const( vm, program_id_vaddr, sizeof(fd_pubkey_t), alignof(uchar) );
  fd_vm_vec_t const * seed_haddr       = fd_vm_translate_vm_to_host_const( vm, seed_vaddr,       seed_sz,             FD_VM_VEC_ALIGN );

  if( FD_UNLIKELY( (!program_id_haddr) | (!seed_haddr) ) ) return NULL;

  for( ulong i=0UL; i<seed_cnt; i++ ) {
    ulong mem_sz = seed_haddr[i].len;
    if( FD_UNLIKELY( mem_sz>FD_VM_CPI_SEED_MEM_MAX ) ) return NULL;
    /* FIXME: WHAT'S THE EXPECTED BEHAVIOR IF SRC_SZ==0? */

    void const * mem_haddr = fd_vm_translate_vm_to_host_const( vm, seed_haddr[i].addr, mem_sz, alignof(uchar) );
    if( FD_UNLIKELY( !mem_haddr ) ) return NULL;

    fd_sha256_append( sha, mem_haddr, mem_sz );
  }

  if( bump_seed ) fd_sha256_append( sha, bump_seed, 1UL );

  return fd_sha256_append( sha, program_id_haddr, sizeof(fd_pubkey_t) );
}

int
fd_vm_syscall_sol_create_program_address( /**/            void *  _vm,
                                          /**/            ulong   seed_vaddr,
                                          /**/            ulong   seed_cnt,
                                          /**/            ulong   program_id_vaddr,
                                          /**/            ulong   out_vaddr,
                                          FD_PARAM_UNUSED ulong   arg4,
                                          /**/            ulong * _ret )  {
  fd_vm_exec_context_t * vm = (fd_vm_exec_context_t *)_vm;

  int err = fd_vm_consume_compute( vm, vm_compute_budget.create_program_address_units );
  if( FD_UNLIKELY( err ) ) return err;

  fd_pubkey_t result[1];

  fd_sha256_t _sha[1];
  fd_sha256_t * sha = fd_sha256_join( fd_sha256_new( _sha ) ); /* FIXME: HAVE A SHA OBJECT THAT IS PRE-JOINED IN VM */

  fd_sha256_init( sha );
  if( FD_LIKELY( !fd_vm_partial_derive_address( vm, sha, program_id_vaddr, seed_vaddr, seed_cnt, NULL ) ) ) {
    /* FIXME: SHOULD HAVE A SHA ABORT HERE (OR HOIST ALL THE SAFETY UP
       SUCH THAT PARTIAL DERIVE ADDRESS CAN'T FAIL) */
    fd_sha256_delete( fd_sha256_leave( sha ) ); /* FIXME: SEE NOTE ABOVE */
    return FD_VM_ERR_PERM;
  }
  fd_sha256_append( sha, "ProgramDerivedAddress", 21UL );
  fd_sha256_fini( sha, result );

  fd_sha256_delete( fd_sha256_leave( sha ) ); /* FIXME: SEE NOTE ABOVE */

  ulong r0;
  if( FD_UNLIKELY( fd_ed25519_point_validate( result->key ) ) ) r0 = 1UL; /* fail if PDA overlaps a valid curve point */
  else {

    /* Note: cannot reorder - out_haddr may be an invalid pointer if PDA
       is invalid */
    fd_pubkey_t * out_haddr = fd_vm_translate_vm_to_host( vm, out_vaddr, sizeof(fd_pubkey_t), alignof(uchar) );
    if( FD_UNLIKELY( !out_haddr ) ) return FD_VM_ERR_PERM;

    memcpy( out_haddr, result->uc, sizeof(fd_pubkey_t) );
    r0 = 0UL; /* success */
  }

  *_ret = r0;
  return FD_VM_SUCCESS;
}

int
fd_vm_syscall_sol_try_find_program_address( void *  _vm,
                                            ulong   seed_vaddr,
                                            ulong   seed_cnt,
                                            ulong   program_id_vaddr,
                                            ulong   out_vaddr,
                                            ulong   bump_seed_vaddr,
                                            ulong * _ret ) {
  fd_vm_exec_context_t * vm = (fd_vm_exec_context_t *)_vm;

  /* FIXME: DOUBLE CHECK COST MODEL (WEIRD CHARGE) */
  int err = fd_vm_consume_compute( vm, vm_compute_budget.create_program_address_units );
  if( FD_UNLIKELY( err ) ) return err;

  /* Similar to create_program_address but appends a 1 byte nonce that
     decrements from 255 down to 1 until a valid PDA is found.

     Solana Labs recomputes the SHA hash for each iteration here.  We
     leverage SHA's streaming properties to precompute all but the last
     two blocks (1 data, 0 or 1 padding).  FIXME: IS THIS COMMENT
     CURRENT ... LOOKS LIKE A FULL RECOMPUTATION EVERYTIME HERE RIGHT
     NOW? (PROBABLY NEED TO ADD CHECKPT / RESTORE CALLS TO SHA TO
     SUPPORT THIS)*/

  /* Translate outputs but delay validation.  In the unlikely case that
     none of the 255 iterations yield a valid PDA, Solana Labs never
     validates whether out_vaddr is a valid pointer.  FIXME: JUST DO THE
     TRANSLATION WHEN VALID PDA IS FOUND (LIKE CREATE ABOVE)? */

  fd_pubkey_t * out_haddr       = fd_vm_translate_vm_to_host( vm, out_vaddr,       sizeof(fd_pubkey_t), alignof(uchar) );
  uchar *       bump_seed_haddr = fd_vm_translate_vm_to_host( vm, bump_seed_vaddr, 1UL,                 alignof(uchar) );

  fd_sha256_t _sha[1];
  fd_sha256_t * sha = fd_sha256_join( fd_sha256_new( _sha ) ); /* FIXME: HAVE A SHA OBJECT THAT IS PRE-JOINED IN VM */

  uchar       suffix[1];
  fd_pubkey_t result[1];
  ulong       r0  = 1UL; /* no PDA found */
  /**/        err = FD_VM_SUCCESS;
  for( ulong i=0UL; i<256UL; i++ ) {
    suffix[0] = (uchar)(255UL- i);

    fd_sha256_init( sha );
    if( FD_UNLIKELY( !fd_vm_partial_derive_address( vm, sha, program_id_vaddr, seed_vaddr, seed_cnt, suffix ) ) ) {
      /* FIXME: SHA ABORT ON FAIL? */
      err = FD_VM_ERR_PERM;
      break;
    }
    fd_sha256_append( sha, "ProgramDerivedAddress", 21UL );
    fd_sha256_fini( sha, result );

    if( FD_LIKELY( !fd_ed25519_point_validate( result->key ) ) ) { /* PDA is valid if it's not a curve point */

      /* Delayed translation and overlap check */
      /* FIXME: USE IS_NONOVERLAPPING FROM {GET,SET}RETURN? (NOTE THAT
         THIS ASSUMES XLAT REJECTS WRAPPING ADDRESS RANGES). */
      /* FIXME: DO THE OVERLAP CHECK ON THE VADDRS INSTEAD? */

      if( FD_UNLIKELY( (!out_haddr) | (!bump_seed_haddr) ) ) { err = FD_VM_ERR_PERM; break; }

      if( (ulong)out_haddr > (ulong)bump_seed_haddr ) {
        if( !(((ulong)out_haddr       - (ulong)bump_seed_haddr)>= 1UL) ) { err = FD_VM_ERR_PERM; break; }
      } else {
        if( !(((ulong)bump_seed_haddr - (ulong)out_haddr      )>=32UL) ) { err = FD_VM_ERR_PERM; break; }
      }

      memcpy( out_haddr, result, sizeof(fd_pubkey_t) );
      *bump_seed_haddr = (uchar)*suffix;
      r0  = 0UL; /* PDA found */
      break;
    }

    /* FIXME: DOUBLE CHECK COST MODEL (THIS IS A WEIRD BUT PLAUSIBLE
       PLACE AND A WEIRD AMOUNT) */
    err = fd_vm_consume_compute( vm, vm_compute_budget.create_program_address_units );
    if( FD_UNLIKELY( err ) ) break;
  }

  fd_sha256_delete( fd_sha256_leave( sha ) ); /* See note above */

  if( FD_LIKELY( !err ) ) *_ret = r0;
  return err;
}
