/* Standalone object wrapper around fd_keccak256_keccak1eo.inc for HOL Light's
   define_assert_from_elf.  Exports the macro body as a single global function
   that follows the System V x86_64 ABI:

     void fd_keccak256_keccak1eo_f1600_proofobj(
            uint32_t       *state,   // rdi - 50 u32 EO state
            const uint32_t *rc_eo);  // rsi - 48 u32 round constants

   The macro itself manages the rbp/rbx prologue/epilogue, so the wrapper is
   just a label plus ret. */

.include "src/ballet/keccak256/proof/fd_keccak256_keccak1eo_proof.inc"

.text
.globl  fd_keccak256_keccak1eo_f1600_proofobj
.type   fd_keccak256_keccak1eo_f1600_proofobj, @function
fd_keccak256_keccak1eo_f1600_proofobj:
    _fd_keccak256_keccak1eo_f1600_raw %rdi, %rsi
    ret
.size   fd_keccak256_keccak1eo_f1600_proofobj, .-fd_keccak256_keccak1eo_f1600_proofobj

.section .note.GNU-stack,"",@progbits
