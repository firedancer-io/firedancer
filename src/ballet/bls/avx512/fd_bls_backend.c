/* Single translation unit for the AVX-512 backend.  Keeping the
   fixed-parameter layers together lets the C compiler inline through RNS,
   extension-field, and Miller operations just as it can for a handwritten
   straight-line kernel.  The object is compiled without semantic
   interposition so internal calls can be folded across these layers. */
#include "fd_bls_rns.c"
#include "fd_bls_field.c"
#include "fd_bls_final.c"
#include "fd_bls_miller.c"
