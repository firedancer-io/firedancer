/* Single translation unit for the generated VROOM backend.  Keeping the
   fixed-parameter layers together lets the C compiler inline through RNS,
   extension-field, and Miller operations just as it can for a handwritten
   straight-line kernel.  The object is compiled without semantic
   interposition so internal calls can be folded across these layers. */
#include "fd_vroom_rns.c"
#include "fd_vroom_field.c"
#include "fd_vroom_final.c"
#include "fd_vroom_miller.c"
