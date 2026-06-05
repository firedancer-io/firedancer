/* ref/fd_bn254.c — Reference (scalar) implementation of bn254 operations.
   This is a unity build: all .c files are #include'd into a single TU. */

#include "./fd_bn254_field.c"
#include "./fd_bn254_field_ext.c"
#include "../fd_bn254_glv.h"
#include "./fd_bn254_g1.c"
#include "./fd_bn254_g2.c"
#include "./fd_bn254_pairing.c"
