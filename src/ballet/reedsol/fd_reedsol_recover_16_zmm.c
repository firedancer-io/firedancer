/* Recompile the generated recovery kernel with 64-byte GFNI vectors. */
#define FD_REEDSOL_ARITH_WIDE 1
#define fd_reedsol_private_recover_var_16 fd_reedsol_private_recover_var_16_zmm
#include "fd_reedsol_recover_16.c"
