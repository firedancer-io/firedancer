#ifndef HEADER_fd_src_util_simd_fd_neon_h
#define HEADER_fd_src_util_simd_fd_neon_h

#if FD_HAS_ARM

#include "../bits/fd_bits.h"
#include <arm_neon.h>

/* Constants for 128-bit NEON (4-wide 32-bit) */
#define V_WIDTH         (4)
#define V_FOOTPRINT    (16)
#define V_ALIGN        (16)
#define V_LG_WIDTH      (2)
#define V_LG_FOOTPRINT  (4)
#define V_LG_ALIGN      (4)
#define V_ATTR         __attribute__((aligned(V_ALIGN)))

/* Baseline NEON types */
typedef uint32x4_t wwu;
typedef int32x4_t  wwi;
typedef float32x4_t wwf;

/* Include sub-headers as they are implemented */
#include "fd_neon_vi.h"
#include "fd_neon_vu.h"

#else
#error "Build target does not support NEON wrappers"
#endif

#endif /* HEADER_fd_src_util_simd_fd_neon_h */
