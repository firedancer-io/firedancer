"""
CPU constraints for the x86_64 arch.
"""

constraint_setting(name = "cpu")

# Target x86-64-v2 feature level (Intel Nehalem gen).
#
# This is the lowest supported x86_64 feature level.
#
# CPU extensions:
#   CMOV, CMPXCHG8B, FPU, FXSR, MMX, FXSR, SCE, SSE, SSE2
#   CMPXCHG16B, LAHF-SAHF, POPCNT, SSE3, SSE4.1, SSE4.2, SSSE3
constraint_value(
    name = "sse_family",
    constraint_setting = ":cpu",
)

# Target x86-64-v3 feature level (Intel 4th gen).
#
# CPU extensions: `sse_family` plus
#   AVX, AVX2, BMI1, BMI2, F16C, FMA, LZCNT, MOVBE, XSAVE
constraint_value(
    name = "avx2_family",
    constraint_setting = ":cpu",
)

# Target x86-64-v4 feature level (AVX512).
#
# CPU extensions: `avx2_family` plus
#   AVX512F, AVX512BW, AVX512CD, AVX512DQ, AVX512VL
constraint_value(
    name = "avx512_family",
    constraint_setting = ":cpu",
)

# Target Icelake Server (Intel 10th gen)
#
# Feature superset of `avx512_family`.
# Corresponds to -march=icelake-server
constraint_value(
    name = "icelake_server",
    constraint_setting = ":cpu",
)
