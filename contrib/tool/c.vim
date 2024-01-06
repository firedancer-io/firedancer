" Add some syntax highlighting for Firedancer style code
" Add these to your ~/.vim/after/syntax/c.vim (or appropriate as per your
" level of vi-fu)

" Versioning

syn keyword cConstant     FD_VERSION_MAJOR FD_VERSION_MINOR FD_VERSION_PATCH

" Build target

syn keyword cConstant     FD_HAS_HOSTED FD_HAS_ATOMIC FD_HAS_THREADS FD_HAS_INT128 FD_HAS_DOUBLE FD_HAS_ALLOCA FD_HAS_X86 FD_HAS_SSE FD_HAS_AVX

" Base development environment

syn keyword cConstant     SHORT_MIN SHORT_MAX USHORT_MAX

" Primitive types

syn keyword cType         schar uchar ushort uint ulong
syn keyword cType         int128 uint128
syn keyword cConstant     INT128_MIN INT128_MAX UINT128_MAX

" Compiler tricks

syn keyword cOperator     FD_STRINGIFY
syn keyword cOperator     FD_CONCAT2 FD_CONCAT3 FD_CONCAT4
syn keyword cOperator     FD_EXPAND_THEN_STRINGIFY
syn keyword cOperator     FD_EXPAND_THEN_CONCAT2 FD_EXPAND_THEN_CONCAT3 FD_EXPAND_THEN_CONCAT4
syn keyword cOperator     FD_VA_ARGS_SELECT
syn keyword cOperator     FD_SRC_LOCATION
syn keyword cOperator     FD_STATIC_ASSERT
syn keyword cOperator     FD_ADDRESS_OF_PACKED_MEMBER
syn keyword cStorageClass FD_PROTOTYPES_BEGIN FD_PROTOTYPES_END
syn keyword cOperator     FD_IMPORT FD_IMPORT_BINARY FD_IMPORT_CSTR

" Optimizer hints

syn keyword cStorageClass FD_RESTRICT
syn keyword cOperator     fd_type_pun fd_type_pun_const
syn keyword cOperator     FD_LIKELY FD_UNLIKELY
syn keyword cStorageClass FD_FN_PURE FD_FN_CONST FD_FN_UNUSED
syn keyword cOperator     FD_COMPILER_FORGET FD_COMPILER_UNPREDICTABLE

" Atomic tricks

syn keyword cStatement    FD_COMPILER_MFENCE
syn keyword cStatement    FD_SPIN_PAUSE FD_YIELD
syn keyword cOperator     FD_VOLATILE_CONST FD_VOLATILE
syn keyword cOperator     FD_ATOMIC_FETCH_AND_ADD FD_ATOMIC_FETCH_AND_SUB FD_ATOMIC_FETCH_AND_OR FD_ATOMIC_FETCH_AND_AND FD_ATOMIC_FETCH_AND_XOR FD_ATOMIC_ADD_AND_FETCH FD_ATOMIC_SUB_AND_FETCH FD_ATOMIC_OR_AND_FETCH FD_ATOMIC_AND_AND_FETCH FD_ATOMIC_XOR_AND_FETCH FD_ATOMIC_CAS FD_ATOMIC_XCHG
syn keyword cStorageClass FD_TL
syn keyword cStatement    FD_ONCE_BEGIN FD_ONCE_END FD_THREAD_ONCE_BEGIN FD_THREAD_ONCE_END

" Logging

syn keyword cOperator     FD_LOG_DEBUG FD_LOG_INFO FD_LOG_NOTICE FD_LOG_WARNING FD_LOG_ERR FD_LOG_CRIT FD_LOG_ALERT FD_LOG_EMERG
syn keyword cOperator     FD_LOG_HEXDUMP_DEBUG FD_LOG_HEXDUMP_INFO FD_LOG_HEXDUMP_NOTICE FD_LOG_HEXDUMP_WARNING FD_LOG_HEXDUMP_ERR FD_LOG_HEXDUMP_CRIT FD_LOG_HEXDUMP_ALERT FD_LOG_HEXDUMP_EMERG

" Testing

syn keyword cOperator     FD_TEST
