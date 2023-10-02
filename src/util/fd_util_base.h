#ifndef HEADER_fd_src_util_fd_util_base_h
#define HEADER_fd_src_util_fd_util_base_h

/* Base development environment */

/* Compiler checks ****************************************************/

#ifdef __cplusplus

#if __cplusplus<201703L
#error "Firedancer requires C++17 or later"
#endif

#else

#if __STDC_VERSION__<201710L
#error "Firedancer requires C Standard version C17 or later"
#endif

#endif //__cplusplus

/* Versioning macros **************************************************/

/* FD_VERSION_{MAJOR,MINOR,PATCH} programmatically specify the
   firedancer version. */

#define FD_VERSION_MAJOR (0)
#define FD_VERSION_MINOR (0)
#define FD_VERSION_PATCH (0)

/* Build target capabilities ******************************************/

/* Different build targets often have different levels of support for
   various language and hardware features.  The presence of various
   features can be tested at preprocessor, compile, or run time via the
   below capability macros.

   Code that does not exploit any of these capabilities written within
   the base development environment should be broadly portable across a
   range of build targets ranging from on-chain virtual machines to
   commodity hosts to custom hardware.

   As such, highly portable yet high performance code is possible by
   writing generic implementations that do not exploit any of the below
   capabilities as a portable fallback along with build target specific
   optimized implementations that are invoked when the build target
   supports the appropriate capabilities.

   The base development itself provide lots of functionality to help
   with implementing portable fallbacks while making very minimal
   assumptions about the build targets and zero use of 3rd party
   libraries (these might make unknown additional assumptions about the
   build target, including availability of a quality implementation of
   the library on the build target). */

/* FD_HAS_HOSTED:  If the build target is hosted (e.g. resides on a host
   with a POSIX-ish environment ... practically speaking, stdio.h,
   stdlib.h, unistd.h, et al more or less behave normally ...
   pedantically XOPEN_SOURCE=700), FD_HAS_HOSTED will be 1.  It will be
   zero otherwise. */

#ifndef FD_HAS_HOSTED
#define FD_HAS_HOSTED 0
#endif

/* FD_HAS_ATOMIC:  If the build target supports atomic operations
   between threads accessing a common memory region (include threads
   that reside in different processes on a host communicating via a
   shared memory region with potentially different local virtual
   mappings).  Practically speaking, does atomic compare-and-swap et al
   work? */

#ifndef FD_HAS_ATOMIC
#define FD_HAS_ATOMIC 0
#endif

/* FD_HAS_THREADS:  If the build target supports a POSIX-ish notion of
   threads (e.g. practically speaking, global variables declared within
   a compile unit are visible to more than one thread of execution,
   pthreads.h / threading parts of C standard, the atomics parts of the
   C standard, ... more or less work normally), FD_HAS_THREADS will be
   1.  It will be zero otherwise.  FD_HAS_THREADS implies FD_HAS_HOSTED
   and FD_HAS_ATOMIC. */

#ifndef FD_HAS_THREADS
#define FD_HAS_THREADS 0
#endif

/* FD_HAS_INT128:  If the build target supports reasonably efficient
   128-bit wide integer operations, define FD_HAS_INT128 to 1 to enable
   use of them in implementations. */

#ifndef FD_HAS_INT128
#define FD_HAS_INT128 0
#endif

/* FD_HAS_DOUBLE:  If the build target supports reasonably efficient
   IEEE 754 64-bit wide double precision floating point options, define
   FD_HAS_DOUBLE to 1 to enable use of them in implementations.  Note
   that even if the build target does not, va_args handling in the C /
   C++ language requires promotion of a float in an va_arg list to a
   double.  Thus, C / C++ language that support IEEE 754 float also
   implies a minimum level of support for double (though not necessarily
   efficient or IEEE 754).  That is, even if a target does not have
   FD_HAS_DOUBLE, there might still be limited use of double in va_arg
   list handling. */

#ifndef FD_HAS_DOUBLE
#define FD_HAS_DOUBLE 0
#endif

/* FD_HAS_ALLOCA:  If the build target supports fast alloca-style
   dynamic stack memory allocation (e.g. alloca.h / __builtin_alloca
   more or less work normally), define FD_HAS_ALLOCA to 1 to enable use
   of it in implementations. */

#ifndef FD_HAS_ALLOCA
#define FD_HAS_ALLOCA 0
#endif

/* FD_HAS_X86:  If the build target supports x86 specific features and
   can benefit from x86 specific optimizations, define FD_HAS_X86.  Code
   needing more specific target features (Intel / AMD / SSE / AVX2 /
   AVX512 / etc) can specialize further as necessary with even more
   precise capabilities (that in turn imply FD_HAS_X86). */

#ifndef FD_HAS_X86
#define FD_HAS_X86 0
#endif

/* These allow even more precise targeting for X86. */

/* FD_HAS_SSE indicates the target supports Intel SSE4 style SIMD
   (basically do the 128-bit wide parts of "x86intrin.h" work).
   Recommend using the simd/fd_sse.h APIs instead of raw Intel
   intrinsics for readability and to facilitate portability to non-x86
   platforms.  Implies FD_HAS_X86. */

#ifndef FD_HAS_SSE
#define FD_HAS_SSE 0
#endif

/* FD_HAS_AVX indicates the target supports Intel AVX2 style SIMD
   (basically do the 256-bit wide parts of "x86intrin.h" work).
   Recommend using the simd/fd_avx.h APIs instead of raw Intel
   intrinsics for readability and to facilitate portability to non-x86
   platforms.  Implies FD_HAS_SSE. */

#ifndef FD_HAS_AVX
#define FD_HAS_AVX 0
#endif

/* FD_HAS_SHANI indicates that the target supports Intel SHA extensions
   which accelerate SHA-1 and SHA-256 computation.  This extension is
   also called SHA-NI or SHA_NI (Secure Hash Algorithm New
   Instructiosn).  Although proposed in 2013, they're only supported on
   Intel Ice Lake and AMD Zen CPUs and newer.  Implies FD_HAS_AVX. */

#ifndef FD_HAS_SHANI
#define FD_HAS_SHANI 0
#endif

/* FD_HAS_GFNI indicates that the target supports Intel Galois Field
 * extensions, which accelerate operations over binary extension fields,
 * especially GF(2^8).  These instructions are supported on Intel Ice
 * Lake and newer and AMD Zen4 and newer CPUs.  Implies FD_HAS_AVX. */

#ifndef FD_HAS_GFNI
#define FD_HAS_GFNI 0
#endif

/* FD_HAS_ASAN indicates that the build target is using ASAN. */
#ifndef FD_HAS_ASAN
#define FD_HAS_ASAN 0
#endif

/* FD_HAS_UBSAN indicates that the build target is using UBSAN. */
#ifndef FD_HAS_UBSAN
#define FD_HAS_UBSAN 0
#endif

/* Base development environment ***************************************/

/* The functionality provided by these vanilla headers are always
   available within the base development environment.  Notably, stdio.h
   / stdlib.h / et al at are not included here as these make lots of
   assumptions about the build target that may not be true (especially
   for on-chain and custom hardware use).  Code should prefer the fd
   util equivalents for such functionality when possible. */

#include <stdalign.h>
#include <string.h>
#include <limits.h>
#include <float.h>

/* Work around some library naming irregularites */
/* FIXME: Consider this for FLOAT/FLT, DOUBLE/DBL too? */

#define  SHORT_MIN  SHRT_MIN
#define  SHORT_MAX  SHRT_MAX
#define USHORT_MAX USHRT_MAX

/* Primitive types ****************************************************/

/* These typedefs provide single token regularized names for all the
   primitive types in the base development environment:

     char !
     schar !   short   int   long   int128 !!
     uchar    ushort  uint  ulong  uint128 !!
     float
     double !!!

   ! Does not assume the sign of char.  A naked char should be treated
     as cstr character and mathematical operations should be avoided on
     them.  This is less than ideal as the patterns for integer types in
     the C/C++ language spec itself are far more consistent with a naked
     char naturally being treated as signed (see above).  But there are
     lots of conflicts between architectures, languages and standard
     libraries about this so any use of a naked char shouldn't assume
     the sign ... sigh.

   !! Only available if FD_HAS_INT128 is defined

   !!! Should only used if FD_HAS_DOUBLE is defined but see note in
       FD_HAS_DOUBLE about C/C++ silent promotions of float to double in
       va_arg lists.

   Note also that these token names more naturally interoperate with
   integer constant declarations, type generic code generation
   techniques, with printf-style format strings than the stdint.h /
   inttypes.h handling.

   To minimize portability issues, unexpected silent type conversion
   issues, align with typical developer implicit usage, align with
   typical build target usage, ..., assumes char / short / int / long
   are 8 / 16 / 32 / 64 twos complement integers and float is IEEE-754
   single precision.  Further assumes little endian, truncating signed
   integer divison, sign extending (arithmetic) signed right shift and
   signed left shift behaves the same as an unsigned left shift from bit
   operations point of view (technically the standard says signed left
   shift is undefined if the result would overflow).  Also, except for
   int128/uint128, assumes that aligned access to these will be
   naturally atomic.  Lastly assumes that unaligned access to these is
   functionally valid but does not assume that unaligned access to these
   is efficient or atomic.

   For values meant to be held in registers, code should prefer long /
   ulong types (improves asm generation given the prevalence of 64-bit
   targets and also to avoid lots of tricky bugs with silent promotions
   in the language ... e.g. ushort should ideally only be used for
   in-memory representations).

   These are currently not prefixed given how often they are used.  If
   this becomes problematic prefixes can be added as necessary.
   Specifically, C++ allows typedefs to be defined multiple times so
   long as they are equivalent.  Inequivalent collisions are not
   supported but should be rare (e.g. if a 3rd party header thinks
   "ulong" should be something other an "unsigned long", the 3rd party
   header probably should be nuked from orbit).  C11 and forward also
   allow multiple equivalent typedefs.  C99 and earlier don't but this
   is typically only a warning and then only if pedantic warnings are
   enabled.  Thus, if we want to support users using C99 and earlier who
   want to do a strict compile and have a superfluous collision with
   these types in other libraries, uncomment the below (or do something
   equivalent for the compiler). */

//#pragma GCC diagnostic push
//#pragma GCC diagnostic ignored "-Wpedantic"

typedef signed char schar; /* See above note of sadness */

typedef unsigned char  uchar;
typedef unsigned short ushort;
typedef unsigned int   uint;
typedef unsigned long  ulong;

#if FD_HAS_INT128

__extension__ typedef          __int128  int128;
__extension__ typedef unsigned __int128 uint128;

#define UINT128_MAX (~(uint128)0)
#define  INT128_MAX ((int128)(UINT128_MAX>>1))
#define  INT128_MIN (-INT128_MAX-(int128)1)

#endif

//#pragma GCC diagnostic pop

/* Compiler tricks ****************************************************/

/* FD_STRINGIFY,FD_CONCAT{2,3,4}:  Various macros for token
   stringification and pasting.  FD_STRINGIFY returns the argument as a
   cstr (e.g. FD_STRINGIFY(foo) -> "foo").  FD_CONCAT* pastes the tokens
   together into a single token (e.g.  FD_CONCAT3(a,b,c) -> abc).  The
   EXPAND variants first expand their arguments and then do the token
   operation (e.g.  FD_EXPAND_THEN_STRINGIFY(__LINE__) -> "104" if done
   on line 104 of the source code file). */

#define FD_STRINGIFY(x)#x
#define FD_CONCAT2(a,b)a##b
#define FD_CONCAT3(a,b,c)a##b##c
#define FD_CONCAT4(a,b,c,d)a##b##c##d

#define FD_EXPAND_THEN_STRINGIFY(x)FD_STRINGIFY(x)
#define FD_EXPAND_THEN_CONCAT2(a,b)FD_CONCAT2(a,b)
#define FD_EXPAND_THEN_CONCAT3(a,b,c)FD_CONCAT3(a,b,c)
#define FD_EXPAND_THEN_CONCAT4(a,b,c,d)FD_CONCAT4(a,b,c,d)

/* FD_SRC_LOCATION returns a const cstr holding the line of code where
   FD_SRC_LOCATION was used. */

#define FD_SRC_LOCATION __FILE__ "(" FD_EXPAND_THEN_STRINGIFY(__LINE__) ")"

/* FD_STATIC_ASSERT tests at compile time if c is non-zero.  If not,
   it aborts the compile with an error.  err itself should be a token
   (e.g. not a string, no whitespace, etc). */

#ifdef __cplusplus
#define FD_STATIC_ASSERT(c,err) static_assert(c, #err)
#else
#define FD_STATIC_ASSERT(c,err) _Static_assert(c, #err)
#endif

/* FD_ADDRESS_OF_PACKED_MEMBER(x):  Linguistically does &(x) but without
   recent compiler complaints that &x might be unaligned if x is a
   member of a packed datastructure.  (Often needed for interfacing with
   hardware / packets / etc.) */

#define FD_ADDRESS_OF_PACKED_MEMBER( x ) (__extension__({                                      \
    char * _fd_aopm = (char *)&(x);                                                            \
    __asm__( "# FD_ADDRESS_OF_PACKED_MEMBER(" #x ") @" FD_SRC_LOCATION : "+r" (_fd_aopm) :: ); \
    (__typeof__(&(x)))_fd_aopm;                                                                \
  }))

/* FD_PROTOTYPES_{BEGIN,END}:  Headers that might be included in C++
   source should encapsulate the prototypes of code and globals
   contained in compilation units compiled as C with a
   FD_PROTOTYPE_{BEGIN,END} pair. */

#ifdef __cplusplus
#define FD_PROTOTYPES_BEGIN extern "C" {
#else
#define FD_PROTOTYPES_BEGIN
#endif

#ifdef __cplusplus
#define FD_PROTOTYPES_END }
#else
#define FD_PROTOTYPES_END
#endif

/* FD_IMPORT declares a variable name and initializes with the contents
   of the file at path (with potentially some assembly directives for
   additional footer info).  It is equivalent to:

     type const name[] __attribute__((aligned(align))) = {

       ... code that would initialize the contents of name to the
       ... raw binary data found in the file at path at compile time
       ... (with any appended information as specified by footer)

     };

     ulong const name_sz = ... number of bytes pointed to by name;

   More precisely, this creates a symbol "name" in the object file that
   points to a read-only copy of the raw data in the file at "path" as
   it was at compile time.  "align" is an unsuffixed power-of-two that
   specifies the minimum alignment required for the copy's first byte.
   footer are assembly commands to permit additional data to be appended
   to the copy (use "" for footer if no footer is necessary).

   Then it exposes a pointer to this copy in the current compilation
   unit as name and the byte size as name_sz.  name_sz covers the first
   byte of the included data to the last byte of the footer inclusive.

   The dummy linker symbol _fd_import_name_sz will also be created in
   the object file as some under the hood magic to make this work.  This
   should not be used in any compile unit as some compilers (I'm looking
   at you clang-15, but apparently not clang-10) will sometimes mangle
   its value from what it was set to in the object file even marked as
   absolute in the object file.

   This should only be used at global scope and should be done at most
   once over all object files / libraries used to make a program.  If
   other compilation units want to make use of an import in a different
   compilation unit, they should declare:

     extern type const name[] __attribute__((aligned(align)));

   and/or:

     extern ulong const name_sz;

   as necessary (that is, do the usual to use name and name_sz as shown
   for the pseudo code above).

   Important safety tip!  gcc -M will generally not detect the
   dependency this creates between the importing file and the imported
   file.  This can cause incremental builds to miss changes to the
   imported file.  Ideally, we would have FD_IMPORT automatically do
   something like:

     _Pragma( "GCC dependency \"" path "\" )

   This doesn't work as is because _Pragma needs some macro expansion
   hacks to accept this (this is doable).  After that workaround, this
   still doesn't work because, due to tooling limitations, the pragma
   path is relative to the source file directory and the FD_IMPORT path
   is relative to the the make directory (working around this would
   require a __FILE__-like directive for the source code directory base
   path).  Even if that did exist, it might still not work because
   out-of-tree builds often require some substitions to the gcc -M
   generated dependencies that this might not pick up (at least not
   without some build system surgery).  And then it still wouldn't work
   because gcc -M seems to ignore all of this anyways (which is the
   actual show stopper as this pragma does something subtly different
   than what the name suggests and there isn't any obvious support for a
   "pseudo-include".)  Another reminder that make clean and fast builds
   are our friend. */

#define FD_IMPORT( name, path, type, align, footer )         \
  __asm__( ".section .rodata,\"a\",@progbits\n"              \
           ".type " #name ",@object\n"                       \
           ".globl " #name "\n"                              \
           ".align " #align "\n"                             \
           #name ":\n"                                       \
           ".incbin \"" path "\"\n"                          \
           footer "\n"                                       \
           ".size " #name ",. - " #name "\n"                 \
           "_fd_import_" #name "_sz = . - " #name "\n"       \
           ".type " #name "_sz,@object\n"                    \
           ".globl " #name "_sz\n"                           \
           ".align 8\n"                                      \
           #name "_sz:\n"                                    \
           ".quad _fd_import_" #name "_sz\n"                 \
           ".size " #name "_sz,8\n"                          \
           ".previous\n" );                                  \
  extern type  const name[] __attribute__((aligned(align))); \
  extern ulong const name##_sz

/* FD_IMPORT_{BINARY,CSTR} are common cases for FD_IMPORT.

   In BINARY, the file is imported into the object file and exposed to
   the caller as a uchar binary data.  name_sz will be the number of
   bytes in the file at time of import.  name will have 128 byte
   alignment.

   In CSTR, the file is imported into the object caller with a '\0'
   termination appended and exposed to the caller as a cstr.  Assuming
   the file is text (i.e. has no internal '\0's), strlen(name) will the
   number of bytes in the file and name_sz will be strlen(name)+1.  name
   can have arbitrary alignment. */

#define FD_IMPORT_BINARY(name, path) FD_IMPORT( name, path, uchar, 128, ""        )
#define FD_IMPORT_CSTR(  name, path) FD_IMPORT( name, path,  char,   1, ".byte 0" )

/* Optimizer tricks ***************************************************/

/* FD_RESTRICT is a pointer modifier for to designate a pointer as
   restricted.  Hoops jumped because C++-17 still doesn't understand
   restrict ... sigh */

#ifndef FD_RESTRICT
#ifdef __cplusplus
#define FD_RESTRICT __restrict
#else
#define FD_RESTRICT restrict
#endif
#endif

/* fd_type_pun(p), fd_type_pun_const(p):  These allow use of type
   punning while keeping strict aliasing optimizations enabled (e.g.
   some UNIX APIs, like sockaddr related APIs are dependent on type
   punning).  These allow these API's to be used cleanly while keeping
   strict aliasing optimizations enabled and strict alias checking done. */

static inline void *
fd_type_pun( void * p ) {
  __asm__( "# fd_type_pun @" FD_SRC_LOCATION : "+r" (p) :: "memory" );
  return p;
}

static inline void const *
fd_type_pun_const( void const * p ) {
  __asm__( "# fd_type_pun_const @" FD_SRC_LOCATION : "+r" (p) :: "memory" );
  return p;
}

/* FD_{LIKELY,UNLIKELY}(c):  Evaluates c and returns whether it is
   logical true/false as long (1L/0L).  It also hints to the optimizer
   whether it should optimize for the case of c evaluating as
   true/false. */

#define FD_LIKELY(c)   __builtin_expect( !!(c), 1L )
#define FD_UNLIKELY(c) __builtin_expect( !!(c), 0L )

/* FD_FN_PURE hints to the optimizer that the function, roughly
   speaking, does not have side effects.  As such, the compiler can
   replace a call to the function with the result of an earlier call to
   that function provide the inputs and memory used hasn't changed. */

#define FD_FN_PURE __attribute__((pure))

/* FD_FN_CONST is like pure but also, even stronger, indicates that the
   function does not depend on the state of memory. */

#define FD_FN_CONST __attribute__((const))

/* FD_FN_UNUSED indicates that it is okay if the function with static
   linkage is not used.  Allows working around -Winline in header only
   APIs where the compiler decides not to actually inline the function.
   (This belief, frequently promulagated by anti-macro cults, that "An
   Inline Function is As Fast As a Macro" ... an entire section in gcc's
   documentation devoted to it in fact ... remains among the biggest
   lies in computer science.  Yes, an inline function is as fast as a
   macro ... when the compiler actually decides to treat the inline
   keyword more than just for entertainment purposes only.  Which, as
   -Winline proves, it frequently doesn't.  Sigh ... force_inline like
   compiler extensions might be an alternative here but they have their
   own portability issues.) */

#define FD_FN_UNUSED __attribute__((unused))

/* FD_WARN_UNUSED tells the compiler the result (from a function) should
   be checked. This is useful to force callers to either check the result
   or deliberately and explicitly ignore it. Good for result codes and
   errors */

#define FD_WARN_UNUSED __attribute__ ((warn_unused_result))

/* FD_COMPILER_FORGET(var):  Tells the compiler that it shouldn't use
   any knowledge it has about the provided register-compatible variable
   var for optimizations going forward (i.e. the variable has changed in
   a deterministic but unknown-to-the-compiler way where the actual
   change is the identity operation).  Useful for inhibiting various
   branch nest misoptimizations (compilers unfortunately tend to
   radically underestimate the impact in raw average performance and
   jitter and the probability of branch mispredicts or the cost to the
   CPU of having lots of branches).  This is not asm volatile (use
   UNPREDICTABLE below for that) and has no clobbers.  So if var is not
   used after the forget, the compiler can optimize the FORGET away
   (along with operations preceeding it used to produce var). */

#define FD_COMPILER_FORGET(var) __asm__( "# FD_COMPILER_FORGET(" #var ")@" FD_SRC_LOCATION : "+r" (var) )

/* FD_COMPILER_UNPREDICTABLE(var):  Same as FD_COMPILER_FORGET(var) but
   the provided variable has changed in a non-deterministic way from the
   compiler's POV (e.g. the value in the variable on output should not
   be treated as a compile time constant even if it is one
   linguistically).  Useful for suppressing unwanted
   compile-time-const-based optimizations like hoisting operations with
   useful CPU side effects out of a critical loop. */

#define FD_COMPILER_UNPREDICTABLE(var) __asm__ __volatile__( "# FD_COMPILER_UNPREDICTABLE(" #var ")@" FD_SRC_LOCATION : "+r" (var) )

/* Atomic tricks ******************************************************/

/* FD_COMPILER_MFENCE():  Tells the compiler that that it can't move any
   memory operations (load or store) from before the MFENCE to after the
   MFENCE (and vice versa).  The processor itself might still reorder
   around the fence though (that requires platform specific fences). */

#define FD_COMPILER_MFENCE() __asm__ __volatile__( "# FD_COMPILER_MFENCE()@" FD_SRC_LOCATION ::: "memory" )

/* FD_SPIN_PAUSE():  Yields the logical core of the calling thread to
   the other logical cores sharing the same underlying physical core for
   a few clocks without yielding it to the operating system scheduler.
   Typically useful for shared memory spin polling loops, especially if
   hyperthreading is in use. */

#if FD_HAS_X86
#define FD_SPIN_PAUSE() __builtin_ia32_pause()
#else
#define FD_SPIN_PAUSE() ((void)0)
#endif

/* FD_YIELD():  Yields the logical core of the calling thread to the
   operating system scheduler if a hosted target and does a spin pause
   otherwise. */

#if FD_HAS_HOSTED
#define FD_YIELD() fd_yield()
#else
#define FD_YIELD() FD_SPIN_PAUSE()
#endif

/* FD_VOLATILE_CONST(x):  Tells the compiler is not able to predict the
   value obtained by dereferencing x and that deferencing x might have
   other side effects (e.g. maybe another thread could change the value
   and the compiler has no way of knowing this).  Generally speaking,
   the volatile keyword is broken linguistically.  Volatility is not a
   property of the variable but of the deferencing of a variable (e.g.
   what is volatile from the POV of a reader of a shared variable is not
   necessarily volatile from the POV a writer of that shared variable in
   a different thread). */

#define FD_VOLATILE_CONST(x) (*((volatile const __typeof__((x)) *)&(x)))

/* FD_VOLATILE(x): tells the compiler is not able to predict the effect
   of modifying x and that deferencing x might have other side effects
   (e.g. maybe another thread is spinning on x waiting for its value to
   change and the compiler has no way of knowing this). */

#define FD_VOLATILE(x) (*((volatile __typeof__((x)) *)&(x)))

#if FD_HAS_ATOMIC

/* FD_ATOMIC_FETCH_AND_{ADD,SUB,OR,AND,XOR}(p,v):

   FD_ATOMIC_FETCH_AND_ADD(p,v) does
     f = *p;
     *p = f + v
     return f;
   as a single atomic operation.  Similarly for the other variants. */

#define FD_ATOMIC_FETCH_AND_ADD(p,v) __sync_fetch_and_add( (p), (v) )
#define FD_ATOMIC_FETCH_AND_SUB(p,v) __sync_fetch_and_sub( (p), (v) )
#define FD_ATOMIC_FETCH_AND_OR( p,v) __sync_fetch_and_or(  (p), (v) )
#define FD_ATOMIC_FETCH_AND_AND(p,v) __sync_fetch_and_and( (p), (v) )
#define FD_ATOMIC_FETCH_AND_XOR(p,v) __sync_fetch_and_xor( (p), (v) )

/* FD_ATOMIC_{ADD,SUB,OR,AND,XOR}_AND_FETCH(p,v):

   FD_ATOMIC_{ADD,SUB,OR,AND,XOR}_AND_FETCH(p,v) does
     r = *p + v;
     *p = r;
     return r;
   as a single atomic operation.  Similarly for the other variants. */

#define FD_ATOMIC_ADD_AND_FETCH(p,v) __sync_add_and_fetch( (p), (v) )
#define FD_ATOMIC_SUB_AND_FETCH(p,v) __sync_sub_and_fetch( (p), (v) )
#define FD_ATOMIC_OR_AND_FETCH( p,v) __sync_or_and_fetch(  (p), (v) )
#define FD_ATOMIC_AND_AND_FETCH(p,v) __sync_and_and_fetch( (p), (v) )
#define FD_ATOMIC_XOR_AND_FETCH(p,v) __sync_xor_and_fetch( (p), (v) )

/* FD_ATOMIC_CAS(p,c,s):

   o = FD_ATOMIC_CAS(p,c,s) conceptually does:
     o = *p;
     if( o==c ) *p = s;
     return o
   as a single atomic operation. */

#define FD_ATOMIC_CAS(p,c,s) __sync_val_compare_and_swap( (p), (c), (s) )

/* FD_ATOMIC_XCHG(p,v):

   o = FD_ATOMIC_XCHG( p, v ) conceptually does:
     o = *p
     *p = v
     return o
   as a single atomic operation.

   Intel's __sync compiler extensions from the days of yore mysteriously
   implemented atomic exchange via the very misleadingly named
   __sync_lock_test_and_set.  And some implementations (and C++)
   debatably then implemented this API according to what the misleading
   name implied as opposed to what it actually did.  But those
   implementations didn't bother to provide an replacment for atomic
   exchange functionality (forcing us to emulate atomic exchange more
   slowly via CAS there).  Sigh ... we do what we can to fix this up. */

#ifndef FD_ATOMIC_XCHG_STYLE
#if FD_HAS_X86 && !__cplusplus
#define FD_ATOMIC_XCHG_STYLE 1
#else
#define FD_ATOMIC_XCHG_STYLE 0
#endif
#endif

#if FD_ATOMIC_XCHG_STYLE==0
#define FD_ATOMIC_XCHG(p,v) (__extension__({                                                                            \
    __typeof__(*(p)) * _fd_atomic_xchg_p = (p);                                                                         \
    __typeof__(*(p))   _fd_atomic_xchg_v = (v);                                                                         \
    __typeof__(*(p))   _fd_atomic_xchg_t;                                                                               \
    for(;;) {                                                                                                           \
      _fd_atomic_xchg_t = FD_VOLATILE_CONST( *_fd_atomic_xchg_p );                                                      \
      if( FD_LIKELY( __sync_bool_compare_and_swap( _fd_atomic_xchg_p, _fd_atomic_xchg_t, _fd_atomic_xchg_v ) ) ) break; \
      FD_SPIN_PAUSE();                                                                                                  \
    }                                                                                                                   \
    _fd_atomic_xchg_t;                                                                                                  \
  }))
#elif FD_ATOMIC_XCHG_STYLE==1
#define FD_ATOMIC_XCHG(p,v) __sync_lock_test_and_set( (p), (v) )
#else
#error "Unknown FD_ATOMIC_XCHG_STYLE"
#endif

#endif /* FD_HAS_ATOMIC */

/* FD_TLS:  This indicates that the variable should be thread local.

   FD_ONCE_{BEGIN,END}:  The block:

     FD_ONCE_BEGIN {
       ... code ...
     } FD_ONCE_END

   linguistically behaves like:

     do {
       ... code ...
     } while(0)

   But provides a low overhead guarantee that:
     - The block will be executed by at most once over all threads
       in a process (i.e. the set of threads which share global
       variables).
     - No thread in a process that encounters the block will continue
       past it until it has executed once.

   This implies that caller promises a ONCE block will execute in a
   finite time.  (Meant for doing simple lightweight initializations.)

   It is okay to nest ONCE blocks.  The thread that executes the
   outermost will execute all the nested once as part of executing the
   outermost.

   A ONCE implicitly provides a compiler memory fence to reduce the risk
   that the compiler will assume that operations done in the once block
   on another thread have not been done (e.g. propagating pre-once block
   variable values into post-once block code).  It is up to the user to
   provide any necessary hardware fencing (usually not necessary).

   FD_THREAD_ONCE_{BEGIN,END}:  The block:

     FD_THREAD_ONCE_BEGIN {
       ... code ...
     } FD_THREAD_ONCE_END;

   is similar except the guarantee is that the block only covers the
   invoking thread and it does not provide any fencing.  If a thread
   once begin is nested inside a once begin, that thread once begin will
   only be executed on the thread that executes the thread once begin.
   It is similarly okay to nest ONCE block inside a THREAD_ONCE block. */

#if FD_HAS_THREADS /* Potentially more than one thread in the process */

#ifndef FD_TLS
#define FD_TLS __thread
#endif

#define FD_ONCE_BEGIN do {                                                \
    FD_COMPILER_MFENCE();                                                 \
    static volatile int _fd_once_block_state = 0;                         \
    for(;;) {                                                             \
      int _fd_once_block_tmp = _fd_once_block_state;                      \
      if( FD_LIKELY( _fd_once_block_tmp>0 ) ) break;                      \
      if( FD_LIKELY( !_fd_once_block_tmp ) &&                             \
          FD_LIKELY( !FD_ATOMIC_CAS( &_fd_once_block_state, 0, -1 ) ) ) { \
        do

#define FD_ONCE_END               \
        while(0);                 \
        FD_COMPILER_MFENCE();     \
        _fd_once_block_state = 1; \
        break;                    \
      }                           \
      FD_YIELD();                 \
    }                             \
  } while(0)

#define FD_THREAD_ONCE_BEGIN do {                        \
    static FD_TLS int _fd_thread_once_block_state = 0;   \
    if( FD_UNLIKELY( !_fd_thread_once_block_state ) ) {  \
      do

#define FD_THREAD_ONCE_END             \
      while(0);                        \
      _fd_thread_once_block_state = 1; \
    }                                  \
  } while(0)

#else /* Only one thread in the process */

#ifndef FD_TLS
#define FD_TLS /**/
#endif

#define FD_ONCE_BEGIN do {                       \
    static int _fd_once_block_state = 0;         \
    if( FD_UNLIKELY( !_fd_once_block_state ) ) { \
      do

#define FD_ONCE_END             \
      while(0);                 \
      _fd_once_block_state = 1; \
    }                           \
  } while(0)

#define FD_THREAD_ONCE_BEGIN FD_ONCE_BEGIN
#define FD_THREAD_ONCE_END   FD_ONCE_END

#endif

FD_PROTOTYPES_BEGIN

/* fd_memcpy(d,s,sz):  On modern x86 in some circumstances, rep mov will
   be faster than memcpy under the hood (basically due to RFO /
   read-for-ownership optimizations in the cache protocol under the hood
   that aren't easily done from the ISA ... see Intel docs on enhanced
   rep mov).  Compile time configurable though as this is not always
   true.  So application can tune to taste.  Hard to beat rep mov for
   code density though (2 bytes) and pretty hard to beat in situations
   needing a completely generic memcpy.  But it can be beaten in
   specialized situations for the usual reasons. */

/* FIXME: CONSIDER MEMCMP TOO! */
/* FIXME: CONSIDER MEMCPY RELATED FUNC ATTRS */

#ifndef FD_USE_ARCH_MEMCPY
#define FD_USE_ARCH_MEMCPY 1
#endif

#if FD_HAS_X86 && FD_USE_ARCH_MEMCPY

static inline void *
fd_memcpy( void       * FD_RESTRICT d,
           void const * FD_RESTRICT s,
           ulong                    sz ) {
  void * p = d;
  __asm__ __volatile__( "rep movsb" : "+D" (p), "+S" (s), "+c" (sz) :: "memory" );
  return d;
}

#else

static inline void *
fd_memcpy( void       * FD_RESTRICT d,
           void const * FD_RESTRICT s,
           ulong                    sz ) {
//if( FD_UNLIKELY( !sz ) ) return d; /* Standard says sz 0 is UB, uncomment if target is insane and doesn't treat sz 0 as a nop */
  return memcpy( d, s, sz );
}

#endif

/* fd_memset(d,c,sz): architecturally optimized memset.  See fd_memcpy
   for considerations. */

/* FIXME: CONSIDER MEMSET RELATED FUNC ATTRS */

#ifndef FD_USE_ARCH_MEMSET
#define FD_USE_ARCH_MEMSET 1
#endif

#if FD_HAS_X86 && FD_USE_ARCH_MEMSET

static inline void *
fd_memset( void  * d,
           int     c,
           ulong   sz ) {
  void * p = d;
  __asm__ __volatile__( "rep stosb" : "+D" (p), "+c" (sz) : "a" (c) : "memory" );
  return d;
}

#else

static inline void *
fd_memset( void  * d,
           int     c,
           ulong   sz ) {
//if( FD_UNLIKELY( !sz ) ) return d; /* See fd_memcpy note */
  return memset( d, c, sz );
}

#endif

/* fd_memeq(s0,s1,sz):  Compares two blocks of memory.  Returns 1 if
   equal or sz is zero and 0 otherwise.  No memory accesses made if sz
   is zero (pointers may be invalid).  On x86, uses repe cmpsb which is
   preferable to __builtin_memcmp in some cases. */

#ifndef FD_USE_ARCH_MEMEQ
#define FD_USE_ARCH_MEMEQ 1
#endif

#if FD_HAS_X86 && FD_USE_ARCH_MEMEQ && defined(__GCC_ASM_FLAG_OUTPUTS__) && __STDC_VERSION__>=199901L

FD_FN_PURE static inline int
fd_memeq( void const * s0,
          void const * s1,
          ulong        sz ) {
  /* ZF flag is set and exported in two cases:
      a) size is zero (via test)
      b) buffer is equal (via repe cmpsb) */
  int r;
  __asm__( "test %3, %3;"
           "repe cmpsb"
         : "=@cce" (r), "+S" (s0), "+D" (s1), "+c" (sz)
         : "m" (*(char const (*)[sz]) s0), "m" (*(char const (*)[sz]) s1)
         : "cc" );
  return r;
}

#else

FD_FN_PURE static inline int
fd_memeq( void const * s1,
          void const * s2,
          ulong        sz ) {
  return 0==memcmp( s1, s2, sz );
}

#endif

/* fd_hash(seed,buf,sz), fd_hash_memcpy(seed,d,s,sz):  High quality
   (full avalanche) high speed variable length buffer -> 64-bit hash
   function (memcpy_hash is often as fast as plain memcpy).  Based on
   the xxhash-r39 (open source BSD licensed) implementation.  In-place
   and out-of-place variants provided (out-of-place variant assumes dst
   and src do not overlap).  Caller promises valid input arguments,
   cannot fail given valid inputs arguments.  sz==0 is fine. */

FD_FN_PURE ulong
fd_hash( ulong        seed,
         void const * buf,
         ulong        sz );

ulong
fd_hash_memcpy( ulong                    seed,
                void       * FD_RESTRICT d,
                void const * FD_RESTRICT s,
                ulong                    sz );

#ifndef FD_TICKCOUNT_STYLE
#if FD_HAS_X86 /* Use RTDSC */
#define FD_TICKCOUNT_STYLE 1
#else /* Use portable fallback */
#define FD_TICKCOUNT_STYLE 0
#endif
#endif

#if FD_TICKCOUNT_STYLE==0 /* Portable fallback (slow).  Ticks at 1 ns / tick */

#define fd_tickcount() fd_log_wallclock() /* TODO: fix ugly pre-log usage */

#elif FD_TICKCOUNT_STYLE==1 /* RTDSC (fast) */

/* fd_tickcount:  Reads the hardware invariant tickcounter ("RDTSC").
   This monotonically increases at an approximately constant rate
   relative to the system wallclock and is synchronous across all CPUs
   on a host.

   The rate this ticks at is not precisely defined (see Intel docs for
   more details) but it is typically in the ballpark of the CPU base
   clock frequency.  The relationship to the wallclock is very well
   approximated as linear over short periods of time (i.e. less than a
   fraction of a second) and this should not exhibit any sudden changes
   in its rate relative to the wallclock.  Notably, its rate is not
   directly impacted by CPU clock frequency adaptation / Turbo mode (see
   other Intel performance monitoring counters for various CPU cycle
   counters).  It can drift over longer period time for the usual clock
   synchronization reasons.

   This is a reasonably fast O(1) cost (~6-8 ns on recent Intel).
   Because of all compiler options and parallel execution going on in
   modern CPUs cores, other instructions might be reordered around this
   by the compiler and/or CPU.  It is up to the user to do lower level
   tricks as necessary when the precise location of this in the
   execution stream and/or when executed by the CPU is needed.  (This is
   often unnecessary as such levels of precision are not frequently
   required and often have self-defeating overheads.)

   It is worth noting that RDTSC and/or (even more frequently) lower
   level performance counters are often restricted from use in user
   space applications.  It is recommended that applications use this
   primarily for debugging / performance tuning on unrestricted hosts
   and/or when the developer is confident that applications using this
   will have appropriate permissions when deployed. */

#define fd_tickcount() ((long)__builtin_ia32_rdtsc())

#else
#error "Unknown FD_TICKCOUNT_STYLE"
#endif

#if FD_HAS_HOSTED

/* fd_yield yields the calling thread to the operating system scheduler. */

void
fd_yield( void );

#endif

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_fd_util_base_h */
