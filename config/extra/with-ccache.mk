# Routes C/C++/asm compilation through ccache.  Intended primarily for
# CI (see .github/actions/ccache) but works for local builds too:
#
#   EXTRAS=ccache make -j
#
# Compilation only: links and archives are never cached (ccache does
# not cache them).  CC/CXX themselves are NOT modified because
# Local.mk files compare them literally (e.g. ifeq ($(CC),gcc) in
# src/app/fdctl/Local.mk); instead config/everything.mk prefixes the
# compile pattern rules with $(FD_COMPILE_PREFIX).  Objects that embed
# build-time-generated files opt out via target-specific
# FD_COMPILE_PREFIX= overrides (see config/everything.mk and
# src/disco/gui/Local.mk).
#
# Correctness configuration, in order of importance:
#
#   sloppiness=incbin + CCACHE_EXTRAFILES  FD_IMPORT_BINARY/_CSTR
#     embed files via the assembler .incbin directive, which the
#     preprocessor never sees.  ccache >= 4.9 detects .incbin in
#     preprocessed output and refuses to cache those TUs entirely
#     (Result: unsupported_code_directive) -- safe, but it makes the
#     ~60 FD_IMPORT-using TUs permanently uncacheable.  Setting
#     sloppiness=incbin re-enables caching them, which is only sound
#     because CCACHE_EXTRAFILES makes ccache hash every embedded
#     file's CONTENT into every cache key (the scanner
#     contrib/ccache/gen-extrafiles.sh enumerates them; FD_IMPORT
#     paths are string literals, so the scan is exact).  Verified
#     behavior: repeat compile = hit; embed content change = miss.
#     contrib/ccache/test-embed-canary.sh asserts both properties and
#     runs in CI (.github/actions/ccache).
#     Objects embedding build-time-GENERATED files (which the scanner
#     cannot hash at parse time) are compiled uncached instead -- see
#     the FD_COMPILE_PREFIX= target overrides in config/everything.mk.
#
#   compiler_check=content  Hash the compiler binary itself, so runner
#     image compiler upgrades (or two different builds of the same
#     version) can never share cache entries.
#
#   base_dir/hash_dir  Make cache entries shareable across different
#     checkout directories (CI workspaces, developer worktrees).
#
#   inode_cache  Avoid re-hashing the (large, rarely changing)
#     extrafiles set on every compilation.
#
# Note: cache entries are effectively per-BUILDDIR because
# -DFD_BUILD_INFO="$(OBJDIR)/info" (config/everything.mk:15) puts the
# OBJDIR path on every compile line.  Irrelevant in CI (BUILDDIR is a
# pure function of MACHINE/CC there), but locally, custom BUILDDIRs
# each warm their own key space.

CCACHE?=ccache

ifeq ($(shell command -v $(CCACHE) 2>/dev/null),)
$(error EXTRAS=ccache requires '$(CCACHE)' in PATH (see .github/actions/ccache))
endif

FD_USING_CCACHE:=1
FD_COMPILE_PREFIX:=$(CCACHE)

export CCACHE_BASEDIR:=$(CURDIR)
export CCACHE_NOHASHDIR:=1
export CCACHE_COMPILERCHECK:=content
export CCACHE_INODECACHE:=1
export CCACHE_SLOPPINESS?=incbin

# The extrafiles are passed as a small sha256 MANIFEST of the embed
# set rather than the ~47MB of files themselves: ccache re-hashes
# extrafiles on every compilation (the inode cache does not cover
# them), which costs ~33ms per compile -- the dominant warm-build
# overhead.  The manifest (hash+path per line) changes whenever any
# embed's content or path changes, so cache keys still re-key exactly
# as before; the 47MB is hashed once per make invocation instead of
# once per TU.  Scanner + digest run takes ~1s at make parse time.
#
# Callers issuing many make invocations (e.g. contrib/build.sh's
# per-target loop) can precompute it once:
#   export CCACHE_EXTRAFILES=$(contrib/ccache/gen-extrafiles.sh --digest)
# Fails loudly rather than silently building without embed protection.
ifeq ($(origin CCACHE_EXTRAFILES),environment)
export CCACHE_EXTRAFILES
else
export CCACHE_EXTRAFILES:=$(shell contrib/ccache/gen-extrafiles.sh --digest 2>/dev/null)
endif
ifeq ($(CCACHE_EXTRAFILES),)
$(error contrib/ccache/gen-extrafiles.sh produced no output; refusing to build with ccache and no embed hashing)
endif

# Make the $(OBJDIR)/info blob deterministic (see the info rule in
# config/everything.mk) so fd_log.o -- which embeds it via
# FD_IMPORT_CSTR -- is cacheable too.  Without this, fd_log.o would
# embed date/user/git-status and is therefore compiled uncached.
# Override with FD_FIXED_BUILD_INFO= to keep the volatile blob (at the
# cost of an uncached fd_log.o compile + relink every build).
FD_FIXED_BUILD_INFO?=1
ifeq ($(FD_FIXED_BUILD_INFO),)
undefine FD_FIXED_BUILD_INFO
endif
