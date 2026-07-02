#!/usr/bin/env bash

# Generates the colon-separated file list for ccache's
# extra_files_to_hash config option (CCACHE_EXTRAFILES).
#
# Background: FD_IMPORT_BINARY / FD_IMPORT_CSTR / FD_IMPORT (see
# src/util/fd_util_base.h) embed files into objects via the assembler
# .incbin directive.  The preprocessor never reads these files, so they
# appear neither in preprocessed output nor in -MD depfiles.  ccache
# therefore cannot see them and would serve a stale cached object when
# only the embedded file changed.  (This is the same blind spot that
# forces Local.mk files to declare the embeds as explicit make
# prerequisites, e.g. src/disco/gui/Local.mk.)
#
# The fix is to make ccache hash the embedded files into every cache
# key.  This script scans the source tree for FD_IMPORT* call sites
# with a string-literal path (paths are repo-root relative by
# convention, since compilation runs from the repo root) and prints
# them colon-separated on stdout.
#
# Exclusions:
#   - src/*/dist_cmp/** : generated at build time by Local.mk pattern
#     rules (gzip/zstd of the committed dist/ tree).  They may not
#     exist when unrelated TUs compile, and a missing extrafile makes
#     ccache fall back to an uncached compile for EVERY TU.  The
#     committed dist/ sources they derive from ARE hashed, so staleness
#     requires a system gzip/zstd behavior change; the CI canary in
#     .github/actions/ccache covers that residual risk.
#   - non-literal paths (FD_BUILD_INFO, __FILE__): FD_BUILD_INFO points
#     at $(OBJDIR)/info which CI builds with deterministic content (see
#     FD_BUILD_INFO_FIXED in config/everything.mk); __FILE__ is the TU
#     itself, which ccache already hashes as the input.
#
# Usage:
#   contrib/ccache/gen-extrafiles.sh           print colon-separated file list
#   contrib/ccache/gen-extrafiles.sh --digest  write a sha256 manifest of all
#     embed files to build/.ccache-embed-digest and print its path.  Passing
#     the (small) manifest as CCACHE_EXTRAFILES instead of the files
#     themselves is the fast path: ccache hashes extrafiles on EVERY
#     compilation (the inode cache does not cover them), and the raw set is
#     ~47MB -- ~33ms per compile, ~3s of a warm full build.  The manifest
#     carries paths + content hashes, so any embed change (or rename) still
#     changes every cache key; the 47MB is hashed once per make invocation.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."

# -z makes grep match across line breaks so call sites split over two
# lines (e.g. src/tango/test_frag_tx.c payload_2ni) are still found.
mapfile -t paths < <(
  grep -rhozE 'FD_IMPORT(_BINARY|_CSTR)?[[:space:]]*\([[:space:]]*[A-Za-z0-9_]+[[:space:]]*,[[:space:]]*"[^"]+"' \
       --include='*.c' --include='*.h' --include='*.S' src \
  | tr '\0' '\n' \
  | sed -nE 's/.*"([^"]+)"$/\1/p' \
  | grep -v '/dist_cmp/' \
  | sort -u
)

missing=0
out=""
for p in "${paths[@]}"; do
  if [[ -d "$p" || "$p" == */ ]]; then
    # Path built by string-literal concatenation, e.g.
    #   FD_IMPORT_BINARY( id, "src/ballet/sbpf/fixtures/" path )
    # The literal we captured is the directory prefix; hash every file
    # under it (over-approximation is safe, it only costs hash time).
    while IFS= read -r f; do
      out+="${out:+:}$f"
    done < <(find "${p%/}" -type f | sort)
    continue
  fi
  if [[ ! -f "$p" ]]; then
    echo "WARNING: FD_IMPORT references missing file: $p" >&2
    missing=1
    continue
  fi
  out+="${out:+:}$p"
done

if [[ -z "$out" ]]; then
  echo "ERROR: no FD_IMPORT files found; scanner is broken" >&2
  exit 1
fi

# A missing embed is not fatal here (the build itself will fail with a
# clear .incbin error if the file is truly needed), but it is loud.
if [[ "$missing" == 1 ]]; then
  echo "WARNING: some embeds missing; their TUs will fail to build anyway" >&2
fi

if [[ "${1:-}" == "--digest" ]]; then
  digest="build/.ccache-embed-digest"
  mkdir -p "$(dirname "$digest")"
  # sha256sum output is "hash  path" per line: renames and content
  # changes both alter the manifest.  Write via tmp+mv so a concurrent
  # make invocation never reads a half-written manifest.
  tr ':' '\n' <<< "$out" | xargs -d '\n' sha256sum > "$digest.tmp.$$"
  mv "$digest.tmp.$$" "$digest"
  echo "$digest"
else
  echo "$out"
fi
