#!/bin/bash
# The dragon tile is a reliable consumer of replay's slot statuses: if
# its frag path stops returning, replay stops.  This check holds the
# tile's sources to the rules that keep the frag path from blocking:
#
#   1. The accounts database is read through one call site only, the
#      bounded read in fd_dragon_tile.c, which waits on a write in
#      progress rather than giving up, so it may only be given a frozen
#      fork.  The unbounded read is not used at all.
#   2. The core reads an account in one place only, geyser_read_sealed,
#      and only for a sealed bank (rec->complete), whose fork is frozen.
#      Its one caller is the account read for consumers.
#   3. No spin wait, sleep, or synchronous disk call in the tile's
#      sources.
#
#   contrib/dragon/frag_path_check.sh [repo root]
set -u
cd "${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}" || exit 1
SRC=$(ls src/discof/dragon/fd_*.c src/discof/dragon/fd_*.h)
ok=1
fail(){ echo "FAIL: $*"; ok=0; }

# 1. one accounts database read site, bounded
if grep -n 'fd_accdb_read_one_nocache(' $SRC; then fail "the unbounded accounts database read is used in the dragon tree"; fi
sites=$(grep -c 'fd_accdb_read_one_nocache_max(' src/discof/dragon/fd_dragon_tile.c)
others=$(grep -l 'fd_accdb_read_one_nocache_max(' $SRC | grep -v 'fd_dragon_tile.c' || true)
[ "$sites" = "1" ] && [ -z "$others" ] || fail "expected exactly one accounts database read site in fd_dragon_tile.c (found $sites there, others: ${others:-none})"
for f in $(grep -l 'fd_accdb_' $SRC); do
  grep -n 'fd_accdb_[a-z_]*(' $f | grep -vE 'fd_accdb_read_one_nocache_max\(|fd_accdb_(join|align|footprint|shmem_join|fork_id)' && fail "$f calls an accounts database function other than the bounded read"
done

# 2. the core reads accounts of sealed banks only
core=src/discof/dragon/fd_geyser_core.c
reads=$(grep -n 'read_fn( *core->read_ctx' $core | cut -d: -f1)
[ "$(echo "$reads" | grep -c .)" = "1" ] || fail "expected one account read in fd_geyser_core.c, found: $reads"
fn_start=$(grep -n '^geyser_read_sealed(' $core | tail -1 | cut -d: -f1)
fn_end=$(awk -v s="$fn_start" 'NR>s && /^}/ {print NR; exit}' $core)
[ -n "$fn_start" ] && [ "$reads" -gt "$fn_start" ] && [ "$reads" -lt "$fn_end" ] || fail "the account read is not inside geyser_read_sealed"
sed -n "${fn_start},${reads}p" $core | grep -q '!rec->complete' || fail "geyser_read_sealed reads without requiring a sealed bank"
callers=$(grep -c 'geyser_read_sealed( core' $core)
[ "$callers" = "1" ] || fail "expected geyser_read_sealed to be called from one place (consumer reads), found $callers"

# 3. nothing that waits or touches disk in the tile's sources
pat='FD_SPIN_PAUSE|while *\( *FD_VOLATILE|\bpreadv2? *\(|\bpread *\(|\bfsync *\(|\busleep *\(|\bnanosleep *\(|\bsleep *\(|\bpoll *\(|\bselect *\('
if grep -nE "$pat" $SRC | grep -vE ':\s*(/\*|\*|//)'; then fail "a waiting or disk call appears in the dragon sources"; fi

[ $ok = 1 ] && echo "PASS: dragon frag path keeps the no-blocking rules" || exit 1
