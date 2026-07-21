#!/usr/bin/env bash
# Regenerate the TEST_GIGANTIC_PAGES table embedded in run_unit_tests.sh.
#
# run_unit_tests.sh always invokes tests with `--page-sz gigantic`, so
# every test's anonymous workspace is backed by 1 GiB gigantic pages
# regardless of the test's own --page-sz default.  The number of gigantic
# pages a test needs is therefore ceil(footprint / 1 GiB), where the
# footprint is the test's own default workspace size:
#
#     footprint = default(--page-cnt) * sizeof(default(--page-sz))
#
# Most tests default to a single small page and so need exactly one
# gigantic page; the scheduler treats one page as the default.  This
# script emits the bash associative-array body for the tests that need
# MORE than one gigantic page, sorted by descending page count, so the
# scheduler can reserve their pages and avoid over-subscribing the
# hugetlbfs pool (an over-subscribed test hard-fails when
# fd_wksp_new_anonymous cannot acquire its pages).
#
# Usage:
#   contrib/test/gen_unit_test_pages.sh          # print the table
#
# Paste the output into the TEST_GIGANTIC_PAGES=( ... ) block in
# contrib/test/run_unit_tests.sh.

# Note: no `pipefail` — the inner `... | head -1` pipelines intentionally
# close early, which SIGPIPEs the upstream grep; under pipefail that would
# abort the scan loop partway through.
set -eu

cd "$(dirname "$0")/../.."

GIB=$((1<<30))

# grep is allowed to find nothing here, so guard each pipeline against
# `set -e` with `|| true`.
{
grep -rln '"--page-cnt"' src/ | while read -r f; do
  # The test's own default --page-cnt (the literal after the NULL env key).
  cnt=$( { grep -oE '"--page-cnt"[^;]*NULL,[[:space:]]*[0-9]+UL' "$f" || true; } \
         | grep -oE '[0-9]+UL' | grep -oE '[0-9]+' | head -1 )
  # The test's own default --page-sz (defaults to gigantic if unspecified).
  psz=$( { grep -oE '"--page-sz"[^;]*NULL,[[:space:]]*"(gigantic|huge|normal)"' "$f" || true; } \
         | grep -oE '(gigantic|huge|normal)' | head -1 )
  cnt=${cnt:-1}
  psz=${psz:-gigantic}
  case "$psz" in
    normal)   bytes=$(( cnt * 4096 ))    ;;
    huge)     bytes=$(( cnt * (1<<21) )) ;;
    gigantic) bytes=$(( cnt * GIB ))     ;;
  esac
  # Gigantic pages the harness must hand this test = ceil(bytes / 1 GiB).
  pages=$(( (bytes + GIB - 1) / GIB ))
  if [[ "$pages" -gt 1 ]]; then
    printf '%s %s\n' "$(basename "$f" .c)" "$pages"
  fi
done
# Groove tests size their shmem by --volume-cnt * FD_GROOVE_VOLUME_FOOTPRINT
# (1 GiB per volume), not --page-cnt.
grep -rln '"--volume-cnt"' src/ | while read -r f; do
  cnt=$( { grep -oE '"--volume-cnt"[^;]*NULL,[[:space:]]*[0-9]+UL' "$f" || true; } \
         | grep -oE '[0-9]+UL' | grep -oE '[0-9]+' | head -1 )
  cnt=${cnt:-1}
  if [[ "$cnt" -gt 1 ]]; then
    printf '%s %s\n' "$(basename "$f" .c)" "$cnt"
  fi
done
} | sort -k2 -rn -k1 | awk '{ printf "  [%s]=%s\n", $1, $2 }'
