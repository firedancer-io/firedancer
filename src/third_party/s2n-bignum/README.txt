This directory contains a subset of the s2n-bignum library at
https://github.com/awslabs/s2n-bignum

Files are copied exactly from commit
cba3956c7a20d22f08ef6f49fe162e9d7c07867c, with no Firedancer specific
modifications.  s2n-bignum is formally verified assembly: never edit
vendored files locally, as any change invalidates the correctness
proofs.  Update only by re-running `vendor.sh` against a new pinned
commit.

Only the .S files backing symbols referenced by Firedancer are
vendored (see vendor.sh for the derivation).  On x86-64 both the ADX
and the _alt (pre-Broadwell) variants of each routine are included;
which one a binary calls is decided at C preprocess time of the
*_s2n.c wrapper TUs via __ADX__.  Unreferenced variants are dropped
at link time by archive member selection.  On aarch64 __ADX__ is
never defined so the wrappers always take the _alt redirects; only
that variant set is vendored (some arm/ files define the base symbol
and an _alt alias in one file).  include/s2n-bignum.h declares many
more functions than are vendored; calling an un-vendored one fails
loudly at link time -- rerun vendor.sh after adding the caller.

For licensing information (Apache-2.0 OR ISC OR MIT-0), see LICENSE
in this directory and NOTICE in the root of this repo.
