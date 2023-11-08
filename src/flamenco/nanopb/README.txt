This directory contains a copy of the Nanopb library.

This library is copied exactly from commit `839156b`, and there are
no Firedancer specific modifications to the code.  `pb_firedancer.h`
has a few Firedancer specific #defines, which are loaded into the
library by #define'ing the `PB_SYSTEM_HEADER` to it as part of our
build.  You should not make local modifications to nanopb.  instead
prefer to upstream changes, or make a local patch if needed.

For licensing information, refer to NOTICE in the root of this repo.
