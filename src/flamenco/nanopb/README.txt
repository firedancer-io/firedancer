This directory contains a copy of the Nanopb library.

This library is copied exactly from commit `839156b`, and there are
no Firedancer specific modifications to the code.  You should not make
local modifications to nanopb.  Instead prefer to upstream changes, or
make a local patch if needed.

For licensing information, refer to NOTICE in the root of this repo.

nanopb_generator.py can be invoked like so:

  cd src/flamenco/types
  nanopb_generator.py -L "" fd_solana_block.proto
