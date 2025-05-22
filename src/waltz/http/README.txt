This directory contains a copy of the picohttpparser library.

This library is copied exactly from commit `66534e6`.  This commit
doesn't compile with our compilation options, so the code has a small
patch which is applied at build time.

To update the patch, just edit `fd_picohttpparser.c`, then do

 $ diff picohttpparser.c fd_picohttpparser.c > fd_picohttpparser.patch

For licensing information, refer to NOTICE in the root of this repo.
