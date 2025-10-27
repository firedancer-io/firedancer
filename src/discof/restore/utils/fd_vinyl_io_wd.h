/* fd_vinyl_io_wd.h is a vinyl_io driver that only supports O_DIRECT
   appending to a file (bypasses page cache).  This is a fast way to
   create a bstream on Linux.

   Uses synchronous blocking O_DIRECT.  If paired with a fast file
   system (e.g. XFS), and when using large block sizes (~16 MiB), does
   DMA/IOMMU-style writes. */

#include "../../../vinyl/io/fd_vinyl_io.h"

/* fd_vinyl_io_wd_{align,footprint} specify the alignment and footprint
   needed for a bstream O_DIRECT writer with a spad_max append scratch
   pad.  align will be a reasonable power-of-2 and footprint will be a
   multiple of align.  Returns 0 for an invalid spad_max. */

ulong fd_vinyl_io_wd_align    ( void );
ulong fd_vinyl_io_wd_footprint( ulong spad_max );

/* fd_vinyl_io_bd_init starts a new bstream.  lmem points to a local
   memory region with suitable alignment and footprint to hold bstream's
   state.  spad_max gives the size of the append scratch pad (should be
   a FD_VINYL_BSTREAM_BLOCK_SZ multiple).  dev_fd is a file descriptor
   for the block device / large file.  The file should already exist and
   be sized to the appropriate capacity.

   Ignores any existing file contents.  The bstream metadata user info
   will be set to the info_sz bytes at info and the bstream will use
   io_seed for its data integrity hashing seed.

   Returns a handle to the bstream on success (has ownership of lmem and
   dev_fd, ownership returned on fini) and NULL on failure (logs
   details, no ownership changed).  Retains no interest in info. */

fd_vinyl_io_t *
fd_vinyl_io_wd_init( void *       lmem,
                     ulong        spad_max,
                     int          dev_fd,
                     void const * info,
                     ulong        info_sz,
                     ulong        io_seed );

/* API restrictions:

   - Any method is unsupported (crash application if called) unless
     otherwise specified
   - Supported methods: append, commit, alloc, sync, fini
   - In-place append not supported.  All appends must use a buffer
     sourced from alloc as the input buffer. */
