#ifndef HEADER_fd_src_disco_topo_fd_topo_h
#define HEADER_fd_src_disco_topo_fd_topo_h

/* The topology of Firedancer is the arrangement of the various objects,
   links, tiles, workspaces, CPU cores, and so on with respect to each
   other.

   Topology exists to support the following things,

    * Responding to queries about the system.  For example, "How many
      tiles are there?" or "How many mcaches does this tile read from?".
      It is also used for more complicated queries like "How large does
      this workspace need to be fit all the objects in it?" or "How much
      memory will this tile need to mlock?"

    * Allowing flexible definition of the system.  We want to easily be
      able to change things like the number of tiles, which cores they
      run on, or what links they consume.

    * Enabling extensibility of the system.  Different modules might
      want to define new objects and use them at runtime, without all
      other parts of the toplogy needing to know about them.

    * Enabling auto-discovery for tools and external code like the
      monitoring binary.

  The topology can be thought of as a graph.  The nodes are the various
  workspaces, links, and tiles.  The edges are the relationships between
  them (which link is in which workspace, which tile reads from which
  link).

  The fd_pod, a generic in-memory key value store is used to define and
  store the topology.  The pod, and by extension the topology definition
  is extensible, flexible, and supports multi language consumers.

  Although the pod is extensible and flexible, it is unwieldy to work
  with because all vertices and edges are just lists of key-value pairs.
  For most consumers, it is better to have a pre-constructed object
  graph in memory.

  This object graph is not extensible and can't support user-configured
  data, but it is very useful for routine use.  We tag the object graph
  with the underlying pod keys, so that we can always go back to the pod
  if needed.

  The object graph is specified below, and can be constructed as a view
  over the underlying pod data.  The object graph shouldn't be modified
  once it's constructed, but it can be augmented.  The main ways to do
  this are

   1. Attaching to a topology.  This is the process of mapping the
      underlying memory of the workspaces into the address space of the
      calling process, and uses `mmap(2)`.  A tile will attach to the
      workspaces it needs to run, but a monitoring tool might attach to
      all of the workspaces.

   2. Joining objects.  Once a topology is attached to the process, it
      can be joined, which consists of joining all the standard objects
      in it.  Joining the topology will update some pointers into the
      object graph view so that the objects can be referred to easily.

   3. Detaching.  This is the opposite of attaching, and will unmap the
      workspaces from the address space of the calling process.

  As well as providing these convenience overlay functions, a topology
  supports one core function, which is to run the tiles.  This can be
  done in two ways, either in a single process, or in multiple
  processes.  Single process mode is useful for debugging and tooling,
  although is not used in production. */

#include "../fd_disco_base.h"

#include "../quic/fd_tpu.h"

#define FD_TOPO_WKSP_MAX 32UL
#define FD_TOPO_TILE_MAX 64UL
#define FD_TOPO_LINK_MAX 128UL
#define FD_TOPO_TILE_IN_MAX 32UL
#define FD_TOPO_LINK_OUT_MAX 32UL

#define FD_TOPO_WKSP_MMAP_MODE_NONE  (0)
#define FD_TOPO_WKSP_MMAP_MODE_READ  (1)
#define FD_TOPO_WKSP_MMAP_MODE_WRITE (2)

/* A fd_topo_wksp_sz is returned when querying the size of a workspace.
   The workspace sizing is non-trivial.  It consists of a "known
   footprint", which is space we know the workspace will need in
   advance, which is then padded with a "loose footprint" which is how
   much extra space we would like to leave in the workspace for runtime
   allocations.  This is then aligned up to the page size. */

struct fd_topo_wksp_sz {
  /* The maximum number of partitions supported by the workspace.  See
     details in fd_wksp.h */

  ulong part_max;

  /* The total size in bytes required to store all the objects which
     will be placed in this workspace.  This includes padding and
     alignment. */

  ulong known_footprint;

  /* The total size in bytes of the data region of the workspace.  This
     is the total workspace size, less the header and padding of the
     workspace struct itself.  It is not the size of the actual
     workspace in memory, which can be retrieved with page_sz * page_cnt */

  ulong total_footprint;

  /* The size of pages underlying the workspace.  Will be either
     FD_SHMEM_GIGANTIC_PAGE_SZ or FD_SHMEM_HUGE_PAGE_SZ.
     
     The topology uses huge pages if the total footprint size is less
     than 8MiB, otherwise it will use gigantic pages. */

  ulong page_sz;

  /* The number of pages required to store the workspace. */

  ulong page_cnt;
};

typedef struct fd_topo_wksp_sz fd_topo_wksp_sz_t;

/* The fd_topo_memory is returned by functions relating to how much
   memory components will require.  For example, we can ask how much
   memory a tile will mlock, which will consist of normal, huge, and
   gigantic pages. */

struct fd_topo_memory {
  ulong normal_page_cnt;
  ulong huge_page_cnt;
  ulong gigantic_page_cnt;

  ulong total_sz;
};

typedef struct fd_topo_memory fd_topo_memory_t;

struct fd_topo_run_tile_args {
  ulong rlimit_file_cnt;

  void  (* join_privileged )( void * shmem, uchar const * pod, char const * id );
  ulong (* seccomp_policy  )( void * shmem, struct sock_filter * out, ulong out_cnt );
  ulong (* allowed_fds     )( void * shmem, int * out, ulong out_cnt );
  void  (* join            )( void * shmem, uchar const * pod, char const * id );
  void  (* run             )( void * shmem, fd_cnc_t * cnc, ulong in_cnt, fd_frag_meta_t const ** in_mcache, ulong ** in_fseq, fd_frag_meta_t * mcache, ulong out_cnt, ulong ** out_fseq );
};

typedef struct fd_topo_run_tile_args fd_topo_run_tile_args_t;

typedef struct fd_topo_wksp fd_topo_wksp_t;
typedef struct fd_topo_link fd_topo_link_t;
typedef struct fd_topo_link_in fd_topo_link_in_t;
typedef struct fd_topo_cnc fd_topo_cnc_t;
typedef struct fd_topo_tile fd_topo_tile_t;
typedef struct fd_topo_metrics fd_topo_metrics_t;
typedef struct fd_topo_fseq fd_topo_fseq_t;
typedef struct fd_topo fd_topo_t;

/* A workspace is a Firedancer specific memory management structure
   that sits on top of 1 or more memory mapped gigantic or huge pages
   mounted on a hugetlbfs.

   A workspace corresponds to one file in the hugetlbfs and almost
   all memory in Firedancer is allocated out of workspaces. */

struct fd_topo_wksp {
  ulong        idx;
  fd_topo_t *  topo;

  char         name[ 13UL ];

  ulong loose_sz;
  fd_topo_wksp_sz_t sz;

  ulong contains_cnt;
  char const * contains[ 256UL ];

  fd_wksp_t * wksp;
};

/* A link is a message passing channel between two tiles.  It is
   single producer multi consumer, and build on top of a ring buffer
   called an mcache.

   A link might optionally have a data region associated with it, for
   holding the data fragments of the messages that are passed in the
   ring buffer.  This is typically a dcache, although in one case is
   a "reasm" instead (reassembly buffer).

   A link belongs to exactly one workspace.  A link has exactly one
   producer, and 1 or more consumers.  Each consumer is either
   reliable or not reliable.  A link has a depth and a MTU, which
   correspond to the depth and MTU of the mcache and dcache
   respectively.  A MTU of zero means no dcache is needed, as there
   is no data. */

struct fd_topo_link {
  ulong        idx;
  fd_topo_t *  topo;

  char         name[ 13UL ];
  ulong        lidx;

  ulong depth;
  ulong mtu;
  ulong burst;
  int   is_reasm;

  fd_topo_wksp_t *    wksp;
  fd_topo_tile_t *    producer;
  ulong link_in_cnt;
  fd_topo_link_in_t * link_ins[ FD_TOPO_LINK_OUT_MAX ];
  ulong consumer_cnt;
  fd_topo_tile_t *    consumers[ FD_TOPO_LINK_OUT_MAX ];

  fd_frag_meta_t * mcache;
  void *           dcache;
  fd_tpu_reasm_t * reasm;
};

struct fd_topo_link_in {
  ulong        idx;
  fd_topo_t *  topo;

  int reliable;
  int polled;

  fd_topo_tile_t const * producer;
  fd_topo_link_t const * link;
  fd_topo_tile_t const * consumer;

  ulong * fseq;
};

/* A tile is a unique process that is spawned by Firedancer to represent
   one thread of execution.  Firedancer sandboxes all tiles to their own
   process for security reasons.

   A tile belongs to exactly one workspace.  A tile is a consumer of 0
   or more links, it's inputs.  A tile is a producer of 0 or more output
   links.  Either zero or one of the output links is considered the
   primary output, which will be managed automatically by the tile
   infrastructure.

   All input links will be automatically polled by the tile
   infrastructure, but only the primary output will be written to. */

struct fd_topo_tile {
  ulong        idx;  /* The index of the tile in the list of tiles in the toplogy, betwen [0, tile_cnt). */
  fd_topo_t *  topo; /* Pointer to the parent topology of the tile. */

  char         name[ 8UL ]; /* The name of the tile, like "pack" or "bank". */
  ulong        tidx;        /* Tile idx, the index of the tile in the list of tiles with the same name, the bank:3 tile has tidx 3. */
  ulong        cpu_idx;     /* The CPU idx that the tile will be pinned to.  ULONG_MAX means the tile is a floating tile. */
  int          solana_labs; /* 1 if the tile runs in the Solana Labs address space, or 0 if it does not. */

  fd_topo_wksp_t * wksp;
  ulong joins_cnt;
  ulong joins_mode[ 256UL ];
  fd_topo_wksp_t * joins[ 256UL ];
  fd_topo_link_t * primary_output;
  ulong secondary_outputs_cnt;
  fd_topo_link_t * secondary_outputs[ 256UL ];
  ulong in_cnt;
  fd_topo_link_in_t * in[ FD_TOPO_TILE_IN_MAX ];

  fd_cnc_t * cnc;
  ulong *    metrics;
};

struct fd_topo {
  uchar const * pod;

  char const * app_name;

  ulong wksp_cnt;
  fd_topo_wksp_t    wksps[ FD_TOPO_WKSP_MAX ][ 1 ];

  ulong link_cnt;
  fd_topo_link_t    links[ FD_TOPO_LINK_MAX ][ 1 ];

  ulong link_in_cnt;
  fd_topo_link_in_t link_ins[ 256 ][ 1 ];

  ulong tile_cnt;
  fd_topo_tile_t    tiles[ FD_TOPO_TILE_MAX ][ 1 ];
};

#define FD_TOPO_ALIGN     (alignof(fd_topo_t))
#define FD_TOPO_FOOTPRINT (sizeof(fd_topo_t))

FD_PROTOTYPES_BEGIN

FD_FN_CONST static inline ulong fd_topo_align    ( void ) { return FD_TOPO_ALIGN; }
FD_FN_CONST static inline ulong fd_topo_footprint( void ) { return FD_TOPO_FOOTPRINT; }

void *
fd_topo_new( void *        shmem,
             uchar const * pod );

static inline fd_topo_t * fd_topo_join  ( void            * shtopo ) { return (fd_topo_t *)shtopo; }
static inline void      * fd_topo_leave ( fd_topo_t const * topo   ) { return (void *)topo;        }
static inline void      * fd_topo_delete( void            * shtopo ) { return shtopo;              }

void
fd_topo_wksp_layout( uchar * pod,
                     ulong (* align    )( uchar const * pod, char const * id ),
                     ulong (* footprint)( uchar const * pod, char const * id ) );

void
fd_topo_wksp_new( uchar * pod );

void
fd_topo_wksp_attach( fd_topo_wksp_t * wksp, int mode );

void
fd_topo_wksp_attach_all( fd_topo_t * topo, int mode );

void
fd_topo_wksp_attach_tile( fd_topo_tile_t * tile );

void
fd_topo_wksp_join( fd_topo_t * topo );

void
fd_topo_wksp_apply( fd_topo_t const * topo,
                    void (* fn )( void * laddr, uchar const * pod, char const * id ) );

void
fd_topo_wksp_detach( fd_topo_t * topo );

/* fd_topo_run_single_process runs all the tiles and the Solana Labs
   components in a single process (the calling process).  This spawns
   each tile, and then a significant number of Solana Labs components
   as threads in the process.

   This is useful for tooling and debugging, but is not how the
   production process runs.  For production, each tile is run in its
   own address space with a separate process and security sandbox. */

ulong
fd_topo_run_single_process( uchar *    pod,
                            int        solana_labs,
                            uint       uid,
                            uint       gid,
                            pthread_t  out_threads[ static FD_TOPO_TILE_MAX+1UL] );

/* fd_topo_run_tile runs the given tile directly within the current
   process (and thread).  The function will never return, as tiles are
   expected to run forever.  An error is logged and the application will
   exit if the tile exits.
   
   The sandbox argument determines if the current process will be
   sandboxed fully before starting the tile.  The thread will switch to
   the uid and gid provided before starting the tile, even if the thread
   is not being sandboxed.  Although POSIX specifies that all threads in
   a process must share a UID and GID, this is not the case on Linux.
   The thread will switch to the provided UID and GID without switching
   the other threads in the process.
   
   The allow_fd argument is only used if sandbox is true, and is a file
   descriptor which will be allowed to exist in the process.  Normally
   the sandbox code rejects and aborts if there is an unexpected file
   descriptor present on boot.  This is helpful to allow a parent
   process to be notified on termination of the tile by waiting for a
   pipe file descriptor to get closed. */

void
fd_topo_run_tile( fd_topo_tile_t *          tile,
                  int                       sandbox,
                  uint                      uid,
                  uint                      gid,
                  int                       allow_fd,
                  fd_topo_run_tile_args_t * args );

/* fd_topo_memory_mlock_tile returns the amount of memory that
   will be `mlock()`ed by the provide tile.  This is typically the sum
   of the size of all the workspaces which the tile needs to map in. */

FD_FN_PURE ulong
fd_topo_memory_mlock_tile( fd_topo_tile_t const * tile );

/* fd_topo_memory_mlock_multi_process returns the maximum amount of
   memory that will be `mlock()`ed by any one process if the topology is
   started in multi-process mode.  RLIMIT_MLOCK must be set to at least
   this value for all `mlock()` calls to succeed.

   The upper bound here is roughly max(sum(tile_maps_workspaces))
   across all of the tiles in the topology, although the real number
   will probably be lower as it's unlikely one tile would map all of the
   workspaces at once. */ 

FD_FN_PURE ulong
fd_topo_memory_mlock_multi_process( uchar const * pod );

/* fd_topo_memory_mlock_single_process returns the amount of memory that
   will be `mlock()`ed by the process if starting the entire toplogy as
   threads inside the process.

   This is roughly the sum of the size of all the workspaces, with a
   little bit of extra memory for stack pages, extra anonymous pages
   mapped by the tile. */

FD_FN_PURE ulong
fd_topo_memory_mlock_single_process( uchar const * pod );

/* fd_topo_memory_required_pages returns the number of huge and gigantic
   pages that are required to be free on the system to create the
   topology successfully with fd_topo_wksp_new.

   If the required number of pages are not free, the topology creation
   will likely fail with ENOMEM or similar. */

FD_FN_PURE fd_topo_memory_t
fd_topo_memory_required_pages( uchar const * pod );

void
fd_topo_print( uchar const * pod,
               int           stdout );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_topo_fd_topo_h */
