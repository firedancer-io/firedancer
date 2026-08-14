#ifndef HEADER_fd_src_app_shared_fd_bootinfo_h
#define HEADER_fd_src_app_shared_fd_bootinfo_h

/* fd_bootinfo publishes a small ABI-frozen descriptor of a running
   validator at <mount_path>/<name>.bootinfo so control commands can
   discover and attach to it without the configuration file.

   The descriptor only locates the validator, it never authorizes:
   commands must still validate in-band magic and payload versions of
   whatever they attach to.  Liveness is decided by matching the pid
   and pid start time against /proc, never by file existence.

   The struct layout is frozen.  Grow only by appending fields and
   bumping FD_BOOTINFO_VERSION, never reorder or resize fields. */

#include "fd_config.h"

#define FD_BOOTINFO_MAGIC   (0xF17EDA2C3B007117UL)
#define FD_BOOTINFO_VERSION (1UL)

struct fd_bootinfo {
  ulong magic;                      /* ==FD_BOOTINFO_MAGIC */
  ulong version;                    /* >=FD_BOOTINFO_VERSION for newer writers, this prefix stays valid */
  ulong pid;                        /* run supervisor pid (host pidns) */
  ulong pid_start_time;             /* /proc/<pid>/stat field 22, defeats pid reuse */
  long  boot_wallclock_nanos;
  char  commit_ref[ 48UL ];         /* git commit of the running build */
  ulong fd_version[ 3UL ];          /* major, minor, patch */
  char  name[ 64UL ];               /* config->name */
  uint  uid;
  uint  gid;
  ulong topo_layout_hash;           /* fd_topo_t layout_hash of the running build */
  char  adminctl_wksp_file[ 64UL ]; /* "<name>_adminctl.wksp", empty if no adminctl */
  ulong adminctl_page_sz;           /* page size of the adminctl workspace */
  ulong adminctl_offset;            /* adminctl obj offset within the workspace */
  char  config_file[ 64UL ];        /* "<name>.config" resolved config blob, empty if none */
  ulong config_sz;                  /* size of the config blob, ==sizeof(config_t) of the running build */
};
typedef struct fd_bootinfo fd_bootinfo_t;

#define FD_BOOTINFO_INSTANCE_MAX (16UL)

struct fd_bootinfo_instance {
  char          mount_path[ PATH_MAX ];
  fd_bootinfo_t info;
  int           live;
};
typedef struct fd_bootinfo_instance fd_bootinfo_instance_t;

FD_PROTOTYPES_BEGIN

/* fd_bootinfo_write publishes the resolved config blob and the
   descriptor for the given config to <mount_path>/<name>.{config,
   bootinfo} (atomic same-dir renames).  The blob cannot go stale
   because readers only trust it via a descriptor whose process is
   verified live.  A memfd recovered via /proc/<pid>/fd would be
   simpler but the supervisor drops privileges which makes /proc/<pid>
   root-only (non-dumpable), and these commands must work without
   root.  Logs a warning and returns on failure, boot proceeds without
   discovery support. */

void
fd_bootinfo_write( config_t const * config );

/* fd_bootinfo_unlink removes the descriptor for the given config, if
   present. */

void
fd_bootinfo_unlink( config_t const * config );

/* fd_bootinfo_path_read reads and validates the descriptor at path.
   Returns 0 on success and fills out, -1 otherwise.  Rejects files not
   owned by root or the caller, world-writable files, and bad magic or
   size.  Descriptors from newer builds (version>FD_BOOTINFO_VERSION)
   are accepted, only the frozen prefix in out is meaningful. */

int
fd_bootinfo_path_read( char const *    path,
                       fd_bootinfo_t * out );

/* fd_bootinfo_live returns 1 if the process described by info is still
   running (pid exists and start time matches), 0 otherwise. */

int
fd_bootinfo_live( fd_bootinfo_t const * info );

/* fd_bootinfo_discover scans hugetlbfs mounts (and the default mount
   path) for bootinfo descriptors.  Returns the number of instances
   found, at most max.  Both live and stale instances are returned,
   distinguished by out[ i ].live. */

ulong
fd_bootinfo_discover( fd_bootinfo_instance_t * out,
                      ulong                    max );

/* fd_bootinfo_check_layout errs if a validator is running with the
   config's name and mount path whose topology layout differs from the
   one this binary computes.  No-op if no live validator is found. */

void
fd_bootinfo_check_layout( config_t const * config );

/* fd_bootinfo_print prints a table of discovered instances to stdout,
   colorized when stdout is a terminal. */

void
fd_bootinfo_print( fd_bootinfo_instance_t const * instances,
                   ulong                          cnt );

/* fd_bootinfo_notice logs a NOTICE describing the instance a command
   attached to. */

void
fd_bootinfo_notice( fd_bootinfo_instance_t const * instance );

/* fd_bootinfo_adopt prepares config for a command that attaches to the
   full topology of a running validator.  If --config was given, the
   topology from the file is used and only the layout is verified.
   Otherwise the running validator is discovered and config is replaced
   with the validator's own published resolved config, so all topology
   offsets are exactly the ones in use.  Logs an error and exits if no
   or multiple validators are running, or on a version mismatch. */

void
fd_bootinfo_adopt( config_t * config );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_shared_fd_bootinfo_h */
