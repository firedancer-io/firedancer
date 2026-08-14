#ifndef HEADER_fd_src_app_shared_gdb_fd_gdb_scripts_h
#define HEADER_fd_src_app_shared_gdb_fd_gdb_scripts_h

/* Including fd_gdb_scripts.h injects Firedancer's GDB Python scripts into
   the build.  This currently includes Base58 pretty printing. */

extern char const fd_gdb_scripts[];

__attribute__((used)) static char const * const
fd_gdb_scripts_ref = fd_gdb_scripts;

#endif /* HEADER_fd_src_app_shared_gdb_fd_gdb_scripts_h */
