#define _GNU_SOURCE
#include "adminctl_client.h"

#include "../../shared/fd_bootinfo.h"
#include "../../../disco/topo/fd_topo.h"
#include "../../../util/pod/fd_pod.h"
#include "../../../util/fd_version.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static fd_adminctl_t *
attach_from_config( config_t * config ) {
  ulong admin_ctl_obj_id = fd_pod_query_ulong( config->topo.props, "adminctl", ULONG_MAX );
  if( FD_UNLIKELY( admin_ctl_obj_id==ULONG_MAX ) ) FD_LOG_ERR(( "The command could not communicate with the running Firedancer process. "
                                                                "It is possible you are running the command from an older or newer "
                                                                "version of Firedancer that is no longer compatible." ));

  fd_topo_obj_t const * admin_ctl_obj = &config->topo.objs[ admin_ctl_obj_id ];

  fd_topo_join_workspace( &config->topo, &config->topo.workspaces[ admin_ctl_obj->wksp_id ], FD_SHMEM_JOIN_MODE_READ_WRITE, FD_TOPO_CORE_DUMP_LEVEL_DISABLED );

  fd_adminctl_t * adminctl = fd_adminctl_join( fd_topo_obj_laddr( &config->topo, admin_ctl_obj->id ) );
  if( FD_UNLIKELY( !adminctl ) ) FD_LOG_ERR(( "The command could not communicate with the running Firedancer process. "
                                              "It is possible you are running the command from an older or newer "
                                              "version of Firedancer that is no longer compatible." ));
  return adminctl;
}

static fd_adminctl_t *
attach_from_bootinfo( fd_bootinfo_instance_t const * instance ) {
  fd_bootinfo_t const * info = &instance->info;

  if( FD_UNLIKELY( !info->adminctl_wksp_file[ 0 ] ) )
    FD_LOG_ERR(( "The running validator `%s` does not support being administered by this command.", info->name ));

  fd_bootinfo_notice( instance );

  if( FD_UNLIKELY( strcmp( info->commit_ref, fd_commit_ref_cstr ) ) )
    FD_LOG_INFO(( "running validator is commit %s, this binary is commit %s", info->commit_ref, fd_commit_ref_cstr ));

  char path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "%s/.%s/%s", instance->mount_path, fd_shmem_page_sz_to_cstr( info->adminctl_page_sz ), info->adminctl_wksp_file ) );

  int fd = open( path, O_RDWR );
  if( FD_UNLIKELY( -1==fd ) ) FD_LOG_ERR(( "open(%s) failed (%i-%s).  The validator `%s` appears to be running but its "
                                           "shared memory could not be opened.", path, errno, fd_io_strerror( errno ), info->name ));

  struct stat st;
  if( FD_UNLIKELY( -1==fstat( fd, &st ) ) ) FD_LOG_ERR(( "fstat(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( info->adminctl_offset+fd_adminctl_footprint()>(ulong)st.st_size ) )
    FD_LOG_ERR(( "The validator `%s` published an invalid control region descriptor.  It is possible you are "
                 "running the command from an older or newer version of Firedancer that is no longer compatible.", info->name ));

  void * base = mmap( NULL, (ulong)st.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0 );
  if( FD_UNLIKELY( base==MAP_FAILED ) ) FD_LOG_ERR(( "mmap(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( close( fd ) ) ) FD_LOG_WARNING(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  fd_adminctl_t * adminctl = fd_adminctl_join( (uchar *)base+info->adminctl_offset );
  if( FD_UNLIKELY( !adminctl ) ) FD_LOG_ERR(( "The command could not communicate with the running Firedancer process. "
                                              "It is possible you are running the command from an older or newer "
                                              "version of Firedancer that is no longer compatible." ));
  return adminctl;
}

fd_adminctl_t *
adminctl_client_attach( config_t *   config,
                        char const * opt_name ) {
  if( FD_LIKELY( config->has_user_config ) ) return attach_from_config( config );

  fd_bootinfo_instance_t instances[ FD_BOOTINFO_INSTANCE_MAX ];
  ulong cnt = fd_bootinfo_discover( instances, FD_BOOTINFO_INSTANCE_MAX );

  fd_bootinfo_instance_t * match     = NULL;
  ulong                    match_cnt = 0UL;
  ulong                    stale_cnt = 0UL;
  for( ulong i=0UL; i<cnt; i++ ) {
    if( FD_UNLIKELY( opt_name && opt_name[ 0 ] && strcmp( instances[ i ].info.name, opt_name ) ) ) continue;
    if( FD_UNLIKELY( !instances[ i ].live ) ) { stale_cnt++; continue; }
    match = &instances[ i ];
    match_cnt++;
  }

  if( FD_UNLIKELY( !match_cnt ) ) {
    if( FD_UNLIKELY( cnt ) ) fd_bootinfo_print( instances, cnt );
    if( FD_UNLIKELY( stale_cnt ) ) FD_LOG_ERR(( "No running validator found, but %lu stopped validator(s) left shared memory "
                                                "behind.  Start the validator, or pass --config to attach explicitly.", stale_cnt ));
    FD_LOG_ERR(( "No running validator found.  If a validator is running, pass --config with the "
                 "configuration file it was started with." ));
  }

  if( FD_UNLIKELY( match_cnt>1UL ) ) {
    fd_bootinfo_print( instances, cnt );
    FD_LOG_ERR(( "Multiple running validators found.  Pass --name to select one." ));
  }

  return attach_from_bootinfo( match );
}
