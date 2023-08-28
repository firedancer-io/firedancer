#include "fd_leader_schedule.h"
#include "../../util/wksp/fd_wksp_private.h"
#include <stdio.h>

void *
fd_leader_schedule_new( void * mem )
{
  fd_leader_schedule_t * schedule = ( fd_leader_schedule_t * )mem;
  fd_memset( schedule, 0, fd_leader_schedule_footprint() );
  return (void *)schedule;
}

/* TODO: LML same functionality as run.c:workspace_pod_join we should refactor */
fd_leader_schedule_t *
fd_leader_schedule_get( char const * app_name ) {
  char name[ FD_WKSP_CSTR_MAX ];
  snprintf( name, FD_WKSP_CSTR_MAX, "%s_forward0.wksp", app_name );

  fd_wksp_t * wksp = fd_wksp_attach( name );
  if( FD_UNLIKELY( !wksp ) ) FD_LOG_ERR(( "could not attach to workspace `%s`", name ));

  void * laddr = fd_wksp_laddr( wksp, wksp->gaddr_lo );
  if( FD_UNLIKELY( !laddr ) ) FD_LOG_ERR(( "could not get gaddr_low from workspace `%s`", name ));

  uchar const * pod = fd_pod_join( laddr );
  if( FD_UNLIKELY( !pod ) ) FD_LOG_ERR(( "fd_pod_join to pod at gaddr_lo failed" ));

  fd_leader_schedule_t  * leader_schedule = (fd_leader_schedule_t *)fd_wksp_pod_map( pod, "leader_schedule" );
  if( FD_UNLIKELY( !leader_schedule ) ) FD_LOG_ERR(( "fd_wksp_pod_map failed" ));

  return leader_schedule;
}
