#include "fd_vinyl.h"

/* FIXME: HAVE ERR_TIMEOUT? */

int
fd_vinyl_halt( fd_cnc_t * cnc ) {

  int err = fd_cnc_open( cnc ); /* logs details */
  if( FD_UNLIKELY( err ) ) return err==FD_CNC_ERR_AGAIN ? FD_VINYL_ERR_AGAIN : FD_VINYL_ERR_CORRUPT;

  fd_cnc_signal( cnc, FD_VINYL_CNC_SIGNAL_HALT );

  err = FD_LIKELY( fd_cnc_wait( cnc, FD_VINYL_CNC_SIGNAL_HALT, (long)5e9, NULL )==FD_VINYL_CNC_SIGNAL_BOOT )
      ? FD_VINYL_SUCCESS : FD_VINYL_ERR_CORRUPT;

  fd_cnc_close( cnc );

  return err;
}

int
fd_vinyl_sync( fd_cnc_t * cnc ) {

  int err = fd_cnc_open( cnc ); /* logs details */
  if( FD_UNLIKELY( err ) ) return err==FD_CNC_ERR_AGAIN ? FD_VINYL_ERR_AGAIN : FD_VINYL_ERR_CORRUPT;

  fd_cnc_signal( cnc, FD_VINYL_CNC_SIGNAL_SYNC );

  err = FD_LIKELY( fd_cnc_wait( cnc, FD_VINYL_CNC_SIGNAL_SYNC, (long)5e9, NULL )==FD_VINYL_CNC_SIGNAL_RUN )
      ? FD_VINYL_SUCCESS : FD_VINYL_ERR_CORRUPT;

  fd_cnc_close( cnc );

  return err;
}

int
fd_vinyl_get( fd_cnc_t * cnc,
              int        opt,
              ulong *    opt_val ) {

  int err = fd_cnc_open( cnc ); /* logs details */
  if( FD_UNLIKELY( err ) ) return err==FD_CNC_ERR_AGAIN ? FD_VINYL_ERR_AGAIN : FD_VINYL_ERR_CORRUPT;

  fd_vinyl_cmd_t * cmd = (fd_vinyl_cmd_t *)fd_cnc_app_laddr( cnc );

  cmd->get.opt = opt;

  fd_cnc_signal( cnc, FD_VINYL_CNC_SIGNAL_GET );

  err = FD_LIKELY( fd_cnc_wait( cnc, FD_VINYL_CNC_SIGNAL_GET, (long)5e9, NULL )==FD_VINYL_CNC_SIGNAL_RUN )
      ? cmd->get.err : FD_VINYL_ERR_CORRUPT;

  fd_cnc_close( cnc );

  if( opt_val ) *opt_val = cmd->get.val;
  return err;
}

int
fd_vinyl_set( fd_cnc_t * cnc,
              int        opt,
              ulong      val,
              ulong *    opt_val ) {

  int err = fd_cnc_open( cnc ); /* logs details */
  if( FD_UNLIKELY( err ) ) return err==FD_CNC_ERR_AGAIN ? FD_VINYL_ERR_AGAIN : FD_VINYL_ERR_CORRUPT;

  fd_vinyl_cmd_t * cmd = (fd_vinyl_cmd_t *)fd_cnc_app_laddr( cnc );

  cmd->set.opt = opt;
  cmd->set.val = val;

  fd_cnc_signal( cnc, FD_VINYL_CNC_SIGNAL_SET );

  err = FD_LIKELY( fd_cnc_wait( cnc, FD_VINYL_CNC_SIGNAL_SET, (long)5e9, NULL )==FD_VINYL_CNC_SIGNAL_RUN )
      ? cmd->set.err : FD_VINYL_ERR_CORRUPT;

  fd_cnc_close( cnc );

  if( opt_val ) *opt_val = cmd->set.val;
  return err;
}

int
fd_vinyl_client_join( fd_cnc_t *      cnc,
                      fd_vinyl_rq_t * rq,
                      fd_vinyl_cq_t * cq,
                      fd_wksp_t *     wksp,
                      ulong           link_id,
                      ulong           burst_max,
                      ulong           quota_max ) {

  int err = fd_cnc_open( cnc ); /* logs details */
  if( FD_UNLIKELY( err ) ) return err==FD_CNC_ERR_AGAIN ? FD_VINYL_ERR_AGAIN : FD_VINYL_ERR_CORRUPT;

  /* At this point, we have a command session on cnc and a superficially
     valid request.  Issue the command and wait for the response. */

  fd_vinyl_cmd_t * cmd = (fd_vinyl_cmd_t *)fd_cnc_app_laddr( cnc );

  cmd->join.link_id   = link_id;
  cmd->join.burst_max = burst_max;
  cmd->join.quota_max = quota_max;

  if( FD_UNLIKELY( !fd_wksp_cstr_laddr( rq, cmd->join.rq ) ) ||
      FD_UNLIKELY( !fd_wksp_cstr_laddr( cq, cmd->join.cq ) ) ||
      FD_UNLIKELY( !wksp                                   ) ) {
    fd_cnc_close( cnc );
    return FD_VINYL_ERR_INVAL;
  }

  strcpy( cmd->join.wksp, fd_wksp_name( wksp ) );

  fd_cnc_signal( cnc, FD_VINYL_CNC_SIGNAL_CLIENT_JOIN );

  err = FD_LIKELY( fd_cnc_wait( cnc, FD_VINYL_CNC_SIGNAL_CLIENT_JOIN, (long)5e9, NULL )==FD_VINYL_CNC_SIGNAL_RUN )
      ? cmd->join.err : FD_VINYL_ERR_CORRUPT;

  fd_cnc_close( cnc );

  return err;
}

int
fd_vinyl_client_leave( fd_cnc_t * cnc,
                       ulong      link_id ) {

  int err = fd_cnc_open( cnc ); /* logs details */
  if( FD_UNLIKELY( err ) ) return err==FD_CNC_ERR_AGAIN ? FD_VINYL_ERR_AGAIN : FD_VINYL_ERR_CORRUPT;

  /* At this point, we have a command session on cnc and a superficially
     valid request.  Issue the command and wait for the response. */

  fd_vinyl_cmd_t * cmd = (fd_vinyl_cmd_t *)fd_cnc_app_laddr( cnc );

  cmd->leave.link_id = link_id;

  fd_cnc_signal( cnc, FD_VINYL_CNC_SIGNAL_CLIENT_LEAVE );

  err = FD_LIKELY( fd_cnc_wait( cnc, FD_VINYL_CNC_SIGNAL_CLIENT_LEAVE, (long)5e9, NULL )==FD_VINYL_CNC_SIGNAL_RUN )
      ? cmd->leave.err : FD_VINYL_ERR_CORRUPT;

  fd_cnc_close( cnc );

  return err;
}
