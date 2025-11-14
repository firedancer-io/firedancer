  case FD_VINYL_REQ_TYPE_TEST: {

    ulong const * req_val_gaddr = MAP_REQ_GADDR( req->val_gaddr_gaddr, ulong, 2UL*batch_cnt );
    schar *       req_err       = MAP_REQ_GADDR( req->err_gaddr,       schar,     batch_cnt );

    if( FD_UNLIKELY( (!!batch_cnt) & ((!req_val_gaddr) | (!req_err)) ) ) {
      comp_err = FD_VINYL_ERR_INVAL;
      break;
    }

    ulong const * req_try = req_val_gaddr + batch_cnt;

    for( ulong batch_idx=0UL; batch_idx<batch_cnt; batch_idx++ ) {

      /* Get the line index and version of the try.  The line index is
         invalid or has a different version than the try, tell the
         client the corresponding try failed (with INVAL and CORRUPT
         respectively).  Otherwise, tell the client the try succeeded. */

      ulong try = req_try[ batch_idx ];

      ulong ver      = try >> 32;
      ulong line_idx = try & FD_VINYL_LINE_MAX;

      int err = FD_UNLIKELY( line_idx>=line_cnt                                 ) ? FD_VINYL_ERR_INVAL
              : FD_UNLIKELY( fd_vinyl_line_ctl_ver( line[ line_idx ].ctl )!=ver ) ? FD_VINYL_ERR_CORRUPT
              :                                                                     FD_VINYL_SUCCESS;

      FD_COMPILER_MFENCE();
      req_err[ batch_idx ] = (schar)err;
      FD_COMPILER_MFENCE();

      fail_cnt += (ulong)!!err;

    }

    comp_err = FD_VINYL_SUCCESS;
    break;
  }
