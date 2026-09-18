#include "fd_failover_role.h"

#include "../../ballet/sha256/fd_sha256.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int
role_valid( fd_failover_role_file_t const * role ) {
  return role->version==FD_FAILOVER_ROLE_VERSION &&
         role->role<FD_FAILOVER_STATE_CNT        &&
         role->paused<=1U;
}

static ulong
pack_body( fd_failover_role_file_t const * role,
           uchar *                         buf ) {
  ulong off = 0UL;
  FD_STORE( uint,  buf+off, role->version       ); off += 4UL;
  FD_STORE( ulong, buf+off, role->term          ); off += 8UL;
  buf[ off++ ] = role->role;
  fd_memcpy( buf+off, role->staked_pubkey, 32UL );     off += 32UL;
  buf[ off++ ] = role->paused;
  FD_STORE( ulong, buf+off, role->baton_slot    ); off += 8UL;
  FD_STORE( ulong, buf+off, role->engaged_floor ); off += 8UL;
  return off;
}

ulong
fd_failover_role_ser( fd_failover_role_file_t const * role,
                      uchar *                         buf ) {
  if( FD_UNLIKELY( !role_valid( role ) ) ) return 0UL;
  ulong body_sz = pack_body( role, buf );
  fd_sha256_hash( buf, body_sz, buf+body_sz );
  return body_sz+32UL;
}

int
fd_failover_role_de( uchar const *             buf,
                     ulong                     buf_sz,
                     fd_failover_role_file_t * out ) {
  if( FD_UNLIKELY( buf_sz<FD_FAILOVER_ROLE_FILE_SZ ) ) return EPROTO;

  uchar digest[ 32 ];
  fd_sha256_hash( buf, FD_FAILOVER_ROLE_BODY_SZ, digest );
  if( FD_UNLIKELY( !fd_memeq( digest, buf+FD_FAILOVER_ROLE_BODY_SZ, sizeof(digest) ) ) ) return EPROTO;

  fd_failover_role_file_t role;
  fd_memset( &role, 0, sizeof(role) );
  ulong off = 0UL;
  role.version = FD_LOAD( uint, buf+off );                            off += 4UL;
  role.term    = FD_LOAD( ulong, buf+off );                           off += 8UL;
  role.role    = buf[ off++ ];
  fd_memcpy( role.staked_pubkey, buf+off, sizeof(role.staked_pubkey) ); off += sizeof(role.staked_pubkey);
  role.paused        = buf[ off++ ];
  role.baton_slot    = FD_LOAD( ulong, buf+off );                     off += 8UL;
  role.engaged_floor = FD_LOAD( ulong, buf+off );

  if( FD_UNLIKELY( !role_valid( &role ) ) ) return EPROTO;
  *out = role;
  return 0;
}

int
fd_failover_role_load( int                       dir_fd,
                       fd_failover_role_file_t * out ) {
  int fd = openat( dir_fd, FD_FAILOVER_ROLE_PATH, O_RDONLY|O_CLOEXEC|O_NOFOLLOW );
  if( FD_UNLIKELY( fd<0 ) ) return errno;

  struct stat dir_st;
  struct stat st;
  if( FD_UNLIKELY( fstat( dir_fd, &dir_st ) || fstat( fd, &st ) ) ) {
    int err = errno;
    close( fd );
    return err;
  }
  if( FD_UNLIKELY( !S_ISREG( st.st_mode ) || st.st_uid!=dir_st.st_uid ||
                   !(st.st_mode&S_IRUSR) || (st.st_mode & (S_IRWXG|S_IRWXO)) ) ) {
    close( fd );
    return EACCES;
  }
  if( FD_UNLIKELY( st.st_size!=(long)FD_FAILOVER_ROLE_FILE_SZ ) ) {
    close( fd );
    return EPROTO;
  }

  uchar img[ FD_FAILOVER_ROLE_FILE_SZ ];
  ulong read_sz = 0UL;
  int err = fd_io_read( fd, img, sizeof(img), sizeof(img), &read_sz );
  if( FD_UNLIKELY( close( fd ) && !err ) ) err = errno;
  if( FD_UNLIKELY( err ) ) return err==-1 ? EPROTO : err;
  return fd_failover_role_de( img, read_sz, out );
}

static int
remove_tmp( int dir_fd,
            char const * path,
            int err ) {
  if( FD_UNLIKELY( unlinkat( dir_fd, path, 0 ) && errno!=ENOENT && !err ) ) err = errno;
  return err;
}

static int
store_file( int           dir_fd,
            int           file_fd,
            int           sandboxed,
            uint          owner_uid,
            uint          owner_gid,
            char const *  path,
            char const *  tmp_path,
            uchar const * img,
            ulong         img_sz ) {
  int err = remove_tmp( dir_fd, tmp_path, 0 );
  if( FD_UNLIKELY( err ) ) return err;

  /* Under seccomp we close the reserved descriptor first so that openat
     gives the same number back, which only works while no lower number is
     free.  Without a sandbox, as in the threaded dev launcher where all
     tiles share one descriptor table, we cannot get the same number, so we
     open the file and move it onto the reserved number with dup2. */
  if( FD_UNLIKELY( sandboxed && close( file_fd ) && errno!=EBADF ) ) return errno;
  int fd = openat( dir_fd, tmp_path,
                   O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW, 0600 );
  if( FD_UNLIKELY( fd<0 ) ) return errno;
  if( FD_UNLIKELY( fd!=file_fd ) ) {
    if( FD_UNLIKELY( sandboxed ) ) {
      close( fd );
      return remove_tmp( dir_fd, tmp_path, EIO );
    }
    if( FD_UNLIKELY( -1==dup2( fd, file_fd ) || -1==fcntl( file_fd, F_SETFD, FD_CLOEXEC ) ) ) {
      err = errno;
      close( fd );
      return remove_tmp( dir_fd, tmp_path, err );
    }
    close( fd );
    fd = file_fd;
  }

  ulong write_sz = 0UL;
  err = fd_io_write( fd, img, img_sz, img_sz, &write_sz );
  if( FD_UNLIKELY( !err && write_sz!=img_sz ) ) err = EIO;
  if( FD_UNLIKELY( !err && fsync( fd ) ) ) err = errno;
  /* The write at boot runs as root, before the uid switch, and the loader
     refuses a file whose owner differs from the directory's, so the tile
     passes the validator user for that one.  This comes before the rename,
     so no file owned by root is ever in place. */
  if( FD_UNLIKELY( !err && ( owner_uid!=UINT_MAX || owner_gid!=UINT_MAX ) &&
                   fchown( fd, (uid_t)owner_uid, (gid_t)owner_gid ) ) ) err = errno;
  if( FD_UNLIKELY( err ) ) return remove_tmp( dir_fd, tmp_path, err );

  if( FD_UNLIKELY( renameat( dir_fd, tmp_path, dir_fd, path ) ) )
    return remove_tmp( dir_fd, tmp_path, errno );
  if( FD_UNLIKELY( fsync( dir_fd ) ) ) return errno;
  return 0;
}

int
fd_failover_role_store( int                             dir_fd,
                        int                             file_fd,
                        int                             sandboxed,
                        uint                            owner_uid,
                        uint                            owner_gid,
                        fd_failover_role_file_t const * role ) {
  uchar img[ FD_FAILOVER_ROLE_FILE_SZ ];
  ulong img_sz = fd_failover_role_ser( role, img );
  if( FD_UNLIKELY( !img_sz ) ) return EINVAL;
  return store_file( dir_fd, file_fd, sandboxed, owner_uid, owner_gid, FD_FAILOVER_ROLE_PATH, FD_FAILOVER_ROLE_TMP_PATH, img, img_sz );
}

static int
demoted_valid( fd_failover_demoted_record_t const * record ) {
  if( FD_UNLIKELY( record->demoted.term>=ULONG_MAX-1UL ||
                   record->demoted.last_vote_slot==FD_FAILOVER_SLOT_NULL ||
                   record->demoted.mode!=(uchar)FD_FAILOVER_MODE_TOWER ||
                   !record->demoted.state_len ||
                   record->demoted.state_len>FD_FAILOVER_TOWER_STATE_MAX ) ) return 0;
  uchar digest[ FD_FAILOVER_DEMOTED_DIGEST_SZ ];
  fd_sha256_hash( record->state, record->demoted.state_len, digest );
  return fd_memeq( digest, record->digest, sizeof(digest) );
}

ulong
fd_failover_demoted_ser( fd_failover_demoted_record_t const * record,
                         uchar *                               buf ) {
  if( FD_UNLIKELY( !demoted_valid( record ) ) ) return 0UL;

  ulong off = 0UL;
  FD_STORE( uint,  buf+off, FD_FAILOVER_DEMOTED_VERSION      ); off += 4UL;
  FD_STORE( ulong, buf+off, record->demoted.term             ); off += 8UL;
  FD_STORE( ulong, buf+off, record->demoted.last_vote_slot   ); off += 8UL;
  FD_STORE( ulong, buf+off, record->demoted.watermark        ); off += 8UL;
  FD_STORE( uchar, buf+off, record->demoted.mode             ); off += 1UL;
  FD_STORE( ushort, buf+off, record->demoted.state_len       ); off += 2UL;
  fd_memcpy( buf+off, record->state, record->demoted.state_len ); off += record->demoted.state_len;
  fd_memcpy( buf+off, record->digest, sizeof(record->digest) );  off += sizeof(record->digest);
  fd_sha256_hash( buf, off, buf+off );
  return off+32UL;
}

int
fd_failover_demoted_de( uchar const *                   buf,
                        ulong                           buf_sz,
                        fd_failover_demoted_record_t * out ) {
  if( FD_UNLIKELY( buf_sz<FD_FAILOVER_DEMOTED_FILE_BODY_MIN+32UL ||
                   buf_sz>FD_FAILOVER_DEMOTED_FILE_MAX ) ) return EPROTO;

  uint version = FD_LOAD( uint, buf );
  if( FD_UNLIKELY( version!=FD_FAILOVER_DEMOTED_VERSION ) ) return EPROTO;

  fd_failover_demoted_record_t record;
  fd_memset( &record, 0, sizeof(record) );
  ulong off = 4UL;
  record.demoted.term           = FD_LOAD( ulong, buf+off ); off += 8UL;
  record.demoted.last_vote_slot = FD_LOAD( ulong, buf+off ); off += 8UL;
  record.demoted.watermark      = FD_LOAD( ulong, buf+off ); off += 8UL;
  record.demoted.mode           = FD_LOAD( uchar, buf+off ); off += 1UL;
  record.demoted.state_len      = FD_LOAD( ushort, buf+off ); off += 2UL;
  if( FD_UNLIKELY( record.demoted.state_len>FD_FAILOVER_TOWER_STATE_MAX ) ) return EPROTO;

  ulong body_sz = FD_FAILOVER_DEMOTED_FILE_BODY_MIN+(ulong)record.demoted.state_len;
  if( FD_UNLIKELY( buf_sz!=body_sz+32UL ) ) return EPROTO;
  fd_memcpy( record.state,  buf+off, record.demoted.state_len ); off += record.demoted.state_len;
  fd_memcpy( record.digest, buf+off, sizeof(record.digest) );

  uchar file_digest[ 32 ];
  fd_sha256_hash( buf, body_sz, file_digest );
  if( FD_UNLIKELY( !fd_memeq( file_digest, buf+body_sz, sizeof(file_digest) ) ||
                   !demoted_valid( &record ) ) ) return EPROTO;

  *out = record;
  return 0;
}

int
fd_failover_demoted_load( int                             dir_fd,
                          fd_failover_demoted_record_t * out ) {
  int fd = openat( dir_fd, FD_FAILOVER_DEMOTED_PATH, O_RDONLY|O_CLOEXEC|O_NOFOLLOW );
  if( FD_UNLIKELY( fd<0 ) ) return errno;

  struct stat dir_st;
  struct stat st;
  if( FD_UNLIKELY( fstat( dir_fd, &dir_st ) || fstat( fd, &st ) ) ) {
    int err = errno;
    close( fd );
    return err;
  }
  if( FD_UNLIKELY( !S_ISREG( st.st_mode ) || st.st_uid!=dir_st.st_uid ||
                   !(st.st_mode&S_IRUSR) || (st.st_mode & (S_IRWXG|S_IRWXO)) ) ) {
    close( fd );
    return EACCES;
  }
  if( FD_UNLIKELY( st.st_size<0L ||
                   (ulong)st.st_size<FD_FAILOVER_DEMOTED_FILE_BODY_MIN+32UL ||
                   (ulong)st.st_size>FD_FAILOVER_DEMOTED_FILE_MAX ) ) {
    close( fd );
    return EPROTO;
  }

  uchar img[ FD_FAILOVER_DEMOTED_FILE_MAX ];
  ulong read_sz = 0UL;
  int err = fd_io_read( fd, img, (ulong)st.st_size, (ulong)st.st_size, &read_sz );
  if( FD_UNLIKELY( close( fd ) && !err ) ) err = errno;
  if( FD_UNLIKELY( err ) ) return err==-1 ? EPROTO : err;
  return fd_failover_demoted_de( img, read_sz, out );
}

int
fd_failover_demoted_store( int                                   dir_fd,
                           int                                   file_fd,
                           int                                   sandboxed,
                           uint                                  owner_uid,
                           uint                                  owner_gid,
                           fd_failover_demoted_record_t const * record ) {
  uchar img[ FD_FAILOVER_DEMOTED_FILE_MAX ];
  ulong img_sz = fd_failover_demoted_ser( record, img );
  if( FD_UNLIKELY( !img_sz ) ) return EINVAL;
  return store_file( dir_fd, file_fd, sandboxed, owner_uid, owner_gid, FD_FAILOVER_DEMOTED_PATH, FD_FAILOVER_DEMOTED_TMP_PATH, img, img_sz );
}
