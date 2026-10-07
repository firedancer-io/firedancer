#define _GNU_SOURCE
#include "configure.h"
#include "../../../platform/fd_file_util.h"
#include "../../../../disco/net/iavf/fd_iavf.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/ipmi.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define FW_DIR "/var/lib/fd-iavf-firmware"
#define FW_OUTPUT_SZ (65536UL)

/* fw_ctx_t holds the temporary iDRAC account and its local ownership record. */
typedef struct {
  int   ipmi;
  int   dir;
  int   lock;
  long  msg_id;
  uchar reservation;
  uchar user_id;
  char  user[17];
  char  host[INET_ADDRSTRLEN];
  char  port[6];
} fw_ctx_t;

/* fw_nic_t identifies the selected controller and all its port views. */
typedef struct {
  char  group[160];
  char  fqdd[96];
  char  ports[FD_IAVF_MEMBER_MAX][96];
  ulong port_cnt;
} fw_nic_t;

static volatile sig_atomic_t fw_interrupted;

static void
fw_signal( int sig ) { fw_interrupted = sig; }

static long
fw_millis( void ) {
  struct timespec ts;
  if( clock_gettime( CLOCK_MONOTONIC, &ts ) ) return 0L;
  return ts.tv_sec*1000L + ts.tv_nsec/1000000L;
}

static int
fw_error( char const * message ) {
  FD_LOG_WARNING(( "iavf-firmware, %s", message ));
  return -1;
}

static int
fw_write_all( int fd, void const * data, ulong size ) {
  uchar const * p = data;
  while( size ) {
    ssize_t n = write( fd, p, size );
    if( n<0 && errno==EINTR ) continue;
    if( n<=0 ) return -1;
    p += (ulong)n;
    size -= (ulong)n;
  }
  return 0;
}

/* fw_ipmi uses Linux OpenIPMI. The response includes the completion code. */
static int
fw_ipmi( fw_ctx_t * ctx, uchar netfn, uchar cmd, uchar * data, ushort data_sz,
         uchar out[256] ) {
  struct ipmi_system_interface_addr addr = {
    .addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE, .channel = IPMI_BMC_CHANNEL, .lun = 0
  };
  struct ipmi_req request = {
    .addr = (uchar *)&addr, .addr_len = sizeof(addr), .msgid = ++ctx->msg_id,
    .msg = { .netfn = netfn, .cmd = cmd, .data_len = data_sz, .data = data }
  };
  if( ioctl( ctx->ipmi, IPMICTL_SEND_COMMAND, &request ) ) return fw_error( "IPMI send failed" );
  long deadline = fw_millis()+5000L;
  while( fw_millis()<deadline ) {
    struct pollfd pfd = { .fd = ctx->ipmi, .events = POLLIN };
    long remaining = deadline-fw_millis();
    if( remaining<=0L ) break;
    int ready = poll( &pfd, 1, (int)remaining );
    if( ready<0 && errno==EINTR ) continue;
    if( ready<=0 ) break;
    struct ipmi_addr response_addr;
    struct ipmi_recv response = {
      .addr = (uchar *)&response_addr, .addr_len = sizeof(response_addr),
      .msg = { .data = out, .data_len = 256 }
    };
    if( ioctl( ctx->ipmi, IPMICTL_RECEIVE_MSG, &response ) ) return fw_error( "IPMI receive failed" );
    if( response.recv_type!=IPMI_RESPONSE_RECV_TYPE || response.msgid!=request.msgid ) continue;
    if( response.msg.netfn!=(netfn|1U) || response.msg.cmd!=cmd || !response.msg.data_len ) {
      return fw_error( "invalid IPMI response" );
    }
    if( out[0] ) {
      FD_LOG_WARNING(( "iavf-firmware, IPMI netfn %#x command %#x returned completion code %#x",
                       (uint)netfn, (uint)cmd, (uint)out[0] ));
      return -1;
    }
    return (int)response.msg.data_len;
  }
  return fw_error( "IPMI response timed out" );
}

static int
fw_reserve( fw_ctx_t * ctx ) {
  uchar req[] = { 0xa2, 2, 0 };
  uchar out[256];
  if( fw_ipmi( ctx, 0x2e, 1, req, sizeof(req), out )!=5 || memcmp( out+1, req, 3 ) ) {
    return fw_error( "Dell extended configuration reservation failed" );
  }
  ctx->reservation = out[4];
  return 0;
}

static int
fw_ext_read( fw_ctx_t * ctx, uchar group, uchar index, ushort offset, uchar size, uchar * data ) {
  uchar req[] = { 0xa2, 2, 0, ctx->reservation, group, index, (uchar)offset, (uchar)(offset>>8), size };
  uchar out[256];
  int n = fw_ipmi( ctx, 0x2e, 2, req, sizeof(req), out );
  if( n!=7+(int)size || memcmp( out+1, req, 3 ) || out[4]!=group || out[5]!=index || out[6]!=size ) {
    return fw_error( "unexpected Dell extended configuration response" );
  }
  memcpy( data, out+7, size );
  return 0;
}

static int
fw_ext_get( fw_ctx_t * ctx, uchar group, uchar index, uchar * data, ulong data_sz ) {
  uchar header[5];
  if( fw_reserve( ctx ) || fw_ext_read( ctx, group, index, 0, 5, header ) ) return -1;
  ulong size = (ulong)header[0] | ((ulong)header[1]<<8);
  if( header[2]!=1 || size!=data_sz+5UL ) return fw_error( "unsupported Dell configuration schema" );
  for( ulong off=0UL; off<data_sz; off+=16UL ) {
    uchar count = (uchar)fd_ulong_min( 16UL, data_sz-off );
    if( fw_ext_read( ctx, group, index, (ushort)(off+5UL), count, data+off ) ) return -1;
  }
  return 0;
}

/* fw_role writes Dell's iDRAC role mask, separate from IPMI channel privilege.
   Group 4 uses a nine-byte version 1 record with field mask 1. */
static int
fw_role( fw_ctx_t * ctx, uint role ) {
  if( fw_reserve( ctx ) ) return -1;
  uchar value[] = { (uchar)role, (uchar)(role>>8), (uchar)(role>>16), (uchar)(role>>24) };
  uchar req[] = { 0xa2, 2, 0, ctx->reservation, 4, ctx->user_id, 0, 0, 1,
                  9, 0, 1, 1, 0, value[0], value[1], value[2], value[3] };
  uchar out[256];
  uchar actual[4];
  if( fw_ipmi( ctx, 0x2e, 3, req, sizeof(req), out )<4 || memcmp( out+1, req, 3 ) ||
      fw_ext_get( ctx, 4, ctx->user_id, actual, sizeof(actual) ) || memcmp( actual, value, sizeof(value) ) ) {
    return fw_error( "iDRAC user role verification failed" );
  }
  return 0;
}

static int
fw_username( fw_ctx_t * ctx, uchar id, char name[17] ) {
  uchar out[256];
  if( fw_ipmi( ctx, 6, 0x46, &id, 1, out )!=17 ) return -1;
  memcpy( name, out+1, 16 );
  name[16] = '\0';
  return 0;
}

static int
fw_enabled( fw_ctx_t * ctx, uchar enable ) {
  uchar req[] = { ctx->user_id, enable };
  uchar out[256];
  return fw_ipmi( ctx, 6, 0x47, req, sizeof(req), out )==1 ? 0 : -1;
}

static int
fw_open( fw_ctx_t * ctx ) {
  ctx->ipmi = open( "/dev/ipmi0", O_RDWR|O_CLOEXEC );
  if( ctx->ipmi<0 ) return fw_error( "cannot open /dev/ipmi0, local OpenIPMI access is required" );
  uchar out[256];
  if( fw_ipmi( ctx, 6, 1, NULL, 0, out )<12 || out[7]!=0xa2 || out[8]!=2 || out[9] ) {
    close( ctx->ipmi );
    ctx->ipmi = -1;
    return fw_error( "this prototype requires a Dell iDRAC" );
  }
  return 0;
}

static int
fw_state_open( fw_ctx_t * ctx ) {
  if( mkdir( FW_DIR, 0700 ) && errno!=EEXIST ) return fw_error( "cannot create " FW_DIR );
  ctx->dir = open( FW_DIR, O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC );
  struct stat st;
  if( ctx->dir<0 || fstat( ctx->dir, &st ) || st.st_uid || (st.st_mode&0777)!=0700 ) {
    return fw_error( FW_DIR " must be a root-owned directory with mode 0700" );
  }
  ctx->lock = openat( ctx->dir, "lock", O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC, 0600 );
  if( ctx->lock<0 || flock( ctx->lock, LOCK_EX|LOCK_NB ) ) return fw_error( "another firmware configure process holds the lock" );
  return 0;
}

static int
fw_record( fw_ctx_t * ctx, char const * file, char const * text ) {
  int fd = openat( ctx->dir, "record.tmp", O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW|O_CLOEXEC, 0600 );
  if( fd<0 ) return -1;
  int err = fw_write_all( fd, text, strlen(text) ) || fsync( fd );
  if( close( fd ) ) err = 1;
  if( !err ) err = renameat( ctx->dir, "record.tmp", ctx->dir, file ) || fsync( ctx->dir );
  return err ? fw_error( "cannot save firmware configuration state" ) : 0;
}

/* fw_run bounds the subprocess and captures its output. */
static int
fw_run( char const * path, char * const argv[], char out[FW_OUTPUT_SZ], int interruptible ) {
  out[0] = '\0';
  if( interruptible && fw_interrupted ) return -1;
  int pipefd[2];
  if( pipe2( pipefd, O_CLOEXEC ) ) return -1;
  pid_t parent = getpid();
  pid_t pid = fork();
  if( pid<0 ) { close( pipefd[0] ); close( pipefd[1] ); return -1; }
  if( !pid ) {
    if( setsid()<0 || prctl( PR_SET_PDEATHSIG, SIGKILL ) || getppid()!=parent ) _exit( 127 );
    int null_fd = open( "/dev/null", O_RDONLY );
    if( null_fd<0 || dup2( null_fd, 0 )<0 || dup2( pipefd[1], 1 )<0 || dup2( pipefd[1], 2 )<0 ) _exit( 127 );
    close( null_fd );
    close( pipefd[0] );
    close( pipefd[1] );
    char * const env[] = { "LC_ALL=C", "DISPLAY=fd-iavf-firmware",
      "SSH_ASKPASS=" FW_DIR "/askpass", "SSH_ASKPASS_REQUIRE=force", NULL };
    execve( path, argv, env );
    _exit( 127 );
  }
  close( pipefd[1] );
  ulong used = 0UL;
  long deadline = fw_millis()+30000L;
  int failed = 0;
  int status = 0;
  for(;;) {
    if( (interruptible && fw_interrupted) || fw_millis()>=deadline || used==FW_OUTPUT_SZ-1UL ) { failed=1; break; }
    struct pollfd pfd = { .fd = pipefd[0], .events = POLLIN };
    int ready = poll( &pfd, 1, 100 );
    if( ready<0 && errno==EINTR ) continue;
    if( ready<0 ) { failed=1; break; }
    if( ready ) {
      ssize_t n = read( pipefd[0], out+used, FW_OUTPUT_SZ-1UL-used );
      if( n<0 && errno==EINTR ) continue;
      if( n<0 ) { failed=1; break; }
      if( !n ) break;
      used += (ulong)n;
    }
  }
  out[used] = '\0';
  close( pipefd[0] );
  if( failed ) { kill( -pid, SIGKILL ); kill( pid, SIGKILL ); }
  for(;;) {
    pid_t waited = waitpid( pid, &status, WNOHANG );
    if( waited==pid ) break;
    if( waited<0 && errno==EINTR ) continue;
    if( waited<0 ) { failed=1; break; }
    if( (interruptible && fw_interrupted) || fw_millis()>=deadline ) { failed=1; kill( -pid, SIGKILL ); kill( pid, SIGKILL ); }
    struct timespec delay = { .tv_nsec = 10000000L };
    nanosleep( &delay, NULL );
  }
  return !failed && WIFEXITED(status) && !WEXITSTATUS(status) ? 0 : -1;
}

static int
fw_ssh( fw_ctx_t * ctx, char const * command, char out[FW_OUTPUT_SZ] ) {
  char * const argv[] = {
    "ssh", "-F", "/dev/null", "-n", "-T", "-p", ctx->port, "-l", ctx->user,
    "-oControlMaster=auto", "-oControlPersist=15", "-oControlPath=" FW_DIR "/ssh",
    "-oBatchMode=no", "-oPubkeyAuthentication=no", "-oIdentityAgent=none",
    "-oStrictHostKeyChecking=accept-new", "-oUserKnownHostsFile=" FW_DIR "/known_hosts",
    "-oHostKeyAlias=fd-iavf-idrac", "-oLogLevel=ERROR",
    "-oGlobalKnownHostsFile=/dev/null", "-oConnectTimeout=5", "-oConnectionAttempts=1",
    "-oServerAliveInterval=5", "-oServerAliveCountMax=2", "-oClearAllForwardings=yes",
    "-oForwardAgent=no", "-oPreferredAuthentications=keyboard-interactive,password", "-oNumberOfPasswordPrompts=1",
    "-oKbdInteractiveAuthentication=yes", ctx->host, (char *)command, NULL
  };
  int err = fw_run( "/usr/bin/ssh", argv, out, 1 );
  if( err || strcasestr( out, "ERROR:" ) ) {
    FD_LOG_WARNING(( "iavf-firmware, %s failed\n%s", command, out ));
    return -1;
  }
  return 0;
}

static int
fw_unlink( fw_ctx_t * ctx, char const * name ) {
  return unlinkat( ctx->dir, name, 0 ) && errno!=ENOENT ? -1 : 0;
}

static int
fw_ssh_close( fw_ctx_t * ctx ) {
  struct stat st;
  if( fstatat( ctx->dir, "ssh", &st, AT_SYMLINK_NOFOLLOW ) ) return errno==ENOENT ? 0 : -1;
  if( !S_ISSOCK(st.st_mode) || st.st_uid ) return fw_error( "invalid SSH control socket" );
  char * const argv[] = { "ssh", "-F", "/dev/null", "-S", FW_DIR "/ssh", "-O", "exit", "fd-iavf-idrac", NULL };
  char out[FW_OUTPUT_SZ];
  if( !fw_run( "/usr/bin/ssh", argv, out, 0 ) ) return 0;

  /* A killed SSH master can leave its socket behind. */
  int fd = socket( AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0 );
  if( fd<0 ) return -1;
  struct sockaddr_un addr = { .sun_family = AF_UNIX, .sun_path = FW_DIR "/ssh" };
  int connected = connect( fd, (struct sockaddr *)&addr, sizeof(addr) );
  int err = errno;
  close( fd );
  if( connected<0 && (err==ECONNREFUSED || err==ENOENT) ) return fw_unlink( ctx, "ssh" );
  FD_LOG_WARNING(( "iavf-firmware, could not close the SSH master\n%s", out ));
  return -1;
}

static int
fw_cleanup( fw_ctx_t * ctx ) {
  int ssh_err = fw_ssh_close( ctx );
  int fd = openat( ctx->dir, "account", O_RDONLY|O_NOFOLLOW|O_CLOEXEC );
  if( fd<0 ) {
    if( errno==ENOENT ) goto local_cleanup;
    return -1;
  }
  char record[64] = {0};
  ssize_t n = read( fd, record, sizeof(record)-1UL );
  close( fd );
  uint id;
  char name[17];
  int consumed = 0;
  if( n<=0 || sscanf( record, "%u %16s\n%n", &id, name, &consumed )!=2 || consumed!=n || id<3U || id>16U ) {
    return fw_error( "invalid account ownership record, manual review required" );
  }
  char actual[17];
  ctx->user_id = (uchar)id;
  if( fw_username( ctx, ctx->user_id, actual ) ) return -1;
  if( actual[0] && strcmp( actual, name ) ) return fw_error( "iDRAC account ownership changed, refusing cleanup" );
  if( actual[0] ) {
    if( fw_enabled( ctx, 0 ) || fw_role( ctx, 0U ) ) return fw_error( "could not revoke temporary iDRAC access" );
    uchar access_req[] = { 1, ctx->user_id };
    uchar access_out[256];
    if( fw_ipmi( ctx, 6, 0x44, access_req, sizeof(access_req), access_out )!=5 ||
        (access_out[2]&0xc0U)!=0x80U ) return fw_error( "temporary account disable verification failed" );
    uchar empty[17] = { ctx->user_id };
    uchar out[256];
    if( fw_ipmi( ctx, 6, 0x45, empty, sizeof(empty), out )!=1 ||
        fw_username( ctx, ctx->user_id, actual ) || actual[0] ) return fw_error( "could not clear temporary account name" );
  }
local_cleanup:
  if( fw_unlink( ctx, "record.tmp" ) || fw_unlink( ctx, "password" ) ||
      fw_unlink( ctx, "askpass" ) ||
      fw_unlink( ctx, "account" ) || fsync( ctx->dir ) ) return fw_error( "could not remove temporary local credentials" );
  ctx->user_id = 0;
  return ssh_err;
}

static int
fw_bootstrap( fw_ctx_t * ctx ) {
  uchar ssh[9];
  if( fw_ext_get( ctx, 10, 0, ssh, sizeof(ssh) ) ) return -1;
  uint port = (uint)ssh[7] | ((uint)ssh[8]<<8);
  if( ssh[0]!=1 || !port ) return fw_error( "enable SSH in iDRAC before running this prototype" );
  FD_TEST( fd_cstr_printf_check( ctx->port, sizeof(ctx->port), NULL, "%u", port ) );
  struct in_addr ip;
  uchar req[] = { 1, 3, 0, 0 };
  uchar out[256];
  if( fw_ipmi( ctx, 0x0c, 2, req, sizeof(req), out )!=6 ) return -1;
  memcpy( &ip, out+2, 4 );
  if( !ip.s_addr || ip.s_addr==0xffffffffU || !inet_ntop( AF_INET, &ip, ctx->host, sizeof(ctx->host) ) ) {
    return fw_error( "local iDRAC has no usable management IPv4 address" );
  }

  int trust = openat( ctx->dir, "known_hosts", O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC, 0600 );
  struct stat st;
  if( trust<0 ) return fw_error( "cannot open the saved iDRAC SSH host key file" );
  if( fstat( trust, &st ) || !S_ISREG(st.st_mode) || st.st_uid || (st.st_mode&0022) ) {
    close( trust );
    return fw_error( "known_hosts must be a root-owned regular file, not writable by other users" );
  }
  close( trust );
  FD_LOG_NOTICE(( "iavf-firmware, local iDRAC is %s, SSH port %u", ctx->host, port ));
  if( !st.st_size ) FD_LOG_NOTICE(( "iavf-firmware, accepting and saving the local iDRAC SSH host key on first connection" ));

  for( uchar id=3; id<=16; id++ ) {
    char name[17];
    uchar role[4];
    uchar access_req[] = { 1, id };
    uchar access_out[256];
    if( fw_username( ctx, id, name ) ) return -1;
    if( name[0] ) continue;
    if( fw_ipmi( ctx, 6, 0x44, access_req, sizeof(access_req), access_out )!=5 ||
        fw_ext_get( ctx, 4, id, role, sizeof(role) ) ) return -1;
    if( (access_out[2]&0xc0U)!=0x80U || role[0] || role[1] || role[2] || role[3] ) continue;
    ctx->user_id = id;
    break;
  }
  if( !ctx->user_id ) return fw_error( "no unused, disabled iDRAC account slot is available" );
  uchar random[32];
  if( getrandom( random, sizeof(random), 0 )!=(ssize_t)sizeof(random) ) return fw_error( "credential randomness failed" );
  FD_TEST( fd_cstr_printf_check( ctx->user, sizeof(ctx->user), NULL, "fdfw%02x%02x%02x%02x%02x%02x",
           random[0], random[1], random[2], random[3], random[4], random[5] ) );
  char record[64];
  FD_TEST( fd_cstr_printf_check( record, sizeof(record), NULL, "%u %s\n", (uint)ctx->user_id, ctx->user ) );
  if( fw_record( ctx, "account", record ) ) return -1;
  char actual[17];
  if( fw_username( ctx, ctx->user_id, actual ) || actual[0] ) return fw_error( "chosen iDRAC account slot was claimed concurrently" );
  if( fw_interrupted ) return -1;
  uchar name_req[17] = { ctx->user_id };
  uchar response[256];
  memcpy( name_req+1, ctx->user, 16 );
  if( fw_ipmi( ctx, 6, 0x45, name_req, sizeof(name_req), response )!=1 ) return -1;
  if( fw_interrupted ) return -1;
  uchar password[22] = { (uchar)(ctx->user_id|0x80U), 2, 'A', 'a', '7', '!' };
  char const alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  for( ulong i=0UL; i<16UL; i++ ) password[i+6UL] = (uchar)alphabet[random[i+8UL]&63U];
  int result = fw_ipmi( ctx, 6, 0x47, password, sizeof(password), response );
  char password_text[22];
  memcpy( password_text, password+2, 20 );
  password_text[20] = '\n';
  password_text[21] = '\0';
  explicit_bzero( password, sizeof(password) );
  explicit_bzero( random, sizeof(random) );
  int password_saved = result==1 ? fw_record( ctx, "password", password_text ) : -1;
  explicit_bzero( password_text, sizeof(password_text) );
  if( password_saved || fw_interrupted || fw_role( ctx, 19U ) ) return -1;
  if( fw_record( ctx, "askpass", "#!/bin/sh\nexec /bin/cat " FW_DIR "/password\n" ) ) return -1;
  int helper = openat( ctx->dir, "askpass", O_RDONLY|O_NOFOLLOW|O_CLOEXEC );
  if( helper<0 ) return -1;
  int helper_err = fchmod( helper, 0700 );
  close( helper );
  if( helper_err || fw_interrupted || fw_enabled( ctx, 1 ) ) return -1;
  FD_LOG_NOTICE(( "iavf-firmware, temporary iDRAC account %s in slot %u", ctx->user, (uint)ctx->user_id ));
  return 0;
}

/* fw_value accepts RACADM's colon and equals forms and ignores spaces in labels. */
static int
fw_value( char const * text, char const * key, char * value, ulong value_sz ) {
  int found = 0;
  for( char const * line=text; *line; ) {
    char const * end = strchr( line, '\n' );
    if( !end ) end = line+strlen(line);
    char const * p = line;
    char label[128];
    ulong len = 0UL;
    while( p<end && *p!='=' && *p!=':' ) {
      if( !isspace((uchar)*p) ) {
        if( len==sizeof(label)-1UL ) break;
        label[len++] = *p;
      }
      p++;
    }
    label[len] = '\0';
    if( p<end && (*p=='=' || *p==':') && !strcmp( label, key ) ) {
      if( found++ ) return -1;
      p++;
      while( p<end && isspace((uchar)*p) ) p++;
      char const * tail = end;
      while( tail>p && isspace((uchar)tail[-1]) ) tail--;
      ulong size = (ulong)(tail-p);
      if( size>=value_sz ) return -1;
      memcpy( value, p, size );
      value[size] = '\0';
    }
    line = *end ? end+1 : end;
  }
  return found==1 ? 0 : -1;
}

static int
fw_number( char const * text, char const * key, uint * number ) {
  char value[32];
  if( fw_value( text, key, value, sizeof(value) ) || !isdigit((uchar)value[0]) ) return -1;
  char * end;
  errno = 0;
  ulong n = strtoul( value, &end, 10 );
  if( errno || *end || n>UINT_MAX ) return -1;
  *number = (uint)n;
  return 0;
}

static int
fw_token( char const * text ) {
  if( !text[0] ) return 0;
  for( ; *text; text++ ) if( !isalnum((uchar)*text) && *text!='.' && *text!='-' && *text!='_' ) return 0;
  return 1;
}

static int
fw_ready( config_t const * config ) {
  char members[FD_IAVF_MEMBER_MAX][IFNAMSIZ];
  ulong count;
  if( fd_iavf_member_interfaces( config->net.interface, members, &count ) || !count ) return -1;
  int ready = 1;
  for( ulong i=0UL; i<count; i++ ) {
    char path[PATH_MAX];
    uint total;
    FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "/sys/class/net/%s/device/sriov_totalvfs", members[i] ) );
    if( fd_file_util_read_uint( path, &total ) ) {
      if( errno!=ENOENT ) return fw_error( "could not read sriov_totalvfs" );
      ready = 0;
    } else if( !total ) ready = 0;
  }
  return ready;
}

static int
fw_match_nic( config_t const * config, char const * inventory, int * selected ) {
  *selected = 0;
  char vendor[16];
  if( fw_value( inventory, "PCIVendorID", vendor, sizeof(vendor) ) ) return fw_error( "cannot read NIC vendor from iDRAC inventory" );
  if( strcmp( vendor, "8086" ) ) return 0;
  uint bus, device, function;
  if( fw_number( inventory, "BusNumber", &bus ) || fw_number( inventory, "DeviceNumber", &device ) ||
      fw_number( inventory, "FunctionNumber", &function ) ) return fw_error( "cannot read the NIC PCI address from iDRAC inventory" );
  char members[FD_IAVF_MEMBER_MAX][IFNAMSIZ];
  ulong count;
  if( fd_iavf_member_interfaces( config->net.interface, members, &count ) || !count ) return -1;
  for( ulong i=0UL; i<count; i++ ) {
    char path[PATH_MAX], resolved[PATH_MAX];
    FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "/sys/class/net/%s/device", members[i] ) );
    if( !realpath( path, resolved ) ) return -1;
    char * pci = strrchr( resolved, '/' );
    uint dom, b, d, f;
    int consumed = 0;
    if( !pci || sscanf( pci+1, "%x:%x:%x.%x%n", &dom, &b, &d, &f, &consumed )!=4 || pci[1+consumed] ) return -1;
    if( dom || b!=bus || d!=device ) return 0;
    *selected |= f==function;
    FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "/sys/class/net/%s/device/driver", members[i] ) );
    if( !realpath( path, resolved ) || !(pci=strrchr( resolved, '/' )) || strcmp( pci+1, "i40e" ) ) {
      return fw_error( "this prototype supports Intel i40e controllers on Dell servers" );
    }
  }
  return 1;
}

static int
fw_nic_key( char const * text, char fqdd[96] ) {
  char const * key = strcasestr( text, "[Key=NIC." );
  char const * end = key ? strchr( key, '#' ) : NULL;
  if( !end || (ulong)(end-(key+5))>=96UL || !strchr( end, ']' ) || strcasestr( key+1, "[Key=NIC." ) ) {
    return fw_error( "cannot associate NIC settings with one NIC FQDD" );
  }
  memcpy( fqdd, key+5, (ulong)(end-(key+5)) );
  fqdd[end-(key+5)] = '\0';
  return fw_token(fqdd) ? 0 : fw_error( "invalid NIC FQDD" );
}

static int
fw_nic_port( fw_nic_t const * nic, char const * fqdd ) {
  for( ulong i=0UL; i<nic->port_cnt; i++ ) if( !strcmp( nic->ports[i], fqdd ) ) return 1;
  return 0;
}

static int
fw_nic_find( fw_ctx_t * ctx, config_t const * config, fw_nic_t * nic ) {
  FD_LOG_NOTICE(( "iavf-firmware, finding the controller for %s", config->net.interface ));
  char list[FW_OUTPUT_SZ];
  if( fw_ssh( ctx, "racadm get NIC.DeviceLevelConfig", list ) ) return -1;
  char * save;
  for( char * line=strtok_r( list, "\r\n", &save ); line; line=strtok_r( NULL, "\r\n", &save ) ) {
    while( isspace((uchar)*line) ) line++;
    if( !*line ) continue;
    char fqdd[96];
    if( fw_nic_key( line, fqdd ) ) return -1;
    ulong len = 0UL;
    while( line[len] && !isspace((uchar)line[len]) ) len++;
    line[len] = '\0';
    if( len>=sizeof(nic->group) || strncasecmp( line, "NIC.DeviceLevelConfig.", 22UL ) || !fw_token(line) ) {
      return fw_error( "invalid NIC device configuration group" );
    }
    char command[160], out[FW_OUTPUT_SZ];
    FD_TEST( fd_cstr_printf_check( command, sizeof(command), NULL, "racadm hwinventory %s", fqdd ) );
    if( fw_ssh( ctx, command, out ) ) return -1;
    int selected;
    int match = fw_match_nic( config, out, &selected );
    if( match<0 ) return -1;
    if( !match ) continue;
    if( nic->port_cnt==FD_IAVF_MEMBER_MAX || fw_nic_port( nic, fqdd ) ) return fw_error( "unexpected NIC controller port list" );
    fd_cstr_ncpy( nic->ports[nic->port_cnt++], fqdd, sizeof(nic->ports[0]) );
    if( selected && !nic->group[0] ) {
      fd_cstr_ncpy( nic->group, line, sizeof(nic->group) );
      fd_cstr_ncpy( nic->fqdd, fqdd, sizeof(nic->fqdd) );
    }
  }
  if( !nic->group[0] ) return fw_error( "no iDRAC NIC matches net.interface, this prototype requires one i40e controller for all configured members" );
  FD_LOG_NOTICE(( "iavf-firmware, %s matches %s (%s)", config->net.interface, nic->fqdd, nic->group ));
  return 0;
}

static int
fw_nic_check( fw_ctx_t * ctx, fw_nic_t const * nic ) {
  char command[192];
  FD_TEST( fd_cstr_printf_check( command, sizeof(command), NULL, "racadm get %s", nic->group ) );
  char out[FW_OUTPUT_SZ];
  if( fw_ssh( ctx, command, out ) ) return -1;
  char fqdd[96], value[128];
  if( fw_nic_key( out, fqdd ) || strcmp( fqdd, nic->fqdd ) ) {
    return fw_error( "NIC settings no longer match the selected NIC" );
  }
  if( (fw_value( out, "#SRIOVSupport", value, sizeof(value) ) &&
       fw_value( out, "SRIOVSupport", value, sizeof(value) )) || strcmp( value, "Available" ) ) {
    return fw_error( "the selected NIC does not advertise SR-IOV support" );
  }
  if( fw_value( out, "VirtualizationMode", value, sizeof(value) ) ) {
    return fw_error( "the selected NIC does not expose a writable VirtualizationMode setting" );
  }
  if( strcasestr( value, "pending" ) ) return fw_error( "the selected NIC already has a pending VirtualizationMode change, review it in iDRAC before retrying" );
  if( strcmp( value, "NONE" ) ) return fw_error( "expected VirtualizationMode=NONE, refusing to replace another virtualization mode" );
  return 0;
}

static int
fw_nic_jobs_idle( fw_ctx_t * ctx, fw_nic_t const * nic ) {
  char out[FW_OUTPUT_SZ];
  if( fw_ssh( ctx, "racadm jobqueue view", out ) ) return -1;
  if( strcasestr( out, "no jobs" ) || strcasestr( out, "job queue is empty" ) ) return 0;
  char * job = strstr( out, "[Job ID" );
  if( !job ) return fw_error( "could not read the iDRAC job queue" );
  while( job ) {
    char * next = strstr( job+1, "[Job ID" );
    if( next ) *next = '\0';
    char name[160];
    if( fw_value( job, "JobName", name, sizeof(name) ) ) return fw_error( "could not identify an iDRAC job" );
    char const prefix[] = "Configure: ";
    if( !strncmp( name, prefix, sizeof(prefix)-1UL ) && fw_nic_port( nic, name+sizeof(prefix)-1UL ) ) {
      char status[64];
      if( fw_value( job, "Status", status, sizeof(status) ) && fw_value( job, "JobStatus", status, sizeof(status) ) ) {
        return fw_error( "could not read the NIC configuration job status" );
      }
      if( strcmp( status, "Completed" ) && strcmp( status, "Failed" ) && strcmp( status, "Reboot Completed" ) ) {
        FD_LOG_WARNING(( "iavf-firmware, %s has status %s, review its job before retrying", name, status ));
        return -1;
      }
    }
    if( next ) *next = '[';
    job = next;
  }
  return 0;
}

static int
fw_schedule( fw_ctx_t * ctx, config_t const * config ) {
  char out[FW_OUTPUT_SZ];
  char tag[64];
  ulong tag_sz;
  if( !fd_file_util_read_cstr( "/sys/class/dmi/id/product_serial", tag, sizeof(tag), &tag_sz ) ) return -1;
  while( tag_sz && isspace((uchar)tag[tag_sz-1UL]) ) tag[--tag_sz] = '\0';
  if( !fw_token(tag) || fw_ssh( ctx, "racadm getsvctag", out ) ) return -1;
  char * p = out;
  while( isspace((uchar)*p) ) p++;
  ulong n = strlen(p);
  while( n && isspace((uchar)p[n-1UL]) ) p[--n] = '\0';
  if( strcmp( p, tag ) ) return fw_error( "SSH endpoint service tag does not match this server" );
  if( fw_ssh( ctx, "racadm get BIOS.IntegratedDevices.SriovGlobalEnable", out ) ) return -1;
  char value[128];
  if( fw_value( out, "SriovGlobalEnable", value, sizeof(value) ) || strcmp( value, "Enabled" ) ) {
    return fw_error( "enable global SR-IOV in the system BIOS first, this prototype changes only the NIC setting" );
  }

  char command[256];
  fw_nic_t nic = {0};
  if( fw_nic_find( ctx, config, &nic ) ||
      fw_nic_check( ctx, &nic ) ||
      fw_nic_jobs_idle( ctx, &nic ) ) return -1;
  if( fw_interrupted ) return -1;
  char const * group = nic.group;
  char const * fqdd = nic.fqdd;
  FD_LOG_NOTICE(( "iavf-firmware, this NIC job also applies any other pending settings on %s", fqdd ));
  FD_LOG_NOTICE(( "iavf-firmware, staging SRIOV" ));
  char record[384];
  FD_TEST( fd_cstr_printf_check( record, sizeof(record), NULL, "setting %s %s\n", fqdd, group ) );
  if( fw_record( ctx, "job", record ) ) return -1;
  FD_TEST( fd_cstr_printf_check( command, sizeof(command), NULL, "racadm set %s.VirtualizationMode SRIOV", group ) );
  if( fw_ssh( ctx, command, out ) ) {
    return fw_error( "NIC setting result is uncertain, retained " FW_DIR "/job for review" );
  }
  FD_TEST( fd_cstr_printf_check( command, sizeof(command), NULL, "racadm get %s.VirtualizationMode", group ) );
  if( fw_ssh( ctx, command, out ) || fw_value( out, "VirtualizationMode", value, sizeof(value) ) ||
      strcmp( value, "NONE (Pending Value=SRIOV)" ) ) {
    FD_LOG_WARNING(( "iavf-firmware, cannot verify the pending SRIOV value, no job submitted\n%s", out ));
    return -1;
  }
  FD_TEST( fd_cstr_printf_check( record, sizeof(record), NULL, "submitting %s %s\n", fqdd, group ) );
  if( fw_record( ctx, "job", record ) ) return -1;
  FD_TEST( fd_cstr_printf_check( command, sizeof(command), NULL, "racadm jobqueue create %s -s TIME_NOW", fqdd ) );
  if( fw_ssh( ctx, command, out ) ) return fw_error( "job submission result is uncertain, do not resubmit without checking iDRAC" );
  char jid[64];
  if( fw_value( out, "CommitJID", jid, sizeof(jid) ) || strncmp( jid, "JID_", 4 ) || !fw_token(jid) ) {
    return fw_error( "job submission returned no recognized ID, check iDRAC before retrying" );
  }
  FD_TEST( fd_cstr_printf_check( record, sizeof(record), NULL, "%s %s %s\n", jid, fqdd, group ) );
  if( fw_record( ctx, "job", record ) ) return -1;
  FD_LOG_NOTICE(( "iavf-firmware, created %s without a reboot job", jid ));
  for( uint attempt=0U; attempt<30U && !fw_interrupted; attempt++ ) {
    FD_TEST( fd_cstr_printf_check( command, sizeof(command), NULL, "racadm jobqueue view -i %s", jid ) );
    if( fw_ssh( ctx, command, out ) ) return -1;
    if( fw_value( out, "Status", value, sizeof(value) ) && fw_value( out, "JobStatus", value, sizeof(value) ) ) {
      return fw_error( "cannot read configuration job status" );
    }
    if( !strcmp( value, "Scheduled" ) ) {
      FD_LOG_WARNING(( "SR-IOV firmware job %s is scheduled. Reboot the server when ready. IAVF will only be supported once the restart is complete. Then run configure init all.", jid ));
      return 0;
    }
    if( strcmp( value, "New" ) && strcmp( value, "Scheduling" ) ) {
      FD_LOG_WARNING(( "iavf-firmware, job %s has unexpected status %s\n%s", jid, value, out ));
      return -1;
    }
    struct timespec delay = { .tv_sec = 1 };
    nanosleep( &delay, NULL );
  }
  return fw_error( "job did not reach Scheduled, inspect iDRAC before rebooting" );
}

void
iavf_firmware_cmd( args_t const * args, config_t const * config ) {
  int fini = args->configure.command==CONFIGURE_CMD_FINI;
  if( !fini && strcmp( config->net.provider, "iavf" ) ) FD_LOG_ERR(( "iavf-firmware requires net.provider=iavf" ));
  int ready = fw_ready( config );
  if( ready<0 && !fini ) FD_LOG_ERR(( "could not inspect Linux SR-IOV support" ));
  if( ready<0 ) ready = 0;
  if( args->configure.command==CONFIGURE_CMD_CHECK ) {
    if( ready ) FD_LOG_NOTICE(( "iavf-firmware, Linux exposes SR-IOV for every configured member" ));
    else FD_LOG_ERR(( "Linux does not expose SR-IOV for every configured member. A missing capability alone does not identify a firmware setting. For a staged iavf-firmware job, review " FW_DIR "/job and its iDRAC status before rebooting." ));
    return;
  }
  struct rlimit core = {0};
  if( setrlimit( RLIMIT_CORE, &core ) || prctl( PR_SET_DUMPABLE, 0 ) ) {
    FD_LOG_ERR(( "could not disable credential-bearing core dumps" ));
  }
  fw_ctx_t ctx = { .ipmi = -1, .dir = -1, .lock = -1 };
  struct sigaction action = { .sa_handler = fw_signal };
  struct sigaction old_int, old_term;
  sigemptyset( &action.sa_mask );
  if( sigaction( SIGINT, &action, &old_int ) || sigaction( SIGTERM, &action, &old_term ) ) {
    FD_LOG_ERR(( "could not install firmware configure signal handlers" ));
  }
  int err = fw_state_open( &ctx ) || fw_open( &ctx );
  if( !err ) err = fw_cleanup( &ctx );
  if( !err && args->configure.command==CONFIGURE_CMD_INIT && !ready ) {
    struct stat st;
    if( !fstatat( ctx.dir, "job", &st, AT_SYMLINK_NOFOLLOW ) ) {
      err = fw_error( "a previous job or uncertain write is recorded in " FW_DIR "/job, review it before any retry" );
    } else if( errno!=ENOENT ) err = -1;
    if( !err ) err = fw_bootstrap( &ctx );
    if( !err ) err = fw_schedule( &ctx, config );
  }
  if( ctx.dir>=0 && ctx.lock>=0 && ctx.ipmi>=0 ) {
    if( fw_cleanup( &ctx ) ) {
      FD_LOG_WARNING(( "Temporary iDRAC access could not be fully removed. Preserve " FW_DIR " and rerun configure fini iavf-firmware." ));
      err = -1;
    }
  }
  if( !err && args->configure.command==CONFIGURE_CMD_FINI ) {
    if( ready && fw_unlink( &ctx, "job" ) ) err = -1;
    FD_LOG_NOTICE(( "iavf-firmware, temporary access removed. Firmware settings and queued jobs are retained." ));
  }
  if( !err && args->configure.command==CONFIGURE_CMD_INIT && ready ) {
    FD_LOG_NOTICE(( "iavf-firmware, Linux already exposes SR-IOV, no firmware change required" ));
  }
  if( ctx.ipmi>=0 ) close( ctx.ipmi );
  if( ctx.lock>=0 ) close( ctx.lock );
  if( ctx.dir>=0 ) close( ctx.dir );
  sigaction( SIGINT, &old_int, NULL );
  sigaction( SIGTERM, &old_term, NULL );
  if( err || fw_interrupted ) FD_LOG_ERR(( "iavf-firmware did not complete, see diagnostics above" ));
}
