#!/usr/bin/env python3
"""votor_peers_report.py: read-only report of a running validator's votor
peer table, straight from its workspace on hugetlbfs.

  sudo python3 -I votor_peers_report.py [--wksp PATH] [--peer PUBKEY ...] [--all]

It mmaps <name>_votor.wksp read-only and never signals, ptraces or pauses
the validator.  For each peer the votor tile knows it reports:
  - its ranks (prev/curr/next epoch)
  - the contact info votor dials (alpenglow ip:port)
  - the outbound (tx) and inbound (rx) QUIC connection, with the conn
    state and close reason when the process mapping can be resolved
  - redial bookkeeping: reconn_pending, backoff and last attempt age.

Layouts match src/discof/votor/fd_votor_tile.c on v26.10 (peer_t 96 B,
contact_info_t 44 B) and fd_quic_conn_t from the same build.  The script
checks the maps it finds (key_cnt against occupied slots) and the conn
objects it follows (conn->context points at the peer's own id key), and
says so when a check fails instead of printing garbage."""

import argparse, datetime, glob, mmap, os, re, struct, subprocess, sys, time

B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def b58enc( b ):
  n = int.from_bytes( b, 'big' ); s = ''
  while n: n, r = divmod( n, 58 ); s = B58[ r ] + s
  return '1'*( len( b )-len( b.lstrip( b'\0' ) ) ) + s

def b58dec( s ):
  n = 0
  for c in s: n = n*58 + B58.index( c )
  return n.to_bytes( 32, 'big' )

RANK_NULL      = 0xFFFF
BAN_TIMEOUT_NS = 10_000_000_000

PEER_SZ, PEER_LG, PEER_SLOT_OFF = 96, 13, 32  # fd_map_dynamic header is 28 B, slot aligned to 8
CI_SZ,   CI_LG,   CI_SLOT_OFF   = 44, 16, 28  # slot aligned to 4

# fd_quic_conn_t field offsets, v26.10 gcc build (gdb against firedancer-dev).
# Every conn read is checked: conn_idx/quic must agree with its pool and
# context must point at the owning peer's id key.
CONN_OFF = dict( conn_idx=0, quic=8, context=16, flags=24, host=96, peer=104, exp_pkt_number=1336, pkt_number=1360,
                 state=3496, reason=3500, app_reason=3504, idle_timeout=5800, last_activity=5808 )

# fd_quic_t.metrics (fd_quic_metrics_t) offsets, v26.10 gcc build.
QUIC_METRICS_OFF = 448
QUIC_METRICS = [ ( 'net_rx_pkt',0,1 ), ( 'net_tx_pkt',16,1 ), ( 'retry_tx',32,1 ), ( 'conn_created',48,1 ), ( 'conn_closed',56,1 ),
                 ( 'conn_aborted',64,1 ), ( 'conn_timeout',72,1 ), ( 'conn_retry',80,1 ), ( 'conn_err_no_slots',88,1 ), ( 'conn_err_retry_fail',96,1 ),
                 ( 'pkt_net_hdr_err',168,1 ), ( 'pkt_quic_hdr_err',176,1 ), ( 'pkt_undersz',184,1 ), ( 'pkt_oversz',192,1 ),
                 ( 'pkt_decrypt_fail[i,h,0rtt,1rtt]',200,4 ), ( 'pkt_no_key[i,h,0rtt,1rtt]',232,4 ), ( 'pkt_no_conn[i,h,0rtt,1rtt]',264,4 ),
                 ( 'pkt_wrong_src',296,1 ), ( 'pkt_verneg',328,1 ), ( 'pkt_retransmissions[i,h,0rtt,1rtt]',336,4 ),
                 ( 'initial_token_len[0,retry,invalid]',368,3 ), ( 'frame_rx_err',576,1 ), ( 'hs_created',584,1 ),
                 ( 'hs_err_alloc_fail',592,1 ), ( 'hs_evicted',600,1 ) ]

CONN_STATE = { 0:'INVALID', 1:'HANDSHAKE', 2:'HS_COMPLETE', 3:'ACTIVE', 4:'PEER_CLOSE', 5:'ABORT', 6:'CLOSE_PENDING', 7:'DEAD' }

def find_maps( m, lg, slot_off, slot_sz ):
  """fd_map_dynamic header: key_cnt, seed, slot_mask, lg_slot_cnt, slot[]."""
  pat   = struct.pack( '<QI', (1<<lg)-1, lg )
  found = []
  for hit in re.finditer( re.escape( pat ), m ):
    hdr = hit.start()-16
    if hdr<0 or hdr%4: continue
    key_cnt, seed = struct.unpack_from( '<QQ', m, hdr )
    slots = hdr+slot_off
    if slots+(slot_sz<<lg)>len( m ): continue
    occ = sum( 1 for i in range( 1<<lg ) if m[ slots+i*slot_sz : slots+i*slot_sz+32 ]!=b'\0'*32 )
    found.append( dict( hdr=hdr, key_cnt=key_cnt, seed=seed, slots=slots, occ=occ ) )
  return found

def pick( maps, what ):
  good = [ x for x in maps if x[ 'key_cnt' ] and abs( x[ 'key_cnt' ]-x[ 'occ' ] )<=8 ]
  if not good:
    sys.exit( f'no valid {what} map found (candidates: {maps})' )
  if len( good )>1:
    print( f'warning: {len(good)} {what} maps pass validation, using the first: {[hex(x["hdr"]) for x in good]}' )
  return good[ 0 ]

def proc_tree( root ):
  """root and all its descendants (tiles run as child processes unless --no-clone)."""
  kids = {}
  for d in os.listdir( '/proc' ):
    if not d.isdigit(): continue
    try:
      pp = int( open( f'/proc/{d}/stat' ).read().rsplit( ')', 1 )[ 1 ].split()[ 1 ] )
      kids.setdefault( pp, [] ).append( int( d ) )
    except OSError: continue
  out, todo = set(), [ root ]
  while todo:
    q = todo.pop(); out.add( q ); todo += kids.get( q, [] )
  return out

def tile_pid( tree, tile ):
  """Process running 'run1 <tile>' in the tree, else None (threaded --no-clone)."""
  for q in tree:
    try:
      if f' run1 {tile} ' in ' '+open( f'/proc/{q}/cmdline', 'rb' ).read().replace( b'\0', b' ' ).decode( errors='replace' )+' ': return q
    except OSError: continue
  return None

def proc_mapping( path ):
  """Return (pid, base_laddr) of the validator process mapping path at
  file offset 0.  Skips this script, which maps the file itself."""
  real = os.path.realpath( path )
  for d in os.listdir( '/proc' ):
    if not d.isdigit() or int( d )==os.getpid(): continue
    try:
      for ln in open( f'/proc/{d}/maps' ):
        f = ln.split()
        if len( f )>=6 and os.path.realpath( f[ 5 ] )==real:
          lo  = int( f[ 0 ].split( '-' )[ 0 ], 16 )
          off = int( f[ 2 ], 16 )
          return int( d ), lo-off
    except OSError:
      continue
  return None, None

def udp_sockets():
  """Every UDP socket on the host: local port, rx queue, drops, owning pids."""
  socks = {}
  for f in ( '/proc/net/udp', '/proc/net/udp6' ):
    try: lines = open( f ).read().splitlines()[ 1: ]
    except OSError: continue
    for ln in lines:
      c = ln.split()
      lport = int( c[ 1 ].split( ':' )[ 1 ], 16 )
      rxq   = int( c[ 4 ].split( ':' )[ 1 ], 16 )
      socks[ int( c[ 9 ] ) ] = dict( file=f[ -4: ], local=c[ 1 ], lport=lport, rxq=rxq, drops=int( c[ 12 ] ), pids=set() )
  for d in os.listdir( '/proc' ):
    if not d.isdigit(): continue
    try:
      for fd in os.listdir( f'/proc/{d}/fd' ):
        try: t = os.readlink( f'/proc/{d}/fd/{fd}' )
        except OSError: continue
        if t.startswith( 'socket:[' ):
          ino = int( t[ 8:-1 ] )
          if ino in socks: socks[ ino ][ 'pids' ].add( int( d ) )
    except OSError: continue
  return socks

def proc_desc( pid ):
  try:
    cmd = open( f'/proc/{pid}/cmdline', 'rb' ).read().replace( b'\0', b' ' ).decode( errors='replace' ).strip()
    st  = os.stat( f'/proc/{pid}' ).st_mtime
    return f'{cmd[:80]} (started {datetime.datetime.fromtimestamp( st ):%m-%d %H:%M:%S})'
  except OSError: return '?'

def sh( cmd ):
  try: return subprocess.run( cmd, shell=True, capture_output=True, text=True, timeout=30 ).stdout
  except Exception: return ''

def snmp():
  out = {}
  try: lines = open( '/proc/net/snmp' ).read().splitlines()
  except OSError: return out
  for h, v in zip( lines[ ::2 ], lines[ 1::2 ] ):
    k = h.split(); w = v.split()
    for name, val in zip( k[ 1: ], w[ 1: ] ): out[ k[ 0 ]+name ] = int( val )
  return out

QRE = re.compile( r'^\s*rx[-_]?(?:queue_)?(\d+)[._]packets:\s*(\d+)', re.M )

def host_snap():
  """Kernel-side view of the network path, sampled so deltas can be taken."""
  xdp_if = {}
  for ln in sh( 'bpftool net 2>/dev/null' ).splitlines():
    m_ = re.match( r'\s*(\S+)\((\d+)\)\s+(\w+)\s+id\s+(\d+)', ln )
    if m_: xdp_if[ m_.group( 1 ) ] = dict( mode=m_.group( 3 ), prog=int( m_.group( 4 ) ) )
  for name, x in xdp_if.items():
    t = sh( f'bpftool prog show id {x["prog"]} 2>/dev/null' )
    m_ = re.search( r'loaded_at (\S+)', t ); x[ 'loaded_at' ] = m_.group( 1 ) if m_ else '?'
    m_ = re.search( r'pids (.*)', t );       x[ 'pids' ]      = m_.group( 1 ).strip() if m_ else ''
  xsk = []
  for ln in sh( 'ss -H --xdp -p 2>/dev/null' ).splitlines():
    m_ = re.search( r'(\S+):q(\d+).*pid=(\d+)', ln )
    if m_: xsk.append( ( m_.group( 1 ), int( m_.group( 2 ) ), int( m_.group( 3 ) ) ) )
  ifs = set( xdp_if )
  for d in os.listdir( '/sys/class/net' ):
    try:
      mst = os.path.basename( os.readlink( f'/sys/class/net/{d}/master' ) )
      if mst in xdp_if: ifs.add( d )
    except OSError: pass
  queues = {}
  for d in sorted( ifs ):
    queues[ d ] = { int( q ): int( n ) for q, n in QRE.findall( sh( f'ethtool -S {d} 2>/dev/null' ) ) }
  masters = {}
  for d in ifs:
    try: masters[ d ] = os.path.basename( os.readlink( f'/sys/class/net/{d}/master' ) )
    except OSError: pass
  bonds = {}
  for f in glob.glob( '/proc/net/bonding/*' ):
    try: bonds[ os.path.basename( f ) ] = open( f ).read()
    except OSError: pass
  ifstat = {}
  for d in os.listdir( '/sys/class/net' ):
    st = {}
    for k in ( 'rx_packets', 'tx_packets', 'rx_dropped', 'tx_dropped', 'rx_errors', 'tx_errors', 'rx_missed_errors' ):
      try: st[ k ] = int( open( f'/sys/class/net/{d}/statistics/{k}' ).read() )
      except (OSError, ValueError): pass
    try: st[ 'operstate' ] = open( f'/sys/class/net/{d}/operstate' ).read().strip()
    except OSError: pass
    ifstat[ d ] = st
  nicstat = {}  # hardware/driver counters, include kernel-bypass (mlx5/XDP) traffic
  for d in os.listdir( '/sys/class/net' ):
    if not os.path.exists( f'/sys/class/net/{d}/device' ): continue
    st = {}
    for ln in sh( f'ethtool -S {d} 2>/dev/null' ).splitlines():
      m_ = re.match( r'\s*([\w.\-]+):\s*(\d+)\s*$', ln )
      if m_ and re.search( r'_phy$|steer|discard|out_of_buffer|^rx_packets$|^tx_packets$|^rx_vport_unicast_packets$|^tx_vport_unicast_packets$', m_.group( 1 ) ):
        st[ m_.group( 1 ) ] = int( m_.group( 2 ) )
    nicstat[ d ] = st
  ib = {}
  for dev in sorted( glob.glob( '/sys/class/infiniband/*' ) ):
    for pt in sorted( glob.glob( f'{dev}/ports/*' ) ):
      nd = sorted( set( os.path.basename( os.readlink( x ) ) if os.path.islink( x ) else open( x ).read().strip() for x in glob.glob( f'{pt}/gid_attrs/ndevs/*' ) if os.path.exists( x ) ) - { '' } )
      st = ''
      try: st = open( f'{pt}/state' ).read().strip()
      except OSError: pass
      cnt = {}
      for c in ( 'port_rcv_packets', 'port_xmit_packets', 'port_rcv_discards', 'port_xmit_discards' ):
        try: cnt[ c ] = int( open( f'{pt}/counters/{c}' ).read() )
        except (OSError, ValueError): pass
      ib[ f'{os.path.basename(dev)}/{os.path.basename(pt)}' ] = dict( ndevs=nd, state=st, cnt=cnt )
  return dict( t=time.time(), snmp=snmp(), xdp_if=xdp_if, xsk=xsk, queues=queues, masters=masters, socks=udp_sockets(), bonds=bonds, ifstat=ifstat, nicstat=nicstat, ib=ib )

def related_procs( vpid ):
  """Processes that look like a validator, with start times."""
  out = []
  for d in os.listdir( '/proc' ):
    if not d.isdigit(): continue
    try:
      cmd = open( f'/proc/{d}/cmdline', 'rb' ).read().replace( b'\0', b' ' ).decode( errors='replace' )
      if re.search( r'(^|/)(firedancer|firedancer-dev|fdctl|fddev|agave-validator|solana-validator) ', cmd ):
        out.append( ( int( d ), os.stat( f'/proc/{d}' ).st_mtime, cmd.strip()[ :100 ] ) )
    except OSError: continue
  return out

def main():
  ap = argparse.ArgumentParser( description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter )
  ap.add_argument( '--wksp', help='votor workspace file (default: the only /mnt/.fd/*/*_votor.wksp)' )
  ap.add_argument( '--peer', action='append', default=[], help='base58 identity to show in detail (repeatable)' )
  ap.add_argument( '--identity', help='this validator\'s base58 identity, labelled self in the report' )
  ap.add_argument( '--all', action='store_true', help='list every ranked peer, not only the unconnected ones' )
  ap.add_argument( '--interval', type=float, default=0, help='also sample fd_quic metrics twice, this many seconds apart, and print the deltas' )
  ap.add_argument( '--conn-off', default='', help='override fd_quic_conn_t offsets, e.g. state=3496,last_activity=5808' )
  a = ap.parse_args()

  paths = [ a.wksp ] if a.wksp else sorted( f for f in glob.glob( '/mnt/.fd/.gigantic/*_votor.wksp' )+glob.glob( '/mnt/.fd/.huge/*_votor.wksp' )
                                              if re.fullmatch( r'[^_]+_votor\.wksp', os.path.basename( f ) ) ) # not link wksps like fd1_net_votor
  if len( paths )!=1: sys.exit( f'need exactly one votor wksp, found {paths}; pass --wksp' )
  path = paths[ 0 ]
  fh = open( path, 'rb' )
  m  = mmap.mmap( fh.fileno(), 0, prot=mmap.PROT_READ )

  now_ns = time.time_ns()
  ct     = datetime.datetime.now( datetime.timezone( datetime.timedelta( hours=-5 ) ) )
  print( f'# votor peer report  {ct:%Y-%m-%d %H:%M:%S} CT  host {os.uname().nodename}' )
  print( f'wksp {path}' )

  pm = pick( find_maps( m, PEER_LG, PEER_SLOT_OFF, PEER_SZ ), 'peers' )
  cm = pick( find_maps( m, CI_LG,   CI_SLOT_OFF,   CI_SZ   ), 'contact_infos' )
  print( f'peers map @{pm["hdr"]:#x} keys {pm["key_cnt"]}   contact_infos map @{cm["hdr"]:#x} keys {cm["key_cnt"]}' )

  pid, base = proc_mapping( path )
  if pid is None: print( 'process mapping not found (run as root to resolve QUIC conn state)' )
  else:           print( f'pid {pid}  wksp mapped at {base:#x}' )

  cis = {}
  for i in range( 1<<CI_LG ):
    o = cm[ 'slots' ]+i*CI_SZ
    k = m[ o:o+32 ]
    if k==b'\0'*32: continue
    _, ip, port = struct.unpack_from( '<IIH', m, o+32 )
    cis[ k ] = ( '.'.join( str( x ) for x in struct.pack( '<I', ip ) ), port )

  for kv in filter( None, a.conn_off.split( ',' ) ):
    k, v = kv.split( '=' ); CONN_OFF[ k ] = int( v, 0 )
  memf = None
  tree = proc_tree( pid ) if pid else set()
  # the validator's root process: walk up while the parent maps the same wksp
  vpid = pid
  vtile = tile_pid( tree, 'votor' ) if pid else None
  mpid = vtile or pid  # conn objects live in the votor tile's address space
  if vtile: print( f'votor tile process {vtile} (reading QUIC objects from its memory)' )
  if pid is not None:
    try: memf = open( f'/proc/{mpid}/mem', 'rb' )
    except OSError as e: print( f'cannot read /proc/{mpid}/mem ({e}); QUIC conn state unavailable' )
  def rd( addr, n ):
    if memf is None: return None
    try:
      memf.seek( addr ); b = memf.read( n )
      return b if len( b )==n else None
    except OSError: return None
  def u( addr, fmt ):
    b = rd( addr, struct.calcsize( fmt ) )
    return struct.unpack( fmt, b ) if b else None

  def conn_obj( ptr ):
    """Raw fields of the fd_quic_conn_t at ptr, or None if unreadable."""
    O = CONN_OFF
    f = {}
    for name, fmt in ( ( 'conn_idx','<I' ), ( 'quic','<Q' ), ( 'context','<Q' ), ( 'flags','<I' ), ( 'host','<IH' ), ( 'peer','<IH' ),
                       ( 'exp_pkt_number','<QQQ' ), ( 'pkt_number','<QQQ' ), ( 'state','<I' ), ( 'reason','<I' ),
                       ( 'app_reason','<I' ), ( 'idle_timeout','<q' ), ( 'last_activity','<q' ) ):
      v = u( ptr+O[ name ], fmt )
      if v is None: return None
      f[ name ] = v if len( v )>1 else v[ 0 ]
    hip, hport = f.pop( 'host' )
    f[ 'host_addr' ] = '.'.join( str( x ) for x in struct.pack( '<I', hip ) )+f':{hport}'
    ip, port = f.pop( 'peer' )
    f[ 'peer_ip' ]   = '.'.join( str( x ) for x in struct.pack( '<I', ip ) )
    f[ 'peer_port' ] = port
    f[ 'server' ]    = f[ 'flags' ]&1
    f[ 'state_s' ]   = CONN_STATE.get( f[ 'state' ], str( f[ 'state' ] ) )
    f[ 'ptr' ]       = ptr
    f[ 'ctx_key' ]   = rd( f[ 'context' ], 32 ) if f[ 'context' ] else None
    return f

  def conn( ptr, key ):
    if not ptr: return None
    f = conn_obj( ptr )
    if f is None: return dict( ptr=ptr, state='?', check='unreadable' )
    f[ 'state' ] = f[ 'state_s' ]
    f[ 'check' ] = 'ok' if f[ 'ctx_key' ]==key else 'context!=peer'
    return f

  peers = []
  for i in range( 1<<PEER_LG ):
    o = pm[ 'slots' ]+i*PEER_SZ
    k = m[ o:o+32 ]
    if k==b'\0'*32: continue
    _, pr, cr, nr = struct.unpack_from( '<IHHH', m, o+32 )
    tx, rx, ban, cts, bo, rp = struct.unpack_from( '<QQqqqi', m, o+48 )
    peers.append( dict( key=k, id=b58enc( k ), prev=pr, curr=cr, next=nr, ci=cis.get( k ),
                        tx=conn( tx, k ), rx=conn( rx, k ), ban_ts=ban, conn_ts=cts, backoff=bo, reconn=rp ) )

  ranked = [ p for p in peers if p[ 'curr' ]!=RANK_NULL ]
  self_key = b58dec( a.identity ) if a.identity else None
  def cls( p ):
    if p[ 'key' ]==self_key:                                              return 'self'
    if p[ 'tx' ] and p[ 'tx' ][ 'state' ]=='ACTIVE':                     return 'tx ACTIVE'
    if p[ 'tx' ]:                                                         return f'tx {p["tx"]["state"]}'
    if p[ 'ban_ts' ] and now_ns<p[ 'ban_ts' ]+BAN_TIMEOUT_NS:            return 'no tx: banned'
    if not p[ 'ci' ]:                                                     return 'no tx: no contact info'
    if p[ 'reconn' ]:                                                     return 'no tx: redial queued'
    return 'no tx: STUCK (ci, no redial queued)'

  print( f'\n## {len(ranked)} peers ranked this epoch ({len(peers)} known)\n' )
  print( '| state | peers | with rx conn |' )
  print( '|---|---|---|' )
  groups = {}
  for p in ranked: groups.setdefault( cls( p ), [] ).append( p )
  for g in sorted( groups, key=lambda g: -len( groups[ g ] ) ):
    print( f'| {g} | {len(groups[g])} | {sum(1 for p in groups[g] if p["rx"])} |' )
  rx_only = [ p for p in ranked if p[ 'rx' ] and not ( p[ 'tx' ] and p[ 'tx' ][ 'state' ]=='ACTIVE' ) ]
  print( f'\nrx conn without an ACTIVE tx conn: {len(rx_only)}   no rx conn at all: {sum(1 for p in ranked if not p["rx"])}' )

  bo = {}
  for p in ranked:
    if not ( p[ 'tx' ] and p[ 'tx' ][ 'state' ]=='ACTIVE' ): bo[ p[ 'backoff' ]//1_000_000_000 ] = bo.get( p[ 'backoff' ]//1_000_000_000, 0 )+1
  if bo: print( 'backoff of unconnected peers (s: count): '+', '.join( f'{k}: {v}' for k, v in sorted( bo.items() ) ) )
  bad = [ p for p in peers if ( p[ 'tx' ] and p[ 'tx' ][ 'check' ] not in ( 'ok', ) ) or ( p[ 'rx' ] and p[ 'rx' ][ 'check' ] not in ( 'ok', ) ) ]
  if bad: print( f'warning: {len(bad)} conn pointers failed the context check (conn offsets may not match this build; see --conn-off)' )

  # QUIC conn pools: infer each pool's base and stride from the conns the
  # peers point at (conn_idx is stored in every conn), then walk the pool.
  # Freed conns keep their fields until reused, so the last attempt to a
  # peer stays readable after it failed.
  ptrs = {}
  for p in peers:
    for c in ( p[ 'tx' ], p[ 'rx' ] ):
      if c and c.get( 'check' )=='ok': ptrs.setdefault( c[ 'quic' ], [] ).append( ( c[ 'conn_idx' ], c[ 'ptr' ] ) )
  pools = []
  for q, lst in ptrs.items():
    lst.sort()
    strides = {}
    for ( i0, p0 ), ( i1, p1 ) in zip( lst, lst[ 1: ] ):
      if i1>i0 and ( p1-p0 )%( i1-i0 )==0: strides[ ( p1-p0 )//( i1-i0 ) ] = strides.get( ( p1-p0 )//( i1-i0 ), 0 )+1
    if not strides: continue
    stride = max( strides, key=strides.get )
    base0  = lst[ 0 ][ 1 ]-lst[ 0 ][ 0 ]*stride
    conns  = []
    for i in range( 1<<17 ):
      f = conn_obj( base0+i*stride )
      if f is None or f[ 'conn_idx' ]!=i or f[ 'quic' ]!=q: break
      conns.append( f )
    pools.append( dict( quic=q, stride=stride, base=base0, conns=conns, server=sum( c[ 'server' ] for c in conns if c[ 'state' ] )>0 ) )

  def quic_metrics( q ):
    out = {}
    for name, off, n in QUIC_METRICS:
      v = u( q+QUIC_METRICS_OFF+off, '<'+'Q'*n )
      out[ name ] = None if v is None else ( v if n>1 else v[ 0 ] )
    return out
  h0 = host_snap()
  td = None
  # Packet capture on the votor ports.  XDP mode: only on the XDP interfaces
  # (taps there run after generic XDP, so a packet seen escaped the
  # redirect; member NICs of a bond are tapped before it and would show
  # everything).  Sock mode: every interface, to see per flow which bond
  # member carries it and whether the peer ever answers.
  td_mode = 'xdp' if h0[ 'xdp_if' ] else 'sock'
  if a.interval>0:
    ifs = [ d for d in h0[ 'xdp_if' ] if d!='lo' ] if td_mode=='xdp' else [ 'any' ]
    td = [ subprocess.Popen( f'timeout {a.interval} tcpdump -nn -l -i {d} -c 200000 "udp port 8004 or udp port 8005" 2>/dev/null', shell=True, stdout=subprocess.PIPE, text=True ) for d in ifs ]
  m0 = { pl[ 'quic' ]: quic_metrics( pl[ 'quic' ] ) for pl in pools }
  if a.interval>0:
    time.sleep( a.interval )
    m1 = { pl[ 'quic' ]: quic_metrics( pl[ 'quic' ] ) for pl in pools }
  h1 = host_snap() if a.interval>0 else None
  td_out = ''.join( t.communicate()[ 0 ] for t in td ) if td else ''
  print( f'\n## fd_quic metrics{" (delta over %gs)" % a.interval if a.interval>0 else " (since boot)"}\n' )
  names = [ pl and ( 'server' if pl[ 'server' ] else 'client' ) for pl in pools ]
  print( '| metric | ' + ' | '.join( names ) + ' |' )
  print( '|---|' + '---|'*len( pools ) )
  for name, _, n in QUIC_METRICS:
    cells = []
    for pl in pools:
      v0 = m0[ pl[ 'quic' ] ][ name ]
      if a.interval>0:
        v1 = m1[ pl[ 'quic' ] ][ name ]
        v  = None if v0 is None or v1 is None else ( tuple( y-x for x, y in zip( v0, v1 ) ) if n>1 else v1-v0 )
      else: v = v0
      cells.append( str( v ) )
    print( f'| {name} | ' + ' | '.join( cells ) + ' |' )

  # ---- host network path: verifies "lost below QUIC because flows hash to a
  # dead socket or an unserved NIC queue left by the old process" ----
  print( '\n## Host network path' + ( f' (deltas over {a.interval:g}s)' if h1 else ' (no --interval: absolute values only)' ) + '\n' )
  root = pid
  while True:
    try: pp = int( open( f'/proc/{root}/stat' ).read().rsplit( ')', 1 )[ 1 ].split()[ 1 ] )
    except OSError: break
    try: pcmd = open( f'/proc/{pp}/cmdline', 'rb' ).read()
    except OSError: break
    if b'firedancer' not in pcmd and b'fdctl' not in pcmd: break
    root = pp
  tree = proc_tree( root )
  pid = root
  try: vstart = os.stat( f'/proc/{pid}' ).st_mtime if pid else None
  except OSError: vstart = None
  fmt_t = lambda t: datetime.datetime.fromtimestamp( t, datetime.timezone( datetime.timedelta( hours=-5 ) ) ).strftime( '%m-%d %H:%M:%S CT' )
  print( f'validator pid {pid} started {fmt_t(vstart) if vstart else "?"}, {len(tree)} processes in its tree' )
  verdict = []

  rp = [ x for x in related_procs( pid ) if x[ 0 ]!=os.getpid() ]
  print( '\n### validator-like processes\n' )
  print( '| pid | started | cmdline |' ); print( '|---|---|---|' )
  for q, st, cmd in sorted( rp, key=lambda x: x[ 1 ] ): print( f'| {q}{" (validator)" if q==pid else " (validator tile)" if q in tree else ""} | {fmt_t(st)} | {cmd} |' )
  stale = [ x for x in rp if x[ 0 ] not in tree and vstart and x[ 1 ]<vstart and 'firedancer' in x[ 2 ] ]
  verdict.append( ( 'leftover process older than the validator', bool( stale ), ', '.join( str( x[ 0 ] ) for x in stale ) or 'none' ) )

  print( '\n### XDP programs and AF_XDP sockets\n' )
  if not h0[ 'xdp_if' ]: print( 'no XDP program attached (sock net provider?)' )
  for d, x in sorted( h0[ 'xdp_if' ].items() ):
    print( f'- {d}: {x["mode"]} prog {x["prog"]} loaded_at {x["loaded_at"]} {("pids "+x["pids"]) if x["pids"] else ""}' )
  old_prog = []
  for d, x in h0[ 'xdp_if' ].items():
    try:
      t = datetime.datetime.strptime( x[ 'loaded_at' ][ :19 ], '%Y-%m-%dT%H:%M:%S' ).replace( tzinfo=datetime.timezone.utc ).timestamp()
      if vstart and t<vstart-5: old_prog.append( d )
    except ValueError: pass
  verdict.append( ( 'XDP program loaded before the validator started (left by an older process)', bool( old_prog ), ', '.join( old_prog ) or 'none' ) )
  xsk_by_if = {}
  for d, q, owner in h0[ 'xsk' ]: xsk_by_if.setdefault( d, {} )[ q ] = owner
  print( '| interface | XSK queues (owner pid) |' ); print( '|---|---|' )
  for d in sorted( set( list( xsk_by_if )+list( h0[ 'xdp_if' ] ) ) ):
    print( f'| {d} | ' + ( ', '.join( f'q{q} ({o}{"" if o in tree else " NOT THE VALIDATOR"})' for q, o in sorted( xsk_by_if.get( d, {} ).items() ) ) or 'none' ) + ' |' )
  foreign_xsk = [ ( d, q, o ) for d, q, o in h0[ 'xsk' ] if o not in tree ]
  verdict.append( ( 'AF_XDP socket owned by another process', bool( foreign_xsk ), str( foreign_xsk ) if foreign_xsk else 'none' ) )

  print( '\n### NIC rx queues' + ( ' (packets in interval)' if h1 else ' (packets since driver start)' ) + '\n' )
  unserved = []
  print( '| interface | xdp on | queue | rx packets | XSK bound |' ); print( '|---|---|---|---|---|' )
  for d, qs in sorted( h0[ 'queues' ].items() ):
    on = d if d in h0[ 'xdp_if' ] else h0[ 'masters' ].get( d, d )
    for q, n0 in sorted( qs.items() ):
      n = ( h1[ 'queues' ].get( d, {} ).get( q, n0 )-n0 ) if h1 else n0
      if not n: continue
      bound = q in xsk_by_if.get( on, {} )
      print( f'| {d} | {on} | {q} | {n} | {"yes" if bound else "NO"} |' )
      if not bound and h1: unserved.append( f'{d} q{q} ({n} pkts)' )
  verdict.append( ( 'NIC queue receiving traffic with no XSK bound on the XDP interface (generic XDP on a bond uses the bond queue index, so check the bond rows)', bool( unserved ), ', '.join( unserved ) or 'none' ) )

  print( '\n### bonded interfaces' + ( ' (packets in interval)' if h1 else ' (packets since boot)' ) + '\n' )
  if not h0[ 'bonds' ]: print( 'no bonding interfaces' )
  bad_member = []
  for b, txt in sorted( h0[ 'bonds' ].items() ):
    hdr = {}
    for key in ( 'Bonding Mode', 'Transmit Hash Policy', 'MII Status', 'Currently Active Slave' ):
      m_ = re.search( rf'^{key}: (.*)$', txt, re.M )
      if m_: hdr[ key ] = m_.group( 1 )
    print( f'- {b}: ' + '; '.join( f'{k}: {v}' for k, v in hdr.items() ) )
    m_ = re.search( r'Active Aggregator Info:\s*\n\s*Aggregator ID: (\d+)', txt )
    active_agg = m_.group( 1 ) if m_ else None
    print( '\n(partner column: partner mac, actor/partner LACP port state with C=collecting D=distributing; a member missing D carries no traffic)' )
    print( '\n| member | MII | link failures | aggregator | actor churn | partner churn | partner mac / LACP state | rx pkts | tx pkts | rx drop | tx drop | rx err |' )
    print( '|---|---|---|---|---|---|---|---|---|---|---|---|' )
    for blk in txt.split( 'Slave Interface: ' )[ 1: ]:
      name = blk.split( '\n', 1 )[ 0 ].strip()
      g = lambda pat: ( re.search( pat, blk, re.M ).group( 1 ).strip() if re.search( pat, blk, re.M ) else '?' )
      mii, fails, agg = g( r'^MII Status: (.*)$' ), g( r'^Link Failure Count: (.*)$' ), g( r'^Aggregator ID: (.*)$' )
      achurn, pchurn = g( r'Actor Churn State: (.*)$' ), g( r'Partner Churn State: (.*)$' )
      pmac = g( r'details partner lacp pdu:[\s\S]*?system mac address: (.*)$' )
      ast  = g( r'details actor lacp pdu:[\s\S]*?port state: (\d+)' )
      pst  = g( r'details partner lacp pdu:[\s\S]*?port state: (\d+)' )
      bits = lambda v: ( '?' if not v.isdigit() else ''.join( c for c, b in ( ( 'C', 0x10 ), ( 'D', 0x20 ) ) if int( v )&b ) or 'none' )
      pmac = f'{pmac} actor {ast}({bits(ast)}) partner {pst}({bits(pst)})'
      st0 = h0[ 'ifstat' ].get( name, {} ); st1 = ( h1 or h0 )[ 'ifstat' ].get( name, {} )
      dv = lambda k: ( st1.get( k, 0 )-st0.get( k, 0 ) ) if h1 else st0.get( k, 0 )
      print( f'| {name} | {mii} | {fails} | {agg}{" (active)" if agg==active_agg else " (NOT ACTIVE)" if active_agg and agg!="?" else ""} | {achurn} | {pchurn} | {pmac} | {dv("rx_packets")} | {dv("tx_packets")} | {dv("rx_dropped")} | {dv("tx_dropped")} | {dv("rx_errors")} |' )
      if ( ast.isdigit() and not int( ast )&0x30==0x30 ) or ( pst.isdigit() and ( int( pst )&0x30 )!=0x30 ): bad_member.append( f'{b}/{name} LACP not collecting+distributing' )
      if mii!='up' or ( active_agg and agg not in ( '?', active_agg ) ) or 'churned' in achurn+pchurn or ( h1 and ( dv( 'rx_packets' )==0 ) != ( dv( 'tx_packets' )==0 ) ):
        bad_member.append( f'{b}/{name}' )
  print( '\n### NIC hardware counters' + ( ' (delta in interval)' if h1 else ' (since driver load)' ) + ': include kernel-bypass traffic the kernel counters above do not see\n' )
  keys = [ 'rx_packets_phy', 'tx_packets_phy', 'rx_vport_unicast_packets', 'tx_vport_unicast_packets', 'rx_discards_phy', 'tx_discards_phy', 'rx_out_of_buffer', 'rx_steer_missed_packets' ]
  shown = [ d for d in sorted( h0[ 'nicstat' ] ) if any( k in h0[ 'nicstat' ][ d ] for k in keys ) ]
  if shown:
    print( '| interface | ' + ' | '.join( keys ) + ' |' ); print( '|---|' + '---|'*len( keys ) )
    for d in shown:
      v0 = h0[ 'nicstat' ][ d ]; v1 = ( h1 or h0 )[ 'nicstat' ].get( d, v0 )
      print( f'| {d} | ' + ' | '.join( ( str( v1[ k ]-v0[ k ] ) if h1 else str( v0[ k ] ) ) if k in v0 else '-' for k in keys ) + ' |' )
    if h1:
      for b in h0[ 'bonds' ]:
        mem = [ d for d in shown if h0[ 'masters' ].get( d )==b or d in re.findall( r'Slave Interface: (\S+)', h0[ 'bonds' ][ b ] ) ]
        rxp = { d: ( h1[ 'nicstat' ][ d ].get( 'rx_packets_phy', 0 )-h0[ 'nicstat' ][ d ].get( 'rx_packets_phy', 0 ) ) for d in mem if 'rx_packets_phy' in h0[ 'nicstat' ][ d ] }
        txp = { d: ( h1[ 'nicstat' ][ d ].get( 'tx_packets_phy', 0 )-h0[ 'nicstat' ][ d ].get( 'tx_packets_phy', 0 ) ) for d in mem if 'tx_packets_phy' in h0[ 'nicstat' ][ d ] }
        dead = [ d for d in rxp if rxp[ d ]<0.05*max( rxp.values() or [ 0 ] ) or txp.get( d, 1 )<0.05*max( txp.values() or [ 0 ] ) ]
        verdict.append( ( f'{b} member passing (almost) no hardware traffic in one direction while another carries it', bool( dead ) and len( mem )>1, f'phy rx {rxp} tx {txp}' ) )
      miss = { d: h1[ 'nicstat' ][ d ].get( 'rx_steer_missed_packets', 0 )-h0[ 'nicstat' ][ d ].get( 'rx_steer_missed_packets', 0 ) for d in shown }
      verdict.append( ( 'packets dropped for missing steering rules (rx_steer_missed_packets rising)', any( v>0 for v in miss.values() ), str( { k: v for k, v in miss.items() if v } ) or 'none' ) )
  else: print( 'no driver counters (ethtool -S) available' )
  if h0[ 'ib' ]:
    print( '\n| rdma device/port | state | netdevs | rcv pkts | xmit pkts |' ); print( '|---|---|---|---|---|' )
    for k, v in h0[ 'ib' ].items():
      c1 = ( h1 or h0 )[ 'ib' ].get( k, v )[ 'cnt' ]
      dv = lambda c: ( c1.get( c, 0 )-v[ 'cnt' ].get( c, 0 ) ) if h1 else v[ 'cnt' ].get( c, '-' )
      print( f'| {k} | {v["state"]} | {",".join(v["ndevs"]) or "-"} | {dv("port_rcv_packets")} | {dv("port_xmit_packets")} |' )
    print( '(the mlx5 net tile binds the FIRST rdma device/port whose netdev is the configured interface or one of its bond members; without RoCE LAG that is one physical port)' )

  verdict.append( ( 'bond member down, in a different LACP aggregator, churned, or carrying traffic in only one direction (a layer3+4 hash would then lose a fixed half of all flows, both directions)', bool( bad_member ), ', '.join( bad_member ) or 'none' ) )

  print( '\n### kernel UDP sockets on the votor port and on ports the validator owns\n' )
  socks = h0[ 'socks' ]
  mine  = { x[ 'lport' ] for x in socks.values() if x[ 'pids' ]&tree }
  show_s = { ino: x for ino, x in socks.items() if x[ 'lport' ] in mine|{ 8004, 8005 } }
  if not show_s: print( 'none on 8004 (expected in XDP mode: XDP redirects the votor port to the net tile)' )
  else:
    print( '| port | local | rx queue | drops' + ( ' (delta)' if h1 else '' ) + ' | owner pids |' ); print( '|---|---|---|---|---|' )
    for ino, x in sorted( show_s.items(), key=lambda kv: ( kv[ 1 ][ 'lport' ], kv[ 1 ][ 'local' ] ) ):
      dd = ( h1[ 'socks' ].get( ino, x )[ 'drops' ]-x[ 'drops' ] ) if h1 else x[ 'drops' ]
      own = ', '.join( f'{q}{"" if q in tree else " NOT THE VALIDATOR"}' for q in sorted( x[ 'pids' ] ) ) or 'none (orphaned)'
      print( f'| {x["lport"]} | {x["local"]} | {x["rxq"]} | {dd} | {own} |' )
  dead = [ f'port {x["lport"]} owners {sorted(x["pids"]) or "none"}' for x in show_s.values() if not ( x[ 'pids' ]&tree ) ]
  per_port = {}
  for x in show_s.values(): per_port.setdefault( x[ 'lport' ], [] ).append( x )
  multi = [ f'port {pt}: {len(l)} sockets' for pt, l in per_port.items() if len( l )>1 ]
  verdict.append( ( 'socket on a validator port not owned by the validator, or several sockets sharing a port (REUSEPORT hash split)', bool( dead or multi ), '; '.join( dead+multi ) or 'none' ) )

  if h1:
    d_ = lambda k: h1[ 'snmp' ].get( k, 0 )-h0[ 'snmp' ].get( k, 0 )
    print( f'\nkernel UDP in interval: InDatagrams {d_("UdpInDatagrams")}  NoPorts {d_("UdpNoPorts")}  RcvbufErrors {d_("UdpRcvbufErrors")}  InErrors {d_("UdpInErrors")}  ICMP OutDestUnreachs {d_("IcmpOutDestUnreachs")}' )
    print( '(NoPorts counts UDP that XDP passed up to a port with no kernel socket, on any port)' )
    # parse "IFACE In|Out IP a.b.c.d.P > e.f.g.h.Q: UDP" (any) or "IP a.b.c.d.P > ..." (single iface)
    flows = {}
    for ln in td_out.splitlines():
      m_ = re.search( r'(?:(\S+)\s+(In|Out|P|M)\s+)?IP (\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+): UDP', ln )
      if not m_: continue
      dev, dirn, sip, sp, dip, dp = m_.groups()
      if sp in ( '8004', '8005' ) and ( dirn in ( None, 'Out' ) ): peer, way = dip, 'out'
      else: peer, way = sip, 'in'
      f = flows.setdefault( peer, { 'in': {}, 'out': {} } )
      f[ way ][ dev or '?' ] = f[ way ].get( dev or '?', 0 )+1
    ip2peer = { p[ 'ci' ][ 0 ]: p for p in ranked if p[ 'ci' ] }
    failing = { ip for ip, p in ip2peer.items() if not ( p[ 'tx' ] and p[ 'tx' ][ 'state' ]=='ACTIVE' ) and p[ 'key' ]!=self_key }
    working = { ip for ip, p in ip2peer.items() if p[ 'tx' ] and p[ 'tx' ][ 'state' ]=='ACTIVE' }
    if td_mode=='xdp':
      esc = { ip: sum( f[ 'in' ].values() ) for ip, f in flows.items() if f[ 'in' ] }
      print( f'\nvotor-port packets that escaped XDP on {",".join( d for d in h0["xdp_if"] if d!="lo" )} in interval: {sum(esc.values())} from {len(esc)} ips' )
      verdict.append( ( 'votor-port packets passing XDP up to the kernel instead of the net tile', bool( esc ), f'{sum(esc.values())} pkts from {len(esc)} ips' if esc else 'none' ) )
    else:
      def summ( ips, way ):
        per = {}
        for ip in ips:
          for d, n in flows.get( ip, { 'in': {}, 'out': {} } )[ way ].items(): per[ d ] = per.get( d, 0 )+n
        return per
      seen_in  = lambda ips: sum( 1 for ip in ips if flows.get( ip, {} ).get( 'in' ) )
      seen_out = lambda ips: sum( 1 for ip in ips if flows.get( ip, {} ).get( 'out' ) )
      print( '\nvotor packets on ports 8004/8005 in interval, by peer group and interface\n' )
      print( '| peers | count | peers we sent to | peers heard from | out packets by interface | in packets by interface |' )
      print( '|---|---|---|---|---|---|' )
      for name, ips in ( ( 'working (tx ACTIVE)', working ), ( 'failing (no ACTIVE tx)', failing ) ):
        print( f'| {name} | {len(ips)} | {seen_out(ips)} | {seen_in(ips)} | {summ(ips,"out")} | {summ(ips,"in")} |' )
      print( '\nfailing peers (first 40): packets out / in by interface\n' )
      print( '| identity | addr | out | in |' ); print( '|---|---|---|---|' )
      for ip in sorted( failing, key=lambda i: ip2peer[ i ][ 'curr' ] )[ :40 ]:
        f = flows.get( ip, { 'in': {}, 'out': {} } )
        print( f'| {ip2peer[ip]["id"]} | {ip}:{ip2peer[ip]["ci"][1]} | {f["out"] or "-"} | {f["in"] or "-"} |' )
      fo = summ( failing, 'out' ); wo = summ( working, 'out' )
      phys = lambda d: { k: v for k, v in d.items() if k not in ( 'bond0', '?', 'any' ) and not k.startswith( 'bond' ) }
      fo_p, wo_p = phys( fo ), phys( wo )
      one_member = len( fo_p )==1 and len( wo_p )>=1 and set( fo_p )!=set( wo_p )
      verdict.append( ( 'failing-peer votor flows leave on a different bond member than working ones', one_member, f'failing out {fo_p}, working out {wo_p}' ) )
      verdict.append( ( 'we send to failing peers but never hear back', seen_out( failing )>0 and seen_in( failing )==0, f'sent to {seen_out(failing)}/{len(failing)}, heard from {seen_in(failing)}/{len(failing)}' ) )

  print( '\n### claim check\n' )
  print( '| check | result | detail |' ); print( '|---|---|---|' )
  for name, hit, det in verdict: print( f'| {name} | {"FOUND" if hit else "not found"} | {det} |' )
  if not h1: print( '\nrun with --interval 70 for queue, drop and tcpdump deltas (one full 64 s redial cycle)' )

  ip2key = {}
  for k, ci in cis.items(): ip2key.setdefault( ci[ 0 ], [] ).append( k )
  def who( c ):
    if c[ 'ctx_key' ] and c[ 'ctx_key' ]!=b'\0'*32: return b58enc( c[ 'ctx_key' ] )
    ks = ip2key.get( c[ 'peer_ip' ], [] )
    return ( 'ip of '+b58enc( ks[ 0 ] ) ) if len( ks )==1 else f'{len(ks)} ids on this ip' if ks else 'unknown ip'
  def age( t ):
    d = ( now_ns-t )/1e9
    return f'{d:.0f}s' if t and -60<d<1e7 else ( '-' if not t else f'raw {t}' )

  print( '\n## QUIC conn pools\n' )
  print( '| pool | conns | ' + ' | '.join( CONN_STATE.values() ) + ' |' )
  print( '|---|---|' + '---|'*len( CONN_STATE ) )
  for pl in pools:
    cnt = {}
    for c in pl[ 'conns' ]: cnt[ c[ 'state' ] ] = cnt.get( c[ 'state' ], 0 )+1
    name = 'server (inbound)' if pl[ 'server' ] else 'client (outbound)'
    print( f'| {name} | {len(pl["conns"])} | ' + ' | '.join( str( cnt.get( k, 0 ) ) for k in CONN_STATE ) + ' |' )
  print( '\nrx pkt numbers = exp_pkt_number[initial,handshake,app]: 0,0,0 means nothing was ever received from that peer on this conn' )
  print( '\n### live conns not ACTIVE\n' )
  print( '| pool | our addr | peer addr | identity | state | reason | app reason | last activity | rx pkt numbers | tx pkt numbers |' )
  print( '|---|---|---|---|---|---|---|---|---|---|' )
  for pl in pools:
    for c in pl[ 'conns' ]:
      if c[ 'state' ] in ( 0, 3 ): continue
      print( f'| {"server" if pl["server"] else "client"} | {c["host_addr"]} | {c["peer_ip"]}:{c["peer_port"]} | {who(c)} | {c["state_s"]} | {c["reason"]} | {c["app_reason"]} | {age(c["last_activity"])} | {c["exp_pkt_number"]} | {c["pkt_number"]} |' )
  if not pools: print( 'no pools resolved (no readable conn pointers)' )

  def row( p ):
    ci  = f'{p["ci"][0]}:{p["ci"][1]}' if p[ 'ci' ] else '-'
    age = f'{(now_ns-p["conn_ts"])/1e9:.0f}s' if p[ 'conn_ts' ] else '-'
    tx  = p[ 'tx' ][ 'state' ] if p[ 'tx' ] else '-'
    rx  = p[ 'rx' ][ 'state' ] if p[ 'rx' ] else '-'
    return f'| {p["id"]} | {p["curr"]} | {ci} | {tx} | {rx} | {p["reconn"]} | {p["backoff"]/1e9:.0f}s | {age} |'
  hdr = '| identity | rank | contact info | tx | rx | redial queued | backoff | last dial |\n|---|---|---|---|---|---|---|---|'

  show = ranked if a.all else [ p for p in ranked if not ( p[ 'tx' ] and p[ 'tx' ][ 'state' ]=='ACTIVE' ) ]
  print( f'\n## {"all ranked" if a.all else "ranked, no ACTIVE tx conn"} ({len(show)})\n' )
  print( hdr )
  for p in sorted( show, key=lambda p: p[ 'curr' ] ): print( row( p ) )

  for s in a.peer:
    k = b58dec( s )
    p = next( ( x for x in peers if x[ 'key' ]==k ), None )
    print( f'\n## peer {s}\n' )
    if not p:
      print( f'not in peers map; contact info: {cis.get(k)}' ); continue
    for f in ( 'prev', 'curr', 'next', 'ci', 'tx', 'rx', 'ban_ts', 'conn_ts', 'backoff', 'reconn' ): print( f'- {f}: {p[f]}' )
    print( f'- class: {cls(p)}' )
    if p[ 'ci' ]:
      hits = [ ( pl, c ) for pl in pools for c in pl[ 'conns' ] if c[ 'peer_ip' ]==p[ 'ci' ][ 0 ] or c[ 'ctx_key' ]==k ]
      print( f'- conn objects to/from {p["ci"][0]} (incl. freed, fields kept until reuse): {len(hits)}' )
      for pl, c in sorted( hits, key=lambda h: -h[ 1 ][ 'last_activity' ] )[ :12 ]:
        print( f'  - {"server" if pl["server"] else "client"} idx {c["conn_idx"]} {c["host_addr"]} -> {c["peer_ip"]}:{c["peer_port"]} {c["state_s"]} reason {c["reason"]} app {c["app_reason"]} last {age(c["last_activity"])} rx_pn {c["exp_pkt_number"]} tx_pn {c["pkt_number"]}' )

if __name__=='__main__': main()
