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

import argparse, datetime, glob, mmap, os, re, struct, sys, time

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
  if pid is not None:
    try: memf = open( f'/proc/{pid}/mem', 'rb' )
    except OSError as e: print( f'cannot read /proc/{pid}/mem ({e}); QUIC conn state unavailable' )
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
  m0 = { pl[ 'quic' ]: quic_metrics( pl[ 'quic' ] ) for pl in pools }
  if a.interval>0:
    time.sleep( a.interval )
    m1 = { pl[ 'quic' ]: quic_metrics( pl[ 'quic' ] ) for pl in pools }
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

  print( '\n## UDP sockets on the votor ports and the validator\'s ports\n' )
  socks = udp_sockets()
  vports = set( [ 8004 ] + [ c[ 1 ] for c in ( cis.get( self_key ), ) if c ] )
  mine   = { s_[ 'lport' ] for s_ in socks.values() if pid in s_[ 'pids' ] }
  show_s = [ s_ for s_ in socks.values() if s_[ 'lport' ] in vports|mine ]
  if not show_s: print( f'no kernel UDP sockets on ports {sorted(vports)} (XDP net provider: packets bypass the kernel)' )
  else:
    print( '| port | local | rx queue | drops | owner pids |' )
    print( '|---|---|---|---|---|' )
    for s_ in sorted( show_s, key=lambda x: ( x[ 'lport' ], x[ 'local' ] ) ):
      own = ', '.join( f'{q}{"" if q==pid else " NOT THE VALIDATOR"}' for q in sorted( s_[ 'pids' ] ) ) or 'none (orphaned?)'
      print( f'| {s_["lport"]} | {s_["local"]} | {s_["rxq"]} | {s_["drops"]} | {own} |' )
    others = sorted( { q for s_ in show_s for q in s_[ 'pids' ] if q!=pid } )
    for q in others: print( f'- pid {q}: {proc_desc( q )}' )
    dup = {}
    for s_ in show_s: dup.setdefault( s_[ 'lport' ], [] ).append( s_ )
    for port, lst in sorted( dup.items() ):
      if len( lst )>1: print( f'- port {port} has {len(lst)} sockets: with SO_REUSEPORT the kernel spreads flows across them by 4-tuple hash; one nobody reads drops its share' )
  try:
    xdp = [ d for d in os.listdir( '/sys/class/net' ) ]
    for d in xdp:
      ch = os.popen( f'ip -d link show dev {d} 2>/dev/null' ).read()
      if 'xdp' in ch or ' master ' in ch or d.startswith( ( 'bond', 'en', 'eth' ) ):
        chans = os.popen( f'ethtool -l {d} 2>/dev/null' ).read().split( 'Current hardware settings:' )[ -1 ].split()
        cur = ' '.join( chans[ i ]+chans[ i+1 ] for i in range( 0, len( chans )-1, 2 ) ) if chans else '?'
        print( f'- {d}: channels now [{cur}]  master: {ch.split(" master ")[1].split()[0] if " master " in ch else "-"}' )
      if 'xdp' in ch: print( f'- {d}: XDP program attached ({" ".join( w for w in ch.split() if w.startswith( "prog" ) or w=="xdp" or w=="xdpdrv" or w=="xdpgeneric" )})' )
  except OSError: pass

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
