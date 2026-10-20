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

def main():
  ap = argparse.ArgumentParser( description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter )
  ap.add_argument( '--wksp', help='votor workspace file (default: the only /mnt/.fd/*/*_votor.wksp)' )
  ap.add_argument( '--peer', action='append', default=[], help='base58 identity to show in detail (repeatable)' )
  ap.add_argument( '--identity', help='this validator\'s base58 identity, labelled self in the report' )
  ap.add_argument( '--all', action='store_true', help='list every ranked peer, not only the unconnected ones' )
  ap.add_argument( '--conn-state-off',  type=lambda x: int( x, 0 ), default=3496, help='offsetof(fd_quic_conn_t,state) (v26.10 gcc: 3496)' )
  ap.add_argument( '--conn-context-off', type=lambda x: int( x, 0 ), default=16,  help='offsetof(fd_quic_conn_t,context)' )
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

  def conn( ptr, key ):
    if not ptr: return None
    if base is None: return dict( ptr=ptr, state='?', check='unresolved' )
    o = ptr-base
    if not 0<=o<len( m )-8192: return dict( ptr=ptr, state='?', check='outside wksp' )
    state, reason, app = struct.unpack_from( '<III', m, o+a.conn_state_off )
    ctxp, = struct.unpack_from( '<Q', m, o+a.conn_context_off )
    ok = 'ok' if ctxp and 0<=ctxp-base<len( m ) and m[ ctxp-base:ctxp-base+32 ]==key else 'context!=peer'
    return dict( ptr=ptr, state=CONN_STATE.get( state, str( state ) ), reason=reason, app_reason=app, check=ok )

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
  if bad: print( f'warning: {len(bad)} conn pointers failed the context check (conn offsets may not match this build)' )

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

if __name__=='__main__': main()
