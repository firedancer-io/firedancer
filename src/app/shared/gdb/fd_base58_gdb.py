# Base58 printing support for GDB

import gdb

_BASE58_CHARS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def fd_base58_encode( raw ):
  out = []
  num = int.from_bytes( raw, "big" )
  while num:
    num, rem = divmod( num, 58 )
    out.append( _BASE58_CHARS[ rem ] )
  for byte in raw:  # Leading zero bytes become leading '1's
    if byte: break
    out.append( _BASE58_CHARS[ 0 ] )
  out.reverse()
  return "".join( out ) or _BASE58_CHARS[ 0 ]

def _read_bytes( val, sz ):
  """Extract sz bytes out of a gdb.Value, or None if unavailable."""
  if val.address is not None:
    try:
      return bytes( gdb.selected_inferior().read_memory( val.address, sz ) )
    except ( gdb.MemoryError, gdb.error ):
      return None
  try:  # Value lives in a register or is otherwise synthetic
    uc = val[ "uc" ]
    return bytes( int( uc[ i ] ) & 0xff for i in range( sz ) )
  except ( gdb.error, KeyError ):
    return None

class _FdBase58Printer:
  def __init__( self, val, sz ):
    self._val = val
    self._sz  = sz
  def to_string( self ):
    raw = _read_bytes( self._val, self._sz )
    if raw is None: return "<unreadable>"
    return fd_base58_encode( raw )

# Types rendered as base58, keyed by union tag => encoded length

_FD_BASE58_TYPES = {
  "fd_hash":      32,
  "fd_pubkey":    32,
  "fd_signature": 64,
}

def fd_base58_lookup( val ):
  try:
    typ = val.type.strip_typedefs()
  except gdb.error:
    return None
  if typ.code != gdb.TYPE_CODE_UNION: return None
  sz = _FD_BASE58_TYPES.get( typ.tag or typ.name )
  if sz is None or typ.sizeof != sz: return None
  return _FdBase58Printer( val, sz )

class _FdBase58Command( gdb.Command ):
  """Print memory as base58.

Usage: b58 EXPR [LEN]

EXPR may be a pointer, an array, or an lvalue of any type.  LEN defaults
to 32, or to sizeof(EXPR) when EXPR is not a pointer."""

  def __init__( self ):
    super( _FdBase58Command, self ).__init__( "b58", gdb.COMMAND_DATA )

  def invoke( self, arg, from_tty ):
    argv = gdb.string_to_argv( arg )
    if not argv: raise gdb.GdbError( "usage: b58 EXPR [LEN]" )

    sz  = None
    val = None
    try:  # The whole argument is usually just an expression
      val = gdb.parse_and_eval( " ".join( argv ) )
    except gdb.error as err:
      if len( argv )<2: raise gdb.GdbError( str( err ) )
      try:  # Retry with the trailing token split off as LEN
        sz  = int( gdb.parse_and_eval( argv[ -1 ] ) )
        val = gdb.parse_and_eval( " ".join( argv[ :-1 ] ) )
      except gdb.error:
        raise gdb.GdbError( str( err ) )

    typ = val.type.strip_typedefs()
    if typ.code==gdb.TYPE_CODE_PTR:
      addr = int( val )
      if sz is None: sz = 32
    else:
      if val.address is None: raise gdb.GdbError( "expression has no address" )
      addr = int( val.address )
      if sz is None: sz = int( typ.sizeof )

    if sz<=0: raise gdb.GdbError( "invalid length" )
    raw = bytes( gdb.selected_inferior().read_memory( addr, sz ) )
    gdb.write( fd_base58_encode( raw ) + "\n" )

if not any( getattr( fn, "__name__", "" )=="fd_base58_lookup"
            for fn in gdb.pretty_printers ):
  gdb.pretty_printers.append( fd_base58_lookup )
  _FdBase58Command()
