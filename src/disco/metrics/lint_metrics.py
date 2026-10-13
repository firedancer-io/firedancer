#!/usr/bin/env python3
"""Checks metrics.xml against the NAMING RULES at the top of the file.

Run by `make -C src/disco/metrics metrics` (and so by CI).  Exits 1 and
prints every violation if any rule fails.

A deliberate exception is marked on the element, so it is visible in
review:  <gauge name="RouteCount" lint-allow="count" ... />
(several ids are space separated).  Rule ids are printed with each
violation."""

import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

METRIC_TAGS = ( 'counter', 'gauge', 'histogram', 'bool', 'time' )

UNITS   = ( 'Nanos', 'Bytes', 'Lamports', 'Pct', 'Slot' )
BAD_UNITS = ( 'Seconds', 'Millis', 'Micros', 'Timestamp' )
BAD_UNIT_SUFFIX = ( 'Ms', 'Us' )  # only as the last word

# Rule 10: enum names end in their dimension
ENUM_SUFFIX = ( 'Result', 'Reason', 'Type', 'Class', 'Regime', 'State', 'Level', 'Version', 'Lane', 'Method', 'Cause' )

# Rule 3: occupancy words that have a fixed replacement
OCCUPANCY = { 'Occupied': 'the bare Subject or Used', 'InUse': 'the bare Subject or Used',
              'Current': 'the bare Subject or Used', 'Live': 'the bare Subject or Used',
              'Active': 'the bare Subject or Open', 'Max': 'Capacity', 'Watermark': 'Peak' }
POOL_SIBLING = ( 'Capacity', 'Free', 'Allocated', 'Peak' )
GAUGE_LAST   = { 'Count', 'Open', 'Idle', 'Pending', 'InFlight', 'Online', 'Available', 'Pinned', 'Reserved',
                 'Used', 'Capacity', 'Free', 'Allocated', 'Peak', 'Target', 'LowWater', 'Progress', 'Expected',
                 'Height', 'Slot', 'State', 'Index', 'Id', 'Rank', 'Version', 'Distance', 'Cost' }

# Rule 2: a counter's last word (before the unit) is an Action
ACTION_IRREGULAR = { 'Rx', 'Tx', 'Hit', 'Miss', 'Read', 'Written', 'Done', 'Taken', 'Chosen',
                     'Frozen', 'Torn', 'Overrun', 'Sent', 'Lost', 'Seen', 'Built', 'Run' }
ACTION_PHRASAL   = ( 'LookedUp', 'TimedOut' )
BARE_EVENT       = { 'Backpressure', 'Irq', 'Softirq', 'Shootdown', 'Switch', 'Fault' }   # external events with no object (ContextSwitch, PageFault)
GAUGE_BANNED_END = { 'Rx', 'Tx', 'Hit', 'Miss', 'Dropped', 'Rejected', 'Failed', 'Attempted', 'Processed' }

def is_action( name ):
    if name.endswith( ACTION_PHRASAL ): return True
    w = [ x for x in words( name ) if x not in UNITS ]
    if len( w ) > 2 and w[ -2 ] == 'By': w = w[ :-2 ]                 # TxnProcessedByVersion
    if not w: return False
    if name.endswith( ( 'DurationNanos', 'IntegralNanos' ) ): return True  # accumulated time
    return w[ -1 ].endswith( 'ed' ) or w[ -1 ] in ACTION_IRREGULAR or any( x in BARE_EVENT for x in w )

# Rule 2: endings never used on a counter
COUNTER_BANNED = ( 'Count', 'Cnt', 'Total', 'Num' )

# Rule 9: abbreviations that must be written mixed case (all caps forms are errors)
ABBREV = ( 'Rx', 'Tx', 'Pkt', 'Txn', 'Frag', 'Cu', 'Fec', 'Crds', 'Conn', 'Sched', 'Lut', 'Alut',
           'Cpi', 'Vm', 'Id', 'Ip', 'Rtt', 'Cpu', 'Xdp', 'Xsk', 'Gre', 'Poh', 'Quic', 'Irq', 'Tlb',
           'Db', 'Kv', 'Pct' )
BANNED_WORDS = { 'Cnt': 'Count or an Action', 'Blk': 'Block', 'Num': 'an Action', 'Ok': 'Accepted' }

# Rule 1: plural-looking final words that are fine
PLURAL_OK = { 'Bytes', 'Lamports', 'Nanos', 'Process', 'Success', 'Status', 'Bus', 'Alias', 'Crds',
              'Address', 'Miss', 'Pass', 'Access', 'Progress', 'Class', 'Loss', 'Ns', 'Is',
              'Previous', 'Cross', 'Gas', 'Bps', 'Pps', 'Series' }

# CamelCase words in summaries that are prose, not metric names
PROSE_CAMEL = { 'WebSocket', 'ShredStream', 'TowerSync', 'BlockEngine', 'ParentFecSetCount', 'FecSetRoot',
                'WindowIndexForBlockId', 'WindowIndex', 'HighestWindowIndex' }

SUMMARY_BANNED = ( 'Number of ', 'How many ', 'Total ', 'The ' )
SUMMARY_BANNED_ANY = ( 'in seconds', 'in nanoseconds', 'in bytes', '1 or 0', '0 or 1', 'either 1', '-1 ' )

RESERVED_COLUMNS = { 'kind_id', 'sample_id', 'sample_reason', 'sample_slot', 'sample_snapct_state',
                     'sample_tile_cnt', 'timestamp', 'identity', 'instance_id' }

def words( name ):
    return re.findall( r'[A-Z][a-z0-9]*', name )

def snake( name ):
    return re.sub( r'(?<!^)(?=[A-Z])', '_', name ).lower()

class Linter:
    def __init__( self ):
        self.errors = []

    def err( self, where, rule, msg, el=None ):
        if el is not None and rule in ( el.attrib.get( 'lint-allow', '' ).split() ): return
        self.errors.append( f'{where}: [{rule}] {msg}' )

    def metric( self, section, el ):
        tag  = el.tag
        name = el.attrib.get( 'name', '' )
        where = f'{section}.{name}'
        w = words( name )
        summary = el.attrib.get( 'summary' )
        if summary is None and el.find( 'summary' ) is not None: summary = el.find( 'summary' ).text or ''
        summary = summary or ''

        # Rule 1: shape
        if not re.fullmatch( r'([A-Z][a-z0-9]*)+', name ):
            self.err( where, 'pascal', 'name must be PascalCase', el )
        if re.search( r'_(?!b$)[a-z](?:_|$)', snake( name ) ):
            self.err( where, 'snake', f'snake form {snake( name )} has a one-letter word; write units as Kib/Mib', el )
        if len( snake( name ) ) > 48:
            self.err( where, 'length', f'snake_case name is {len( snake( name ) )} chars (max 48)', el )
        if section not in ( 'common', 'linkin' ) and w and w[ 0 ].lower() == section.lower():
            self.err( where, 'tile-prefix', f'name repeats the tile name "{w[ 0 ]}"', el )
        if snake( name ) in RESERVED_COLUMNS:
            self.err( where, 'collision', 'name collides with a reserved ClickHouse column', el )
        for x in w[ :-1 ] + ( [ w[ -1 ] ] if w and w[ -1 ] not in UNITS else [] ):
            if x.endswith( 's' ) and len( x ) > 3 and x not in PLURAL_OK and not x.endswith( 'ss' ):
                self.err( where, 'plural', f'"{x}" looks plural; subjects are singular', el )
        for bad, fix in BANNED_WORDS.items():
            if bad in w: self.err( where, 'abbrev', f'"{bad}" is not allowed; use {fix}', el )
        for a in ABBREV:
            if a.upper() in re.findall( r'[A-Z]{2,}', name ) and a.upper() != a:
                self.err( where, 'abbrev', f'write "{a}" in mixed case', el )

        # Rule 2: counters
        if tag == 'counter' and w and w[ -1 ] in COUNTER_BANNED:
            self.err( where, 'count', f'counters never end in {w[ -1 ]}', el )
        if tag == 'counter' and 'Total' in w:
            self.err( where, 'count', 'counters never contain Total', el )

        if tag == 'counter' and not is_action( name ):
            self.err( where, 'action', 'counters end in an Action (Rx, Tx, Hit, Miss or a past participle) before the unit', el )

        # Rule 3: a name that reads as the other kind is marked
        if tag in ( 'counter', 'gauge' ) and el.attrib.get( 'ambiguous-kind' )!='true':
            core = [ x for x in w if x not in UNITS ] or w
            if tag == 'counter' and not core[ -1 ].endswith( 'ed' ) and core[ -1 ] not in ACTION_IRREGULAR and not name.endswith( ACTION_PHRASAL ) \
               and not name.endswith( ( 'DurationNanos', 'IntegralNanos' ) ) and not ( len( core ) > 2 and core[ -2 ] == 'By' ):
                self.err( where, 'kind', 'counter name has no Action and reads as a gauge; add ambiguous-kind="true"', el )
            if tag == 'gauge' and 'states' not in el.attrib and w[ 0 ] not in ( 'Last', 'Highest', 'First', 'Next' ) and w[ -1 ] != 'Nanos' \
               and ( core[ -1 ] == 'Height' or ( core[ -1 ].endswith( 'ed' ) and core[ -1 ] not in ( 'Used', 'Allocated', 'Expected' ) ) ):
                self.err( where, 'kind', f'gauge name ending in "{core[ -1 ]}" reads as a counter; add ambiguous-kind="true"', el )

        # Rule 3: gauges
        if tag == 'gauge':
            q = w[ -2 ] if len( w ) > 1 and w[ -1 ] in UNITS else ( w[ -1 ] if w else '' )
            if q in OCCUPANCY and not ( w and w[ -1 ] == 'Slot' ):  # CurrentSlot: selector, not occupancy
                self.err( where, 'occupancy', f'use {OCCUPANCY[ q ]} instead of {q}', el )
            if q in GAUGE_BANNED_END and w[ 0 ] not in ( 'Last', 'Highest', 'First', 'Next' ):  # LastInsertFailedSlot: slot of an event
                self.err( where, 'action', f'gauges have no Action; "{q}" reads as a counter', el )
            tail = ''.join( w[ -2: ] ) if len( w ) > 1 and ''.join( w[ -2: ] ) in GAUGE_LAST else ( w[ -1 ] if w else '' )
            if 'states' not in el.attrib and w and w[ -1 ] not in UNITS and tail not in GAUGE_LAST:
                self.err( where, 'vocab', f'gauges end in Count, a state ({", ".join( sorted( GAUGE_LAST ) )}) or a unit, not "{tail}"', el )
            if q == 'Conn':
                self.err( where, 'occupancy', 'open connections are ConnOpen (ConnUsed for a bounded pool)', el )

        # Rule 4: units
        for b in BAD_UNITS:
            if b in w: self.err( where, 'unit', f'"{b}" is not a unit; use Nanos (or <time> for wall clock)', el )
        if w and w[ -1 ] in BAD_UNIT_SUFFIX:
            self.err( where, 'unit', f'"{w[ -1 ]}" is not a unit; use Nanos', el )
        if 'source' in el.attrib and not name.endswith( 'Nanos' ):
            self.err( where, 'unit', 'source="ticks" needs a *Nanos name', el )
        if name.endswith( 'Time' ) and tag != 'time':
            self.err( where, 'time', '*Time metrics must be <time> elements', el )
        if tag == 'time' and not name.endswith( 'Time' ):
            self.err( where, 'time', '<time> names end in Time', el )

        # Rule 5: booleans
        if tag == 'bool' and not ( len( w ) > 1 and w[ 0 ] == 'Is' ):
            self.err( where, 'bool', '<bool> names start with Is', el )
        if tag != 'bool' and w and w[ 0 ] == 'Is':
            self.err( where, 'bool', 'Is* metrics must be <bool> elements', el )

        # Rule 6: states
        if tag == 'gauge' and name.endswith( 'State' ) and 'states' not in el.attrib and 'enum' not in el.attrib:
            self.err( where, 'state', '*State gauges need states="<Enum>"', el )
        if 'states' in el.attrib and not name.endswith( 'State' ):
            self.err( where, 'state', 'states= is only for *State gauges', el )
        if tag == 'gauge' and 'states' not in el.attrib and re.search( r'\b\d+=\w', summary ):
            self.err( where, 'state', 'value list in the summary; declare an <enum> and use states=', el )

        # Rule 9: sentinels
        if tag == 'gauge' and len( w ) > 1 and w[ 0 ] in ( 'Last', 'Highest', 'First', 'Next' ) and w[ -1 ] == 'Slot' and '0 if' not in summary:
            self.err( where, 'sentinel', 'point Slot gauges say "0 if none" (or when they read 0)', el )
        if tag == 'gauge' and w and w[ -1 ] in ( 'Index', 'Id', 'Rank' ) and 'ULONG_MAX' not in summary:
            self.err( where, 'sentinel', 'Index/Id/Rank gauges say when they read ULONG_MAX (lint-allow="sentinel" if never)', el )

        # Rule 8: histograms
        if tag == 'histogram':
            if not ( re.search( r'(Duration|Delay|Latency|Lag|Size|Work|Write)[A-Z]', name ) or 'Per' in w or name.endswith( 'Pct' ) ):
                self.err( where, 'histogram', 'histograms are Subject + Duration|Delay|Latency|Size|Per<X> + unit', el )

        # Rule 10: summaries
        if not summary.strip():
            self.err( where, 'summary', 'missing summary', el )
        else:
            s = summary.strip()
            if s.endswith( '.' ):
                self.err( where, 'summary', 'summary ends with a period', el )
            if not s[ 0 ].isupper() and not s[ 0 ].isdigit() and not re.match( r'[a-z_]+[_A-Z]|[a-z]+(mmsg|_\w+)\b|t_|g[A-Z]|epoll|futex|recv|send', s ):
                self.err( where, 'summary', 'summary starts lowercase', el )
            for b in SUMMARY_BANNED:
                if s.startswith( b ): self.err( where, 'summary', f'summary starts with "{b.strip()}"', el )
            if tag == 'counter' and 'enum' in el.attrib and ', by ' not in s and not s.endswith( 'by ' ):
                self.err( where, 'summary', 'enum counter summary should say ", by <dimension>"', el )
            for b in SUMMARY_BANNED_ANY:
                if b in s: self.err( where, 'summary', f'summary contains "{b.strip()}"', el )

    def enum( self, el, used_as ):
        name = el.attrib[ 'name' ]
        where = f'enum {name}'
        vals = [ v.attrib[ 'name' ] for v in el.findall( 'int' ) ]
        if not name.endswith( ENUM_SUFFIX ):
            self.err( where, 'enum', f'enum names end in their dimension ({", ".join( ENUM_SUFFIX )})', el )
        for v in vals:
            if not re.fullmatch( r'([A-Z][a-z0-9]*)+', v ):
                self.err( f'{where}.{v}', 'enum', 'values are PascalCase', el )
            if re.search( r'_(?!b$)[a-z](?:_|$)', snake( v ) ):
                self.err( f'{where}.{v}', 'snake', f'snake form {snake( v )} has a one-letter word; write units as Kib/Mib', el )
            for bad, fix in BANNED_WORDS.items():
                if bad in words( v ): self.err( f'{where}.{v}', 'abbrev', f'"{bad}" is not allowed; use {fix}', el )
            if re.match( r'No[A-Z]', v ) and any( x in vals for x in ( v[ 2: ], v.replace( 'No', '' ) ) ):
                self.err( f'{where}.{v}', 'enum', 'values are positive (Leader, not NoLeader; None for the empty case)', el )
        if len( vals ) > 1:
            first = [ words( v )[ 0 ] for v in vals if words( v ) ]
            if len( set( first ) ) == 1 and len( first ) == len( vals ):
                self.err( where, 'enum', f'every value starts with "{first[ 0 ]}"', el )
        if name not in used_as:
            self.err( where, 'enum', 'enum is not used by any metric', el )
        nums = sorted( int( v.attrib[ 'value' ] ) for v in el.findall( 'int' ) )
        if nums and nums!=list( range( nums[ 0 ], nums[ 0 ]+len( nums ) ) ):
            self.err( where, 'enum', f'values are not contiguous: {nums}', el )

def c_sources( root: Path ) -> str:
    """Concatenated C sources outside the generated metrics headers."""
    files = subprocess.run( [ 'git', '-C', str( root ), 'ls-files', 'src/*.c', 'src/*.h', 'src/*.cxx' ],
                            capture_output=True, text=True ).stdout.split()
    return '\n'.join( ( root / f ).read_text( errors='ignore' ) for f in files if '/metrics/generated/' not in f )

def referenced_ids( src: str ):
    """(GROUP, ID) pairs the C code names via MIDX/FD_M*/FD_METRICS_*_OFF.
    ID may carry an enum value suffix, matched by prefix."""
    ids = set( re.findall( r'\bFD_M(?:CNT|GAUGE|HIST)_\w+\s*\(\s*(\w+)\s*,\s*(\w+)', src ) )
    ids |= set( re.findall( r'\bMIDX\(\s*(?:COUNTER|GAUGE|HISTOGRAM)\s*,\s*(\w+)\s*,\s*(\w+)', src ) )
    ids |= { ( 'OFF', m ) for m in re.findall( r'\bFD_METRICS_(?:COUNTER|GAUGE|HISTOGRAM)_(\w+?)_OFF\b', src ) }
    # Shared write macros take the group as an argument: expand each use
    macros = {}
    for name, body in re.findall( r'#define\s+(FD_\w+_METRICS_WRITE\w*)\(\s*TILE\s*,[^)]*\)(.*?)(?<!\\)\n', src, re.S ):
        macros[ name ] = { n for g, n in re.findall( r'\bFD_M(?:CNT|GAUGE|HIST)_\w+\s*\(\s*(TILE)\s*,\s*(\w+)', body ) }
    for name, names in macros.items():
        for group in re.findall( r'\b' + name + r'\(\s*(\w+)\s*,', src ):
            ids |= { ( group, n ) for n in names }
    return ids

def lint( text ):
    root = ET.fromstring( text )
    L = Linter()
    used = set()
    for el in root.iter():
        for a in ( 'enum', 'states' ):
            if a in el.attrib and el.tag in METRIC_TAGS: used.add( el.attrib[ a ] )
    common = { m.attrib.get( 'name', '' ).lower() for el in root if el.tag == 'common' for m in el if m.tag in METRIC_TAGS }
    for el in root:
        if el.tag == 'enum':
            L.enum( el, used )
        elif el.tag in ( 'tile', 'common', 'linkin' ):
            section = el.attrib.get( 'name', el.tag )
            seen = set()
            for m in el:
                if m.tag not in METRIC_TAGS: continue
                n = m.attrib.get( 'name', '' )
                if n.lower() in seen: L.err( f'{section}.{n}', 'collision', 'duplicate name (case-insensitive)', m )
                if el.tag == 'tile' and n.lower() in common:
                    L.err( f'{section}.{n}', 'collision', 'name reuses a <common> metric; tile tables carry the common columns', m )
                seen.add( n.lower() )
                L.metric( section, m )

    # Rule 3: Used only for a bounded pool, next to its Capacity/Free/Allocated/Peak
    for el in root:
        if el.tag not in ( 'tile', 'common', 'linkin' ): continue
        names = { m.attrib.get( 'name', '' ) for m in el if m.tag in METRIC_TAGS }
        for m in el:
            mm = re.fullmatch( r'(\w+?)Used(Bytes)?', m.attrib.get( 'name', '' ) )
            if m.tag != 'gauge' or not mm: continue
            if not any( n.startswith( mm.group( 1 )+s ) for n in names for s in POOL_SIBLING ):
                L.err( f'{el.attrib.get( "name", el.tag )}.{m.attrib["name"]}', 'occupancy',
                       'Used is for a bounded pool with a Capacity, Free, Allocated or Peak sibling; otherwise use the bare Subject', m )

    # Rule 10: metrics shared across tiles (same name and enum) read the same
    shared = {}
    for el in root:
        if el.tag != 'tile': continue
        for m in el:
            if m.tag not in METRIC_TAGS: continue
            summary = m.attrib.get( 'summary' )
            if summary is None and m.find( 'summary' ) is not None: summary = m.find( 'summary' ).text or ''
            key = ( m.attrib[ 'name' ], m.attrib.get( 'enum' ) )
            shared.setdefault( key, {} ).setdefault( summary, [] ).append( el.attrib[ 'name' ] )
    for ( name, enum ), by_summary in shared.items():
        tiles = [ t for ts in by_summary.values() for t in ts ]
        if len( by_summary ) > 1 and ( name.startswith( ( 'Accdb', 'Progcache' ) ) ):
            L.err( f'{",".join( tiles )}.{name}', 'summary', 'shared metric has different summaries across tiles' )

    # Rule 10: a metric named in a summary must exist in the same section
    for el in root:
        if el.tag not in ( 'tile', 'common', 'linkin' ): continue
        section = el.attrib.get( 'name', el.tag )
        names = { m.attrib.get( 'name' ) for m in el if m.tag in METRIC_TAGS }
        for m in el:
            if m.tag not in METRIC_TAGS: continue
            summary = m.attrib.get( 'summary' ) or ( m.find( 'summary' ).text if m.find( 'summary' ) is not None else '' ) or ''
            for cited in re.findall( r'\b([A-Z][a-z0-9]+(?:[A-Z][a-z0-9]+)+)\b', summary ):
                if cited in PROSE_CAMEL: continue
                if cited not in names and not any( cited in other for other in names ):
                    L.err( f'{section}.{m.attrib["name"]}', 'summary', f'summary cites {cited}, which is not a metric of this tile', m )
    return L.errors

def lint_writers( text, root: Path ):
    """Every metric must be referenced by C code; an unwritten metric is
    a permanent zero column."""
    errors = []
    ids = referenced_ids( c_sources( root ) )
    snake = lambda n: re.sub( r'(?<!^)(?=[A-Z])', '_', n ).upper()
    for el in ET.fromstring( text ):
        if el.tag not in ( 'tile', 'common', 'linkin' ): continue
        group = { 'common': 'TILE', 'linkin': 'LINK' }.get( el.tag ) or el.attrib[ 'name' ].upper()
        for m in el:
            if m.tag not in METRIC_TAGS or 'writer' in m.attrib.get( 'lint-allow', '' ).split(): continue
            n = snake( m.attrib[ 'name' ] )
            if any( ( g==group and ( i==n or i.startswith( n+'_' ) ) ) or ( g=='OFF' and ( i==f'{group}_{n}' or i.startswith( f'{group}_{n}_' ) ) ) for g, i in ids ):
                continue
            errors.append( f'{el.attrib.get( "name", el.tag )}.{m.attrib["name"]}: [writer] metric is never referenced by C code' )
    return errors

def main():
    path = Path( sys.argv[ 1 ] if len( sys.argv ) > 1 else Path( __file__ ).parent / 'metrics.xml' )
    errors = lint( path.read_text() )
    errors += lint_writers( path.read_text(), path.resolve().parents[ 3 ] )
    for e in errors: print( e )
    if errors:
        print( f'{len( errors )} metrics naming violation(s); see the NAMING RULES in {path.name}' )
        sys.exit( 1 )

if __name__ == '__main__':
    main()
