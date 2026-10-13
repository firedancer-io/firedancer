#!/usr/bin/env python3
"""Formats metrics.xml into the house style:

  - top-level elements (<enum>, <tile>, <common>, <linkin>) at column 0
  - their children indented 4 spaces, a histogram's <summary> 8
  - one space between attributes, attributes in a fixed order
  - one blank line between top-level elements, at most one blank line
    inside them, none after an opening tag or before a closing tag
  - multi-line comments re-indented, continuation lines aligned under
    the opening "<!-- " text

Usage: fmt_metrics.py [--check] [metrics.xml]

Rewrites in place (or with --check, exits 1 if the file would change).
Refuses to write if the result does not parse to the same element tree
as the input."""

import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

INDENT = '    '
TOP    = ( 'enum', 'tile', 'common', 'linkin' )
ORDER  = ( 'value', 'name', 'telemetry', 'enum', 'states', 'values',
           'min', 'max', 'source', 'ambiguous-kind', 'renamed_from', 'deprecated', 'label', 'summary', 'lint-allow' )

ATTR_RE = re.compile( r'([\w:-]+)\s*=\s*"([^"]*)"' )

def fmt_tag( body: str ) -> str:
    """Normalize one start or empty tag body (without the indent)."""
    m = re.match( r'<(\w+)(.*?)\s*(/?)>$', body, re.S )
    if not m: return body
    name, rest, empty = m.groups()
    attrs = ATTR_RE.findall( rest )
    if ATTR_RE.sub( '', rest ).strip():
        raise SystemExit( f'unparsed attribute text in: {body}' )
    unknown = [ k for k, _ in attrs if k not in ORDER ]
    if unknown: raise SystemExit( f'unknown attribute(s) {unknown} in: {body}; add them to ORDER' )
    attrs.sort( key=lambda kv: ORDER.index( kv[0] ) )
    out = '<' + name + ''.join( f' {k}="{v}"' for k, v in attrs )
    return out + ( ' />' if empty else '>' )

def tree_sig( text: str ):
    def sig( e ):
        return ( e.tag, sorted( e.attrib.items() ), ( e.text or '' ).strip(), [ sig( c ) for c in e ] )
    return sig( ET.fromstring( text ) )

def fmt( text: str ) -> str:
    head_end = text.index( '-->' ) + 3                 # leading rules comment kept verbatim
    head, body = text[ :head_end ], text[ head_end: ]

    # Split into logical items: comments (possibly multi-line), tags, text.
    items = re.findall( r'<!--.*?-->|<[^>]*>|[^<]+', body, re.S )
    out = []      # list of (depth, kind, text)
    depth = 0
    for it in items:
        if it.startswith( '<!--' ):
            out.append( ( depth, 'comment', it ) )
        elif it.startswith( '</' ):
            if it.strip() != '</metrics>': depth -= 1   # <metrics> root does not indent
            out.append( ( depth, 'close', it.strip() ) )
        elif it.startswith( '<' ):
            t = fmt_tag( it.strip() )
            out.append( ( depth, 'open' if not t.endswith( '/>' ) else 'empty', t ) )
            if not t.endswith( '/>' ) and t != '<metrics>': depth += 1
        else:
            blanks = it.count( '\n' ) - 1
            stripped = it.strip()
            if stripped:  # element text (e.g. <summary>)
                out.append( ( depth, 'text', stripped ) )
            elif blanks > 0:
                out.append( ( depth, 'blank', '' ) )

    # Render.  A blank item becomes '' and is cleaned up by the policy below.
    lines = []
    i = 0
    while i < len( out ):
        d, kind, t = out[ i ]
        ind = INDENT*d
        if kind == 'blank':
            lines.append( '' )
        elif kind == 'open' and i+2 < len( out ) and out[ i+1 ][1] == 'text' and out[ i+2 ][1] == 'close':
            lines.append( f'{ind}{t}{out[ i+1 ][2]}{out[ i+2 ][2]}' )   # <summary>text</summary>
            i += 2
        elif kind == 'comment':
            cl = t.split( '\n' )
            lines.append( ind + cl[ 0 ].strip() )
            lines.extend( ind + '     ' + l.strip() for l in cl[ 1: ] )
        else:
            lines.append( ind + t )
        i += 1

    # Blank line policy.
    is_top_open  = lambda l: re.match( r'^<(' + '|'.join( TOP ) + r')\b', l ) is not None
    is_open      = lambda l: re.match( r'^\s*<\w[^>]*[^/]>$', l ) is not None and '</' not in l and l != '<metrics>'
    is_close     = lambda l: re.match( r'^\s*</', l ) is not None
    res = []
    for ln in lines:
        if ln == '':
            if res and res[ -1 ] != '' and not is_open( res[ -1 ] ): res.append( '' )
            continue
        if is_close( ln ) and res and res[ -1 ] == '' and ln != '</metrics>': res.pop()
        if ln == '</metrics>' and res and res[ -1 ] != '': res.append( '' )
        if is_top_open( ln ) and res and res[ -1 ] != '':
            # A comment directly above a top-level element belongs to it.
            j = len( res )
            while j > 0 and ( res[ j-1 ].startswith( '<!--' ) or res[ j-1 ].startswith( '     ' ) ): j -= 1
            if j > 0 and res[ j-1 ] != '': res.insert( j, '' )
        res.append( ln )
    while res and res[ 0 ] == '': res.pop( 0 )
    return head + '\n\n' + '\n'.join( res ).rstrip() + '\n'

def main():
    args = [ a for a in sys.argv[ 1: ] if a != '--check' ]
    check = '--check' in sys.argv[ 1: ]
    path = Path( args[ 0 ] if args else Path( __file__ ).parent / 'metrics.xml' )
    text = path.read_text()
    new = fmt( text )
    if tree_sig( new ) != tree_sig( text ):
        raise SystemExit( 'formatted document does not match the input tree; not writing' )
    if check:
        if new != text:
            print( f'{path}: needs formatting (run {Path( __file__ ).name})' )
            sys.exit( 1 )
        return
    if new != text: path.write_text( new )

if __name__ == '__main__':
    main()
