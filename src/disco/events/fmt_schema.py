#!/usr/bin/env python3
"""Formats event schema JSON files into the house style: one line per
field with per-block aligned columns.  Inline entries (no element,
variants, or fields) render as

    "key":     { "type": "T",    "compression": "C", "description": "...", "max_len": N },

with the key, type, and compression columns padded to the widest entry
in their block.  Aggregate entries render as indented blocks with their
attributes one per line and their element/variants/fields nested.

Usage: fmt_schema.py [file.json ...]   (default: schema/*.json)

Rewrites in place.  Refuses to write if the reformatted document is not
json-identical to the input, or if it contains unknown structural keys.
"""
import json
import sys
import glob
import os

INDENT = "    "

ATTRS = ( "type", "compression", "description", "max_len", "dynamic" )
NESTED = ( "element", "variants", "fields" )


def is_inline( obj ):
    return isinstance( obj, dict ) and not ( obj.keys() & set( NESTED ) )


def check_keys( key, obj ):
    unknown = obj.keys() - set( ATTRS ) - set( NESTED )
    if unknown:
        raise SystemExit( f"unknown schema key(s) {sorted(unknown)} under {key}; teach fmt_schema.py about them first" )


def jstr( v ):
    return json.dumps( v, ensure_ascii=False )


def inline_body( obj, type_w, comp_w ):
    """The { ... } body of an inline entry, padded to the block's column widths."""
    out = "{ "
    if "type" in obj:
        seg = f'"type": {jstr(obj["type"])},'
        out += seg + " " * ( type_w - len( seg ) ) + " "
    if comp_w:
        seg = f'"compression": {jstr(obj["compression"])},' if "compression" in obj else ""
        out += seg + " " * ( comp_w - len( seg ) ) + " "
    out += f'"description": {jstr(obj["description"])}'
    if "max_len" in obj:
        out += f', "max_len": {obj["max_len"]}'
    return out + " }"


def block( entries, depth, blanks=None ):
    """Renders a { key: obj } map of fields or variants, one entry per line."""
    pad = INDENT * depth
    inl = { k: v for k, v in entries.items() if is_inline( v ) }
    key_w  = max( ( len( jstr( k ) + ":" ) for k in inl ), default=0 )
    type_w = max( ( len( f'"type": {jstr(v["type"])},' ) for v in inl.values() if "type" in v ), default=0 )
    comp_w = max( ( len( f'"compression": {jstr(v["compression"])},' ) for v in inl.values() if "compression" in v ), default=0 )
    lines = []
    for k, v in entries.items():
        check_keys( k, v )
        if blanks: lines.extend( [ "" ] * blanks.get( k, 0 ) )
        key = jstr( k ) + ":"
        if is_inline( v ):
            lines.append( f"{pad}{key}{' '*(key_w-len(key))} {inline_body( v, type_w, comp_w )}," )
        else:
            lines.append( f"{pad}{key} {{" )
            for a in ATTRS:
                if a in v:
                    lines.append( f"{pad}{INDENT}{jstr(a)}: {jstr(v[ a ])}," )
            for n in NESTED:
                if n not in v: continue
                if n == "element" and is_inline( v[ n ] ):
                    check_keys( k + ".element", v[ n ] )
                    body = inline_body( v[ n ], 0, 0 )
                    lines.append( f'{pad}{INDENT}"element": {body}' )
                else:
                    sub = v[ n ] if n != "element" else None
                    if n == "element":
                        check_keys( k + ".element", v[ n ] )
                        lines.append( f'{pad}{INDENT}"element": {{' )
                        for a in ATTRS:
                            if a in v[ n ]:
                                lines.append( f"{pad}{INDENT*2}{jstr(a)}: {jstr(v[ n ][ a ])}," )
                        lines.append( f'{pad}{INDENT*2}"fields": {{' )
                        lines.extend( block( v[ n ][ "fields" ], depth + 3 ) )
                        lines.append( f"{pad}{INDENT*2}}}" )
                        lines.append( f"{pad}{INDENT}}}" )
                    else:
                        lines.append( f"{pad}{INDENT}{jstr(n)}: {{" )
                        lines.extend( block( sub, depth + 2 ) )
                        lines.append( f"{pad}{INDENT}}}" )
            lines.append( f"{pad}}}," )
    if lines:
        lines[ -1 ] = lines[ -1 ].rstrip( "," )
    return lines


def top_level_blanks( text ):
    """Blank separator lines the file carries between top-level field
    groups, keyed by the field that follows them."""
    blanks, run = {}, 0
    for line in text.splitlines():
        if not line.strip():
            run += 1
        else:
            if run and line.startswith( INDENT * 2 + '"' ) and not line.startswith( INDENT * 3 ):
                blanks[ line.split( '"' )[ 1 ] ] = run
            run = 0
    return blanks


def render( doc ):
    lines = [ "{" ]
    lines.append( f'{INDENT}"name": {jstr(doc["name"])},' )
    lines.append( f'{INDENT}"id": {doc["id"]},' )
    lines.append( f'{INDENT}"description": {jstr(doc["description"])},' )
    lines.append( f'{INDENT}"fields": {{' )
    lines.extend( block( doc[ "fields" ], 2, blanks=doc.get( "_blanks" ) ) )
    lines.append( f"{INDENT}}}" )
    lines.append( "}" )
    return "\n".join( lines ) + "\n"


def main():
    paths = sys.argv[ 1: ]
    if not paths:
        paths = sorted( glob.glob( os.path.join( os.path.dirname( __file__ ), "schema", "*.json" ) ) )
    for path in paths:
        with open( path ) as f:
            text = f.read()
        doc = json.loads( text )
        doc[ "_blanks" ] = top_level_blanks( text )
        out = render( doc )
        del doc[ "_blanks" ]
        if json.loads( out ) != doc:
            raise SystemExit( f"{path}: reformatted document is not identical, refusing to write" )
        with open( path, "w" ) as f:
            f.write( out )
        print( f"formatted {path}" )


if __name__ == "__main__":
    main()
