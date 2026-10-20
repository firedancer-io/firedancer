#!/usr/bin/env python3
"""Checks that one event schema is a subset of another: every message
field and enum value in SUB has the same number, name, type and label in
SUPER.  buf breaking compares a change against its own base branch only,
so a backport that numbers a field differently from main passes it.

Usage: check_schema_subset.py SUB.json SUPER.json
where each file is `buf build -o x.json src/disco/events/schema`."""

import json
import sys

def index(path: str) -> dict:
    """{(message or enum path, number): (name, type, label)}."""
    out = {}
    def walk(prefix: str, msgs: list, enums: list):
        for e in enums:
            for v in e.get('value', []):
                out[( f'{prefix}{e["name"]}', v.get('number', 0) )] = ( v['name'], 'enum', '' )
        for m in msgs:
            name = f'{prefix}{m["name"]}'
            for f in m.get('field', []):
                out[( name, f['number'] )] = ( f['name'], f.get('typeName') or f['type'], f.get('label', '') )
            walk(f'{name}.', m.get('nestedType', []), m.get('enumType', []))
    for f in json.load(open(path))['file']:
        walk('', f.get('messageType', []), f.get('enumType', []))
    return out

def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    sub, sup = index(sys.argv[1]), index(sys.argv[2])
    errs = []
    for key, want in sorted(sub.items(), key=lambda kv: (kv[0][0], kv[0][1])):
        got = sup.get(key)
        if got is None:
            errs.append(f'{key[0]} = {key[1]}: {want[0]} has no counterpart')
        elif got != want:
            errs.append(f'{key[0]} = {key[1]}: {want[0]} ({want[1]}) here, {got[0]} ({got[1]}) on the other branch')
    for e in errs: print(f'ERROR: {e}')
    if errs:
        raise SystemExit(f'{len(errs)} event schema numbers differ between branches.  A backport must keep the field numbers '
                         'main gave the fields: copy main\'s "field_number" for each field that lands at a different position.')
    print(f'ok: {len(sub)} fields and values match')

if __name__ == '__main__':
    main()
