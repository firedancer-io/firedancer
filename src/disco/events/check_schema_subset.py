#!/usr/bin/env python3
"""Checks that one event schema is a subset of another: every message
field and enum value in SUB has the same number, name, type and label in
SUPER.  buf breaking compares a change against its own base branch only,
so a backport that numbers a field differently from main passes it.

A field SUPER removed (its number and name both reserved there) is
skipped, and so is every message or enum of SUB reachable only through
removed fields.

Usage: check_schema_subset.py SUB.json SUPER.json
where each file is `buf build -o x.json src/disco/events/schema`."""

import json
import sys

def index(path: str) -> tuple:
    """{(message or enum path, number): (name, type, label)} and
    {message path: (reserved numbers, reserved names)}."""
    out, reserved = {}, {}
    def walk(prefix: str, msgs: list, enums: list):
        for e in enums:
            for v in e.get('value', []):
                out[( f'{prefix}{e["name"]}', v.get('number', 0) )] = ( v['name'], 'enum', '' )
        for m in msgs:
            name = f'{prefix}{m["name"]}'
            reserved[name] = ( { n for r in m.get('reservedRange', []) for n in range(r.get('start', 0), r['end']) },
                               set(m.get('reservedName', [])) )
            for f in m.get('field', []):
                out[( name, f['number'] )] = ( f['name'], f.get('typeName') or f['type'], f.get('label', '') )
            walk(f'{name}.', m.get('nestedType', []), m.get('enumType', []))
    for f in json.load(open(path))['file']:
        walk('', f.get('messageType', []), f.get('enumType', []))
    return out, reserved

def drop_removed(sub: dict, reserved: dict) -> dict:
    """sub without the fields reserved (by number and name) in the other
    schema, nor the types reachable only through them."""
    removed = { k for k, v in sub.items() if k[1] in reserved.get(k[0], ( (), () ))[0] and v[0] in reserved[k[0]][1] }
    types = { k[0] for k in sub }
    def ref(t: str) -> str:  # '.events.v1.A.B' -> 'A.B'; '' for a scalar
        parts = t.lstrip('.').split('.') if t.startswith('.') else []
        return next(( '.'.join(parts[i:]) for i in range(len(parts)) if '.'.join(parts[i:]) in types ), '')
    edges = {}
    for k, v in sub.items():
        if k not in removed and ref(v[1]): edges.setdefault(k[0], set()).add(ref(v[1]))
    roots = types - { ref(v[1]) for v in sub.values() }
    seen, todo = set(), list(roots)
    while todo:
        t = todo.pop()
        if t in seen: continue
        seen.add(t)
        todo += edges.get(t, ())
    return { k: v for k, v in sub.items() if k not in removed and k[0] in seen }

def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    ( sub, _ ), ( sup, reserved ) = index(sys.argv[1]), index(sys.argv[2])
    sub = drop_removed(sub, reserved)
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
