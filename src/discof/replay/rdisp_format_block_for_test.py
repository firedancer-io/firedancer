#!/usr/bin/env python3

# Example usage:  solana -um block 123456789 --output json-compact | src/discof/replay/rdisp_format_block_for_test.py > /tmp/123456789.bin &&  build/native/gcc/unit-test/test_rdisp --block-file /tmp/123456789.bin
import solders
from solders.transaction import Transaction, VersionedTransaction
from solders.pubkey import Pubkey
import base64
import json
import struct
import sys

pubkey_to_idx_ver = {}
j = json.load(sys.stdin)
for txn in j['transactions']:
    binary = base64.b64decode(txn['transaction'][0])
    writable_alt = list(map( Pubkey.from_string, txn['meta']['loadedAddresses']['writable'] ))
    readonly_alt = list(map( Pubkey.from_string, txn['meta']['loadedAddresses']['readonly'] ))
    ptxn = solders.transaction.VersionedTransaction.from_bytes(binary)

    sys.stdout.buffer.write(struct.pack("<IIII", txn['meta']['computeUnitsConsumed'], len(binary), len(writable_alt)+len(readonly_alt), len(ptxn.message.account_keys)+len(writable_alt)+len(readonly_alt)))
    sys.stdout.buffer.write(binary)
    for a in writable_alt + readonly_alt:
        sys.stdout.buffer.write(bytes(a))
    h = ptxn.message.header
    writable = [True ]*(h.num_required_signatures - h.num_readonly_signed_accounts) + \
               [False]*h.num_readonly_signed_accounts + \
               [True ]*( len(ptxn.message.account_keys) - h.num_readonly_unsigned_accounts - h.num_required_signatures) + \
               [False]*h.num_readonly_unsigned_accounts + \
               [True ]*len(writable_alt) + \
               [False]*len(readonly_alt)
    for i, a in enumerate(ptxn.message.account_keys + writable_alt + readonly_alt):
        if a in pubkey_to_idx_ver:
            idx, ver = pubkey_to_idx_ver[a]
        else:
            idx = len(pubkey_to_idx_ver)
            ver = 0
        sys.stdout.buffer.write(struct.pack("<HH", idx, ver+ 0x8000*writable[i]))
        if writable[i]:
            ver += 1
        pubkey_to_idx_ver[a] = (idx, ver)
