# import numpy as np
from base58 import b58decode
from multiprocessing import Pool
import random
import math

fd_pubkey_pending_reserved_keys_tbl = [
    "AddressLookupTab1e1111111111111111111111111",
    "ComputeBudget111111111111111111111111111111",
    "Ed25519SigVerify111111111111111111111111111",
    "LoaderV411111111111111111111111111111111111",
    "KeccakSecp256k11111111111111111111111111111",
    "ZkE1Gama1Proof11111111111111111111111111111",
    "ZkTokenProof1111111111111111111111111111111",
    "SysvarEpochRewards1111111111111111111111111",
    "SysvarLastRestartS1ot1111111111111111111111",
    "Sysvar1111111111111111111111111111111111111",
    "Secp256r1SigVerify1111111111111111111111111",
]

fd_native_program_fn_lookup_tbl = [
    "Vote111111111111111111111111111111111111111",
    "11111111111111111111111111111111",
    "Config1111111111111111111111111111111111111",
    "Stake11111111111111111111111111111111111111",
    "ComputeBudget111111111111111111111111111111",
    "AddressLookupTab1e1111111111111111111111111",
    "ZkE1Gama1Proof11111111111111111111111111111",
    "BPFLoader1111111111111111111111111111111111",
    "BPFLoader2111111111111111111111111111111111",
    "BPFLoaderUpgradeab1e11111111111111111111111",
    "Ed25519SigVerify111111111111111111111111111",
    "KeccakSecp256k11111111111111111111111111111",
    "Secp256r1SigVerify1111111111111111111111111",
]

fd_pack_builtin = [
    "Stake11111111111111111111111111111111111111",
    "Config1111111111111111111111111111111111111",
    "Vote111111111111111111111111111111111111111",
    "11111111111111111111111111111111",
    "ComputeBudget111111111111111111111111111111",
    "AddressLookupTab1e1111111111111111111111111",
    "BPFLoaderUpgradeab1e11111111111111111111111",
    "BPFLoader1111111111111111111111111111111111",
    "BPFLoader2111111111111111111111111111111111",
    "LoaderV411111111111111111111111111111111111",
    "KeccakSecp256k11111111111111111111111111111",
    "Ed25519SigVerify111111111111111111111111111",
    "Secp256r1SigVerify1111111111111111111111111",
]

fd_pack_unwritable = [
    # Sysvars
    "SysvarC1ock11111111111111111111111111111111",
    "SysvarEpochSchedu1e111111111111111111111111",
    "SysvarFees111111111111111111111111111111111",
    "SysvarRecentB1ockHashes11111111111111111111",
    "SysvarRent111111111111111111111111111111111",
    "SysvarRewards111111111111111111111111111111",
    "SysvarS1otHashes111111111111111111111111111",
    "SysvarS1otHistory11111111111111111111111111",
    "SysvarStakeHistory1111111111111111111111111",
    "Sysvar1nstructions1111111111111111111111111",
    "SysvarEpochRewards1111111111111111111111111",
    "SysvarLastRestartS1ot1111111111111111111111",
    # Programs
    "Config1111111111111111111111111111111111111",
    "Feature111111111111111111111111111111111111",
    "NativeLoader1111111111111111111111111111111",
    "Stake11111111111111111111111111111111111111",
    "StakeConfig11111111111111111111111111111111",
    "Vote111111111111111111111111111111111111111",
    "11111111111111111111111111111111",
    "BPFLoader1111111111111111111111111111111111",
    "BPFLoader2111111111111111111111111111111111",
    "BPFLoaderUpgradeab1e11111111111111111111111",
    # Extras
    "Ed25519SigVerify111111111111111111111111111",
    "KeccakSecp256k11111111111111111111111111111",
    "ComputeBudget111111111111111111111111111111",
    "AddressLookupTab1e1111111111111111111111111",
    "So11111111111111111111111111111111111111112",
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
    "Secp256r1SigVerify1111111111111111111111111",
]

def map_perfect_el(s):
    x = b58decode(s)
    return x[8] | (x[9]<<8) | (x[10]<<16) | (x[11]<<24)

def map_perfect_4(k, c):
    return ((k * c)>>(32-4)) & 0x0F

def map_perfect_5(k, c):
    return ((k * c)>>(32-5)) & 0x1F

# last c found = 146
arr = [map_perfect_el(x) for x in fd_pubkey_pending_reserved_keys_tbl]
for c in range(200):
    cur = len(set( map_perfect_4(x, c) for x in arr ))
    if cur == len(arr):
        print(f"fd_pubkey_pending_reserved_keys_tbl: use MAP_PERFECT_HASH_C = {c}")
        break

# last c found = 468
arr = [map_perfect_el(x) for x in fd_native_program_fn_lookup_tbl]
for c in range(500):
    cur = len(set( map_perfect_4(x, c) for x in arr ))
    if cur == len(arr):
        print(f"fd_native_program_fn_lookup_tbl: use MAP_PERFECT_HASH_C = {c}")
        break

# last c found = 468
arr = [map_perfect_el(x) for x in fd_pack_builtin]
for c in range(500):
    cur = len(set( map_perfect_4(x, c) for x in arr ))
    if cur == len(arr):
        print(f"fd_pack_builtin: use MAP_PERFECT_HASH_C = {c}")
        break

# last c found = 1227063708
arr = [map_perfect_el(x) for x in fd_pack_unwritable]
for c in range(1227063708-1, 1227063708+1):
    cur = len(set( map_perfect_5(x, c) for x in arr ))
    if cur == len(arr):
        print(f"fd_pack_unwritable: use MAP_PERFECT_HASH_C = {c}")
        # break

# the example below runs over all 2^32 keys
# last c found = ...
# arr = [map_perfect_el(x) for x in fd_pack_unwritable]
# def parallel_find(i):
#     c = i
#     if c % 10_000_000 == 0:
#         print(c, "...")
#     cur = len(set( map_perfect_5(x, c) for x in arr ))
#     if cur == len(arr):
#         print(f"fd_pack_unwritable: use MAP_PERFECT_HASH_C = {c}")
#         return
# pool = Pool(processes=100)
# pool.map(parallel_find, range(2**32-1))
