#

# without podman
#   sudo dnf install -y python38-devel
#   /bin/python3.8 -m pip install solana solders base58 --user
#   python3.8 gen_c_tests.py -j system_program_tests.json

# with podman
#   podman run -v .:/tests --security-opt label=disable python3.8 python3 /tests/gen_c_tests.py -j /tests/system_program_tests.json
#
# to generate data
#   ./cargo nightly test --package solana-runtime --lib -- system_instruction_processor::tests --nocapture

# formatting:
#   sudo dnf install -y python3.11-pip
#   pip3.11 install black
#   black gen_c_tests.py

import argparse
from typing import Dict, List, Set, Tuple
import base58
import base64
import urllib
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
from solders.instruction import AccountMeta, Instruction
from solders.pubkey import Pubkey
from solders.hash import Hash
from solders.transaction import Transaction, VersionedTransaction
from solders.transaction_status import EncodedTransactionWithStatusMeta, UiConfirmedBlock
from solders.keypair import Keypair
from solders.signature import Signature
from tqdm import tqdm

from solana.rpc.api import Client
from graphviz import Digraph
from graphviz.dot import Dot
from collections import defaultdict
import itertools

def parse_args():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("-r", "--rpc-url", help="Solana RPC URL to use", required=True, type=str)
    arg_parser.add_argument("-b", "--block-num", help="Block number to analyze", required=True, type=int)
    arg_parser.add_argument("-x", "--exclude-no-deps", help="Exclude transactions with no deps", action='store_true')
    arg_parser.add_argument("-v", "--exclude-votes", help="Exclude transactions with votes", action='store_true')
    arg_parser.add_argument("-f", "--block-file", help="Block file")
    
    return arg_parser.parse_args()

TxnIdx = Tuple[int, int, int]
class TxnNode:
    def __init__(self, 
                 txn: EncodedTransactionWithStatusMeta, 
                 sig: Signature,
                 global_txn_idx: int,
                 mblk_batch_idx: int, 
                 mblk_idx: int, 
                 txn_idx: int) -> None:
        self.txn = txn
        self.sig = sig
        self.r_accs = set()
        self.w_accs = set()
        self.global_txn_idx = global_txn_idx
        self.mblk_batch_idx = mblk_batch_idx
        self.mblk_idx = mblk_idx
        self.txn_idx = txn_idx

    def add_readonly_acc(self, acc):
        self.r_accs.add(acc)

    def add_writable_acc(self, acc):
        self.w_accs.add(acc)

def parse_block_info(content: str):
    tot_txn_cnt = 0
    tot_hash_cnt = 0
    global_txn_idx = 0
    global_mblk_idx = 0
    raw = base64.b64decode(content)
    block_info: List[List[Tuple[int, List[Tuple[VersionedTransaction, int]]]]] = []
    txn_idxs: List[TxnIdx] = []
    while len(raw) > 0:
        microblock_batch_info = []
        num_microblocks = int.from_bytes(raw[:8], "little")
        raw = raw[8:]
        for mblk_idx in range(num_microblocks):
            microblock_info = []
            hash_cnt = int.from_bytes(raw[:8], "little")
            tot_hash_cnt += hash_cnt
            raw = raw[8:]
            poh_hash = Hash.from_bytes(raw[:32])
            raw = raw[32:]
            txn_cnt = int.from_bytes(raw[:8], "little")
            raw = raw[8:]
            for txn_idx in range(txn_cnt):
                txn = VersionedTransaction.from_bytes(raw[:max(1280, len(raw))])
                tot_txn_cnt += 1
                txn_sz = len(bytes(txn))
                raw = raw[txn_sz:]
                microblock_info.append((txn, global_txn_idx))
                txn_idxs.append((len(block_info), mblk_idx, txn_idx))
                global_txn_idx += 1
            microblock_batch_info.append((global_mblk_idx, microblock_info))
            global_mblk_idx += 1
        block_info.append(microblock_batch_info)
    return (block_info, txn_idxs, global_mblk_idx)

def get_txn_nodes(block: UiConfirmedBlock, txn_idxs: List[TxnIdx]) -> List[TxnNode]:
    txn_nodes: List[TxnNode] = []
    for i, txn in enumerate(tqdm(block.transactions, desc="Generate Txn Nodes")):
        mblk_batch_idx, mblk_idx, txn_idx = txn_idxs[i]
        txn_node = TxnNode(txn, txn.transaction.signatures[0], i, mblk_batch_idx, mblk_idx, txn_idx)
        if str(txn.transaction.signatures[0]) == "23xqpLodQvDMRTi5h5NdHB3eoz6g7n5V2yTbnEB3TitHL227Fb2YFrZnSCfxYCvV5czUuLEwDxBGRDTdhLu5E31z":
            print(mblk_batch_idx, mblk_idx, txn_idx)

        signature_cnt = len(txn.transaction.signatures)
        readonly_signed_cnt = txn.transaction.message.header.num_readonly_signed_accounts
        acct_addr_cnt = len(txn.transaction.message.account_keys)
        readonly_unsigned_cnt = txn.transaction.message.header.num_readonly_unsigned_accounts
        for j, acc, in enumerate(txn.transaction.message.account_keys):
            if j < (signature_cnt - readonly_signed_cnt):
                txn_node.add_writable_acc(acc)
            elif j < signature_cnt:
                txn_node.add_readonly_acc(acc)
            elif j < (acct_addr_cnt - readonly_unsigned_cnt):
                txn_node.add_writable_acc(acc)
            else:
                txn_node.add_readonly_acc(acc)
            
        for j, writeable_acc in enumerate(txn.meta.loaded_addresses.writable):
            txn_node.add_writable_acc(writeable_acc)
        for j, readable_acc in enumerate(txn.meta.loaded_addresses.readonly):
            txn_node.add_readonly_acc(readable_acc)
        txn_nodes.append(txn_node)
    return txn_nodes

def get_txn_deps(txn_nodes: List[TxnNode]):
    deps: List[Dict[int, List[int]]] = []
    has_dep_set: Set[int] = set()
    for i in tqdm(range(len(txn_nodes)), desc="Analyzing Txn Deps"):
        txn_node0 = txn_nodes[i]
        node_deps = defaultdict(list)
        for acc in set(itertools.chain(txn_node0.r_accs, txn_node0.w_accs)):
            for j in range(i-1, -1, -1):
                txn_node1 = txn_nodes[j]
                dep_found = False
                for w_acc in txn_node1.w_accs:
                    if acc == w_acc:
                        node_deps[j].append(acc)
                        dep_found = True
                        break
                if dep_found:
                    has_dep_set.add(j)
                    break
        deps.append(node_deps)
    return deps, has_dep_set

def draw_txn_node(g: Dot, txn_node: TxnNode, block_txn_idx: int):
    node_name = str(txn_node.sig)

    r_accs_str = "\\n".join([str(acc) for acc in txn_node.r_accs])
    w_accs_str = "\\n".join([str(acc) for acc in txn_node.w_accs])
    
    with g.subgraph(name="cluster{}".format(node_name)) as n:
        n.attr('node', shape='box', fontname="Courier New")
        n.node("{}-x".format(node_name), fontsize="1", height="0.01", margin="0.01", style="invis", shape="box")
        n.attr('node', shape='record')
        n.attr(style="filled", fillcolor="aquamarine")
        n.node("{}-r".format(node_name), "ro | {}".format(r_accs_str))
        n.node("{}-w".format(node_name), "wr | {}".format(w_accs_str))
        status = """<FONT COLOR="darkgreen">Success</FONT>"""
        if txn_node.txn.meta.err is not None:
            status = """<FONT COLOR="red">Failed</FONT>"""
        txn_label = """<<FONT COLOR="black"><B>{}...</B><BR ALIGN="LEFT" />Txn Idx: {}<BR  ALIGN="LEFT" />Status: <B>{}</B><BR ALIGN="LEFT" />CUs Consumed: {}</FONT>>""".format(node_name[:32], block_txn_idx, status, txn_node.txn.meta.compute_units_consumed)
        n.attr(label=txn_label)

def draw_microblock(g: Dot, mblk_batch_idx: int, mblk_idx: int, mblk_info_tup: Tuple[int, List[Tuple[VersionedTransaction, int]]], txn_nodes: List[TxnNode]):
    global_mblk_idx, mblk_info = mblk_info_tup
    with g.subgraph(name="clusterM_{}_{}".format(mblk_batch_idx, mblk_idx)) as m:
        m.attr(label="Microblock: {}".format(mblk_idx))
        m.node("M{}".format(global_mblk_idx), style="invis")
        global_mblk_idx += 1
        m.attr(style="filled", fillcolor="palegreen")
        for txn_idx, txn_info in enumerate(mblk_info):
            txn, global_txn_idx = txn_info
            txn_node = txn_nodes[global_txn_idx]
            draw_txn_node(m, txn_node, global_txn_idx)

def draw_microblock_batch(g: Dot, mblk_batch_idx: int, mblk_batch_info: List[Tuple[int, List[Tuple[VersionedTransaction, int]]]], txn_nodes: List[TxnNode]):
    with g.subgraph(name="clusterMB{}".format(mblk_batch_idx)) as mb:
        mb.node("MB{}".format(mblk_batch_idx), style="invis")
        with mb.subgraph(name="clusterMBD{}".format(mblk_batch_idx)) as mbd:
            mbd.attr(label="Dependencies", style="filled", fillcolor="khaki")
            mbd.node("MBD{}".format(mblk_batch_idx), style="invis")
        mb.attr(label="Microblock Batch: {}".format(mblk_batch_idx))
        mb.attr(style="filled", fillcolor="lightblue")
        for mblk_idx, mblk_info in enumerate(mblk_batch_info):
            draw_microblock(mb, mblk_batch_idx, mblk_idx, mblk_info, txn_nodes)
        mb.edge("M{}".format(mblk_batch_info[-1][0]), "MBD{}".format(mblk_batch_idx), style="invis", weight="100")

def draw_block(g: Dot, block_info: List[List[Tuple[int, List[Tuple[VersionedTransaction, int]]]]], txn_nodes: List[TxnNode]):
    for mblk_batch_idx, mblk_batch_info in enumerate(block_info):
        draw_microblock_batch(g, mblk_batch_idx, mblk_batch_info, txn_nodes)

def draw_binding_edges_for_block(g: Dot, mblk_cnt: int, block_info):
    for i in range(1, mblk_cnt):
        g.edge("M{}".format(i-1), "M{}".format(i), style="invis", weight="100")

    for i in range(1, len(block_info)):
        g.edge("MBD{}".format(i-1), "MB{}".format(i), style="invis",weight="100")

def main(args):
    with open(args.block_file, "r") as f:
        content = f.read()
    block_info, txn_idxs, mblk_cnt = parse_block_info(content)

    client = Client(args.rpc_url)
    block = client.get_block(args.block_num, max_supported_transaction_version=0)
    print("Blockhash:", block.value.blockhash)
    print("Num txns:", len(block.value.transactions))
    
    txn_nodes = get_txn_nodes(block.value, txn_idxs)
    deps, has_dep_set = get_txn_deps(txn_nodes)
        
    print("Analysis done")
    dot = Digraph("X", engine='dot')
    dot.attr(rankdir="LR", compound="true", ranksep="2.0", splines="true")
    dot.attr(fontname="Courier New", labeljust="l")
    
    draw_block(dot, block_info, txn_nodes)
    draw_binding_edges_for_block(dot, mblk_cnt, block_info)
 
    for i, node_deps in enumerate(deps):
        txn_node0 = txn_nodes[i]

        if args.exclude_votes:
            vote_acc = Pubkey(base58.b58decode("Vote111111111111111111111111111111111111111"))
            if vote_acc in txn_node0.r_accs:
                continue
            if vote_acc in txn_node0.w_accs:
                continue

        node_name0 = str(txn_node0.sig)
        for j in node_deps:
            txn_node1 = txn_nodes[j]
            if args.exclude_votes:
                vote_acc = Pubkey(base58.b58decode("Vote111111111111111111111111111111111111111"))
                if vote_acc in txn_node1.r_accs:
                    continue
                if vote_acc in txn_node1.w_accs:
                    continue
            node_name1 = str(txn_node1.sig)
            dep_node_name = "{}-{}-dep".format(node_name0, node_name1)
            dep_node_label = "\\n".join("(MB: {}, M: {}, T: {}) -> {} -> (MB: {}, M: {}, T: {})".format(txn_node1.mblk_batch_idx, txn_node1.mblk_idx, txn_node1.txn_idx, x, txn_node0.mblk_batch_idx, txn_node0.mblk_idx, txn_node0.txn_idx) for x in node_deps[j])
            
            if txn_node0.mblk_batch_idx == txn_node1.mblk_batch_idx:
                with dot.subgraph(name="clusterMB{}".format(txn_node0.mblk_batch_idx)) as mb:
                    mb.attr('node', shape='box', fontname="Courier New", style="filled", fillcolor="lightcoral")
                    if txn_node0.mblk_idx == txn_node1.mblk_idx:
                        with mb.subgraph(name="clusterM_{}_{}".format(txn_node0.mblk_batch_idx, txn_node0.mblk_idx)) as m:
                            m.node(dep_node_name, dep_node_label)
                    else: 
                        mb.node(dep_node_name, dep_node_label)
            else:
                with dot.subgraph(name="clusterMB{}".format(txn_node1.mblk_batch_idx)) as mb:
                    with mb.subgraph(name="clusterMBD{}".format(txn_node1.mblk_batch_idx)) as mbd:
                        mbd.attr('node', shape='box', fontname="Courier New", style="filled", fillcolor="lightsalmon")
                        mbd.node(dep_node_name, dep_node_label)

            if txn_node0.mblk_batch_idx == txn_node1.mblk_batch_idx:
                dot.attr("edge", constraint="false")
            else:
                dot.attr("edge", constraint="false")
            dot.edge(
                "{}-x".format(node_name1),
                dep_node_name,
                ltail="cluster{}".format(node_name1),
                constraint="true"
            )

            dot.edge(
                dep_node_name,
                "{}-x".format(node_name0),
                lhead="cluster{}".format(node_name0),
            )

    print("Rendering")
    dot.render(directory='build/dot-out', format="pdf")

if __name__ == "__main__":
    args = parse_args()
    main(args)
