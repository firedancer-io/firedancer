#!/usr/bin/env python3
"""Writes the reference byte vector test_txn_meta compares its own
encoding against.

The message built here is the one test_txn_meta's first fixture
describes: a legacy transaction that succeeded, with two log messages,
a return value, and one top level instruction that invoked two nested
ones.  The bytes come out of the protobuf runtime, from the vendored
.proto files, so they are what any protobuf implementation produces for
that message.

Usage, from the repository root:

  cd src/discof/dragon/proto && \
  protoc --experimental_allow_proto3_optional --python_out=/tmp/pb \
         geyser.proto solana_storage.proto timestamp.proto
  PYTHONPATH=/tmp/pb PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python \
    python3 src/flamenco/txnmeta/gen_test_vectors.py \
    > src/flamenco/txnmeta/test_txn_meta_success.inc
"""

import sys

import geyser_pb2 as geyser
import solana_storage_pb2 as storage


def legacy_payload():
    """The bytes pl_legacy writes for the first fixture."""
    out = bytearray()
    out.append(1)                       # one signature
    out += b"\x11" * 64
    out += bytes([1, 0, 1])             # signers, readonly signed, readonly unsigned
    out.append(3)                       # account addresses
    for i in range(3):
        out += bytes([0x20 + i]) * 32
    out += b"\x30" * 32                 # recent blockhash
    out.append(1)                       # one instruction
    out += bytes([2, 2, 0, 1, 3, 0xAA, 0xBB, 0xCC])
    return bytes(out)


def main():
    payload = legacy_payload()

    message = storage.Message(
        header=storage.MessageHeader(
            num_required_signatures=1,
            num_readonly_signed_accounts=0,
            num_readonly_unsigned_accounts=1,
        ),
        account_keys=[bytes([0x20 + i]) * 32 for i in range(3)],
        recent_blockhash=b"\x30" * 32,
        instructions=[
            storage.CompiledInstruction(
                program_id_index=2, accounts=bytes([0, 1]), data=bytes([0xAA, 0xBB, 0xCC])
            )
        ],
        versioned=False,
    )

    meta = storage.TransactionStatusMeta(
        fee=6000,
        pre_balances=[10, 20, 30],
        post_balances=[9, 19, 29],
        inner_instructions=[
            storage.InnerInstructions(
                index=0,
                instructions=[
                    storage.InnerInstruction(
                        program_id_index=1,
                        accounts=bytes([0]),
                        data=bytes([0xDD, 0xEE]),
                        stack_height=2,
                    ),
                    storage.InnerInstruction(
                        program_id_index=1,
                        accounts=bytes([0]),
                        data=bytes([0xFF]),
                        stack_height=3,
                    ),
                ],
            )
        ],
        inner_instructions_none=False,
        log_messages=["Program log: hello", "Program log: bye"],
        log_messages_none=False,
        return_data=storage.ReturnData(program_id=b"\x22" * 32, data=bytes([0x01, 0x02])),
        return_data_none=False,
        compute_units_consumed=4321,
        cost_units=1234,
    )

    info = geyser.SubscribeUpdateTransactionInfo(
        signature=b"\x11" * 64,
        is_vote=False,
        transaction=storage.Transaction(signatures=[payload[1:65]], message=message),
        meta=meta,
        index=2,
    )

    update = geyser.SubscribeUpdateTransaction(transaction=info, slot=100, bank_id=7)
    raw = update.SerializeToString()

    for off in range(0, len(raw), 12):
        line = ", ".join("0x%02x" % b for b in raw[off:off + 12])
        sys.stdout.write("  " + line + ",\n")


if __name__ == "__main__":
    main()
