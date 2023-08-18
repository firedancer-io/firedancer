# python3.8 gen_c_tests_sign.py -j ~/solana/signs.json

import argparse
import base58
import json
import os
from pathlib import Path
import sys
from solders.instruction import AccountMeta, Instruction
from solders.pubkey import Pubkey
from solders.transaction import Transaction
from solders.keypair import Keypair
from solana.transaction import Transaction

"""
Test framework:
- Each test contains:
    - Test name
    - Instruction data (uchar array)
    - Program key
    - Expected result
        - Either SUCCESS or instruction error code
"""


def read_test_cases(path):
    with open(path, "r") as f:
        return json.loads('[' + f.read()[:-2] + ']')

def serializeInstructionError(err):
    if err == "InvalidDataOffsets":
        return -100
    if err == "InvalidInstructionDataSize":
        return -101
    if err == "InvalidSignature":
        return -102

def serializeResult(result):
    if "Ok" in result:
        return 0
    if "Err" in result:
        return serializeInstructionError(result["Err"])


def set_stdout(file_path, append=False):
    sys.stdout.flush()
    sys.stdout = open(file_path, "a" if append else "w")


def main():
    argParser = argparse.ArgumentParser()
    argParser.add_argument(
        "-j", "--json", help="Path to the Solana test cases input JSON", required=True
    )
    args = argParser.parse_args()

    json_test_cases = read_test_cases(args.json)

    generated_dir = Path(__file__).parent / "generated"
    generated_dir.mkdir(exist_ok=True)

    for test_case_idx, test_case in enumerate(json_test_cases):
        set_stdout(generated_dir / f"test_signer_{test_case_idx:03d}.h")

        bt = "".join(test_case["backtrace"].split("\n")[4:12])

        # Hack to deal with broken unit test data
        if test_case_idx in [9,17,19]:
            d = test_case["instruction_data"]
            while len(d) < 100:
                d.append(0)

        print(
            f"""int test_{test_case_idx}(fd_executor_test_suite_t *suite) {{
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.bt = "{bt}";
  test.test_name = "{test_case["name"]}";
  test.test_number = {test_case_idx};
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
"""
        )
        data=bytes(test_case["instruction_data"])
        instruction = Instruction(
            accounts=[],
            program_id=Pubkey.from_bytes(base58.b58decode(test_case["prog"])),
            data=data
        )

        tx = Transaction().add(instruction)
        message = tx.serialize_message()

        print(
            f'  fd_base58_decode_32( "{test_case["prog"]}",  (unsigned char *) &test.program_id);'
        )
        print(f"""  static uchar const fd_flamenco_signer_test_{test_case_idx}_raw[] = {{ 0,{",".join([f"0x{b:02x}" for b in message])} }};
  test.raw_tx = fd_flamenco_signer_test_{test_case_idx}_raw;
  test.raw_tx_len = {len(message)+1}UL;""")
        res = test_case["expected_result"]
        print("  test.expected_result = {};".format(serializeResult(res)))
        if "Err" in res and isinstance(res["Err"], dict):
            print("  test.custom_err = {};".format(res["Err"]["Custom"]))
        else:
            print("  test.custom_err = 0;")
        print("")
        print("  return fd_executor_run_test( &test, suite );")
        print("}")

    set_stdout("test_sign_programs.c")

    hdr = """#include <stdlib.h>
#include <stdio.h>
"""

    print(hdr)
    print(f'#include "fd_tests.h"')
    print(f'#include "../../../ballet/base58/fd_base58.h"')
    print("extern int fd_executor_test_suite_check_filter(fd_executor_test_suite_t *suite, fd_executor_test_t *test);")

    for n in range(test_case_idx):
        h = generated_dir / f"test_signer_{n:03d}.h"
        print(f"#include \"{h}\"")
    print(
        f"""
ulong               test_cnt = {test_case_idx};
fd_executor_test_fn tests[] = {{"""
    )
    for n in range(test_case_idx):
        print(f" test_{n},", end="")
    print(" NULL\n};")

if __name__ == "__main__":
    main()
