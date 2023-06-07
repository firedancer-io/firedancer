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
    - List of transaction accounts
        - Pubkey
        - Contents
            - Lamports (ulong)
            - Data (uchar array)
            - Owner (pubkey)
            - Executable (uchar)
            - Rent epoch (ulong)
    - List of instruction accounts
        - Pubkey
        - Signer (bool)
        - Writer (bool)
    - Expected result
        - Either SUCCESS or instruction error code

- Need to
    - In Python:
        - Create and sign the raw transactions
        - Output list of (raw transactions, result)
        - Output calls to C code which generate the result
    - In C:
        - Test function takes an array of the full transactions and the expected result
        - It parses the transactions
        - Creates a new funk instance
        - Feeds them into the executor
        - Checks to see if the result is what we expect
"""


def read_test_cases(path):
    with open(path, "r") as f:
        return json.load(f)


def serializeInstructionError(err):
    if isinstance(err, dict):
        return -26
    #      return err["Custom"]
    if err == "GenericError":
        return -1
    if err == "InvalidArgument":
        return -2
    if err == "InvalidInstructionData":
        return -3
    if err == "InvalidAccountData":
        return -4
    if err == "AccountDataTooSmall":
        return -5
    if err == "InsufficientFunds":
        return -6
    if err == "IncorrectProgramId":
        return -7
    if err == "MissingRequiredSignature":
        return -8
    if err == "AccountAlreadyInitialized":
        return -9
    if err == "UninitializedAccount":
        return -10
    if err == "UnbalancedInstruction":
        return -11
    if err == "ModifiedProgramId":
        return -12
    if err == "ExternalAccountLamportSpend":
        return -13
    if err == "ExternalAccountDataModified":
        return -14
    if err == "ReadonlyLamportChange":
        return -15
    if err == "ReadonlyDataModified":
        return -16
    if err == "DuplicateAccountIndex":
        return -17
    if err == "ExecutableModified":
        return -18
    if err == "RentEpochModified":
        return -19
    if err == "NotEnoughAccountKeys":
        return -20
    if err == "AccountDataSizeChanged":
        return -21
    if err == "AccountNotExecutable":
        return -22
    if err == "AccountBorrowFailed":
        return -23
    if err == "AccountBorrowOutstanding":
        return -24
    if err == "DuplicateAccountOutOfSync":
        return -25
    if err == "Custom":
        return -26
    if err == "InvalidError":
        return -27
    if err == "ExecutableDataModified":
        return -28
    if err == "ExecutableLamportChange":
        return -29
    if err == "ExecutableAccountNotRentExempt":
        return -30
    if err == "UnsupportedProgramId":
        return -31
    if err == "CallDepth":
        return -32
    if err == "MissingAccount":
        return -33
    if err == "ReentrancyNotAllowed":
        return -34
    if err == "MaxSeedLengthExceeded":
        return -35
    if err == "InvalidSeeds":
        return -36
    if err == "InvalidRealloc":
        return -37
    if err == "ComputationalBudgetExceeded":
        return -38
    if err == "PrivilegeEscalation":
        return -39
    if err == "ProgramEnvironmentSetupFailure":
        return -40
    if err == "ProgramFailedToComplete":
        return -41
    if err == "ProgramFailedToCompile":
        return -42
    if err == "Immutable":
        return -43
    if err == "IncorrectAuthority":
        return -44
    if err == "BorshIoError":
        return -45
    if err == "AccountNotRentExempt":
        return -46
    if err == "InvalidAccountOwner":
        return -47
    if err == "ArithmeticOverflow":
        return -48
    if err == "UnsupportedSysvar":
        return -49
    if err == "IllegalOwner":
        return -50
    if err == "MaxAccountsDataSizeExceeded":
        return -51
    if err == "ActiveVoteAccountClose":
        return -52


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

    feature_list = json.load(open("../feature_map.json", "r"))

    fidx = 1

    fixtures_dir = Path(__file__).parent / "fixtures"
    fixtures_dir.mkdir(parents=True, exist_ok=True)
    generated_dir = Path(__file__).parent / "generated"
    generated_dir.mkdir(exist_ok=True)

    ############################################################################
    # Generate blob files containing tests
    set_stdout(generated_dir / "test_native_programs_imports.h")
    for test_case_idx, test_case in enumerate(json_test_cases):
        open(
            fixtures_dir / f"{test_case_idx}_instr.bin",
            "wb",
        ).write(bytes.fromhex(test_case["instruction_data"]))
        print(
            f'FD_IMPORT_BINARY( fd_flamenco_native_prog_test_{test_case_idx}_instr, "src/ballet/runtime/tests/fixtures/{test_case_idx}_instr.bin" );'
        )
        print(
            f'FD_IMPORT_BINARY( fd_flamenco_native_prog_test_{test_case_idx}_raw, "src/ballet/runtime/tests/fixtures/{test_case_idx}_raw.bin" );'
        )
        for acc_idx, acc in enumerate(test_case["transaction_accounts"]):
            acc_data = bytes.fromhex(acc["shared_data"]["data"])
            open(
                fixtures_dir / f"{test_case_idx}_acc_{acc_idx}_data.bin",
                "wb",
            ).write(acc_data)
            print(
                f'FD_IMPORT_BINARY( fd_flamenco_native_prog_test_{test_case_idx}_acc_{acc_idx}_data, "src/ballet/runtime/tests/fixtures/{test_case_idx}_acc_{acc_idx}_data.bin" );'
            )
        for acc_idx, acc in enumerate(test_case["resulting_accounts"]):
            acc_data = bytes.fromhex(acc["data"])
            open(
                fixtures_dir / f"{test_case_idx}_acc_{acc_idx}_post_data.bin",
                "wb",
            ).write(acc_data)
            print(
                f'FD_IMPORT_BINARY( fd_flamenco_native_prog_test_{test_case_idx}_acc_{acc_idx}_post_data, "src/ballet/runtime/tests/fixtures/{test_case_idx}_acc_{acc_idx}_post_data.bin" );'
            )

    set_stdout("test_native_programs.c")
    print(
        """#include <stdlib.h>
#include <stdio.h>
#include "fd_tests.h"
#include "../../base58/fd_base58.h"

#include "generated/test_native_programs_imports.h"

#ifdef _DISABLE_OPTIMIZATION
#pragma GCC optimize (\"O0\")
#endif

extern int fd_executor_test_suite_check_filter(fd_executor_test_suite_t *suite, fd_executor_test_t *test);"""
    )

    file_idx = -1
    for test_case_idx, test_case in enumerate(json_test_cases):
        if (test_case_idx % 25) == 0:
            file_idx += 1
            set_stdout(generated_dir / f"test_native_programs_{file_idx:02d}.h")
            print('#include "../fd_tests.h"')

        fs = json.loads(test_case["feature_set"])
        if len(fs) > 0:
            feature_idxs = []
            for x in fs:
                disabled_feature = base58.b58encode(bytearray(x)).decode("utf-8")
                # Find index of feature given pubkey
                feature_idx = next(
                    (
                        i
                        for i, f in enumerate(feature_list)
                        if f["pubkey"] == disabled_feature
                    )
                )
                feature_idxs.append(str(feature_idx))

        print(
            f"""int test_{test_case_idx}(fd_executor_test_suite_t *suite) {{
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = {len(fs)};
  uchar disabled_features[] = {{ {",".join(feature_idxs)} }};
  test.disable_feature = disabled_features;
  test.test_name = "{test_case["name"]}";
  test.test_nonce  = {test_case["nonce"]};
  test.test_number = {test_case_idx};
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = {len(test_case["transaction_accounts"])};
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
"""
        )
        if len(test_case["transaction_accounts"]) > 0:
            print("  fd_executor_test_acc_t* test_acc = test_accs;")

        # Serialize the accounts needed for this test case
        for acc_idx, txn_acc in enumerate(test_case["transaction_accounts"]):
            txn_acc_shared_data = txn_acc["shared_data"]
            txn_acc_result = test_case["resulting_accounts"][acc_idx]

            data = bytes.fromhex(txn_acc_shared_data["data"])
            result_data = bytes.fromhex(txn_acc_result["data"])

            print(
                f"""  fd_base58_decode_32( "{txn_acc["pubkey"]}",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "{txn_acc_shared_data["owner"]}",  (uchar *) &test_acc->owner);
  test_acc->lamports        = {txn_acc_shared_data["lamports"]}UL;
  test_acc->result_lamports = {format(txn_acc_result["lamports"])}UL;
  test_acc->executable      = {1 if txn_acc_shared_data["executable"] else 0};
  test_acc->rent_epoch      = {txn_acc_shared_data["rent_epoch"]};
  test_acc->data            = fd_flamenco_native_prog_test_{test_case_idx}_acc_{acc_idx}_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_{test_case_idx}_acc_{acc_idx}_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_{test_case_idx}_acc_{acc_idx}_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_{test_case_idx}_acc_{acc_idx}_post_data_sz;
  test_acc++;
"""
            )

        # Serialize the transaction this test case executes
        accounts = []
        signer_pubkeys = set()
        num_signers = 0
        for account in test_case["instruction_accounts"]:
            if bool(account["is_signer"]) and (account["pubkey"] not in signer_pubkeys):
                num_signers += 1
                signer_pubkeys.add(account["pubkey"])
            accounts.append(
                AccountMeta(
                    pubkey=Pubkey.from_bytes(base58.b58decode(account["pubkey"])),
                    is_signer=bool(account["is_signer"]),
                    is_writable=bool(account["is_writable"]),
                )
            )

        instruction = Instruction(
            accounts=accounts,
            program_id=Pubkey.from_string(test_case["program_id"]),
            data=bytes.fromhex(test_case["instruction_data"]),
        )

        signatures = [os.urandom(64) for _ in range(num_signers)]

        tx = Transaction().add(instruction)
        message = tx.serialize_message()

        components = signatures
        components.append(message)
        #    print(components)
        serialized = [b for bs in components for b in bs]
        serialized.insert(0, num_signers)
        #    print(serialized)

        # Serialize the expected result

        print(
            f'  fd_base58_decode_32( "{test_case["program_id"]}",  (unsigned char *) &test.program_id);'
        )
        open(fixtures_dir / f"{test_case_idx}_raw.bin", "wb").write(bytes(serialized))
        print(f"  test.raw_tx = fd_flamenco_native_prog_test_{test_case_idx}_raw;")
        print(f"  test.raw_tx_len = fd_flamenco_native_prog_test_{test_case_idx}_raw_sz;")
        res = test_case["expected_result"]
        print("  test.expected_result = {};".format(serializeResult(res)))
        if "Err" in res and isinstance(res["Err"], dict):
            print("  test.custom_err = {};".format(res["Err"]["Custom"]))
        else:
            print("  test.custom_err = 0;")
        print("")
        print("  test.accs_len = test_accs_len;")
        print("  test.accs = test_accs;")
        print("")
        print("  return fd_executor_run_test( &test, suite );")
        print("}")
    #    sys.exit(0)

    set_stdout("test_native_programs.c", append=True)
    for idx in range(file_idx + 1):
        print(f'#include "generated/test_native_programs_{idx:02d}.h"')
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
