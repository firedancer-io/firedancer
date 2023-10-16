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
import base64
import urllib
from hashlib import sha256
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


def cmp_key(key):
    if "name" in key:
        return key["name"]
    else:
        return ""

def read_test_cases(path):
    tests = []
    files = os.listdir(path)
    files = [f for f in files if os.path.isfile(path+'/'+f)] #Filtering only the files.
    for file in files:
        if file.endswith(".json"):
            with open(path+'/'+file, "r") as f:
                print(file)
                s = f.read().rstrip(", \n")
                data = json.loads('[' + s + ']')
                tests = tests + sorted(data, key=lambda k: cmp_key(k))
#    return tests.sort(key=lambda k: cmp_key(k))
    return tests

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
    if err == "ActiveVoteAccountClose":
        return -53


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

    feature_list = json.load(open("../../features/feature_map.json", "r"))

    generated_dir = Path(__file__).parent / "generated"
    generated_dir.mkdir(exist_ok=True)

    file_idx = -1

    for test_case_idx, test_case in enumerate(json_test_cases):
        file_idx += 1
        set_stdout(generated_dir / f"test_native_programs_{file_idx:03d}.h")
        print('#include "../fd_tests.h"')

        fs = json.loads(test_case["feature_set"])
        feature_idxs = []
        if len(fs) > 0:
            for x in fs:
                disabled_feature = base58.b58encode(bytearray(x)).decode("utf-8")
                # Find index of feature given pubkey
                feature_idx = -1
                for i, f in enumerate(feature_list):
                    if f["pubkey"] == disabled_feature:
                        feature_idx = i
                if feature_idx != -1:
                    feature_idxs.append(str(feature_idx))
                else:
                    print("Unknown feature " +disabled_feature, file=sys.stderr)
            feature_idxs = sorted(feature_idxs)
        bt = "".join(test_case["backtrace"].split("\n")[4:12])
        # TODO: recent block hashes sys var is too long
        print(
            f"""int test_{test_case_idx}(fd_executor_test_suite_t *suite) {{
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = {len(feature_idxs)};
  test.bt = "{bt}";
  test.test_name = "{test_case["name"]}";
  test.test_number = {test_case_idx};
  test.sysvar_cache.clock = "{test_case["sysvar_cache"]["clock"]}";
  test.sysvar_cache.epoch_schedule = "{test_case["sysvar_cache"]["epoch_schedule"]}";
  test.sysvar_cache.epoch_rewards = "{test_case["sysvar_cache"]["epoch_rewards"]}";
  test.sysvar_cache.fees = "{test_case["sysvar_cache"]["fees"]}";
  test.sysvar_cache.rent = "{test_case["sysvar_cache"]["rent"]}";
  test.sysvar_cache.slot_hashes = "{test_case["sysvar_cache"]["slot_hashes"]}";
  test.sysvar_cache.stake_history = "{test_case["sysvar_cache"]["stake_history"]}";
  test.sysvar_cache.slot_history = "{test_case["sysvar_cache"]["last_restart_slot"]}";
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = {len(test_case["transaction_accounts"])};
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
"""
        )

        if len(fs) > 0:
            print(f"""
  uchar disabled_features[] = {{ {",".join(feature_idxs)} }};
  test.disable_feature = disabled_features;
            """
        )

        if "sysvar_cache" in test_case:
            svc = test_case["sysvar_cache"]
            print(f" // {svc}")

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
  fd_base58_decode_32( "{txn_acc_result["owner"]}",  (uchar *) &test_acc->result_owner);
  test_acc->lamports        = {txn_acc_shared_data["lamports"]}UL;
  test_acc->result_lamports = {format(txn_acc_result["lamports"])}UL;
  test_acc->executable      = {1 if txn_acc_shared_data["executable"] else 0};
  test_acc->result_executable= {1 if txn_acc_result["executable"] else 0};
  test_acc->rent_epoch      = {txn_acc_shared_data["rent_epoch"]};
  test_acc->result_rent_epoch      = {txn_acc_result["rent_epoch"]};""")
            if len(data) > 0:
                print(f"""  static uchar const fd_flamenco_native_prog_test_{test_case_idx}_acc_{acc_idx}_data[] = {{ {",".join([f"0x{b:02x}" for b in data])} }};
  test_acc->data            = fd_flamenco_native_prog_test_{test_case_idx}_acc_{acc_idx}_data;
  test_acc->data_len        = {len(data)}UL;""")
            if len(result_data) > 0:
                print(f"""  static uchar const fd_flamenco_native_prog_test_{test_case_idx}_acc_{acc_idx}_post_data[] = {{ {",".join([f"0x{b:02x}" for b in result_data])} }};
  test_acc->result_data     = fd_flamenco_native_prog_test_{test_case_idx}_acc_{acc_idx}_post_data;
  test_acc->result_data_len = {len(result_data)}UL;""")
            print("""  test_acc++;""")

        # Serialize the transaction this test case executes
        accounts = []
        signer_pubkeys = set()
        num_signers = 0
        for account in test_case["instruction_accounts"]:
            if "pubkey" not in account:
                idx = int(account["index_in_transaction"])
                if idx < len(test_case["transaction_accounts"]):
                    account["pubkey"] = test_case["transaction_accounts"][int(account["index_in_transaction"])]["pubkey"]
                else:
                    pkey = sha256(str(account).encode('utf-8')).digest()
                    account["pubkey"] = base58.b58encode(pkey).decode("utf-8")
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

        signatures = [[0] * 64 for _ in range(num_signers)]

        tx = Transaction().add(instruction)
        message = tx.serialize_message()

        url = "https://explorer.solana.com/tx/inspector?message="+ urllib.parse.quote_plus(base64.b64encode(message).decode('utf-8'))

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
        print(f"""  static uchar const fd_flamenco_native_prog_test_{test_case_idx}_raw[] = {{ {",".join([f"0x{b:02x}" for b in serialized])} }};
  test.raw_tx = fd_flamenco_native_prog_test_{test_case_idx}_raw;
  test.raw_tx_len = {len(serialized)}UL;""")
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
        print("// {}".format(url))
    #    sys.exit(0)

    set_stdout("test_native_programs.c")

    hdr = """#include <stdlib.h>
#include <stdio.h>
"""

    print(hdr)
    print(f'#include "fd_tests.h"')
    print("extern int fd_executor_test_suite_check_filter(fd_executor_test_suite_t *suite, fd_executor_test_t *test);")

    for idx in range(file_idx + 1):
        print("extern int test_{}(fd_executor_test_suite_t *suite);".format(idx));
    print(
        f"""
ulong               test_cnt = {test_case_idx};
fd_executor_test_fn tests[] = {{"""
    )
    for n in range(test_case_idx):
        print(f" test_{n},", end="")
    print(" NULL\n};")

    for idx in range(file_idx + 1):
        if idx % 50 == 0:
            set_stdout("generated/test_native_programs_{}.c".format(idx))
            print(hdr)
            print(f'#include "../fd_tests.h"')
            print(f'#include "../../../../ballet/base58/fd_base58.h"')
            print("extern int fd_executor_test_suite_check_filter(fd_executor_test_suite_t *suite, fd_executor_test_t *test);")
        print(f'#include "test_native_programs_{idx:03d}.h"')

if __name__ == "__main__":
    main()
