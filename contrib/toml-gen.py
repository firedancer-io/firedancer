# To setup the environment:
#
#   python3 -m ensurepip --default-pip
#   python3 -m pip install toml
#
# To run:
#
#   python3 contrib/toml-gen.py -f FILE [--systemd] [-o OUTPUT-TOML]

import os
import re
import sys
import toml
import logging
import argparse

from pprint import pprint

# regex patterns for parsing files
pattern1 = re.compile(r'ADD.?\(\s*"([^"]*)"\s*(?:,\s*([^)]*))?\s*\)')  # ADD macros
pattern2 = re.compile(
    r"if\(\s*(?:FD_(?:LIKELY|UNLIKELY)\(\s*)?!?(.*?)(?:\s*\)\s*\)|\s*\))"
)   # if statements for boolean flags

# files containing flag-parsing content
FD_DEFAULT_TOML = "src/app/fdctl/config/default.toml"
FD_AGAVE_FILE   = "src/app/fdctl/commands/run_agave.c"
FD_CONFIG_FILE  = "src/app/shared/fd_config_parse.c"

# generated maps
flag_config_map = {}  #  --agave-flag: config.option
config_type_map = {}  # config.option: data_type

#    --agave-flags                          ->      confg.option
FLAG_CONFIG_MAP = {
    "--dynamic-port-range":                         "dynamic_port_range",
    "--bind-address":                               "net.bind_address",
    "--identity":                                   "consensus.identity_path",
    "--vote-account":                               "consensus.vote_account_path",
    "--authorized-voter":                           "consensus.authorized_voter_paths",
    "--no-snapshot-fetch":                          "consensus.snapshot_fetch",
    "--no-genesis-fetch":                           "consensus.genesis_fetch",
    "--no-poh-speed-test":                          "consensus.poh_speed_test",
    "--expected-genesis-hash":                      "consensus.expected_genesis_hash",
    "--wait-for-supermajority":                     "consensus.wait_for_supermajority_at_slot",
    "--expected-bank-hash":                         "consensus.expected_bank_hash",
    "--expected-shred-version":                     "consensus.expected_shred_version",
    "--no-wait-for-vote-to-start-leader":           "consensus.wait_for_vote_to_start_leader",
    "--hard-fork":                                  "consensus.hard_fork_at_slots",
    "--known-validator":                            "consensus.known_validators",
    "--snapshot-archive-format":                    "ledger.snapshot_archive_format",
    "--require-tower":                              "ledger.require_tower",
    "--no-os-network-limits-test":                  "consensus.os_network_limits_test",
    "--ledger":                                     "ledger.path",
    "--limit-ledger-size":                          "ledger.limit_size",
    "--accounts":                                   "ledger.accounts_path",
    "--accounts-index-path":                        "ledger.accounts_index_path",
    "--accounts-hash-cache-path":                   "ledger.accounts_hash_cache_path",
    "--disable-accounts-disk-index":                "ledger.enable_accounts_disk_index",
    "--account-index":                              "ledger.account_indexes",
    "--account-index-exclude-key":                  "ledger.account_index_exclude_keys",
    "--account-index-include-key":                  "ledger.account_index_include_keys",
    "--entrypoint":                                 "gossip.entrypoints",
    "--no-port-check":                              "gossip.port_check",
    "--gossip-port":                                "gossip.port",
    "--gossip-host":                                "gossip.host",
    "--allow-private-addr":                         "development.gossip.allow_private_address",
    "--rpc-port":                                   "rpc.port",
    "--full-rpc-api":                               "rpc.full_api",
    "--private-rpc":                                "rpc.private",
    "--rpc-bind-address":                           "rpc.bind_address",
    "--enable-rpc-transaction-history":             "rpc.transaction_history",
    "--enable-extended-tx-metadata-storage":        "rpc.extended_tx_metadata_storage",
    "--only-known-rpc":                             "rpc.only_known",
    "--rpc-pubsub-enable-block-subscription":       "rpc.pubsub_enable_block_subscription",
    "--rpc-pubsub-enable-vote-subscription":        "rpc.pubsub_enable_vote_subscription",
    "--enable-rpc-bigtable-ledger-storage":         "rpc.bigtable_ledger_storage",
    "--no-snapshots":                               "snapshots.enabled",
    "--full-snapshot-interval-slots":               "snapshots.full_snapshot_interval_slots",
    "--snapshot-interval-slots":                    "snapshots.incremental_snapshot_interval_slots",
    "--no-incremental-snapshots":                   "snapshots.incremental_snapshots",
    "--snapshots":                                  "snapshots.path",
    "--incremental-snapshot-archive-path":          "snapshots.incremental_path",
    "--maximum-snapshots-to-retain":                "snapshots.maximum_full_snapshots_to_retain",
    "--maximum-incremental-snapshots-to-retain":    "snapshots.maximum_incremental_snapshots_to_retain",
    "--maximum-snapshot-download-abort":            "snapshots.maximum_snapshot_download_abort",
    "--minimal-snapshot-download-speed":            "snapshots.minimum_snapshot_download_speed",
    "--unified-scheduler-handler-threads":          "layout.agave_unified_scheduler_handler_threads"
}


# parse a systemd unit file to get the agave-validator commandline part
def parse_systemd_cmdline(unit_file):
    with open(unit_file) as f:
        lines = f.readlines()

    cmdline    = ""
    in_cmdline = False
    for i in range(len(lines)):
        line = lines[i].strip()
        if "agave-validator" in line and not in_cmdline:
            cmdline += f"{line[line.find('agave-validator'):]}\n"
            in_cmdline = True
        elif in_cmdline:
            cmdline += f"{line}\n"
            if not line.endswith("\\"):
                in_cmdline = False

    return cmdline


# parse a agave-validator commandline to get a list of (flag, arg)
def parse_cmdline(flags_string):
    flags = []
    flag  = ()
    for line in flags_string.splitlines():
        if line.startswith("#"):
            # ignore comments
            continue
        # standardize lines for multiline strings
        sline = line.strip().rstrip("\\")
        for word in sline.split(" "):
            if "agave-validator" in word:
                # ignore binary
                continue
            sword = word.strip()
            if not sword:
                # ignore extraneous whitespaces
                continue
            # encountered a new flag
            if sword.startswith("--"):
                if len(flag) == 1 and flag[0].startswith("--"):
                    # the previous flag does not have an argument (boolean flag)
                    flag += (True,)
                if flag:
                    flags.append(flag)
                flag = (sword,)
            elif not sword.startswith("--"):
                # argument for the currently parsing flag
                flag += (sword,)
            else:
                raise SystemExit(f"unrecognized token while parsing - {sword}")

    if flag:
        # properly parse the last flag in the file
        if len(flag) == 1 and flag[0].startswith("--"):
            flag += (True,)
        flags.append(flag)

    return flags


# use default.toml data to build config_type_map
def build_config_type_map(data, prefix=None):
    if not isinstance(data, dict):
        return
    for key, value in data.items():
        full_key = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            config_type_map[full_key] = "dict"
            build_config_type_map(value, full_key)
        elif isinstance(value, list):
            config_type_map[full_key] = "list"
        else:
            config_type_map[full_key] = type(value).__name__


# parse FD_AGAVE_FILE lines to build flag_config_map
def build_flag_config_map(lines):
    for i in range(len(lines)):
        line  = lines[i].strip()
        match = pattern1.search(line) # find ADD macro
        if not match:
            continue
        flag   = match.group(1)
        config = match.group(2).strip() if match.group(2) else None
        if not config:
            # in case it is a boolean flag, look for if statements
            # which could also be on the previous line
            if line.startswith("if"):
                match  = pattern2.search(line)
            else:
                match  = pattern2.search(lines[i - 1].strip())
            if match:
                config = match.group(1)
        if not flag or flag in flag_config_map or "firedancer" in flag:
            continue
        if not config or not config.startswith("config"):
            continue
        # remove the `config` prefix
        key = config.split("->")[-1]
        # adjust frankendancer specific flag options
        key = key.replace("frankendancer.", "")
        # if it's a list, remove the [ ] indexing
        if key.find("[") != -1:
            key = key[: key.find("[")]
        flag_config_map[flag] = key


# parse FD_CONFIG_FILE lines to update flag_config_map
def update_flag_config_map(lines):
    for line in lines:
        line = line.strip()
        # look for lines that have multiple config options
        if not line.startswith("CFG_POP1") and not line.startswith("CFG_POPARRAY1"):
            continue
        start = line.find("(")
        end   = line.find(")")
        args  = line[start + 1 : end].split(",")
        arg1, arg2, arg3 = args[0].strip(), args[1].strip(), args[2].strip()
        for key in flag_config_map:
            if arg3 == flag_config_map[key]:
                # we have encountered this flag-config combo, update the config option
                flag_config_map[key] = arg2
    # hardcode the --snapshot-interval-slots flag as it can be used 2 ways
    flag_config_map["--snapshot-interval-slots"] = (
        "snapshots.incremental_snapshot_interval_slots"
    )


# build a dictionary from nested keys
def build_dict_from_key(data, key, data_type, value):
    # key is a . separated nested key
    # value is a tuple
    parts = key.split(".")
    if len(parts) != 1:
        # found nested key
        if parts[0] not in data:
            data[parts[0]] = {}
        build_dict_from_key(data[parts[0]], ".".join(parts[1:]), data_type, value)
        return
    # reached the end of nesting
    if data_type == "list":
        if parts[0] in data:
            data[parts[0]].extend(value)
        else:
            data[parts[0]] = value
    elif data_type == "dict":
        raise SystemExit(f"value cannot be a dict - key={key}, value={value}")
    else:
        # cannot set a value more than once
        if parts[0] in data:
            raise SystemExit(f"value cannot be updated - key={key}, value={value}")
        # only 1 argument for flags that are not `list` or `dict`
        elif len(value) != 1:
            raise SystemExit(
                f"expected 1 value, found {len(value)} - key={key}, value={value}"
            )
        else:
            data[parts[0]] = value[0]


def generate_maps():
    default = toml.load(FD_DEFAULT_TOML)

    with open(FD_AGAVE_FILE, "r") as f:
        agave = f.readlines()

    with open(FD_CONFIG_FILE, "r") as f:
        config = f.readlines()

    build_config_type_map(default)
    build_flag_config_map(agave)
    update_flag_config_map(config)


def main():

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
    )

    arguments = argini()

    logging.info("building maps")
    generate_maps()

    if arguments.detect_mismatch and FLAG_CONFIG_MAP != flag_config_map:
        # shows a mismatch in keys between the hardcoded and parsed maps
        if len(FLAG_CONFIG_MAP) > len(flag_config_map):
            logging.error(
                f"diff keys - {FLAG_CONFIG_MAP.keys()-flag_config_map.keys()}"
            )
        else:
            logging.error(
                f"diff keys - {flag_config_map.keys()-FLAG_CONFIG_MAP.keys()}"
            )
        # shows all key-value pairs in the parsed map
        if flag_config_map.keys() == FLAG_CONFIG_MAP.keys():
            logging.error("parsed map values")
            pprint(flag_config_map)
        raise SystemExit("detected difference between config maps")

    if not os.path.exists(arguments.file_name):
        raise SystemExit(f"file {arguments.file_name} does not exist")

    logging.info("parsing commandline")
    if arguments.systemd:
        cmdline_str = parse_systemd_cmdline(arguments.file_name)
    else:
        with open(arguments.file_name, "r") as f:
            cmdline_str = f.read()

    flags_to_parse = parse_cmdline(cmdline_str)

    # markers for full and incremental snapshot interval setting
    seen_full = False
    seen_incr = False

    data = {}
    for (flag, *args) in flags_to_parse:
        # flags that we do not support
        if flag not in FLAG_CONFIG_MAP:
            logging.warning(f"cannot convert flag {flag}")
            continue
        # making sure there are not too many args
        if (
            config_type_map[FLAG_CONFIG_MAP[flag]] not in ["dict", "list"]
            and len(args) != 1
        ):
            raise SystemExit(f"invalid arguments {args} for flag {flag}")
        # FD inverts flags with `--no` and `--disable`
        if config_type_map[FLAG_CONFIG_MAP[flag]] == "bool":
            if flag.startswith("--no") or flag.startswith("--disable"):
                args[0] = False
        # parse argument types
        if config_type_map[FLAG_CONFIG_MAP[flag]] == "int":
            args[0] = int(args[0])
        elif config_type_map[FLAG_CONFIG_MAP[flag]] == "float":
            args[0] = float(args[0])
        if flag == "--full-snapshot-interval-slots":
            seen_full = True
        if flag == "--snapshot-interval-slots":
            seen_incr = True
        build_dict_from_key(
            data, FLAG_CONFIG_MAP[flag], config_type_map[FLAG_CONFIG_MAP[flag]], args
        )

    # --snapshot-interval-slots sets the full snapshot interval if --full-snapshot-interval-slots is not specified
    if seen_incr and not seen_full:
        data["snapshots"]["full_snapshot_interval_slots"] = data["snapshots"][
            "incremental_snapshot_interval_slots"
        ]
        data["snapshots"].pop("incremental_snapshot_interval_slots")

    logging.info("generating toml")
    if arguments.output_file:
        if os.path.exists(arguments.output_file):
            raise SystemExit(f"file {arguments.output_file} already exists")
        out = open(arguments.output_file, "w")
    else:
        out = sys.stdout

    print("# Generated Firedancer TOML Config", file=out)
    print(toml.dumps(data), file=out)

    if arguments.output_file:
        out.close()

    logging.info("done")


def argini():
    parser = argparse.ArgumentParser(
        prog="toml-gen.py",
        description="Convert Agave commandline to Firedancer TOML",
        add_help=True,
    )

    parser.add_argument(
        "--systemd",
        "-s",
        action="store_true",
        help="Specify this if the file is a systemd unit file",
    )
    parser.add_argument(
        "--file-name",
        "-f",
        required=True,
        type=str,
        help="Path to file containing Agave commandline",
    )
    parser.add_argument(
        "--output-file",
        "-o",
        default="",
        help="Specify the path to the TOML file to create",
    )
    parser.add_argument(
        "--detect-mismatch",
        "-d",
        action="store_true",
        help="Exit if there is a discrepancy between hardcoded and parsed flag maps",
    )

    return parser.parse_args()


if __name__ == "__main__":
    main()
