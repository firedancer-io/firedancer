import argparse
import json
from typing import Any, Callable, Dict, List, Optional

import pytest
import requests
from deepdiff import DeepDiff
from deepdiff.helper import COLORED_COMPACT_VIEW

### Formatted with Black ###

SERVER1_URL = "http://localhost:8899"
SERVER2_URL = "http://solana-testnet-rpc.jumpisolated.com:8899"


class RPCTester:
    def __init__(self, server1_url: str, server2_url: str):
        self.server1_url = server1_url
        self.server2_url = server2_url
        self.session = requests.Session()

    def make_rpc_call(
        self, url: str, payload: Dict[str, Any], timeout: int = 10
    ) -> Dict[str, Any]:
        """Make an RPC call to the specified server"""
        headers = {"Content-Type": "application/json"}
        try:
            response = self.session.post(
                url, json=payload, headers=headers, timeout=timeout
            )
            response.raise_for_status()
            return {"msg": response.json(), "status": response.status_code}
        except requests.exceptions.RequestException as e:
            response = getattr(e, "response", None)
            if response is not None:
                return {"msg": response.text, "status": response.status_code}
            return {"msg": str(e), "status": None}

    def compare_responses(
        self,
        resp1: Dict[str, Any],
        resp2: Dict[str, Any],
        exclude_paths: Optional[List[str]] = None,
        prediff: Optional[Callable] = None,
    ) -> tuple[bool, Optional[DeepDiff]]:
        """
        Compare two JSON responses

        Args:
            resp1: Response from server 1
            resp2: Response from server 2
            exclude_paths: List of paths to ignore during comparison (e.g., timestamps)

        Returns:
            Tuple of (is_equal, diff_object)
        """
        if prediff is not None:
            resp1, resp2 = prediff(resp1, resp2)

        diff = DeepDiff(
            resp1,
            resp2,
            exclude_paths=exclude_paths,
            ignore_order=False,
            significant_digits=2,
            # Ignore errors where we explicitly don't support
            exclude_obj_callback=lambda obj, path: (
                (isinstance(obj, str) and obj.startswith("Firedancer Error"))
                or obj == -32065
                or "\'tpu\'" in path or "\'tpuForwards\'" in path
            ),
            view=COLORED_COMPACT_VIEW,
        )

        return (len(diff) == 0, diff if len(diff) > 0 else None)

    def test_rpc_method(
        self,
        payload: Dict[str, Any],
        exclude_paths: Optional[List[str]] = None,
        prediff: Optional[Callable] = None,
        description: str = "",
    ) -> bool:
        """
        Test a single RPC method against both servers

        Args:
            payload: The JSON-RPC request payload
            ignore_keys: Keys to ignore when comparing responses
            description: Test description for logging

        Returns:
            True if responses match, False otherwise
        """

        print(f"-- {description} --")

        resp1 = self.make_rpc_call(self.server1_url, payload)
        resp2 = self.make_rpc_call(self.server2_url, payload)

        # Compare responses
        is_equal, diff = self.compare_responses(resp1, resp2, exclude_paths, prediff)

        if not is_equal:
            print(f"\n{'=' * 60}")
            print(f"Test: {description}")
            print(f"{'=' * 60}")
            print(f"Payload: {json.dumps(payload, indent=2)}")

            print(diff)

            print("\n✗ FAIL: Responses differ")

        return is_equal


def run_test_suite(
    tester: RPCTester, test_cases: List[Dict[str, Any]], only_first: int
):
    """
    Run a batch of test cases

    Args:
        tester: tester object
        test_cases: List of test case dictionaries with keys:
            - payload: The RPC request
            - exclude_paths: Optional paths to ignore
            - description: Optional test description
            - prediff: function to preprocess response before diff
        only_first: quit test suite early after first failing only_first tests
    """
    results = []
    failed_cnt = 0

    for i, test_case in enumerate(test_cases, 1):
        payload = test_case["payload"]
        description = test_case.get("description", f"Test case {i}")
        exclude_paths = test_case.get("exclude_paths")
        prediff = test_case.get("prediff")

        result = tester.test_rpc_method(payload, exclude_paths, prediff, description)
        results.append({"test": description, "passed": result})

        failed_cnt += int(not result)

        if only_first is not None and failed_cnt >= only_first:
            break

    print(f"\n{'=' * 60}")
    print("TEST SUMMARY")
    print(f"{'=' * 60}")
    passed = sum(1 for r in results if r["passed"])
    print(
        f"<# passed>/<# failed>/<# tests available> {passed}/{len(results) - passed}/{len(test_cases)}"
    )

    return results


ALL_TYPES = [
    0,
    1,
    0.0,
    1.0,
    1.1,
    -1,
    -1.0,
    -1.1,
    9999999999999,
    None,
    True,
    "abc",
    "",
    [],
    [[]],
    [[[]]],
    {},
    [1],
    {"1": 1},
    1e16,
]

def get_rpc_result(url: str, method: str, params=None):
    payload = {"jsonrpc": "2.0", "id": 0, "method": method}
    if params is not None:
        payload["params"] = params

    response = requests.post(
        url, json=payload, headers={"Content-Type": "application/json"}, timeout=10
    )
    response.raise_for_status()
    msg = response.json()
    if not isinstance(msg, dict) or "result" not in msg:
        raise RuntimeError(f"failed to fetch {method} from {url}: {msg}")
    return msg["result"]


def get_current_slot_epoch():
    params = [{"commitment": "finalized"}]
    epoch_info1 = get_rpc_result(SERVER1_URL, "getEpochInfo", params)
    epoch_info2 = get_rpc_result(SERVER2_URL, "getEpochInfo", params)

    slot1 = int(epoch_info1["absoluteSlot"])
    slot2 = int(epoch_info2["absoluteSlot"])
    epoch1 = int(epoch_info1["epoch"])
    epoch2 = int(epoch_info2["epoch"])
    slot = min(slot1, slot2)
    epoch = min(epoch1, epoch2)

    print(
        f"Live slot/epoch: server1={slot1}/{epoch1}, "
        f"server2={slot2}/{epoch2}, using={slot}/{epoch}"
    )

    return {"slot": slot, "epoch": epoch}

# okay to perform RPC tests on import since this is a test file
CURRENT_SLOT_EPOCH = get_current_slot_epoch()
CURRENT_SLOT = CURRENT_SLOT_EPOCH["slot"]
CURRENT_EPOCH = CURRENT_SLOT_EPOCH["epoch"]


MISC = [
    {
        "payload": {
            "JsOnRpC": "2.0",
            "id": 1,
            "method": "getHealth",
        },
        "description": f"misc caps-in-field",
    },
    *[
        {
            "payload": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": e,
                "params": [],
            },
            "description": f"misc method={e}",
            "exclude_paths": [
                "root['msg']['result']['context']['slot']"
            ],  # Checked manually. Excluded since "finalized" slot can be different across validators
        }
        for e in ALL_TYPES
    ],
    *[
        {
            "payload": (
                ({} if missing_jsonrpc else {"jsonrpc": "2.0"})
                | ({} if missing_id else {"id": 1})
                | ({} if missing_method else {"method": "getAccountInfo"})
                | (
                    {}
                    if missing_params
                    else {"params": ["11111111111111111111111111111111"]}
                )
                | ({} if missing_unknown else {"unknown": 1})
            ),
            "description": f"misc missing_jsonrpc={missing_jsonrpc} missing_id={missing_id} missing_method={missing_method} missing_params={missing_params} missing_unknown={missing_unknown}",
            "exclude_paths": ["root['msg']['result']['context']['slot']"],
        }
        for missing_jsonrpc in [True, False]
        for missing_id in [True, False]
        for missing_method in [True, False]
        for missing_params in [True, False]
        for missing_unknown in [True, False]
    ],
    *[{"payload": e, "description": f"misc irregular payload"} for e in ALL_TYPES],
]
GET_HEALTH = [
    {
        "payload": {"jsonrpc": "2.0", "id": 1, "method": "getHealth"},
        "description": "getHealth success",
    },
    *[
        {
            "payload": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getHealth",
                "extra_field": e,
            },
            "description": f"getHealth extra_field={json.dumps(e)}",
        }
        for e in ALL_TYPES
    ],
    *[
        {
            "payload": {"jsonrpc": "2.0", "method": "getHealth", "extra_field": e},
            "description": f"getHealth id=undefined extra_field={json.dumps(e)}",
        }
        for e in ALL_TYPES
    ],
    *[
        {
            "payload": {
                "id": 1,
                "method": "getHealth",
                "extra_field": e,
            },
            "description": f"getHealth jsonrpc=undefined extra_field={json.dumps(e)}",
        }
        for e in ALL_TYPES
    ],
    *[
        {
            "payload": {
                "jsonrpc": e,
                "id": 1,
                "method": "getHealth",
            },
            "description": f"getHealth jsonrpc={json.dumps(e)}",
        }
        for e in [*ALL_TYPES, "1.0", "2.0", "3.0"]
    ],
    *[
        {
            "payload": {
                "jsonrpc": "2.0",
                "id": e,
                "method": "getHealth",
            },
            "description": f"getHealth id={json.dumps(e)}",
        }
        for e in ALL_TYPES
    ],
    *[
        {
            "payload": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getHealth",
                "params": e,
            },
            "description": f"getHealth params={json.dumps(e)}",
            "exclude_paths": ["root['msg']['error']['data']"],
        }
        for e in [*ALL_TYPES, *[[_e] for _e in ALL_TYPES]]
    ],
]

GET_VERSION = [
    {
        "payload": {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getVersion",
        },
        "description": f"getVersion success",
        "exclude_paths": [
            "root['msg']['result']"
        ],  # actual version/feature set will be different
    },
    *[
        {
            "payload": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getVersion",
                "extra_field": e,
            },
            "description": f"getVersion extra_field={json.dumps(e)}",
        }
        for e in ALL_TYPES
    ],
    *[
        {
            "payload": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getVersion",
                "params": e,
            },
            "description": f"getVersion params={json.dumps(e)}",
            "exclude_paths": ["root['msg']['error']['data']", "root['msg']['result']"],
        }
        for e in [*ALL_TYPES, *[[_e] for _e in ALL_TYPES]]
    ],
]

GET_IDENTITY = [
    {
        "payload": {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getIdentity",
        },
        "description": f"getIdentity success",
        "exclude_paths": ["root['msg']['result']['identity']"],
    },
    *[
        {
            "payload": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getIdentity",
                "extra_field": e,
            },
            "description": f"getIdentity extra_field={json.dumps(e)}",
            "exclude_paths": ["root['msg']['result']['identity']"],
        }
        for e in ALL_TYPES
    ],
    *[
        {
            "payload": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getIdentity",
                "params": e,
            },
            "description": f"getIdentity params={json.dumps(e)}",
            "exclude_paths": [
                "root['msg']['error']['data']",
                "root['msg']['result']['identity']",
            ],
        }
        for e in [*ALL_TYPES, *[[_e] for _e in ALL_TYPES]]
    ],
]

GET_ACCOUNT_INFO = [
    *[
        {
            "payload": {
                "jsonrpc": "2.0",
                "id": 0,
                "method": "getAccountInfo",
                "params": [
                    e,
                    {
                        "encoding": "base64",
                        "commitment": "finalized",
                        "data_slice": None,
                        "minContextSlot": None,
                    },
                ],
            },
            "description": f"getAccountInfo account=",
            "exclude_paths": ["root['msg']['result']['context']['slot']"],
        }
        for e in [
            "SysvarRent111111111111111111111111111111111",
        ]
    ],
    *[
        {
            "payload": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getAccountInfo",
                "params": e,
            },
            "description": f"getAccountInfo params={json.dumps(e)}",
            "exclude_paths": ["root['msg']['error']['data']"],
        }
        for e in [
            *ALL_TYPES,
            *[[_e] for _e in ALL_TYPES],
            ["wrong-size"],
            ["???????????????????????????????????????????"],
            ["4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofLRda4"],
        ]
    ],
    *[
        {
            "payload": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getAccountInfo",
                "params": [
                    "11111111111111111111111111111111",  # system program
                    {
                        "commitment": e,
                    },
                ],
            },
            "description": f"getAccountInfo params[2]['commitment']={e}",
            "exclude_paths": [
                "root['msg']['result']['context']['slot']"
            ],  # Checked manually. Excluded since "finalized" slot can be different across validators
        }
        for e in [*ALL_TYPES, "finalized", "confirmed", "processed"]
    ],
    *[
        {
            "payload": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getAccountInfo",
                "params": [
                    "11111111111111111111111111111111",  # system program
                    {
                        "encoding": e,
                    },
                ],
            },
            "description": f"getAccountInfo params[2]['encoding']={e}",
            "exclude_paths": [
                "root['msg']['result']['context']['slot']"
            ],  # Checked manually. Excluded since "finalized" slot can be different across validators
        }
        ###
        ### jsonParsed doesn't match on purpose
        ### base64+zstd doesn't match because different compressed payloads can decompress to the same data
        ###
        for e in [
            *ALL_TYPES,
            *[{"base58": _e} for _e in ALL_TYPES],
            *[{"base64": _e} for _e in ALL_TYPES],
            *[{"binary": _e} for _e in ALL_TYPES],
            {"base58": 1, "unknown": 2},
            "base58",
            "base64",
            "binary",
        ]
    ],
    *[
        {
            "payload": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getAccountInfo",
                "params": [
                    "11111111111111111111111111111111",  # system program
                    {
                        "encoding": "base64",
                        "dataSlice": e,
                    },
                ],
            },
            "description": f"getAccountInfo params[2]['dataSlice']={e}",
            "exclude_paths": [
                "root['msg']['result']['context']['slot']"
            ],  # Checked manually. Excluded since "finalized" slot can be different across validators
        }
        for e in [
            *ALL_TYPES,
            [32, 7],
            [7, 32],
            [7, 3],
            [7],
            *[[7, _e] for _e in ALL_TYPES],
            *[[_e, 3] for _e in ALL_TYPES],
            *[{"length": _e} for _e in ALL_TYPES],
            *[{"offset": _e} for _e in ALL_TYPES],
            *[{"length": _e, "offset": 0} for _e in ALL_TYPES],
            *[{"length": 0, "offset": _e} for _e in ALL_TYPES],
            {"unknown": 1},
            {"length": 1, "offset": 0},
        ]
    ],
    *[
        {
            "payload": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getAccountInfo",
                "params": [
                    "11111111111111111111111111111111",  # system program
                    {
                        "encoding": "base64",
                        "minContextSlot": e,
                    },
                ],
            },
            "description": f"getAccountInfo params[2]['minContextSlot']={e}",
            "exclude_paths": [
                "root['msg']['result']['context']['slot']",
                "root['msg']['error']['data']['contextSlot']",
            ],  # Checked manually. Excluded since "finalized" slot can be different across validators
        }
        for e in ALL_TYPES
    ],
]

GET_BALANCE = [
    {
        "payload": {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "getBalance",
            "params": [
                "SysvarRent111111111111111111111111111111111",
                {
                    "commitment": "finalized",
                    "minContextSlot": None,
                },
            ],
        },
        "description": f"getBalance account=SysvarRent111111111111111111111111111111111",
        "exclude_paths": ["root['msg']['result']['context']['slot']"],
    },
    *[
        {
            "payload": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getBalance",
                "params": e,
            },
            "description": f"getBalance params={json.dumps(e)}",
            "exclude_paths": ["root['msg']['error']['data']"],
        }
        for e in [
            *ALL_TYPES,
            *[[_e] for _e in ALL_TYPES],
            ["wrong-size"],
            ["???????????????????????????????????????????"],
            ["4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofLRda4"],
        ]
    ],
]

GET_HEIGHT = [
    {
        "payload": {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "getBlockHeight",
            "params": [
                {
                    "Commitment": "finalized",
                    "minContextSlot": None,
                }
            ],
        },
        "description": f"getBlockHeight success",
        "exclude_paths": ["root['msg']['result']"],  # Actual block height will differ
    },
    *[
        {
            "payload": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getBlockHeight",
                "params": e,
            },
            "description": f"getBlockHeight params={json.dumps(e)}",
            "exclude_paths": [
                "root['msg']['result']"
            ],  # Actual block height will differ
        }
        for e in [
            *ALL_TYPES,
            *[[_e] for _e in ALL_TYPES],
        ]
    ],
]

GET_GENESIS_HASH = [
    {
        "payload": {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "getGenesisHash",
        },
        "description": f"getGenesisHash success",
    },
    *[
        {
            "payload": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getGenesisHash",
                "params": e,
            },
            "description": f"getGenesisHash params={json.dumps(e)}",
            "exclude_paths": ["root['msg']['error']['data']"],
        }
        for e in [
            *ALL_TYPES,
            *[[_e] for _e in ALL_TYPES],
        ]
    ],
]

GET_INFLATION_GOVERNOR = [
    {
        "payload": {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "getInflationGovernor",
        },
        "description": f"getInflationGovernor success",
    },
    *[
        {
            "payload": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getInflationGovernor",
                "params": e,
            },
            "description": f"getInflationGovernor params={json.dumps(e)}",
        }
        for e in [
            e for e in ALL_TYPES if not isinstance(e, list)
        ]  # Positional config params are not supported
    ],
]

GET_LATEST_BLOCKHASH = [
    {
        "payload": {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "getLatestBlockhash",
            "params": [{"commitment": "processed"}],
            "exclude_paths": [
                "root['msg']['result']['context']['slot']",
                "root['msg']['result']['value']",
            ],  # due to race
        },
        "description": f"getLatestBlockhash success",
    },
]

GET_MINIMUM_BALANCE_FOR_RENT_EXEMPTION = [
    {
        "payload": {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "getMinimumBalanceForRentExemption",
            "params": [12345],
        },
        "description": f"getMinimumBalanceForRentExemption success",
    },
    {
        "payload": {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "getMinimumBalanceForRentExemption",
            "params": [10 * 1024 * 1024 + 1],
        },
        "description": "getMinimumBalanceForRentExemption rejects oversized account",
    },
]

GET_SLOT = [
    {
        "payload": {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "getSlot",
        },
        "description": f"getSlot success",
        "exclude_paths": [
            "root['msg']['result']",
        ],  # due to race
    },
]

GET_SLOT_LEADER = [
    {
        "payload": {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "getSlotLeader",
        },
        "description": f"getSlotLeader success",
        "exclude_paths": [
            "root['msg']['result']"
        ],  # leader identity depends on the (racy) finalized slot
    },
    *[
        {
            "payload": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getSlotLeader",
                "params": [{"commitment": e}],
            },
            "description": f"getSlotLeader params[0]['commitment']={json.dumps(e)}",
            "exclude_paths": ["root['msg']['result']"],
        }
        for e in [*ALL_TYPES, "finalized", "confirmed", "processed"]
    ],
    *[
        {
            "payload": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getSlotLeader",
                "params": [{"minContextSlot": e}],
            },
            "description": f"getSlotLeader params[0]['minContextSlot']={json.dumps(e)}",
            "exclude_paths": [
                "root['msg']['result']",
                "root['msg']['error']['data']['contextSlot']",
            ],
        }
        for e in ALL_TYPES
    ],
    *[
        {
            "payload": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getSlotLeader",
                "params": e,
            },
            "description": f"getSlotLeader params={json.dumps(e)}",
            "exclude_paths": [
                "root['msg']['error']['data']",
                "root['msg']['result']",
            ],
        }
        for e in [*ALL_TYPES, *[[_e] for _e in ALL_TYPES]]
    ],
]

GET_SLOT_LEADERS = [
    {
        "payload": {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "getSlotLeaders",
            "params": [0, 0],
        },
        "description": f"getSlotLeaders limit=0 (empty)",
    },  # limit=0 returns [] without consulting the schedule -> deterministic
    {
        "payload": {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "getSlotLeaders",
            "params": [0, 5001],
        },
        "description": f"getSlotLeaders limit>max",
    },  # -> "Invalid limit; max 5000" on both -> deterministic
    {
        "payload": {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "getSlotLeaders",
            "params": [18446744073709551616, 0],
        },
        "description": f"getSlotLeaders startSlot overflows u64",
    },
    *[
        {
            "payload": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getSlotLeaders",
                "params": [e, 10],
            },
            "description": f"getSlotLeaders params[0] (startSlot)={json.dumps(e)}",
            "exclude_paths": [
                "root['msg']['error']['data']",
                "root['msg']['result']",
            ],
        }
        for e in ALL_TYPES
    ],
    *[
        {
            "payload": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getSlotLeaders",
                "params": [0, e],
            },
            "description": f"getSlotLeaders params[1] (limit)={json.dumps(e)}",
            "exclude_paths": [
                "root['msg']['error']['data']",
                "root['msg']['result']",
            ],
        }
        for e in ALL_TYPES
    ],
    *[
        {
            "payload": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getSlotLeaders",
                "params": e,
            },
            "description": f"getSlotLeaders params={json.dumps(e)}",
            "exclude_paths": [
                "root['msg']['error']['data']",
                "root['msg']['result']",
            ],
        }
        for e in ALL_TYPES
    ],
]

GET_LEADER_SCHEDULE = [
    {
        "payload": {"jsonrpc": "2.0", "id": 0, "method": "getLeaderSchedule"},
        "description": "getLeaderSchedule no params (current epoch)",
        # The two reference clusters have different schedules -> only the
        # response shape is comparable.
        "exclude_paths": ["root['msg']['result']"],
    },
    {
        "payload": {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "getLeaderSchedule",
            "params": [None],
        },
        "description": "getLeaderSchedule params=[null] (current epoch)",
        "exclude_paths": ["root['msg']['result']"],
    },
    {
        "payload": {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "getLeaderSchedule",
            "params": [CURRENT_SLOT],
        },
        "description": f"getLeaderSchedule params=[{CURRENT_SLOT}]",
        "exclude_paths": ["root['msg']['result']"],
    },
    {
        "payload": {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getLeaderSchedule",
            "params": [{"identity": "11111111111111111111111111111111"}, 1],
        },
        "description": "getLeaderSchedule wrapper config with invalid second config",
    },
    *[
        {
            "payload": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getLeaderSchedule",
                "params": [None, {"commitment": e}],
            },
            "description": f"getLeaderSchedule commitment={json.dumps(e)}",
            "exclude_paths": [
                "root['msg']['result']",
                "root['msg']['error']['data']",
            ],
        }
        for e in [*ALL_TYPES, "finalized", "confirmed", "processed"]
    ],
    *[
        {
            "payload": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getLeaderSchedule",
                "params": [None, {"identity": e}],
            },
            "description": f"getLeaderSchedule identity={json.dumps(e)}",
            "exclude_paths": [
                "root['msg']['result']",
                "root['msg']['error']['data']",
            ],
        }
        for e in ALL_TYPES
    ],
    *[
        {
            "payload": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getLeaderSchedule",
                "params": [e],
            },
            "description": f"getLeaderSchedule params[0]={json.dumps(e)}",
            "exclude_paths": [
                "root['msg']['result']",
                "root['msg']['error']['data']",
            ],
        }
        for e in ALL_TYPES
    ],
    *[
        {
            "payload": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getLeaderSchedule",
                "params": e,
            },
            "description": f"getLeaderSchedule params={json.dumps(e)}",
            "exclude_paths": [
                "root['msg']['result']",
                "root['msg']['error']['data']",
            ],
        }
        for e in ALL_TYPES
    ],
    *[
        {
            "payload": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getLeaderSchedule",
                "params": [{"identity": e}],
            },
            "description": f"getLeaderSchedule wrapper identity={json.dumps(e)}",
            "exclude_paths": [
                "root['msg']['result']",
                "root['msg']['error']['data']",
            ],
        }
        for e in ALL_TYPES
    ],
    *[
        {
            "payload": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getLeaderSchedule",
                "params": [{"identity": e}],
            },
            "description": f"getLeaderSchedule wrapper identity string={json.dumps(e)}",
            "exclude_paths": [
                "root['msg']['result']",
                "root['msg']['error']['data']",
            ],
        }
        for e in [
            "0O0O0O0O0O0O0O0O0O0O0O0O0O0O0O0O",
            "deaddeaddeaddeaddeaddeaddeaddeaddeaddeaddead",
        ]
    ],
    *[
        {
            "payload": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getLeaderSchedule",
                "params": [None, e],
            },
            "description": f"getLeaderSchedule params=[null, {json.dumps(e)}]",
            "exclude_paths": [
                "root['msg']['result']",
                "root['msg']['error']['data']",
            ],
        }
        for e in [0, 1, 1.1, -1, True, "abc", "", [1], []]
    ],
]

GET_CURRENT_SLOT_EPOCH = [
    {
        "payload": {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "getSlotLeaders",
            "params": [CURRENT_SLOT, 1],
        },
        "description": f"getSlotLeaders live startSlot={CURRENT_SLOT} limit=1",
    },
    {
        "payload": {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "getAccountInfo",
            "params": [
                "11111111111111111111111111111111",
                {
                    "encoding": "base64",
                    "commitment": "finalized",
                    "minContextSlot": CURRENT_SLOT,
                },
            ],
        },
        "description": f"getAccountInfo live minContextSlot={CURRENT_SLOT}",
        "exclude_paths": ["root['msg']['result']['context']['slot']"],
    },
    {
        "payload": {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "getBalance",
            "params": [
                "SysvarRent111111111111111111111111111111111",
                {"commitment": "finalized", "minContextSlot": CURRENT_SLOT},
            ],
        },
        "description": f"getBalance live minContextSlot={CURRENT_SLOT}",
        "exclude_paths": ["root['msg']['result']['context']['slot']"],
    },
    {
        "payload": {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "getBlockHeight",
            "params": [{"commitment": "finalized", "minContextSlot": CURRENT_SLOT}],
        },
        "description": f"getBlockHeight live minContextSlot={CURRENT_SLOT}",
        "exclude_paths": ["root['msg']['result']"],
    },
    {
        "payload": {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "getEpochInfo",
            "params": [{"commitment": "finalized", "minContextSlot": CURRENT_SLOT}],
        },
        "description": f"getEpochInfo live epoch={CURRENT_EPOCH} minContextSlot={CURRENT_SLOT}",
        "exclude_paths": [
            "root['msg']['result']['absoluteSlot']",
            "root['msg']['result']['blockHeight']",
            "root['msg']['result']['slotIndex']",
            "root['msg']['result']['transactionCount']",
        ],
    },
    {
        "payload": {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "getLatestBlockhash",
            "params": [{"commitment": "finalized", "minContextSlot": CURRENT_SLOT}],
        },
        "description": f"getLatestBlockhash live minContextSlot={CURRENT_SLOT}",
        "exclude_paths": [
            "root['msg']['result']['context']['slot']",
            "root['msg']['result']['value']",
        ],
    },
    {
        "payload": {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "getSlot",
            "params": [{"commitment": "finalized", "minContextSlot": CURRENT_SLOT}],
        },
        "description": f"getSlot live minContextSlot={CURRENT_SLOT}",
        "exclude_paths": ["root['msg']['result']"],
    },
    {
        "payload": {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "getSlotLeader",
            "params": [{"commitment": "finalized", "minContextSlot": CURRENT_SLOT}],
        },
        "description": f"getSlotLeader live minContextSlot={CURRENT_SLOT}",
        "exclude_paths": ["root['msg']['result']"],
    },
    {
        "payload": {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "getTransactionCount",
            "params": [{"commitment": "finalized", "minContextSlot": CURRENT_SLOT}],
        },
        "description": f"getTransactionCount live minContextSlot={CURRENT_SLOT}",
        "exclude_paths": ["root['msg']['result']"],
    },
    {
        "payload": {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "getMultipleAccounts",
            "params": [
                [
                    "11111111111111111111111111111111",
                    "SysvarRent111111111111111111111111111111111",
                ],
                {
                    "encoding": "base64",
                    "commitment": "finalized",
                    "minContextSlot": CURRENT_SLOT,
                },
            ],
        },
        "description": f"getMultipleAccounts live minContextSlot={CURRENT_SLOT}",
        "exclude_paths": ["root['msg']['result']['context']['slot']"],
    },
]

GET_TRANSACTION_COUNT = [
    {
        "payload": {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "getTransactionCount",
        },
        "description": f"getTransactionCount success",
        "exclude_paths": [
            "root['msg']['result']",
        ],  # due to race
    },
]


def get_cluster_nodes_prediff(resp1, resp2):
    if any(
        not isinstance(resp.get("msg", {}).get("result", {}), list)
        for resp in (resp1, resp2)
    ):
        return resp1, resp2

    for resp in (resp1, resp2):
        list_of_dicts = resp["msg"]["result"]
        resp["msg"]["result"] = {n.get("pubkey", None): n for n in list_of_dicts}

    # Only compare intersection, since nodes will have different gossip tables
    result1 = resp1["msg"]["result"]
    result2 = resp2["msg"]["result"]
    resp1["msg"]["result"] = {k: v for k, v in result1.items() if k in result2}
    resp2["msg"]["result"] = {k: v for k, v in result2.items() if k in result1}
    return (resp1, resp2)


GET_CLUSTER_NODES = [
    {
        "payload": {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "getClusterNodes",
        },
        "description": f"getClusterNodes success",
        "prediff": get_cluster_nodes_prediff,
    },
]

GET_EPOCH_INFO = [
    {
        "payload": {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "getEpochInfo",
        },
        "description": f"getEpochInfo success",
        "exclude_paths": [
            "root['msg']['result']['absoluteSlot']",
            "root['msg']['result']['blockHeight']",
            "root['msg']['result']['slotIndex']",
            "root['msg']['result']['transactionCount']",
        ],
    },
]

GET_MULTIPLE_ACCOUNTS = [
    {
        "payload": {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "getMultipleAccounts",
            "params": [
                [
                    "11111111111111111111111111111111",
                    "SysvarRent111111111111111111111111111111111",
                ],
                {"encoding": "base64", "commitment": "finalized"},
            ],
        },
        "description": "getMultipleAccounts success two accounts",
        "exclude_paths": ["root['msg']['result']['context']['slot']"],
    },
    *[
        {
            "payload": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getMultipleAccounts",
                "params": [e],
            },
            "description": f"getMultipleAccounts params[0]={json.dumps(e)}",
            "exclude_paths": [
                "root['msg']['error']['data']",
                "root['msg']['result']['context']['slot']",
            ],
        }
        for e in ALL_TYPES
    ],
    *[
        {
            "payload": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getMultipleAccounts",
                "params": [[e]],
            },
            "description": f"getMultipleAccounts params[0][0]={json.dumps(e)}",
            "exclude_paths": [
                "root['msg']['error']['data']",
                "root['msg']['result']['context']['slot']",
            ],
        }
        for e in ALL_TYPES
    ],
    {
        "payload": {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getMultipleAccounts",
            "params": [[]],
        },
        "description": "getMultipleAccounts empty array",
        "exclude_paths": ["root['msg']['result']['context']['slot']"],
    },
    {
        "payload": {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getMultipleAccounts",
            "params": [
                [
                    "11111111111111111111111111111111",
                    "deaddeaddeaddeaddeaddeaddeaddeaddeaddeaddead",
                    "SysvarRent111111111111111111111111111111111",
                ],
                {"encoding": "base64", "commitment": "finalized"},
            ],
        },
        "description": "getMultipleAccounts mixed existing and missing",
        "exclude_paths": ["root['msg']['result']['context']['slot']"],
    },
    {
        "payload": {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getMultipleAccounts",
            "params": [
                [
                    "deaddeaddeaddeaddeaddeaddeaddeaddeaddeaddead",
                    "beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef",
                ],
                {"encoding": "base64", "commitment": "finalized"},
            ],
        },
        "description": "getMultipleAccounts all missing",
        "exclude_paths": ["root['msg']['result']['context']['slot']"],
    },
]

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process some data")
    parser.add_argument(
        "--only-first", type=int, default=None, help="Only process the first item"
    )
    args = parser.parse_args()

    tester = RPCTester(
        server1_url=SERVER1_URL,
        server2_url=SERVER2_URL,
    )

    test_suite = [
        *MISC,
        *GET_HEALTH,
        *GET_VERSION,
        *GET_IDENTITY,
        *GET_ACCOUNT_INFO,
        *GET_BALANCE,
        *GET_HEIGHT,
        *GET_GENESIS_HASH,
        *GET_INFLATION_GOVERNOR,
        *GET_LATEST_BLOCKHASH,
        *GET_MINIMUM_BALANCE_FOR_RENT_EXEMPTION,
        *GET_SLOT,
        *GET_SLOT_LEADER,
        *GET_SLOT_LEADERS,
        *GET_LEADER_SCHEDULE,
        *GET_CURRENT_SLOT_EPOCH,
        *GET_TRANSACTION_COUNT,
        *GET_CLUSTER_NODES,
        *GET_EPOCH_INFO,
        *GET_MULTIPLE_ACCOUNTS,
    ]

    run_test_suite(tester, test_suite, args.only_first)
