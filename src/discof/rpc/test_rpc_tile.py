import requests
import json
from typing import Dict, Any, List, Optional
from deepdiff import DeepDiff
import pytest
import argparse

### Formatted with Black ###


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
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": response.text, "status": response.status_code}

    def compare_responses(
        self,
        resp1: Dict[str, Any],
        resp2: Dict[str, Any],
        exclude_paths: Optional[List[str]] = None,
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
        diff = DeepDiff(resp1, resp2, exclude_paths=exclude_paths, ignore_order=False)

        return (len(diff) == 0, diff if len(diff) > 0 else None)

    def test_rpc_method(
        self,
        payload: Dict[str, Any],
        exclude_paths: Optional[List[str]] = None,
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

        print(f"-- {description or payload.get('method', 'Unknown')} --")

        resp1 = self.make_rpc_call(self.server1_url, payload)
        resp2 = self.make_rpc_call(self.server2_url, payload)

        # Compare responses
        is_equal, diff = self.compare_responses(resp1, resp2, exclude_paths)

        if not is_equal:
            print(f"\n{'='*60}")
            print(f"Test: {description or payload.get('method', 'Unknown')}")
            print(f"{'='*60}")
            print(f"Payload: {json.dumps(payload, indent=2)}")

            print(f"\n{self.server1_url} Response:\n{json.dumps(resp1, indent=2)}")
            print(f"\n{self.server2_url} Response:\n{json.dumps(resp2, indent=2)}")

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
        only_first: quit test suite early after first failing only_first tests
    """
    results = []
    failed_cnt = 0

    for i, test_case in enumerate(test_cases, 1):
        payload = test_case["payload"]
        exclude_paths = test_case.get("exclude_paths")
        description = test_case.get("description", f"Test case {i}")

        result = tester.test_rpc_method(payload, exclude_paths, description)
        results.append({"test": description, "passed": result})

        failed_cnt += int(not result)

        if only_first is not None and failed_cnt >= only_first:
            break

    print(f"\n{'='*60}")
    print("TEST SUMMARY")
    print(f"{'='*60}")
    passed = sum(1 for r in results if r["passed"])
    print(f"<# passed>/<# failed>/<# tests available> {passed}/{len(results)-passed}/{len(test_cases)}")

    return results


ALL_TYPES = [
    1,
    1.1,
    -1,
    -1.1,
    9999999999999,
    None,
    True,
    "abc",
    "",
    [],
    {},
    [1],
    {"1": 1},
]

MISC = [
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
                "root['result']['context']['slot']"
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
            "exclude_paths": ["root['result']['context']['slot']"],
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
            "exclude_paths": ["root['error']['data']"],
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
            "root['result']"
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
            "exclude_paths": ["root['error']['data']", "root['result']"],
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
        "exclude_paths": ["root['result']['identity']"],
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
            "exclude_paths": ["root['result']['identity']"],
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
            "description": f"getVersion params={json.dumps(e)}",
            "exclude_paths": ["root['error']['data']", "root['result']['identity']"],
        }
        for e in [*ALL_TYPES, *[[_e] for _e in ALL_TYPES]]
    ],
]

GET_ACCOUNT_INFO = [
    *[
        {
            "payload": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getAccountInfo",
                "params": e,
            },
            "description": f"getAccountInfo params={json.dumps(e)}",
            "exclude_paths": ["root['error']['data']"],
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
                "root['result']['context']['slot']"
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
                "root['result']['context']['slot']"
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
                "root['result']['context']['slot']"
            ],  # Checked manually. Excluded since "finalized" slot can be different across validators
        }
        for e in [
            *ALL_TYPES,
            [32, 7],
            [7, 32],
            [7, 3],
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
                "root['result']['context']['slot']",
                "root['error']['data']['contextSlot']",
            ],  # Checked manually. Excluded since "finalized" slot can be different across validators
        }
        for e in ALL_TYPES
    ],
]

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process some data")
    parser.add_argument(
        "--only-first", type=int, default=None, help="Only process the first item"
    )
    args = parser.parse_args()

    tester = RPCTester(
        server1_url="http://localhost:8899",
        server2_url="http://solana-testnet-rpc.jumpisolated.com:8899",
    )

    test_suite = [
        *MISC,
        *GET_HEALTH,
        *GET_VERSION,
        *GET_IDENTITY,
        *GET_ACCOUNT_INFO,
    ]

    run_test_suite(tester, test_suite, args.only_first)
