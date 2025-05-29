#!/usr/bin/env python3

import angr
import claripy
import logging
import time
import os
import sys
from pathlib import Path

# Set up logging
logging.getLogger('angr').setLevel(logging.ERROR)

# Function signature templates (copied from the harness generator)
FUNCTION_TEMPLATES = {
    # Basic arithmetic operations
    "fd_f25519_mul": {"params": 2, "type": "binary_op"},
    "fd_f25519_sqr": {"params": 1, "type": "unary_op"},
    "fd_f25519_add": {"params": 2, "type": "binary_op"},
    "fd_f25519_sub": {"params": 2, "type": "binary_op"},
    "fd_f25519_add_nr": {"params": 2, "type": "binary_op"},
    "fd_f25519_sub_nr": {"params": 2, "type": "binary_op"},
    "fd_f25519_neg": {"params": 1, "type": "unary_op"},
    "fd_f25519_mul_121666": {"params": 1, "type": "unary_op"},
    "fd_f25519_inv": {"params": 1, "type": "unary_op"},

    # Conversion operations
    "fd_f25519_frombytes": {"params": 1, "type": "from_bytes"},
    "fd_f25519_tobytes": {"params": 1, "type": "to_bytes"},

    # Other operations
    "fd_f25519_set": {"params": 1, "type": "unary_op"},
    "fd_f25519_is_zero": {"params": 1, "type": "predicate"},
    "fd_f25519_pow22523": {"params": 1, "type": "unary_op"},
    "fd_f25519_sqrt_ratio": {"params": 2, "type": "binary_op_return_int"},
}

def setup_symbolic_execution(binary_path, function_type):
    """Set up symbolic execution for a binary based on its function type"""
    # Create an angr project
    project = angr.Project(binary_path, auto_load_libs=False)

    # Determine the appropriate size for stdin based on function type
    if function_type == "unary_op" or function_type == "predicate" or function_type == "to_bytes":
        # For 5 ulongs, we need enough bytes for the input
        stdin_size = 5 * 64  # 5 elements x 64 bits each
    elif function_type == "binary_op" or function_type == "binary_op_return_int":
        # For 10 ulongs
        stdin_size = 10 * 64
    elif function_type == "from_bytes":
        # For 32 bytes (hex input)
        stdin_size = 32 * 8
    else:
        raise ValueError(f"Unknown function type: {function_type}")

    # Create fully symbolic stdin
    stdin = claripy.BVS('stdin', stdin_size)

    # Create initial state with symbolic stdin
    state = project.factory.entry_state(args=[binary_path], stdin=stdin)

    # Create simulation manager
    simulation = project.factory.simulation_manager(state)

    return simulation

def run_symbolic_execution(binary_path, function_name, function_info):
    """Run symbolic execution for a single binary"""
    print(f"Running symbolic execution for {function_name}...")

    # Set up symbolic execution
    simulation = setup_symbolic_execution(binary_path, function_info["type"])

    # Add explorer to find states that output "DONE"
    simulation.use_technique(angr.exploration_techniques.Explorer(
        find=lambda s: b"DONE." in s.posix.dumps(1)
    ))

    # Run simulation
    start_time = time.time()

    try:
        # Run with timeout (adjust as needed)
        simulation.run()
    except Exception as e:
        print(f"Error during execution: {e}")
        return False

    end_time = time.time()
    print(f"Execution time: {end_time - start_time:.2f} seconds")

    # Check if we reached a final state
    if not simulation.found:
        print(f"Error: Execution didn't reach the DONE state")
        print(f"Current states: {simulation.stashes}")
        return False

    # Get the found state
    found_state = simulation.found[0]

    # Get the output
    output = found_state.posix.dumps(1)
    print(f"Output: {output}")

    # For functions that produce deterministic outputs, we can check against expected results
    # For now, just printing the result

    # Additional verification could be done here, e.g.:
    # - Check properties that should hold (for addition, subtraction, etc.)
    # - Validate against known test vectors
    # - Verify field element properties (in range, etc.)

    return True

def verify_all_functions(binary_prefix="test_"):
    """Verify all functions"""
    results = {}

    for function_name, function_info in FUNCTION_TEMPLATES.items():
        binary_path = f"{binary_prefix}{function_name}"

        if not os.path.exists(binary_path):
            print(f"Warning: Binary {binary_path} does not exist, skipping")
            results[function_name] = "SKIPPED"
            continue

        print(f"\n=== Verifying {function_name} ===")
        success = run_symbolic_execution(binary_path, function_name, function_info)
        results[function_name] = "PASSED" if success else "FAILED"

    # Print summary
    print("\n=== Summary ===")
    for function_name, result in results.items():
        print(f"{function_name}: {result}")

def verify_single_function(function_name, binary_prefix="test_"):
    """Verify a single function"""
    if function_name not in FUNCTION_TEMPLATES:
        print(f"Error: Unknown function {function_name}")
        return False

    binary_path = f"{binary_prefix}{function_name}"

    if not os.path.exists(binary_path):
        print(f"Error: Binary {binary_path} does not exist")
        return False

    function_info = FUNCTION_TEMPLATES[function_name]
    return run_symbolic_execution(binary_path, function_name, function_info)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        function_name = sys.argv[1]
        binary_prefix = sys.argv[2] if len(sys.argv) > 2 else "test_"
        verify_single_function(function_name, binary_prefix)
    else:
        binary_prefix = sys.argv[1] if len(sys.argv) > 1 else "test_"
        verify_all_functions(binary_prefix)