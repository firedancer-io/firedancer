import time
import angr
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("x25519_verify")

def run_concrete_test(binary_path, private_key, peer_pubkey):
    """Run a concrete test with the given inputs"""
    logger.info(f"Running concrete test for {binary_path}")

    # Create project
    project = angr.Project(binary_path, auto_load_libs=False)

    # Create initial state with concrete input
    input_data = private_key + peer_pubkey
    state = project.factory.entry_state(args=[binary_path], stdin=input_data)

    # Create simulation
    sm = project.factory.simulation_manager(state)
    sm.use_technique(angr.exploration_techniques.Explorer(find=lambda s: b"DONE." in s.posix.dumps(1)))
    sm.use_technique(angr.exploration_techniques.Oppologist())
    sm.run()
    # Run until completion or timeout
    # for n in range(0,10):
    #     sm.step(n=1000)
    #     print(binary_path,(n+1)*1000, time.time())


    # Check results
    if sm.deadended:
        logger.info(f"Program terminated normally with {len(sm.deadended)} end states")

        for i, state in enumerate(sm.deadended):
            exit_code = state.solver.eval(state.posix.exit_code)
            logger.info(f"End state {i} with exit code {exit_code}")

            # Get stdout content
            stdout = state.posix.dumps(1)
            if stdout:
                logger.info(f"Stdout ({len(stdout)} bytes): {stdout[:32].hex()}")
                return stdout[:32]
    else:
        logger.error(f"Program did not terminate normally {binary_path}")
        print(sm)
        for stash_name, stash in sm.stashes.items():
            if stash:
                logger.info(f"{stash_name}: {len(stash)} states")
        return None

def test_with_vectors():
    """Test with concrete vectors from your original code"""
    # Extract test vectors from your code
    private_key = bytes([
        0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d,0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45,
        0xdf,0x4c,0x2f,0x87,0xeb,0xc0,0x99,0x2a,0xb1,0x77,0xfb,0xa5,0x1d,0xb9,0x2c,0x2a
    ])

    peer_pubkey = bytes([
        0xde,0x9e,0xdb,0x7d,0x7b,0x7d,0xc1,0xb4,0xd3,0x5b,0x61,0xc2,0xec,0xe4,0x35,0x37,
        0x3f,0x83,0x43,0xc8,0x5b,0x78,0x67,0x4d,0xad,0xfc,0x7e,0x14,0x6f,0x88,0x2b,0x4f
    ])

    expected_output = bytes([
        0x4a,0x5d,0x9d,0x5b,0xa4,0xce,0x2d,0xe1,0x72,0x8e,0x3b,0xf4,0x80,0x35,0x0f,0x25,
        0xe0,0x7e,0x21,0xc9,0x47,0xd1,0x9e,0x33,0x76,0xf0,0x9b,0x3c,0x1e,0x16,0x17,0x42
    ])

    # Run tests
    avx512_output = run_concrete_test("./x25519_avx2", private_key, peer_pubkey)
    no_avx512_output = run_concrete_test("./x25519_no_avx", private_key, peer_pubkey)

    # Compare outputs
    if avx512_output and no_avx512_output:
        if avx512_output == no_avx512_output:
            logger.info("Test passed: both implementations produced the same output")
            if avx512_output == expected_output:
                logger.info("Output matches expected value from test vector")
            else:
                logger.warning(f"Output differs from expected: {avx512_output.hex()} vs {expected_output.hex()}")
        else:
            logger.error(f"Test failed: outputs differ")
            logger.error(f"AVX512: {avx512_output.hex()}")
            logger.error(f"No AVX512: {no_avx512_output.hex()}")
    else:
        logger.error("Test failed: one or both implementations did not produce output")

if __name__ == "__main__":
    test_with_vectors()