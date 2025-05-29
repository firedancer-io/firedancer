import time
import angr
import claripy
import logging
import threading
# Set up logging
logging.getLogger('angr').setLevel(logging.ERROR)

def setup_symbolic_execution(binary_path):
    """Set up symbolic execution for a single binary"""
    # Create an angr project
    project = angr.Project(binary_path, auto_load_libs=False)

    # Create symbolic bytes for private key and peer public key
    symbolic_private = claripy.BVS('private_key', 8 * 32)
    symbolic_peer = claripy.BVS('peer_pubkey', 8 * 32)
    stdin_bytes = symbolic_private.concat(symbolic_peer)

    # Create initial state
    state = project.factory.entry_state(args=[binary_path],stdin=stdin_bytes)

    # Create simulation
    simulation = project.factory.simulation_manager(state)

    return simulation, symbolic_private, symbolic_peer

def run_and_compare():
    """Run both implementations and compare results"""
    # Paths to the compiled binaries
    binary_avx2 = "./x25519_avx2"
    binary_no_avx = "./x25519_no_avx"

    # Set up symbolic execution for both binaries
    sim_avx2, private_key, peer_pubkey = setup_symbolic_execution(binary_avx2)
    sim_no_avx512, _, _ = setup_symbolic_execution(binary_no_avx)

    sim_avx2.use_technique(angr.exploration_techniques.Explorer(find=lambda s: b"DONE." in s.posix.dumps(1)))
    sim_no_avx512.use_technique(angr.exploration_techniques.Explorer(find=lambda s: b"DONE." in s.posix.dumps(1)))

    def run_avx2():
        # Run until each reaches a state where it has written to stdout
        print("Running AVX2 implementation...")
        # FIX: Use posix.dumps(1) instead of stdout.concrete_bytes
        # sim_avx2.use_technique(angr.exploration_techniques.Oppologist())
        while not sim_avx2.complete():
            sim_avx2.run(n=10)
            print(time.time(), "avx2", sim_avx2)

    def run_noavx():
        print("Running non-AVX implementation...")
        # sim_no_avx512.use_technique(angr.exploration_techniques.Oppologist())
        while not sim_no_avx512.complete():
            sim_no_avx512.run(n=10)
            print(time.time(), "noavx", sim_no_avx512)
            # print(sim_no_avx512.)


   # Create and start threads
    # thread_avx2 = threading.Thread(target=run_avx2)
    # thread_avx2.start()
    # thread_avx2.join()


    # thread_no_avx = threading.Thread(target=run_noavx)
    # thread_no_avx.start()
    # thread_no_avx.join()
    run_noavx()
    run_avx2()

    # Wait for both threads to complete

    if not sim_avx2.found or not sim_no_avx512.found:
        print(f"Error: One or both executions didn't reach the expected state 512{sim_avx2.found}, no{sim_no_avx512.found}")
        return False

    # Get the output from both implementations
    avx512_state = sim_avx2.found[0]
    no_avx512_state = sim_no_avx512.found[0]

    avx512_output = avx512_state.posix.stdout.concrete_bytes
    no_avx512_output = no_avx512_state.posix.stdout.concrete_bytes

    # Check for equality across all possible inputs
    if avx512_state.satisfiable(extra_constraints=[avx512_output != no_avx512_output]):
        print("VERIFICATION FAILED: Implementations can produce different outputs")
        # Get a concrete counterexample
        model = avx512_state.solver.eval(private_key, cast_to=bytes)
        peer_model = avx512_state.solver.eval(peer_pubkey, cast_to=bytes)
        print(f"Counterexample private key: {model.hex()}")
        print(f"Counterexample peer pubkey: {peer_model.hex()}")
        return False
    else:
        print("VERIFICATION PASSED: Implementations are equivalent for all inputs")
        return True

if __name__ == "__main__":
    run_and_compare()
