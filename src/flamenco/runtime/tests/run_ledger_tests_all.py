#!/usr/bin/env python3
import subprocess
import multiprocessing
from multiprocessing import Queue, Value, Event


def group_cpus(batch_size=16):
    import os
    # Get the number of available CPUs
    num_cpus = os.cpu_count()
    print(f"Total CPUs available: {num_cpus}")

    # Create batches of CPUs
    batches = [list(range(i, min(i + batch_size, num_cpus))) for i in range(0, num_cpus, batch_size)]
    return batches


def worker(command_queue, available_params, error_occurred, error_event):
    while not error_event.is_set():
        command = command_queue.get()
        if command is None:  # None signals to the worker to quit
            break

        # Try to acquire a parameter
        param = available_params.get()

        # Execute the command with the parameter
        try:
            process = subprocess.run(f"{command} {param}", shell=True, check=True)
            print(f"Completed: {command} {param}")
        except subprocess.CalledProcessError as e:
            print(f"Command failed: {command} {param}, exit code {e.returncode}")
            error_occurred.value = 1
            error_event.set()
            break
        finally:
            # Release the parameter back to the pool
            available_params.put(param)


def main(file_path):
    cpu_batches = group_cpus()
    print("CPU Batches:", cpu_batches)
    # Define parameter ranges
    parameter_ranges = [ f'--tile-cpus {b[0]}-{b[-1]}' for b in cpu_batches ]
    print(f'{parameter_ranges=}')

    # Load commands from file
    with open(file_path, 'r') as file:
        commands = [line.strip() for line in file.readlines()]

    # Manager to share queues across processes
    manager = multiprocessing.Manager()
    available_params = manager.Queue()
    for param in parameter_ranges:
        available_params.put(param)

    command_queue = manager.Queue()
    for command in commands:
        command_queue.put(command)

    # Flag for error tracking across processes
    error_occurred = manager.Value('i', 0) # Shared integer, initialized to 0
    error_event = Event()

    # Create worker processes
    processes = []
    for _ in range(len(cpu_batches)):  # Adjust the number of processes as needed
        p = multiprocessing.Process(target=worker, args=(command_queue, available_params, error_occurred, error_event))
        processes.append(p)
        p.start()

    # Signal workers to stop when all commands are processed
    for _ in range(len(processes)):
        command_queue.put(None)

    # Wait for all processes to finish
    for p in processes:
        p.join()

    # Check for errors
    if error_occurred.value == 1:
        print("A process failed. Terminating script.")
        for p in processes:
            p.terminate()
        exit(1)

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <file_path>")
    else:
        file_path = sys.argv[1]
        main(file_path)
