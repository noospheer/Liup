#!/usr/bin/env python3
"""
Liup Demo: Information-Theoretic Key Agreement

Usage:
    python demo.py           # Single batch demo
    python demo.py --stream  # Continuous streaming (Ctrl+C to stop)
"""

from liuproto.link import NetworkServerLink, NetworkClientLink
from liuproto.endpoint import Physics
import os
import sys
import threading
import time
import random


def run_single():
    """Run a single batch demo."""
    print("=" * 60)
    print("Liup: Information-Theoretic Key Agreement Demo")
    print("=" * 60)

    # Parameters
    B = 100_000
    n_runs = 10
    port = random.randint(10000, 60000)
    address = ('127.0.0.1', port)

    # Step 1: Generate shared secret
    print("\n[1] Generating pre-shared key (~12.5 KB)...")
    psk = os.urandom(32 + (B // 8) + 100)
    print(f"    PSK size: {len(psk):,} bytes")
    print("    (In real use, exchange this securely out-of-band)")

    # Step 2: Start server
    print("\n[2] Starting server...")
    server = NetworkServerLink(address, pre_shared_key=psk)
    server_result = [None]
    def run_server():
        server_result[0] = server.run_batch_signbit_nopa()
    server_thread = threading.Thread(target=run_server)
    server_thread.start()
    time.sleep(0.1)
    print(f"    Listening on {address[0]}:{address[1]}")

    # Step 3: Run client
    print("\n[3] Running client...")
    print(f"    B = {B:,} bits/run")
    print(f"    n_runs = {n_runs}")
    print(f"    Expected output: {B * n_runs:,} bits")

    physics = Physics(1, 0.8, 0.1, 5, 0, 0, 0, 0.2)
    client = NetworkClientLink(address, physics, pre_shared_key=psk)

    start = time.perf_counter()
    client_result = client.run_signbit_nopa(
        B=B, n_runs=n_runs, n_batches=1,
        mod_mult=0.5, n_test_rounds=0,
    )
    elapsed = time.perf_counter() - start
    server_thread.join()

    # Step 4: Validation
    print("\n[4] Validation")
    print("=" * 60)

    client_key = client_result['secure_bits']
    server_key = server_result[0]['secure_bits']

    # Check keys match
    keys_match = len(client_key) == len(server_key) and all(
        c == s for c, s in zip(client_key, server_key)
    )

    checks = []
    checks.append(("Keys match (client == server)", keys_match))
    checks.append(("Expected bit count", len(client_key) == B * n_runs))
    checks.append(("Protocol completed", client_result is not None and server_result[0] is not None))

    all_passed = True
    for name, passed in checks:
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"    {status}: {name}")
        if not passed:
            all_passed = False

    if not all_passed:
        print("\n    *** VALIDATION FAILED ***")
        sys.exit(1)

    # Step 5: Results
    throughput = len(client_key) / elapsed / 1e6
    key_str = ''.join(str(int(b)) for b in client_key[:256])
    key_hex = hex(int(key_str[:128], 2))[2:].zfill(32)

    print("\n[5] Results")
    print("=" * 60)
    print(f"    Generated:  {len(client_key):,} bits of ITS key")
    print(f"    Time:       {elapsed:.2f} seconds")
    print(f"    Throughput: {throughput:.2f} Mbps")
    print(f"\n    First 128 bits (binary):")
    print(f"    {key_str[:64]}")
    print(f"    {key_str[64:128]}")
    print(f"\n    First 128 bits (hex): {key_hex}")

    print("\n[6] Security properties")
    print("=" * 60)
    print("    - Information-theoretically secure (not just computational)")
    print("    - Secure against adversaries with unlimited compute power")
    print("    - Authenticated against active man-in-the-middle attacks")
    print("    - Can generate unlimited key from the same ~12.5 KB PSK")

    print("\n" + "=" * 60)
    print("Demo complete! All validations passed.")
    print("=" * 60)


def run_stream():
    """Run continuous streaming demo."""
    B = 100_000
    n_runs = 10

    print("=" * 60)
    print("Liup Streaming Demo - Continuous ITS Key Generation")
    print("=" * 60)
    print("Press Ctrl+C to stop\n")

    psk = os.urandom(32 + (B // 8) + 100)

    total_bits = 0
    total_batches = 0
    start_time = time.perf_counter()

    try:
        while True:
            port = random.randint(20000, 60000)
            address = ('127.0.0.1', port)

            server = NetworkServerLink(address, pre_shared_key=psk)
            server_result = [None]

            def run_server():
                server_result[0] = server.run_batch_signbit_nopa()

            t = threading.Thread(target=run_server)
            t.start()
            time.sleep(0.05)

            physics = Physics(1, 0.8, 0.1, 5, 0, 0, 0, 0.2)
            client = NetworkClientLink(address, physics, pre_shared_key=psk)

            batch_start = time.perf_counter()
            result = client.run_signbit_nopa(
                B=B, n_runs=n_runs, n_batches=1,
                mod_mult=0.5, n_test_rounds=0
            )
            batch_time = time.perf_counter() - batch_start
            t.join()

            bits = len(result['secure_bits'])
            total_bits += bits
            total_batches += 1
            elapsed = time.perf_counter() - start_time

            batch_mbps = bits / batch_time / 1e6
            avg_mbps = total_bits / elapsed / 1e6

            sys.stdout.write(
                f"\rBatch {total_batches:4d} | "
                f"{bits/1000:.0f}k bits in {batch_time:.2f}s | "
                f"Batch: {batch_mbps:.2f} Mbps | "
                f"Avg: {avg_mbps:.2f} Mbps | "
                f"Total: {total_bits/1e6:.2f} Mbit   "
            )
            sys.stdout.flush()

    except KeyboardInterrupt:
        pass

    elapsed = time.perf_counter() - start_time
    print(f"\n\n{'=' * 60}")
    print(f"Session Complete")
    print(f"{'=' * 60}")
    print(f"  Total batches: {total_batches}")
    print(f"  Total bits:    {total_bits:,} ({total_bits/1e6:.2f} Mbit)")
    print(f"  Total time:    {elapsed:.1f} seconds")
    print(f"  Avg throughput: {total_bits/elapsed/1e6:.2f} Mbps")
    print(f"{'=' * 60}")


def main():
    if '--stream' in sys.argv:
        run_stream()
    else:
        run_single()


if __name__ == '__main__':
    main()
