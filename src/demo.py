#!/usr/bin/env python3
"""
Liup Demo: Information-Theoretic Key Agreement

This demo runs a complete key agreement between a local server and client,
generating ~1 million bits of information-theoretically secure key material.
"""

from liuproto.link import NetworkServerLink, NetworkClientLink
from liuproto.endpoint import Physics
import os
import threading
import time
import random

def main():
    print("=" * 60)
    print("Liup: Information-Theoretic Key Agreement Demo")
    print("=" * 60)

    # Parameters
    B = 100_000          # bits per run
    n_runs = 10          # runs per batch
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
    server_thread = threading.Thread(target=server.run_batch_signbit_nopa)
    server_thread.start()
    time.sleep(0.1)  # Let server bind
    print(f"    Listening on {address[0]}:{address[1]}")

    # Step 3: Run client
    print("\n[3] Running client...")
    print(f"    B = {B:,} bits/run")
    print(f"    n_runs = {n_runs}")
    print(f"    Expected output: {B * n_runs:,} bits")

    physics = Physics(1, 0.8, 0.1, 5, 0, 0, 0, 0.2)
    client = NetworkClientLink(address, physics, pre_shared_key=psk)

    start = time.perf_counter()
    result = client.run_signbit_nopa(
        B=B,
        n_runs=n_runs,
        n_batches=1,
        mod_mult=0.5,      # σ/p = 2 (recommended for security)
        n_test_rounds=0,   # Skip verification for demo speed
    )
    elapsed = time.perf_counter() - start

    server_thread.join()

    # Step 4: Results
    key_bits = result['secure_bits']
    throughput = len(key_bits) / elapsed / 1e6

    # Convert to string for display
    key_str = ''.join(str(int(b)) for b in key_bits[:256])
    key_hex = hex(int(key_str[:128], 2))[2:].zfill(32)

    print("\n[4] Results")
    print("=" * 60)
    print(f"    Generated:  {len(key_bits):,} bits of ITS key")
    print(f"    Time:       {elapsed:.2f} seconds")
    print(f"    Throughput: {throughput:.2f} Mbps")
    print(f"\n    First 128 bits (binary):")
    print(f"    {key_str[:64]}")
    print(f"    {key_str[64:128]}")
    print(f"\n    First 128 bits (hex): {key_hex}")

    print("\n[5] Security properties")
    print("=" * 60)
    print("    - Information-theoretically secure (not just computational)")
    print("    - Secure against adversaries with unlimited compute power")
    print("    - Authenticated against active man-in-the-middle attacks")
    print("    - Can generate unlimited key from the same ~12.5 KB PSK")

    print("\n" + "=" * 60)
    print("Demo complete!")
    print("=" * 60)

if __name__ == '__main__':
    main()
