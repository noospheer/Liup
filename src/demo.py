#!/usr/bin/env python3
"""
Liup Demo: Information-Theoretic Key Agreement

Usage:
    python demo.py keygen  [--psk-file PATH] [--B N] [--rng-mode MODE]
    python demo.py server  [--psk-file PATH] [--host ADDR] [--port N] [--stream]
    python demo.py client  [--psk-file PATH] --host ADDR  [--port N] [--B N]
                           [--n-runs N] [--rng-mode MODE] [--stream]
    python demo.py local   [--rng-mode MODE] [--stream]
    python demo.py --urandom [--stream]   # backward compat (maps to local)

When --psk-file is omitted for server/client, ECDH (P-256) is used to
establish the PSK automatically. This provides computational security
only. Use --psk-file for information-theoretic security.
"""

from liuproto.link import (
    NetworkServerLink, NetworkClientLink, SigmaDriftError,
)
from liuproto.endpoint import Physics
import argparse
import hashlib
import json
import os
import random
import socket
import sys
import threading
import time

DEFAULT_PORT = 7767
DEFAULT_B = 100_000
DEFAULT_N_RUNS = 10


# ── helpers (unchanged from original) ──────────────────────────────────

def _psk_for_mode(B, rng_mode):
    """Generate a PSK of the correct size for the given rng_mode."""
    base = 32 + (B // 8) + 100
    if rng_mode == 'rdseed':
        base += 96  # Toeplitz seed
    return os.urandom(base)


def _psk_for_mode_size(B, rng_mode):
    """Return required PSK size in bytes for given B and rng_mode."""
    base = 32 + (B // 8) + 100
    if rng_mode == 'rdseed':
        base += 96
    return base


def _mode_label(rng_mode):
    if rng_mode == 'rdseed':
        return 'RDSEED + Toeplitz extraction (near-ITS)'
    return 'os.urandom (ChaCha20 CSPRNG)'


# ── PSK helpers ────────────────────────────────────────────────────────

def _load_psk(path):
    """Read a binary PSK file. Exits with a clear message on failure."""
    try:
        data = open(path, 'rb').read()
    except FileNotFoundError:
        print(f"Error: PSK file not found: {path}")
        print("  Run:  python demo.py keygen --psk-file " + path)
        sys.exit(1)
    if len(data) < 64:
        print(f"Error: PSK file too small ({len(data)} bytes): {path}")
        print("  Run:  python demo.py keygen --psk-file " + path)
        sys.exit(1)
    return data


def _print_psk_fingerprint(psk, is_ecdh=False):
    """Print PSK fingerprint and security classification."""
    fingerprint = hashlib.sha256(psk).hexdigest()[:16]
    print(f"  PSK fingerprint: {fingerprint}")
    if is_ecdh:
        print()
        print("  *** WARNING: PSK established via ECDH (P-256) ***")
        print("  *** Security is COMPUTATIONAL, not information-theoretic ***")
        print("  *** For ITS security, use: demo.py keygen + --psk-file ***")
        print()
        print("  Verify this fingerprint matches on both sides (TOFU).")


def _connect_with_retry(address, physics, psk, timeout=10, retries=3):
    """Connect to server with exponential backoff.

    Returns a NetworkClientLink on success, or exits on failure.
    """
    delay = 1
    for attempt in range(1, retries + 1):
        try:
            client = NetworkClientLink(
                address, physics, pre_shared_key=psk,
                connect_timeout=timeout,
            )
            return client
        except (ConnectionRefusedError, socket.timeout, OSError) as exc:
            if attempt < retries:
                print(f"  Connection attempt {attempt}/{retries} failed: {exc}")
                print(f"  Retrying in {delay}s ...")
                time.sleep(delay)
                delay *= 3
            else:
                print(f"  Connection failed after {retries} attempts: {exc}")
                sys.exit(1)


# ── ECDH key exchange ──────────────────────────────────────────────────

def _recv_exact(sock, n):
    """Receive exactly n bytes from socket, or raise ConnectionError."""
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError(
                f"Connection closed after {len(data)}/{n} bytes during ECDH")
        data += chunk
    return data


def _ecdh_derive_psk(shared_x, psk_size):
    """Expand 32-byte ECDH shared secret to psk_size bytes via counter-mode SHA-256."""
    blocks = []
    n_blocks = (psk_size + 31) // 32
    for i in range(n_blocks):
        h = hashlib.sha256()
        h.update(shared_x)
        h.update(b"liup-psk-")
        h.update(i.to_bytes(4, 'big'))
        blocks.append(h.digest())
    return b''.join(blocks)[:psk_size]


def _ecdh_server(address, timeout=30):
    """Perform ECDH key exchange as server. Returns derived PSK bytes."""
    from Crypto.PublicKey import ECC

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.settimeout(timeout)
    srv.bind(address)
    srv.listen(1)

    print(f"  Waiting for ECDH connection on {address[0]}:{address[1]} ...")
    try:
        conn, peer_addr = srv.accept()
    except socket.timeout:
        srv.close()
        print("Error: No client connected within timeout for ECDH handshake.")
        sys.exit(1)
    finally:
        srv.close()

    conn.settimeout(10)
    try:
        key = ECC.generate(curve='P-256')
        my_pub_der = key.public_key().export_key(format='DER')

        # Receive client's public key
        peer_len = int.from_bytes(_recv_exact(conn, 4), 'big')
        if peer_len < 50 or peer_len > 200:
            raise ValueError(f"Invalid peer public key length: {peer_len}")
        peer_der = _recv_exact(conn, peer_len)

        # Receive client parameters
        params_len = int.from_bytes(_recv_exact(conn, 4), 'big')
        if params_len > 1024:
            raise ValueError(f"Parameter message too large: {params_len}")
        params = json.loads(_recv_exact(conn, params_len))
        B = params['B']
        rng_mode = params['rng_mode']

        # Send server's public key
        conn.sendall(len(my_pub_der).to_bytes(4, 'big') + my_pub_der)

        # Compute shared secret
        peer_key = ECC.import_key(peer_der)
        shared_point = key.d * peer_key.pointQ
        shared_x = int(shared_point.x).to_bytes(32, 'big')

        psk = _ecdh_derive_psk(shared_x, _psk_for_mode_size(B, rng_mode))
    finally:
        conn.close()

    return psk


def _ecdh_client(address, B, rng_mode, timeout=10, retries=3):
    """Perform ECDH key exchange as client. Returns derived PSK bytes."""
    from Crypto.PublicKey import ECC

    delay = 1
    conn = None
    for attempt in range(1, retries + 1):
        try:
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn.settimeout(timeout)
            conn.connect(address)
            break
        except (ConnectionRefusedError, socket.timeout, OSError) as exc:
            if conn:
                conn.close()
            if attempt < retries:
                print(f"  ECDH connection attempt {attempt}/{retries} failed: {exc}")
                print(f"  Retrying in {delay}s ...")
                time.sleep(delay)
                delay *= 3
            else:
                print(f"  ECDH connection failed after {retries} attempts: {exc}")
                sys.exit(1)

    try:
        key = ECC.generate(curve='P-256')
        my_pub_der = key.public_key().export_key(format='DER')

        # Send client's public key
        conn.sendall(len(my_pub_der).to_bytes(4, 'big') + my_pub_der)

        # Send parameters so server knows PSK size
        params = json.dumps({'B': B, 'rng_mode': rng_mode}).encode('utf-8')
        conn.sendall(len(params).to_bytes(4, 'big') + params)

        # Receive server's public key
        peer_len = int.from_bytes(_recv_exact(conn, 4), 'big')
        if peer_len < 50 or peer_len > 200:
            raise ValueError(f"Invalid peer public key length: {peer_len}")
        peer_der = _recv_exact(conn, peer_len)

        # Compute shared secret
        peer_key = ECC.import_key(peer_der)
        shared_point = key.d * peer_key.pointQ
        shared_x = int(shared_point.x).to_bytes(32, 'big')

        psk = _ecdh_derive_psk(shared_x, _psk_for_mode_size(B, rng_mode))
    finally:
        conn.close()

    return psk


# ── local mode (preserved from original) ───────────────────────────────

def run_single(rng_mode):
    """Run a single batch demo."""
    print("=" * 60)
    print("Liup: Information-Theoretic Key Agreement Demo")
    print(f"Randomness: {_mode_label(rng_mode)}")
    print("=" * 60)

    # Parameters
    B = 100_000
    n_runs = 10
    port = random.randint(10000, 60000)
    address = ('127.0.0.1', port)

    # Step 1: Generate shared secret
    print("\n[1] Generating pre-shared key...")
    psk = _psk_for_mode(B, rng_mode)
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
        rng_mode=rng_mode,
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
        status = "PASS" if passed else "FAIL"
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


def run_stream(rng_mode):
    """Run continuous streaming demo."""
    B = 100_000
    n_runs = 10

    print("=" * 60)
    print("Liup Streaming Demo - Continuous ITS Key Generation")
    print(f"Randomness: {_mode_label(rng_mode)}")
    print("=" * 60)
    print("Press Ctrl+C to stop\n")

    psk = _psk_for_mode(B, rng_mode)

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
                mod_mult=0.5, n_test_rounds=0,
                rng_mode=rng_mode,
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


# ── keygen subcommand ──────────────────────────────────────────────────

def cmd_keygen(args):
    B = args.B
    rng_mode = args.rng_mode
    path = args.psk_file

    psk = _psk_for_mode(B, rng_mode)
    with open(path, 'wb') as f:
        f.write(psk)

    fingerprint = hashlib.sha256(psk).hexdigest()[:16]

    print(f"PSK written to {path}")
    print(f"  Size:        {len(psk):,} bytes")
    print(f"  B:           {B:,}")
    print(f"  RNG mode:    {rng_mode}")
    print(f"  Fingerprint: {fingerprint}")
    print()
    print("Copy this file to the remote machine securely (e.g. scp).")
    print("Verify fingerprint matches on both sides before use.")


# ── server subcommand ──────────────────────────────────────────────────

def cmd_server(args):
    address = (args.host, args.port)

    if args.psk_file is not None:
        psk = _load_psk(args.psk_file)
        is_ecdh = False
    else:
        print("=" * 60)
        print("Liup Server — ECDH key establishment")
        print("=" * 60)
        try:
            psk = _ecdh_server(address)
        except ImportError:
            print("Error: pycryptodome is required for ECDH.")
            print("  Install: pip install pycryptodome")
            sys.exit(1)
        except (ConnectionError, ValueError, socket.error) as exc:
            print(f"Error during ECDH handshake: {exc}")
            sys.exit(1)
        is_ecdh = True
        _print_psk_fingerprint(psk, is_ecdh=True)
        time.sleep(0.1)

    if args.stream:
        _server_stream(address, psk, is_ecdh=is_ecdh)
    else:
        _server_single(address, psk, is_ecdh=is_ecdh)


def _server_single(address, psk, is_ecdh=False):
    print("=" * 60)
    print("Liup Server — Waiting for client")
    print(f"Listening on {address[0]}:{address[1]}")
    if is_ecdh:
        print("PSK: ECDH (computational security)")
    print("=" * 60)

    server = NetworkServerLink(address, pre_shared_key=psk)
    start = time.perf_counter()
    result = server.run_batch_signbit_nopa()
    elapsed = time.perf_counter() - start
    server.close()

    bits = len(result['secure_bits'])
    throughput = bits / elapsed / 1e6

    print(f"\nBatch complete")
    print(f"  Generated: {bits:,} bits")
    print(f"  Time:      {elapsed:.2f}s")
    print(f"  Throughput: {throughput:.2f} Mbps")
    if is_ecdh:
        print()
        print("  Note: PSK was established via ECDH. Security is computational, not ITS.")
    else:
        print()
        print("  Note: Use `demo.py local` to verify key agreement (same machine).")


def _server_stream(address, psk, is_ecdh=False):
    print("=" * 60)
    print("Liup Server — Streaming mode")
    print(f"Listening on {address[0]}:{address[1]}")
    if is_ecdh:
        print("PSK: ECDH (computational security)")
    print("=" * 60)
    print("Press Ctrl+C to stop\n")

    total_bits = 0
    total_batches = 0
    start_time = time.perf_counter()

    try:
        while True:
            server = NetworkServerLink(address, pre_shared_key=psk)
            batch_start = time.perf_counter()
            result = server.run_batch_signbit_nopa()
            batch_time = time.perf_counter() - batch_start
            server.close()

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
    print("Server Session Complete")
    print(f"{'=' * 60}")
    print(f"  Total batches: {total_batches}")
    print(f"  Total bits:    {total_bits:,} ({total_bits/1e6:.2f} Mbit)")
    print(f"  Total time:    {elapsed:.1f} seconds")
    if elapsed > 0:
        print(f"  Avg throughput: {total_bits/elapsed/1e6:.2f} Mbps")
    print(f"{'=' * 60}")


# ── client subcommand ──────────────────────────────────────────────────

def cmd_client(args):
    address = (args.host, args.port)
    B = args.B
    rng_mode = args.rng_mode

    if args.psk_file is not None:
        psk = _load_psk(args.psk_file)
        is_ecdh = False
    else:
        print("=" * 60)
        print("Liup Client — ECDH key establishment")
        print("=" * 60)
        try:
            psk = _ecdh_client(address, B, rng_mode)
        except ImportError:
            print("Error: pycryptodome is required for ECDH.")
            print("  Install: pip install pycryptodome")
            sys.exit(1)
        except (ConnectionError, ValueError, socket.error) as exc:
            print(f"Error during ECDH handshake: {exc}")
            sys.exit(1)
        is_ecdh = True
        _print_psk_fingerprint(psk, is_ecdh=True)
        time.sleep(0.1)

    if args.stream:
        _client_stream(address, psk, B, args.n_runs, rng_mode, is_ecdh=is_ecdh)
    else:
        _client_single(address, psk, B, args.n_runs, rng_mode, is_ecdh=is_ecdh)


def _client_single(address, psk, B, n_runs, rng_mode, is_ecdh=False):
    print("=" * 60)
    print("Liup Client — Single batch")
    print(f"Connecting to {address[0]}:{address[1]}")
    print(f"B = {B:,}  n_runs = {n_runs}  rng_mode = {rng_mode}")
    if is_ecdh:
        print("PSK: ECDH (computational security)")
    print("=" * 60)

    physics = Physics(1, 0.8, 0.1, 5, 0, 0, 0, 0.2)
    client = _connect_with_retry(address, physics, psk)
    print(f"  Connected to {address[0]}:{address[1]}")

    start = time.perf_counter()
    try:
        result = client.run_signbit_nopa(
            B=B, n_runs=n_runs, n_batches=1,
            mod_mult=0.5, n_test_rounds=0,
            rng_mode=rng_mode,
        )
    except SigmaDriftError:
        print("\nError: Authentication failed — check that PSK files match.")
        sys.exit(1)
    elapsed = time.perf_counter() - start

    bits = len(result['secure_bits'])
    throughput = bits / elapsed / 1e6

    print(f"\nBatch complete")
    print(f"  Generated: {bits:,} bits")
    print(f"  Time:      {elapsed:.2f}s")
    print(f"  Throughput: {throughput:.2f} Mbps")
    if is_ecdh:
        print()
        print("  Note: PSK was established via ECDH. Security is computational, not ITS.")
    else:
        print()
        print("  Note: Use `demo.py local` to verify key agreement (same machine).")


def _client_stream(address, psk, B, n_runs, rng_mode, is_ecdh=False):
    print("=" * 60)
    print("Liup Client — Streaming mode")
    print(f"Connecting to {address[0]}:{address[1]}")
    print(f"B = {B:,}  n_runs = {n_runs}  rng_mode = {rng_mode}")
    if is_ecdh:
        print("PSK: ECDH (computational security)")
    print("=" * 60)
    print("Press Ctrl+C to stop\n")

    total_bits = 0
    total_batches = 0
    start_time = time.perf_counter()

    try:
        while True:
            physics = Physics(1, 0.8, 0.1, 5, 0, 0, 0, 0.2)
            client = _connect_with_retry(address, physics, psk)

            batch_start = time.perf_counter()
            try:
                result = client.run_signbit_nopa(
                    B=B, n_runs=n_runs, n_batches=1,
                    mod_mult=0.5, n_test_rounds=0,
                    rng_mode=rng_mode,
                )
            except SigmaDriftError:
                print("\nError: Authentication failed — check that PSK files match.")
                sys.exit(1)
            batch_time = time.perf_counter() - batch_start

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
    print("Client Session Complete")
    print(f"{'=' * 60}")
    print(f"  Total batches: {total_batches}")
    print(f"  Total bits:    {total_bits:,} ({total_bits/1e6:.2f} Mbit)")
    print(f"  Total time:    {elapsed:.1f} seconds")
    if elapsed > 0:
        print(f"  Avg throughput: {total_bits/elapsed/1e6:.2f} Mbps")
    print(f"{'=' * 60}")


# ── local subcommand ───────────────────────────────────────────────────

def cmd_local(args):
    rng_mode = args.rng_mode
    if args.stream:
        run_stream(rng_mode)
    else:
        run_single(rng_mode)


# ── CLI ────────────────────────────────────────────────────────────────

def build_parser():
    parser = argparse.ArgumentParser(
        prog='demo.py',
        description='Liup: Information-Theoretic Key Agreement',
    )
    sub = parser.add_subparsers(dest='command')

    # keygen
    kg = sub.add_parser('keygen', help='Generate a pre-shared key file')
    kg.add_argument('--psk-file', default='liup.psk',
                    help='Output PSK file (default: liup.psk)')
    kg.add_argument('--B', type=int, default=DEFAULT_B,
                    help=f'Bits per run (default: {DEFAULT_B:,})')
    kg.add_argument('--rng-mode', choices=['urandom', 'rdseed'],
                    default='urandom',
                    help='Randomness source (default: urandom)')

    # server
    sv = sub.add_parser('server',
                        help='Run as server (omit --psk-file for automatic ECDH)')
    sv.add_argument('--psk-file', default=None,
                    help='PSK file path (omit for automatic ECDH)')
    sv.add_argument('--host', default='0.0.0.0',
                    help='Bind address (default: 0.0.0.0)')
    sv.add_argument('--port', type=int, default=DEFAULT_PORT,
                    help=f'Port (default: {DEFAULT_PORT})')
    sv.add_argument('--stream', action='store_true',
                    help='Continuous streaming mode')

    # client
    cl = sub.add_parser('client',
                        help='Run as client (omit --psk-file for automatic ECDH)')
    cl.add_argument('--psk-file', default=None,
                    help='PSK file path (omit for automatic ECDH)')
    cl.add_argument('--host', required=True, help='Server address')
    cl.add_argument('--port', type=int, default=DEFAULT_PORT,
                    help=f'Port (default: {DEFAULT_PORT})')
    cl.add_argument('--B', type=int, default=DEFAULT_B,
                    help=f'Bits per run (default: {DEFAULT_B:,})')
    cl.add_argument('--n-runs', type=int, default=DEFAULT_N_RUNS,
                    help=f'Runs per batch (default: {DEFAULT_N_RUNS})')
    cl.add_argument('--rng-mode', choices=['urandom', 'rdseed'],
                    default='urandom',
                    help='Randomness source (default: urandom)')
    cl.add_argument('--stream', action='store_true',
                    help='Continuous streaming mode')

    # local
    lo = sub.add_parser('local', help='Run server+client locally (like old behavior)')
    lo.add_argument('--rng-mode', choices=['urandom', 'rdseed'],
                    default='urandom',
                    help='Randomness source (default: urandom)')
    lo.add_argument('--stream', action='store_true',
                    help='Continuous streaming mode')

    return parser


def main():
    # Backward compat: --urandom / --rdseed without a subcommand
    if len(sys.argv) > 1 and sys.argv[1].startswith('--'):
        has_urandom = '--urandom' in sys.argv
        has_rdseed = '--rdseed' in sys.argv
        has_stream = '--stream' in sys.argv

        if not has_urandom and not has_rdseed:
            # No recognized flag — fall through to argparse (prints help)
            pass
        else:
            rng_mode = 'rdseed' if has_rdseed else 'urandom'
            if has_stream:
                run_stream(rng_mode)
            else:
                run_single(rng_mode)
            return

    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    dispatch = {
        'keygen': cmd_keygen,
        'server': cmd_server,
        'client': cmd_client,
        'local':  cmd_local,
    }
    dispatch[args.command](args)


if __name__ == '__main__':
    main()
