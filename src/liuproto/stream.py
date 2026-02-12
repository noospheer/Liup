#!/usr/bin/env python

r"""Streaming OTP engine for real-time ITS communication.

Transforms the Liu protocol from batch key generation into a streaming
OTP engine that can encrypt TCP traffic in real time.

Architecture::

    Alice                              Bob
    StreamPhysics <-- binary wire --> StreamPhysics
         | Z_k per exchange                |
         v                                 v
    ChunkAccumulator (quantize + buffer)
         | chunk full -> Toeplitz hash
         v                                 v
    KeyBuffer (FIFO)                  KeyBuffer (FIFO)
         |                                 |
         v                                 v
    OTPCipher: plaintext XOR key     OTPCipher: ciphertext XOR key

After ramp-up (~60 exchanges), exchanges run continuously without reset.
Each exchange produces one Z sample on the fly via os.urandom + Box-Muller.
Z samples are accumulated into fixed-size chunks, and each chunk is
independently Toeplitz-hashed.  The LHL applies per-chunk since Z
samples are i.i.d. from true RNG.
"""

import hashlib
import math
import os
import struct
import socket
import json
import threading
import numpy as np

from . import leakage as _leakage_mod
from . import privacy as _privacy_mod
from . import security_proof as _sec_mod
from .wire import WireCodec


class AuthCipher:
    """Encrypts auth-channel bytes using a pre-shared key stream.

    Uses counter-mode ``SHAKE-256`` as a deterministic key stream
    generator: chunk *i* is ``SHAKE-256(key || i)`` where *i* is an
    8-byte big-endian counter.  This yields O(1) per chunk instead of
    the O(offset) cost of re-generating from byte 0 on every call.

    The pre-shared key must be at least 32 bytes of true randomness
    for meaningful security.

    Both parties initialise with the same PSK and consume key-stream
    bytes in the same order, so encrypt/decrypt are symmetric XOR
    operations.

    Parameters
    ----------
    pre_shared_key : bytes
        Shared secret, at least 32 bytes.
    """

    _CHUNK_SIZE = 8192

    def __init__(self, pre_shared_key: bytes):
        if not isinstance(pre_shared_key, (bytes, bytearray)):
            raise TypeError("pre_shared_key must be bytes")
        if len(pre_shared_key) < 32:
            raise ValueError(
                "pre_shared_key must be at least 32 bytes, got %d"
                % len(pre_shared_key))
        self._key = bytes(pre_shared_key)
        self._buf = bytearray()
        self._chunk_index = 0

    def _fill(self, min_bytes):
        """Ensure at least *min_bytes* are available in the buffer."""
        while len(self._buf) < min_bytes:
            h = hashlib.shake_256(
                self._key + self._chunk_index.to_bytes(8, 'big'))
            self._buf.extend(h.digest(self._CHUNK_SIZE))
            self._chunk_index += 1

    def encrypt(self, data: bytes) -> bytes:
        """XOR *data* with the next len(data) bytes of key stream."""
        n = len(data)
        self._fill(n)
        ks = bytes(self._buf[:n])
        del self._buf[:n]
        return bytes(a ^ b for a, b in zip(data, ks))

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt is identical to encrypt (XOR is self-inverse)."""
        return self.encrypt(data)


class StreamPhysics:
    """Streaming Liu protocol endpoint with on-the-fly noise generation.

    Unlike ``Physics``, this class runs indefinitely without pre-allocated
    arrays.  Each call to ``exchange()`` generates one Z_k sample via
    cached Box-Muller pairs from ``os.urandom``.

    Parameters
    ----------
    reflection_coefficient : float
        Feedback gain (sign is the secret).
    cutoff : float
        Band-limiting frequency, used to compute sigma_z.
    ramp_time : int
        Transient ramp-up time constant.
    modulus : float
        Mod-p wrapping period.
    sigma_z : float or None
        Standard deviation of Z_k.  If None, computed from cutoff.
    """

    def __init__(self, reflection_coefficient, cutoff, ramp_time,
                 modulus, sigma_z=None):
        self.reflection_coefficient = reflection_coefficient
        self.cutoff = cutoff
        self.ramp_time = ramp_time
        self.modulus = modulus
        self.sigma_z = (sigma_z if sigma_z is not None
                        else _leakage_mod.estimate_sigma_z(cutoff))

        # Sign is set once at construction via true random coin flip.
        if self._true_random_uniform() < 0.5:
            self.reflection_coefficient = -self.reflection_coefficient

        self._k = 0
        self._last_real_sent = 0.0

        # Box-Muller pair cache
        self._cached_gaussian = None

    def exchange(self, incoming_wire, incoming_real):
        """Perform one streaming exchange.

        Parameters
        ----------
        incoming_wire : float
            Mod-p wire value from the other party.
        incoming_real : float
            True (unwrapped) real value via the authenticated channel.

        Returns
        -------
        tuple
            (wire_value, real_value, z_sample) where wire_value is the
            mod-p wrapped output, real_value is the unwrapped output,
            and z_sample is the noise sample used.
        """
        z_k = self.sigma_z * self._next_gaussian()
        ramp_k = 1.0 - math.exp(-self._k / self.ramp_time)
        alpha = self.reflection_coefficient

        real_out = z_k + alpha * ramp_k * incoming_real
        wire_out = real_out - self.modulus * round(real_out / self.modulus)

        self._k += 1
        self._last_real_sent = real_out

        return wire_out, real_out, z_k

    def _next_gaussian(self):
        """Box-Muller with pair caching from os.urandom."""
        if self._cached_gaussian is not None:
            val = self._cached_gaussian
            self._cached_gaussian = None
            return val

        u1 = self._true_random_uniform()
        u2 = self._true_random_uniform()
        r = math.sqrt(-2.0 * math.log(u1))
        theta = 2.0 * math.pi * u2
        self._cached_gaussian = r * math.sin(theta)
        return r * math.cos(theta)

    @staticmethod
    def _true_random_uniform():
        """Return a single float in (0, 1) from os.urandom(8)."""
        while True:
            u = int.from_bytes(os.urandom(8), 'big') / (2**64)
            if u > 0.0:
                return u

    @property
    def is_settled(self):
        """True once the ramp-up transient has decayed."""
        return self._k >= 3 * self.ramp_time

    @property
    def exchange_count(self):
        """Number of exchanges performed so far."""
        return self._k


class ChunkAccumulator:
    """Buffers quantized Z bits and Toeplitz-hashes when a chunk is full.

    Parameters
    ----------
    chunk_steps : int
        Number of Z samples per chunk.
    n_bits : int
        Quantization bits per Z sample.
    sigma_z : float
        Standard deviation of Z_k.
    modulus : float
        Mod-p wrapping period (for security analysis).
    range_sigma : float
        Quantization range in sigma_z units (default 4.0).
    target_epsilon : float
        Target security parameter (default 1e-6).
    """

    def __init__(self, chunk_steps, n_bits, sigma_z, modulus,
                 range_sigma=4.0, target_epsilon=1e-6):
        self.chunk_steps = chunk_steps
        self.n_bits = n_bits
        self.sigma_z = sigma_z
        self.modulus = modulus
        self.range_sigma = range_sigma
        self.target_epsilon = target_epsilon

        self._R = range_sigma * sigma_z
        self._n_bins = 2 ** n_bits
        self._delta = 2.0 * self._R / self._n_bins
        # Precompute bit shift table for vectorized unpacking
        self._bit_shifts = np.arange(n_bits - 1, -1, -1, dtype=np.int32)

        # Compute secure output size via LHL
        self.n_raw = chunk_steps * n_bits
        step_info = _sec_mod.compute_z_pguess_per_step(
            sigma_z, modulus, n_bits=n_bits, range_sigma=range_sigma)
        self.h_min_per_step = step_info['h_min_per_step']

        secure_result = _sec_mod.compute_multibit_secure_length(
            chunk_steps, self.h_min_per_step,
            target_epsilon=target_epsilon)
        self.n_secure = secure_result['n_secure']

        # Pre-build a reusable PrivacyAmplification instance with
        # precomputed Toeplitz matrix.  Safe for independent chunks
        # (standard QKD result).
        if self.n_secure > 0:
            self._pa = _privacy_mod.PrivacyAmplification(
                self.n_raw, self.n_secure, seed=42, precompute=True)
        else:
            self._pa = None

        # Buffer for accumulating raw bits
        self._buffer = np.empty(self.n_raw, dtype=np.uint8)
        self._pos = 0

    def add_sample(self, z_value):
        """Add one Z sample.  Returns secure bits when chunk completes.

        Parameters
        ----------
        z_value : float
            A noise sample Z_k.

        Returns
        -------
        numpy.ndarray or None
            Secure bit array (length n_secure) when a chunk completes,
            or None if the chunk is still accumulating.
        """
        # Quantize z_value to n_bits
        z_clipped = max(-self._R, min(self._R - 1e-15, z_value))
        idx = int((z_clipped + self._R) / self._delta)
        idx = max(0, min(self._n_bins - 1, idx))

        # Vectorized bit unpacking via precomputed shift table
        self._buffer[self._pos:self._pos + self.n_bits] = \
            (idx >> self._bit_shifts) & 1
        self._pos += self.n_bits

        if self._pos >= self.n_raw:
            return self._flush()

        return None

    def _flush(self):
        """Hash the accumulated buffer and reset."""
        if self._pa is None:
            self._pos = 0
            return None

        result = self._pa.hash_fast(self._buffer)
        self._pos = 0
        return result

    @property
    def samples_in_buffer(self):
        """Number of Z samples currently accumulated."""
        return self._pos // self.n_bits


class KeyBuffer:
    """Thread-safe FIFO byte buffer for key material.

    Parameters
    ----------
    max_bytes : int
        Maximum buffer capacity in bytes (default 1,000,000).
    """

    _PACK_WEIGHTS = np.array([128, 64, 32, 16, 8, 4, 2, 1], dtype=np.uint8)

    def __init__(self, max_bytes=1_000_000):
        self.max_bytes = max_bytes
        self._buf = bytearray()
        self._cond = threading.Condition()

    def put(self, secure_bits):
        """Pack secure bits into bytes and append to the buffer.

        Parameters
        ----------
        secure_bits : numpy.ndarray
            Bit array (values 0 or 1).
        """
        bits = np.asarray(secure_bits, dtype=np.uint8)
        n_bytes = len(bits) // 8
        # Vectorized bit packing: reshape into (n_bytes, 8) and dot
        # with [128, 64, 32, 16, 8, 4, 2, 1]
        truncated = bits[:n_bytes * 8].reshape(n_bytes, 8)
        data = bytes(truncated @ self._PACK_WEIGHTS)

        with self._cond:
            # Drop oldest bytes if exceeding capacity
            space = self.max_bytes - len(self._buf)
            if len(data) > space:
                trim = len(data) - space
                self._buf = self._buf[trim:]
            self._buf.extend(data)
            self._cond.notify_all()

    def get(self, n_bytes, block=True, timeout=None):
        """Consume bytes from the front of the buffer.

        Parameters
        ----------
        n_bytes : int
            Number of bytes to retrieve.
        block : bool
            If True, block until enough bytes are available.
        timeout : float or None
            Maximum seconds to block (None = forever).

        Returns
        -------
        bytes
            Consumed key bytes.

        Raises
        ------
        ValueError
            If block=False and not enough bytes are available.
        """
        with self._cond:
            if block:
                while len(self._buf) < n_bytes:
                    if not self._cond.wait(timeout=timeout):
                        if len(self._buf) < n_bytes:
                            raise TimeoutError(
                                "Timed out waiting for %d key bytes "
                                "(have %d)" % (n_bytes, len(self._buf)))
            else:
                if len(self._buf) < n_bytes:
                    raise ValueError(
                        "Not enough key bytes: need %d, have %d" %
                        (n_bytes, len(self._buf)))

            result = bytes(self._buf[:n_bytes])
            self._buf = self._buf[n_bytes:]
            return result

    @property
    def available(self):
        """Number of bytes currently in the buffer."""
        with self._cond:
            return len(self._buf)


class OTPCipher:
    """One-time pad cipher backed by a KeyBuffer.

    Parameters
    ----------
    key_buffer : KeyBuffer
        Source of key material.
    """

    def __init__(self, key_buffer):
        self.key_buffer = key_buffer

    def encrypt(self, plaintext):
        """Encrypt plaintext by XOR with key material.

        Parameters
        ----------
        plaintext : bytes
            Data to encrypt.

        Returns
        -------
        bytes
            Ciphertext (same length as plaintext).
        """
        key = self.key_buffer.get(len(plaintext))
        # Vectorized XOR
        pt = np.frombuffer(plaintext, dtype=np.uint8)
        kt = np.frombuffer(key, dtype=np.uint8)
        return bytes(pt ^ kt)

    def decrypt(self, ciphertext):
        """Decrypt ciphertext by XOR with key material.

        Parameters
        ----------
        ciphertext : bytes
            Data to decrypt.

        Returns
        -------
        bytes
            Plaintext (same length as ciphertext).
        """
        return self.encrypt(ciphertext)  # XOR is its own inverse


class StreamPipe:
    """Local orchestrator wiring Alice and Bob for in-process testing.

    Parameters
    ----------
    cutoff : float
        Band-limiting frequency (default 0.1).
    ramp_time : int
        Ramp-up time constant (default 20).
    modulus_multiplier : float
        Modulus = multiplier * sigma_z (default 0.05).
    reflection_coefficient : float
        Feedback gain magnitude (default 0.5).
    chunk_steps : int
        Z samples per chunk (default 1001).
    n_bits : int
        Quantization bits per Z sample (default 8).
    target_epsilon : float
        Target security parameter (default 1e-6).
    """

    def __init__(self, cutoff=0.1, ramp_time=20, modulus_multiplier=0.05,
                 reflection_coefficient=0.5, chunk_steps=1001,
                 n_bits=8, target_epsilon=1e-6):
        sigma_z = _leakage_mod.estimate_sigma_z(cutoff)
        modulus = modulus_multiplier * sigma_z

        self._alice = StreamPhysics(
            reflection_coefficient=reflection_coefficient,
            cutoff=cutoff, ramp_time=ramp_time,
            modulus=modulus, sigma_z=sigma_z)
        self._bob = StreamPhysics(
            reflection_coefficient=reflection_coefficient,
            cutoff=cutoff, ramp_time=ramp_time,
            modulus=modulus, sigma_z=sigma_z)

        # Single shared accumulator: both parties interleave z_a and z_b
        # into the same stream, producing identical key material.
        # In a real deployment, each party reconstructs the other's Z
        # from M_real via the authenticated channel.
        self._accum = ChunkAccumulator(
            chunk_steps=chunk_steps, n_bits=n_bits,
            sigma_z=sigma_z, modulus=modulus,
            target_epsilon=target_epsilon)

        self._key_buf_a = KeyBuffer()
        self._key_buf_b = KeyBuffer()

        self._ramp_threshold = 3 * ramp_time
        self._exchanges = 0
        self._chunks_completed = 0

    def run(self, n_exchanges=None):
        """Run the exchange loop, filling key buffers.

        Parameters
        ----------
        n_exchanges : int or None
            Number of exchanges to run.  If None, runs until at least
            one chunk is completed.
        """
        target = n_exchanges
        done = 0

        # Initial exchange: Alice sends first
        wire_a, real_a, _ = self._alice.exchange(0.0, 0.0)

        while target is None or done < target:
            # Bob receives Alice's output
            wire_b, real_b, z_b = self._bob.exchange(wire_a, real_a)

            # Alice receives Bob's output
            wire_a, real_a, z_a = self._alice.exchange(wire_b, real_b)

            self._exchanges += 1
            done += 1

            # Skip ramp-up samples
            if not (self._alice.is_settled and self._bob.is_settled):
                continue

            # Both parties reconstruct both Z_a and Z_b from M_real
            # and feed them interleaved into the same accumulator.
            # Order: z_b first (Bob's exchange happened first), then z_a.
            for z in (z_b, z_a):
                secure = self._accum.add_sample(z)
                if secure is not None:
                    self._key_buf_a.put(secure)
                    self._key_buf_b.put(secure)
                    self._chunks_completed += 1

            # If no target set, stop after first chunk
            if target is None and self._chunks_completed > 0:
                break

    @property
    def key_buffer_alice(self):
        """Alice's key buffer."""
        return self._key_buf_a

    @property
    def key_buffer_bob(self):
        """Bob's key buffer."""
        return self._key_buf_b

    @property
    def stats(self):
        """Current statistics."""
        return {
            'exchanges': self._exchanges,
            'chunks_completed': self._chunks_completed,
            'secure_bytes_alice': self._key_buf_a.available,
            'secure_bytes_bob': self._key_buf_b.available,
            'n_secure_per_chunk': self._accum.n_secure,
            'h_min_per_step': self._accum.h_min_per_step,
        }


_Z_FRAME_SIZE = 8  # 2 wire (clear) + 6 encrypted (2 auth + 4 z)


def _encode_z_frame(codec, wire_value, real_value, z_value, cipher):
    """Encode a frame carrying wire, real, and z values.

    Layout: [2 wire clear][6 encrypted (2 auth + 4 z_float32)].
    """
    wire_bytes = codec.encode(wire_value)
    auth_bytes = codec.encode_auth(real_value)
    z_bytes = struct.pack('>f', z_value)
    return wire_bytes + cipher.encrypt(auth_bytes + z_bytes)


def _decode_z_frame(codec, data, cipher):
    """Decode a frame carrying wire, real, and z values.

    Returns (wire_value, real_value, z_value).
    """
    wire_val = codec.decode(data[:2])
    decrypted = cipher.decrypt(data[2:8])
    auth_val = codec.decode_auth(decrypted[:2])
    z_val = struct.unpack('>f', decrypted[2:6])[0]
    return wire_val, auth_val, z_val


class StreamServer:
    """TCP server for streaming OTP key generation.

    Parameters
    ----------
    address : tuple
        (host, port) to bind to.
    cutoff : float
        Band-limiting frequency.
    ramp_time : int
        Ramp-up time constant.
    modulus_multiplier : float
        Modulus = multiplier * sigma_z.
    reflection_coefficient : float
        Feedback gain magnitude.
    chunk_steps : int
        Z samples per chunk.
    n_bits : int
        Quantization bits per Z sample.
    target_epsilon : float
        Target security parameter.
    """

    def __init__(self, address, pre_shared_key, cutoff=0.1, ramp_time=20,
                 modulus_multiplier=0.05, reflection_coefficient=0.5,
                 chunk_steps=1001, n_bits=8, target_epsilon=1e-6):
        if not isinstance(pre_shared_key, (bytes, bytearray)):
            raise TypeError("pre_shared_key must be bytes")
        if len(pre_shared_key) < 32:
            raise ValueError(
                "pre_shared_key must be at least 32 bytes, got %d"
                % len(pre_shared_key))
        self._pre_shared_key = bytes(pre_shared_key)
        self._address = address
        self._params = {
            'cutoff': cutoff,
            'ramp_time': ramp_time,
            'modulus_multiplier': modulus_multiplier,
            'reflection_coefficient': reflection_coefficient,
            'chunk_steps': chunk_steps,
            'n_bits': n_bits,
            'target_epsilon': target_epsilon,
        }
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind(address)
        self._server_socket.listen(1)
        self._stop_event = threading.Event()

    def accept(self):
        """Block until a client connects and complete the handshake.

        Returns
        -------
        OTPCipher
            Cipher backed by the shared key stream.
        """
        conn, addr = self._server_socket.accept()

        # Receive params header from client
        header_len_data = conn.recv(4)
        header_len = struct.unpack('>I', header_len_data)[0]
        header_data = b''
        while len(header_data) < header_len:
            chunk = conn.recv(header_len - len(header_data))
            if not chunk:
                raise ConnectionError("Client disconnected during handshake")
            header_data += chunk

        client_params = json.loads(header_data.decode('utf-8'))

        # Validate client params match server's own config.
        # A misbehaving client must not dictate the server's physics.
        for key in self._params:
            if key not in client_params:
                conn.sendall(b'\x00')
                conn.close()
                raise ValueError(
                    "Client missing parameter %r" % key)
            sv, cv = self._params[key], client_params[key]
            if isinstance(sv, float):
                if abs(sv - cv) > 1e-12 * max(1.0, abs(sv)):
                    conn.sendall(b'\x00')
                    conn.close()
                    raise ValueError(
                        "Parameter mismatch: %s server=%r client=%r"
                        % (key, sv, cv))
            elif sv != cv:
                conn.sendall(b'\x00')
                conn.close()
                raise ValueError(
                    "Parameter mismatch: %s server=%r client=%r"
                    % (key, sv, cv))

        params = self._params  # use server's own params

        # Send ack
        conn.sendall(b'\x01')

        # Set up streaming engine
        sigma_z = _leakage_mod.estimate_sigma_z(params['cutoff'])
        modulus = params['modulus_multiplier'] * sigma_z

        physics = StreamPhysics(
            reflection_coefficient=params['reflection_coefficient'],
            cutoff=params['cutoff'],
            ramp_time=params['ramp_time'],
            modulus=modulus, sigma_z=sigma_z)

        accum = ChunkAccumulator(
            chunk_steps=params['chunk_steps'],
            n_bits=params['n_bits'],
            sigma_z=sigma_z, modulus=modulus,
            target_epsilon=params['target_epsilon'])

        key_buf = KeyBuffer()
        codec = WireCodec(modulus, auth_range=max(2.0, 10.0 * sigma_z))

        # Create per-direction auth ciphers from the PSK.
        # Client→Server uses tag b'C', Server→Client uses tag b'S'.
        enc_cipher = AuthCipher(self._pre_shared_key + b'S')
        dec_cipher = AuthCipher(self._pre_shared_key + b'C')

        ramp_threshold = 3 * params['ramp_time']

        # Start exchange loop in background thread
        # Bob is the server (second mover)
        def _exchange_loop():
            try:
                # Receive Alice's first frame (includes her z)
                frame = _recv_exact(conn, _Z_FRAME_SIZE)
                if frame is None:
                    return
                wire_in, real_in, z_alice = _decode_z_frame(
                    codec, frame, dec_cipher)

                k = 0
                while not self._stop_event.is_set():
                    # Bob exchange
                    wire_out, real_out, z_bob = physics.exchange(
                        wire_in, real_in)

                    # Send Bob's frame (includes his z)
                    conn.sendall(_encode_z_frame(
                        codec, wire_out, real_out, z_bob, enc_cipher))

                    k += 1

                    # Accumulate both z values (z_bob then z_alice)
                    # matching StreamPipe's interleave order.
                    if k >= ramp_threshold:
                        for z in (z_bob, z_alice):
                            secure = accum.add_sample(z)
                            if secure is not None:
                                key_buf.put(secure)

                    # Receive Alice's next frame
                    frame = _recv_exact(conn, _Z_FRAME_SIZE)
                    if frame is None:
                        break
                    wire_in, real_in, z_alice = _decode_z_frame(
                        codec, frame, dec_cipher)
            except (ConnectionError, OSError):
                pass

        thread = threading.Thread(target=_exchange_loop, daemon=True)
        thread.start()

        return OTPCipher(key_buf)

    def close(self):
        """Stop the server."""
        self._stop_event.set()
        self._server_socket.close()


class StreamClient:
    """TCP client for streaming OTP key generation.

    Parameters
    ----------
    address : tuple
        (host, port) to connect to.
    cutoff : float
        Band-limiting frequency.
    ramp_time : int
        Ramp-up time constant.
    modulus_multiplier : float
        Modulus = multiplier * sigma_z.
    reflection_coefficient : float
        Feedback gain magnitude.
    chunk_steps : int
        Z samples per chunk.
    n_bits : int
        Quantization bits per Z sample.
    target_epsilon : float
        Target security parameter.
    """

    def __init__(self, address, pre_shared_key, cutoff=0.1, ramp_time=20,
                 modulus_multiplier=0.05, reflection_coefficient=0.5,
                 chunk_steps=1001, n_bits=8, target_epsilon=1e-6):
        if not isinstance(pre_shared_key, (bytes, bytearray)):
            raise TypeError("pre_shared_key must be bytes")
        if len(pre_shared_key) < 32:
            raise ValueError(
                "pre_shared_key must be at least 32 bytes, got %d"
                % len(pre_shared_key))
        self._pre_shared_key = bytes(pre_shared_key)
        self._address = address
        self._params = {
            'cutoff': cutoff,
            'ramp_time': ramp_time,
            'modulus_multiplier': modulus_multiplier,
            'reflection_coefficient': reflection_coefficient,
            'chunk_steps': chunk_steps,
            'n_bits': n_bits,
            'target_epsilon': target_epsilon,
        }
        self._stop_event = threading.Event()

    def connect(self):
        """Connect to server and start key generation.

        Returns
        -------
        OTPCipher
            Cipher backed by the shared key stream.
        """
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.connect(self._address)

        # Send params header
        header = json.dumps(self._params).encode('utf-8')
        conn.sendall(struct.pack('>I', len(header)))
        conn.sendall(header)

        # Wait for ack
        ack = conn.recv(1)
        if ack != b'\x01':
            raise ConnectionError("Server rejected handshake")

        # Set up streaming engine
        params = self._params
        sigma_z = _leakage_mod.estimate_sigma_z(params['cutoff'])
        modulus = params['modulus_multiplier'] * sigma_z

        physics = StreamPhysics(
            reflection_coefficient=params['reflection_coefficient'],
            cutoff=params['cutoff'],
            ramp_time=params['ramp_time'],
            modulus=modulus, sigma_z=sigma_z)

        accum = ChunkAccumulator(
            chunk_steps=params['chunk_steps'],
            n_bits=params['n_bits'],
            sigma_z=sigma_z, modulus=modulus,
            target_epsilon=params['target_epsilon'])

        key_buf = KeyBuffer()
        codec = WireCodec(modulus, auth_range=max(2.0, 10.0 * sigma_z))

        # Create per-direction auth ciphers from the PSK.
        # Client→Server uses tag b'C', Server→Client uses tag b'S'.
        enc_cipher = AuthCipher(self._pre_shared_key + b'C')
        dec_cipher = AuthCipher(self._pre_shared_key + b'S')

        ramp_threshold = 3 * params['ramp_time']

        # Start exchange loop in background thread
        # Alice is the client (first mover)
        def _exchange_loop():
            try:
                # Alice's first exchange
                wire_out, real_out, z_alice_prev = physics.exchange(
                    0.0, 0.0)
                conn.sendall(_encode_z_frame(
                    codec, wire_out, real_out, z_alice_prev, enc_cipher))

                k = 0
                while not self._stop_event.is_set():
                    # Receive Bob's frame (includes his z)
                    frame = _recv_exact(conn, _Z_FRAME_SIZE)
                    if frame is None:
                        break
                    wire_in, real_in, z_bob = _decode_z_frame(
                        codec, frame, dec_cipher)

                    # Alice exchange
                    wire_out, real_out, z_alice = physics.exchange(
                        wire_in, real_in)

                    # Send Alice's frame (includes her z)
                    conn.sendall(_encode_z_frame(
                        codec, wire_out, real_out, z_alice, enc_cipher))

                    k += 1

                    # Accumulate both z values (z_bob then z_alice_prev)
                    # z_alice_prev is the z Alice sent in the frame that
                    # Bob used for THIS exchange, matching Bob's pairing.
                    if k >= ramp_threshold:
                        for z in (z_bob, z_alice_prev):
                            secure = accum.add_sample(z)
                            if secure is not None:
                                key_buf.put(secure)

                    z_alice_prev = z_alice

            except (ConnectionError, OSError):
                pass

        thread = threading.Thread(target=_exchange_loop, daemon=True)
        thread.start()

        return OTPCipher(key_buf)

    def close(self):
        """Stop the client."""
        self._stop_event.set()


def _recv_exact(sock, n):
    """Receive exactly n bytes from a socket, or None on disconnect."""
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data
