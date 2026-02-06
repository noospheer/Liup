#!/usr/bin/env python

"""Implements local and networked links for the Liu protocol implementation.
"""

from . import endpoint
from . import storage
from . import privacy as _privacy_mod
from . import leakage as _leakage_mod
from . import reconciliation as _recon_mod
from . import security_proof as _sec_mod
from .stream import AuthCipher
import socketserver
import socket
import json
import sys
import base64
import struct
import hashlib
import math as _math
import os
import numpy as np
import ctypes as _ctypes

# Try to load the C extension for fast noise generation.
# Falls back to pure Python/numpy if unavailable.
_fastrand_lib = None
_has_rdseed = False
try:
    _so_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '_fastrand.so')
    _fastrand_lib = _ctypes.CDLL(_so_path)
    _fastrand_lib.batch_gaussian.restype = _ctypes.c_int
    _fastrand_lib.batch_gaussian.argtypes = [_ctypes.c_void_p, _ctypes.c_int]
    _fastrand_lib.has_rdseed.restype = _ctypes.c_int
    _fastrand_lib.batch_rdseed.restype = _ctypes.c_int
    _fastrand_lib.batch_rdseed.argtypes = [_ctypes.c_void_p, _ctypes.c_int]
    _fastrand_lib.toeplitz_extract.restype = _ctypes.c_int
    _fastrand_lib.toeplitz_extract.argtypes = [
        _ctypes.c_void_p, _ctypes.c_int,
        _ctypes.c_void_p, _ctypes.c_void_p]
    _has_rdseed = bool(_fastrand_lib.has_rdseed())
except (OSError, AttributeError):
    _fastrand_lib = None


def _encode_real(value, cipher):
    """Pack float64 -> 8 bytes -> encrypt -> base64 for JSON."""
    raw = struct.pack('>d', value)
    return base64.b64encode(cipher.encrypt(raw)).decode('ascii')


def _decode_real(b64str, cipher):
    """base64 -> decrypt -> unpack float64."""
    raw = cipher.decrypt(base64.b64decode(b64str))
    return struct.unpack('>d', raw)[0]


_MERSENNE_61 = (1 << 61) - 1
_M61_U64 = np.uint64((1 << 61) - 1)
_MASK30 = np.uint64((1 << 30) - 1)
_MASK31 = np.uint64((1 << 31) - 1)
_U64_1 = np.uint64(1)
_U64_30 = np.uint64(30)
_U64_31 = np.uint64(31)
_U64_60 = np.uint64(60)
_U64_61 = np.uint64(61)

_CHISQ_CRITICAL_15 = 70.0        # chi² critical value, df=15, p≈1.2e-8
_SIGMA_P_MIN_THRESHOLD = 1.8     # minimum σ/p for committed verification
_DEFAULT_N_TEST_ROUNDS = 2       # test rounds at session start


class SigmaDriftError(RuntimeError):
    """sigma/p ratio degraded below safe threshold. Restart session."""
    pass


def _mulmod_m61_vec(a, b):
    """Vectorized (a * b) mod (2^61-1) for uint64 arrays.

    Uses 30/31-bit split to avoid uint64 overflow.
    """
    a = np.asarray(a, dtype=np.uint64)
    b = np.asarray(b, dtype=np.uint64)

    a_lo = a & _MASK30                     # < 2^30
    a_hi = a >> _U64_30                    # < 2^31
    b_lo = b & _MASK30
    b_hi = b >> _U64_30

    p_ll = a_lo * b_lo                     # < 2^60
    p_hl = a_hi * b_lo                     # < 2^61
    p_lh = a_lo * b_hi                     # < 2^61
    p_hh = a_hi * b_hi                     # < 2^62

    mid = p_hl + p_lh                      # < 2^62

    # p_hh * 2^60 mod M61: using 2^61 ≡ 1
    term_hh = (p_hh >> _U64_1) + ((p_hh & _U64_1) << _U64_60)

    # mid * 2^30 mod M61
    term_mid = (mid >> _U64_31) + ((mid & _MASK31) << _U64_30)

    total = term_hh + term_mid + p_ll      # < ~2^62.6

    # Final reduction
    hi = total >> _U64_61
    lo = total & _M61_U64
    result = hi + lo
    return np.where(result >= _M61_U64, result - _M61_U64, result)


def _addmod_m61_vec(a, b):
    """Vectorized (a + b) mod (2^61-1)."""
    s = np.asarray(a, dtype=np.uint64) + np.asarray(b, dtype=np.uint64)
    hi = s >> _U64_61
    lo = s & _M61_U64
    result = hi + lo
    return np.where(result >= _M61_U64, result - _M61_U64, result)


def _its_mac_tag(coeffs, r, s):
    """Wegman-Carter MAC: polynomial eval at r, OTP with s, mod 2^61-1."""
    h = 0
    for c in coeffs:
        h = ((h * r) + c) % _MERSENNE_61
    return (h + s) % _MERSENNE_61


def _its_mac_tag_tree(coeffs, r, s):
    """Wegman-Carter MAC via tree reduction.

    Evaluates the same polynomial as _its_mac_tag but using O(log n)
    sequential vectorized numpy steps instead of n sequential Python steps.
    """
    M = _MERSENNE_61
    if not coeffs:
        return s % M

    q = np.array(coeffs, dtype=np.uint64)
    power = int(r) % M

    while len(q) > 1:
        if len(q) % 2 == 1:
            q = np.concatenate([np.array([np.uint64(0)]), q])
        evens = q[0::2]
        odds = q[1::2]
        q = _addmod_m61_vec(
            _mulmod_m61_vec(evens, np.uint64(power)), odds)
        power = (power * power) % M

    h = int(q[0])
    return (h + s) % M


def _psk_mac_keys(psk, run_idx):
    """Extract (r, s) from PSK for run run_idx. Consumes bytes [32+run_idx*18+2 .. +17]."""
    off = 32 + run_idx * 18 + 2
    r = int.from_bytes(psk[off:off+8], 'big') % _MERSENNE_61
    s = int.from_bytes(psk[off+8:off+16], 'big') % _MERSENNE_61
    return r, s


def _psk_alpha_otp(psk, run_idx, role_offset):
    """Extract 1-bit OTP for alpha sign. role_offset: 0=Alice, 1=Bob."""
    return psk[32 + run_idx * 18 + role_offset] & 1


def _z_to_mac_coeffs(z_a, z_b, clean_a, clean_b, sigma_z, n_bits=4, range_sigma=4.0):
    """Quantize clean Z values to integer bin indices for MAC input."""
    R = range_sigma * sigma_z
    n_bins = 2 ** n_bits
    delta = 2.0 * R / n_bins
    z_combined = np.concatenate([z_a[clean_a], z_b[clean_b]])
    return np.clip(((z_combined + R) / delta).astype(int), 0, n_bins - 1).tolist()


def _validate_its_psk(psk, n_runs):
    """Raise ValueError if PSK too short for n_runs of ITS protocol."""
    required = 32 + n_runs * 18
    if not isinstance(psk, (bytes, bytearray)) or len(psk) < required:
        raise ValueError("PSK must be >= %d bytes for %d ITS runs" % (required, n_runs))


def _wire_decode_step(wire_val, center, p):
    """Unwrap a single wire value around a known center.

    Returns (z_hat, reliability, wrap_count) where reliability is in
    [0, 0.5]: 0 = maximally ambiguous, 0.5 = perfectly centred.
    """
    n = round((center - wire_val) / p)
    real_val = wire_val + n * p
    frac = (center - wire_val) / p - n   # in (-0.5, 0.5]
    reliability = 0.5 - abs(frac)
    return real_val - center, reliability, int(n)


def _wire_decode_z_all(wire_a, wire_b, alpha_a, alpha_b, ramp_fn, p):
    """Decode Z_a and Z_b from wire values using known-alpha centers.

    Both parties can call this identically since all inputs are known.

    Parameters
    ----------
    wire_a : list of float, length n_ex + 1
        Alice's wire values W_a[0..n_ex].
    wire_b : list of float, length n_ex
        Bob's wire values W_b[0..n_ex-1].
    alpha_a, alpha_b : float
        Reflection coefficients (signs known via OTP).
    ramp_fn : callable
        Takes array of indices, returns ramp values.
    p : float
        Modulus.

    Returns
    -------
    z_a, z_b : ndarray
    rel_a, rel_b : ndarray   (per-step reliability)
    wrap_a, wrap_b : ndarray of int
    """
    n_ex = len(wire_b)

    z_a = np.empty(n_ex + 1)
    rel_a = np.empty(n_ex + 1)
    wrap_a = np.empty(n_ex + 1, dtype=int)

    # Z_a[0]: center = 0 (ramp(0) = 0)
    z_a[0], rel_a[0], wrap_a[0] = _wire_decode_step(wire_a[0], 0.0, p)

    for k in range(1, n_ex + 1):
        ramp_k = ramp_fn([k])[0]
        center = alpha_a * ramp_k * wire_b[k - 1]
        z_a[k], rel_a[k], wrap_a[k] = _wire_decode_step(wire_a[k], center, p)

    z_b = np.empty(n_ex)
    rel_b = np.empty(n_ex)
    wrap_b = np.empty(n_ex, dtype=int)

    for i in range(n_ex):
        ramp_i = ramp_fn([i])[0]
        center = alpha_b * ramp_i * wire_a[i]
        z_b[i], rel_b[i], wrap_b[i] = _wire_decode_step(wire_b[i], center, p)

    return z_a, z_b, rel_a, rel_b, wrap_a, wrap_b


def _search_decode(coeffs, r, s, target_tag, borderline_idx, delta_bins,
                   r_powers, max_flip=8):
    """Search decoder: flip borderline wrapping counts to match MAC tag.

    Uses incremental tag updates: changing coefficient j by delta changes
    the polynomial hash by delta * r^(n-1-j).

    Parameters
    ----------
    coeffs : list of int
        Initial quantized bin indices.
    r, s : int
        Wegman-Carter MAC key components.
    target_tag : int
        Tag to match.
    borderline_idx : list of int
        Indices into coeffs of the most borderline steps, sorted by
        ascending reliability (most ambiguous first).
    delta_bins : list of int
        For each borderline step, the bin index change if we flip the
        wrapping count (can be positive or negative).
    r_powers : list of int
        Precomputed r^(n-1-j) mod M for each position j in coeffs.
    max_flip : int
        Maximum number of steps to try flipping (default 8 → 2^8 = 256).

    Returns
    -------
    list of int or None
        Corrected coefficients if match found, else None.
    """
    M = _MERSENNE_61
    K = min(len(borderline_idx), max_flip)
    if K == 0:
        return None

    init_tag_no_s = (_its_mac_tag(coeffs, r, 0)) % M
    target_no_s = (target_tag - s) % M

    # Precompute tag deltas for each borderline position
    tag_deltas = []
    for i in range(K):
        j = borderline_idx[i]
        tag_deltas.append((delta_bins[i] * r_powers[j]) % M)

    # Enumerate 2^K combinations (Gray code not needed for K <= 8)
    for mask in range(1, 1 << K):
        tag_mod = init_tag_no_s
        for bit in range(K):
            if mask & (1 << bit):
                tag_mod = (tag_mod + tag_deltas[bit]) % M
        if (tag_mod + s) % M == target_tag:
            # Found match — apply corrections
            corrected = list(coeffs)
            for bit in range(K):
                if mask & (1 << bit):
                    j = borderline_idx[bit]
                    corrected[j] += delta_bins[bit]
            return corrected

    return None


def _compute_r_powers(n, r):
    """Precompute r^(n-1), r^(n-2), ..., r^0 mod Mersenne-61."""
    M = _MERSENNE_61
    powers = [0] * n
    powers[n - 1] = 1
    for j in range(n - 2, -1, -1):
        powers[j] = (powers[j + 1] * r) % M
    return powers


def _batch_rdseed_raw(n_bytes):
    """Read n_bytes of raw RDSEED output via the C extension.

    Returns bytes.  Raises RuntimeError if RDSEED is unavailable or fails.
    """
    if not _has_rdseed or _fastrand_lib is None:
        raise RuntimeError(
            "RDSEED not available (CPU does not support it or C extension missing)")
    buf = (_ctypes.c_uint8 * n_bytes)()
    ret = _fastrand_lib.batch_rdseed(buf, n_bytes)
    if ret != 0:
        raise RuntimeError("RDSEED failed after retries")
    return bytes(buf)


# Toeplitz matrix cache (for numpy fallback path only)
_toeplitz_cache = {}


def _toeplitz_extract(raw_bytes, seed_bytes, ratio=2):
    """Block-wise Toeplitz extraction: 512-bit blocks -> 256-bit output blocks.

    Uses the C extension (_fastrand.so) for ~100x speedup over numpy.
    Falls back to pure numpy if C extension is unavailable.

    Parameters
    ----------
    raw_bytes : bytes
        Input bytes (must be a multiple of 64 = 512/8).
    seed_bytes : bytes
        96 bytes (767 bits) defining the Toeplitz matrix rows.
    ratio : int
        Compression ratio (default 2: 512 -> 256 bits per block).

    Returns
    -------
    bytes
        Extracted output (half the length of raw_bytes).
    """
    in_bits = 512
    out_bits = in_bits // ratio  # 256
    block_bytes_in = in_bits // 8  # 64
    block_bytes_out = out_bits // 8  # 32

    n_blocks = len(raw_bytes) // block_bytes_in
    if n_blocks == 0:
        return b''

    # Fast C path: AND + popcount per row, ~100x faster than numpy
    if _fastrand_lib is not None:
        out_size = n_blocks * block_bytes_out
        out_buf = (_ctypes.c_uint8 * out_size)()
        ret = _fastrand_lib.toeplitz_extract(
            raw_bytes, n_blocks * block_bytes_in,
            seed_bytes, out_buf)
        if ret > 0:
            return bytes(out_buf)[:ret]

    # Numpy fallback
    cache_key = seed_bytes
    if cache_key not in _toeplitz_cache:
        seed_bits = np.unpackbits(np.frombuffer(seed_bytes[:96], dtype=np.uint8))
        n_seed = in_bits + out_bits - 1  # 767
        seed_bits = seed_bits[:n_seed]
        rows = np.empty((out_bits, in_bits), dtype=np.int16)
        for i in range(out_bits):
            rows[i] = seed_bits[i:i + in_bits].astype(np.int16)
        _toeplitz_cache[cache_key] = rows
    toeplitz = _toeplitz_cache[cache_key]

    raw_arr = np.frombuffer(raw_bytes[:n_blocks * block_bytes_in], dtype=np.uint8)
    bits_in = np.unpackbits(raw_arr).reshape(n_blocks, in_bits).astype(np.int16)
    bits_out = (bits_in @ toeplitz.T) % 2
    return np.packbits(bits_out.astype(np.uint8).ravel()).tobytes()[:n_blocks * block_bytes_out]


def _rng_bytes(n_bytes, rng_mode='urandom', toeplitz_seed=None):
    """Unified random byte generation for sign bits and nonces.

    Parameters
    ----------
    n_bytes : int
        Number of output bytes.
    rng_mode : str
        'urandom' or 'rdseed'.
    toeplitz_seed : bytes or None
        96-byte seed for Toeplitz extraction (required for rdseed mode).

    Returns
    -------
    bytes
    """
    if rng_mode == 'rdseed':
        # Toeplitz works in 64-byte input blocks (512 bits) -> 32-byte output blocks.
        # Round up RDSEED request to ensure enough full blocks after extraction.
        n_out_blocks = (n_bytes + 31) // 32  # ceil(n_bytes / 32)
        raw_needed = n_out_blocks * 64  # 2:1 ratio
        raw = _batch_rdseed_raw(raw_needed)
        return _toeplitz_extract(raw, toeplitz_seed)[:n_bytes]
    return os.urandom(n_bytes)


def _batch_true_random_gaussian(n, B, rng_mode='urandom', toeplitz_seed=None):
    """Generate B x n IID standard Gaussians via Box-Muller with getrandom().

    Uses the C extension (_fastrand.so) when available for ~2x speedup.
    Falls back to pure numpy otherwise.  Both paths use the same entropy
    source (Linux urandom pool via getrandom / os.urandom).

    Parameters
    ----------
    n : int
        Number of columns.
    B : int
        Number of rows (channels).
    rng_mode : str
        'urandom' (default) or 'rdseed'.
    toeplitz_seed : bytes or None
        96-byte seed for Toeplitz extraction (required for rdseed mode).
    """
    total = B * n
    if rng_mode == 'urandom' and _fastrand_lib is not None:
        out = np.empty(total, dtype=np.float64)
        ret = _fastrand_lib.batch_gaussian(out.ctypes.data, total)
        if ret == 0:
            return out.reshape(B, n)
        # Fall through to Python implementation on error
    n_pairs = (total + 1) // 2
    raw_needed = n_pairs * 16
    if rng_mode == 'rdseed':
        # Round up to full 64-byte Toeplitz input blocks (2:1 ratio)
        n_out_blocks = (raw_needed + 31) // 32
        rdseed_raw = _batch_rdseed_raw(n_out_blocks * 64)
        raw = _toeplitz_extract(rdseed_raw, toeplitz_seed)[:raw_needed]
    else:
        raw = os.urandom(raw_needed)
    u64 = np.frombuffer(raw, dtype=np.uint64)
    scale = np.float64(1.0 / (2**64))
    u1 = (u64[0::2] * scale).copy()
    u2 = (u64[1::2] * scale).copy()
    np.maximum(u1, 1e-300, out=u1)
    np.log(u1, out=u1)
    u1 *= -2.0
    np.sqrt(u1, out=u1)
    u2 *= 2.0 * np.pi
    cos_t = np.cos(u2)
    sin_t = np.sin(u2)
    samples = np.empty(2 * n_pairs)
    samples[0::2] = u1 * cos_t
    samples[1::2] = u1 * sin_t
    return samples[:total].reshape(B, n)


def _validate_parallel_psk(psk, n_runs, B):
    """Validate PSK length for parallel ITS protocol."""
    per_run = _math.ceil(B / 4) + 16
    required = 32 + n_runs * per_run
    if not isinstance(psk, (bytes, bytearray)) or len(psk) < required:
        raise ValueError("PSK must be >= %d bytes for %d parallel ITS runs with B=%d" % (required, n_runs, B))


def _derive_next_psk(secure_bits, n_runs, B):
    """Derive next PSK from secure key output for key recycling.

    Returns (next_psk, remaining_bits) where next_psk is bytes and
    remaining_bits is the usable secure key (numpy uint8 array).
    Returns (None, secure_bits) if output is too short.
    """
    per_run = _math.ceil(B / 4) + 16
    psk_bytes_needed = 32 + n_runs * per_run
    psk_bits_needed = psk_bytes_needed * 8

    if len(secure_bits) < psk_bits_needed + 64:  # need at least 8 usable bytes
        return None, secure_bits

    psk_raw = secure_bits[:psk_bits_needed]
    remaining = secure_bits[psk_bits_needed:]

    # Pack bits into bytes
    next_psk = bytes(np.packbits(psk_raw))[:psk_bytes_needed]
    return next_psk, remaining


def _validate_signbit_psk(psk, n_runs, B):
    """Validate PSK length for signbit ITS protocol.

    PSK layout per run: ceil(B/8) bytes for Bob's sign OTP + 16 bytes for MAC keys.
    Plus 32 bytes header.
    """
    per_run = _math.ceil(B / 8) + 16
    required = 32 + n_runs * per_run
    if not isinstance(psk, (bytes, bytearray)) or len(psk) < required:
        raise ValueError("PSK must be >= %d bytes for %d signbit ITS runs with B=%d"
                         % (required, n_runs, B))


def _psk_signbit_bob_otp(psk, run_idx, B):
    """Extract B OTP bits for Bob's signs from PSK."""
    per_run = _math.ceil(B / 8) + 16
    off = 32 + run_idx * per_run
    n_bytes = _math.ceil(B / 8)
    raw = np.frombuffer(psk[off:off + n_bytes], dtype=np.uint8)
    return np.unpackbits(raw)[:B].astype(np.uint8)


def _psk_signbit_mac_keys(psk, run_idx, B):
    """Extract (r, s) from PSK for signbit protocol."""
    per_run = _math.ceil(B / 8) + 16
    off = 32 + run_idx * per_run + _math.ceil(B / 8)
    r = int.from_bytes(psk[off:off+8], 'big') % _MERSENNE_61
    s = int.from_bytes(psk[off+8:off+16], 'big') % _MERSENNE_61
    return r, s


def _derive_next_signbit_psk(secure_bits, n_runs, B):
    """Derive next PSK from sign-bit output for key recycling.

    Returns (next_psk, remaining_bits) where next_psk is bytes and
    remaining_bits is the usable secure key (numpy uint8 array).
    Returns (None, secure_bits) if output is too short.
    """
    per_run = _math.ceil(B / 8) + 16
    psk_bytes_needed = 32 + n_runs * per_run
    psk_bits_needed = psk_bytes_needed * 8

    if len(secure_bits) < psk_bits_needed + 64:  # need at least 8 usable bytes
        return None, secure_bits

    psk_raw = secure_bits[:psk_bits_needed]
    remaining = secure_bits[psk_bits_needed:]

    next_psk = bytes(np.packbits(psk_raw))[:psk_bytes_needed]
    return next_psk, remaining


def _signbit_mac_coeffs(wa0, wb0, sigma_z, n_bits, range_sigma,
                        sign_enc=None):
    """Compute MAC polynomial coefficients from wire values and encrypted signs.

    Shared helper for signbit MAC computation: quantize combined wire
    values into bins and pack into polynomial coefficients. If sign_enc
    is provided, the encrypted sign bytes are appended to the coefficient
    list, authenticating the full message (closes active MITM gap).

    Returns list of int coefficients for _its_mac_tag_tree.
    """
    R = range_sigma * sigma_z
    n_bins = 2 ** n_bits
    delta_q = 2.0 * R / n_bins
    wire_combined = np.concatenate([wa0, wb0])
    bins = np.clip(((wire_combined + R) / delta_q).astype(np.int64),
                    0, n_bins - 1)
    bins_per_pack = 61 // n_bits
    flat = bins
    n_total = len(flat)
    pad_n = (-n_total) % bins_per_pack
    if pad_n:
        flat = np.concatenate([flat, np.zeros(pad_n, dtype=np.int64)])
    base = int(n_bins)
    groups = flat.reshape(-1, bins_per_pack)
    pw = np.array([base ** (bins_per_pack - 1 - i)
                   for i in range(bins_per_pack)], dtype=np.int64)
    coeffs = (groups @ pw).tolist()

    # Append encrypted sign bytes as additional coefficients (0-255 each)
    if sign_enc is not None:
        sign_arr = np.asarray(sign_enc, dtype=np.uint8)
        coeffs.extend(sign_arr.tolist())

    return coeffs


def _config_mac_tag(config_dict, psk, nonce):
    """Compute ITS MAC over config dict using PSK bytes 16-31 XOR nonce.

    One-time polynomial MAC. The MAC key (r, s) is derived from PSK XOR nonce,
    ensuring each session has a unique key even if the same PSK is reused.
    This prevents the two-message key recovery attack on polynomial MACs.

    Security: Even if Eve sees multiple (config, tag) pairs from different
    sessions with the same PSK, she can't recover the PSK bytes because each
    session uses PSK XOR nonce_i, and nonces are random.
    """
    # XOR nonce into key derivation — makes (r, s) unique per session
    r_bytes = bytes(a ^ b for a, b in zip(psk[16:24], nonce[0:8]))
    s_bytes = bytes(a ^ b for a, b in zip(psk[24:32], nonce[8:16]))
    r_cfg = int.from_bytes(r_bytes, 'big') % _MERSENNE_61
    s_cfg = int.from_bytes(s_bytes, 'big') % _MERSENNE_61
    config_bytes = json.dumps(config_dict, sort_keys=True).encode('utf-8')
    coeffs = list(config_bytes)
    return _its_mac_tag_tree(coeffs, r_cfg, s_cfg)


def _verify_config_mac(config_dict, psk):
    """Verify config MAC tag. Returns (config_dict, nonce) with tag removed.

    If tag present: verify using embedded nonce, raise SigmaDriftError on mismatch.
    If tag absent: return (config_dict, None) for backward compat with old clients.

    The nonce is returned so it can be used to derive session-specific MAC keys
    for the run MACs (preventing PSK reuse attacks).
    """
    cfg_tag = config_dict.pop('config_tag', None)
    nonce_hex = config_dict.pop('config_nonce', None)
    if cfg_tag is None:
        return config_dict, None  # backward compat
    if nonce_hex is None:
        raise SigmaDriftError("Config authentication failed: missing nonce")
    nonce = bytes.fromhex(nonce_hex)
    expected = _config_mac_tag(config_dict, psk, nonce)
    if cfg_tag != expected:
        raise SigmaDriftError("Config authentication failed: possible MITM")
    return config_dict, nonce


def _check_wire_uniformity(wire_values, p, n_bins=16):
    """Check that wire values are approximately uniform in (-p/2, p/2].

    Uses chi-squared test with n_bins equal-width bins.
    Raises SigmaDriftError if chi² exceeds _CHISQ_CRITICAL_15.

    Returns chi² statistic for tracking.
    """
    bin_edges = np.linspace(-p / 2, p / 2, n_bins + 1)
    observed, _ = np.histogram(wire_values, bins=bin_edges)
    expected = len(wire_values) / n_bins
    chi2 = float(np.sum((observed - expected) ** 2 / expected))
    if chi2 > _CHISQ_CRITICAL_15:
        raise SigmaDriftError(
            "Wire uniformity check failed: chi2=%.1f > %.1f (df=%d)"
            % (chi2, _CHISQ_CRITICAL_15, n_bins - 1))
    return chi2


def _validate_signbit_nopa_psk(psk, B, rng_mode='urandom'):
    """Validate PSK length for signbit no-PA protocol.

    Minimum PSK: 32 bytes header + ceil(B/8) bytes for first run OTP.
    In rdseed mode, 96 extra bytes are required for the Toeplitz seed.
    B must be >= 128 for MAC key recycling from output.
    """
    if B < 128:
        raise ValueError("B must be >= 128 for MAC key recycling, got %d" % B)
    required = 32 + _math.ceil(B / 8)
    if rng_mode == 'rdseed':
        required += 96  # Toeplitz seed bytes
    if not isinstance(psk, (bytes, bytearray)) or len(psk) < required:
        raise ValueError("PSK must be >= %d bytes for signbit no-PA with B=%d (rng_mode=%s)"
                         % (required, B, rng_mode))


class _SignbitPool:
    """Dynamic byte pool for signbit no-PA protocol.

    FIFO buffer: withdraw OTP bytes for each run, deposit agreed sign
    bits after MAC verification.  MAC keys are recycled from deposited
    output, not from the pool itself.

    Pool stays flat: withdraw ceil(B/8) bytes, deposit ceil(B/8) bytes.
    """

    def __init__(self, psk, session_nonce=None):
        """Initialize pool from PSK and optional session nonce.

        PSK layout: bytes 0-15 = initial MAC key seed, bytes 32+ = pool data.

        If session_nonce is provided (16 bytes), it is XORed into the initial
        MAC key derivation. This ensures each session has unique MAC keys even
        if the same PSK is reused, preventing the polynomial MAC key recovery
        attack from two-message observations.
        """
        if len(psk) < 32:
            raise ValueError("PSK must be >= 32 bytes")
        # Initial MAC key from header bytes 0-15, optionally XORed with nonce
        r_bytes = psk[0:8]
        s_bytes = psk[8:16]
        if session_nonce is not None:
            r_bytes = bytes(a ^ b for a, b in zip(r_bytes, session_nonce[0:8]))
            s_bytes = bytes(a ^ b for a, b in zip(s_bytes, session_nonce[8:16]))
        self._mac_r = int.from_bytes(r_bytes, 'big') % _MERSENNE_61
        self._mac_s = int.from_bytes(s_bytes, 'big') % _MERSENNE_61
        # Pool data starts at byte 32
        self._buf = bytearray(psk[32:])
        self._cursor = 0

    def available_bytes(self):
        """Number of bytes available for withdrawal."""
        return len(self._buf) - self._cursor

    def available_bits(self):
        """Number of bits available for withdrawal."""
        return self.available_bytes() * 8

    def withdraw_otp(self, B):
        """Withdraw ceil(B/8) bytes as B OTP bits (uint8 array).

        Raises ValueError if pool has insufficient bytes.
        """
        n_bytes = _math.ceil(B / 8)
        if self.available_bytes() < n_bytes:
            raise ValueError("Pool exhausted: need %d bytes, have %d"
                             % (n_bytes, self.available_bytes()))
        raw = self._buf[self._cursor:self._cursor + n_bytes]
        self._cursor += n_bytes
        bits = np.unpackbits(np.frombuffer(bytes(raw), dtype=np.uint8))
        return bits[:B].astype(np.uint8)

    def get_mac_keys(self):
        """Return current (r, s) MAC keys."""
        return self._mac_r, self._mac_s

    def deposit(self, sign_bits, B):
        """Deposit B sign bits as ceil(B/8) bytes, recycle MAC key from first 128 bits."""
        bits = sign_bits[:B].astype(np.uint8)
        packed = np.packbits(bits)
        self._buf.extend(bytes(packed))
        # Recycle MAC key from first 128 sign bits
        if B >= 128:
            key_bits = sign_bits[:128].astype(np.uint8)
            key_bytes = bytes(np.packbits(key_bits))  # 16 bytes
            self._mac_r = int.from_bytes(key_bytes[0:8], 'big') % _MERSENNE_61
            self._mac_s = int.from_bytes(key_bytes[8:16], 'big') % _MERSENNE_61

    def compact(self):
        """Trim consumed bytes from the front of the buffer."""
        if self._cursor > 0:
            del self._buf[:self._cursor]
            self._cursor = 0


def _psk_parallel_alpha_otps(psk, run_idx, B):
    """Extract 2*B OTP bits for alpha signs from PSK.
    Returns (alice_otps, bob_otps) each length-B arrays of 0/1."""
    per_run = _math.ceil(B / 4) + 16
    off = 32 + run_idx * per_run
    n_bytes = _math.ceil(B / 4)
    raw = np.frombuffer(psk[off:off + n_bytes], dtype=np.uint8)
    # Each byte packs 4 channels: bits [0],[1] for ch0, [2],[3] for ch1, etc.
    # Alice gets even bits (0,2,4,6), Bob gets odd bits (1,3,5,7)
    # Unpack all 8 bits per byte, then select
    all_bits = np.unpackbits(raw, bitorder='little')  # LSB first
    # all_bits layout per byte: [bit0, bit1, bit2, bit3, bit4, bit5, bit6, bit7]
    # Channel k uses bits at positions (k%4)*2 and (k%4)*2+1 within byte k//4
    # With unpackbits LSB-first: byte i → all_bits[8*i .. 8*i+7]
    # For channel b: byte_idx = b//4, bit_off = (b%4)*2
    #   alice = all_bits[8*(b//4) + (b%4)*2]
    #   bob   = all_bits[8*(b//4) + (b%4)*2 + 1]
    # Reshape to (n_bytes, 8), take columns for alice and bob
    bits_2d = all_bits[:n_bytes * 8].reshape(n_bytes, 8)
    # Alice bits: columns 0, 2, 4, 6 → channels 0,1,2,3 per byte
    alice_flat = bits_2d[:, [0, 2, 4, 6]].ravel()[:B]
    # Bob bits: columns 1, 3, 5, 7
    bob_flat = bits_2d[:, [1, 3, 5, 7]].ravel()[:B]
    return alice_flat.astype(int), bob_flat.astype(int)


def _psk_parallel_mac_keys(psk, run_idx, B):
    """Extract (r, s) from PSK for parallel ITS run."""
    per_run = _math.ceil(B / 4) + 16
    off = 32 + run_idx * per_run + _math.ceil(B / 4)
    r = int.from_bytes(psk[off:off+8], 'big') % _MERSENNE_61
    s = int.from_bytes(psk[off+8:off+16], 'big') % _MERSENNE_61
    return r, s


def _parallel_ramp(k, ramp_time):
    """Compute ramp(k) = 1 - exp(-k/ramp_time)."""
    return 1.0 - np.exp(-float(k) / float(ramp_time))


def _parallel_mod_reduce(x, p):
    """Vectorized centered mod reduction into (-p/2, p/2]."""
    return x - p * np.round(x / p)


def _parallel_exchange_step_alice(Z_k, alpha_signs, ramp_k, wire_b_prev, p):
    """Compute wire_a[k] = mod_reduce(Z[k] + alpha * ramp_k * wire_b[k-1])."""
    real = Z_k + alpha_signs * ramp_k * wire_b_prev
    return _parallel_mod_reduce(real, p)


def _parallel_exchange_step_bob(Z_k, alpha_signs, ramp_k, wire_a_cur, p):
    """Compute wire_b[k] = mod_reduce(Z[k] + alpha * ramp_k * wire_a[k])."""
    real = Z_k + alpha_signs * ramp_k * wire_a_cur
    return _parallel_mod_reduce(real, p)


def _encode_wire_array(arr):
    """Encode a numpy float64 array as base64 for compact JSON transport."""
    return base64.b64encode(np.ascontiguousarray(arr).tobytes()).decode('ascii')


def _decode_wire_array(b64str):
    """Decode a base64-encoded float64 array."""
    return np.frombuffer(base64.b64decode(b64str), dtype=np.float64)


def _send_frame(sock, data):
    """Send a length-prefixed binary frame: [4-byte big-endian len][payload]."""
    sock.sendall(len(data).to_bytes(4, 'big') + data)


def _recv_frame(sock, bufsize=1048576):
    """Receive a length-prefixed binary frame."""
    hdr = b''
    while len(hdr) < 4:
        chunk = sock.recv(4 - len(hdr))
        if not chunk:
            return None
        hdr += chunk
    length = int.from_bytes(hdr, 'big')
    buf = bytearray()
    while len(buf) < length:
        chunk = sock.recv(min(length - len(buf), bufsize))
        if not chunk:
            return None
        buf += chunk
    return bytes(buf)


def _pack_signs_wire(sign_enc, wire_arr):
    """Pack encrypted signs (uint8) + wire array (float64) into bytes."""
    return (np.asarray(sign_enc, dtype=np.uint8).tobytes()
            + np.ascontiguousarray(wire_arr).tobytes())


def _unpack_signs_wire(data, B):
    """Unpack signs + wire from binary frame."""
    sign_enc = np.frombuffer(data[:B], dtype=np.uint8)
    wire_arr = np.frombuffer(data[B:], dtype=np.float64)
    return sign_enc, wire_arr


def _pack_wire(wire_arr):
    """Pack wire array as raw float64 bytes."""
    return np.ascontiguousarray(wire_arr).tobytes()


def _unpack_wire(data):
    """Unpack wire array from raw bytes."""
    return np.frombuffer(data, dtype=np.float64)


def _pack_wire_tag(wire_arr, tag):
    """Pack wire array + MAC tag (int, 8 bytes big-endian)."""
    return (np.ascontiguousarray(wire_arr).tobytes()
            + int(tag).to_bytes(8, 'big'))


def _unpack_wire_tag(data):
    """Unpack wire array + MAC tag from binary frame."""
    wire_arr = np.frombuffer(data[:-8], dtype=np.float64)
    tag = int.from_bytes(data[-8:], 'big')
    return wire_arr, tag


def _pack_tag(tag):
    """Pack MAC tag as 8 bytes big-endian."""
    return int(tag).to_bytes(8, 'big')


def _unpack_tag(data):
    """Unpack MAC tag from 8 bytes."""
    return int.from_bytes(data, 'big')


def _batch_wire_decode_step(wire_vals, centers, p):
    """Vectorized wire decode across B channels.

    Parameters
    ----------
    wire_vals : ndarray, shape (B,)
    centers : ndarray, shape (B,)
    p : float

    Returns
    -------
    z_hat, reliability : ndarray (B,)
    """
    n = np.round((centers - wire_vals) / p)
    real_vals = wire_vals + n * p
    frac = (centers - wire_vals) / p - n
    reliability = 0.5 - np.abs(frac)
    return real_vals - centers, reliability


def _batch_wire_decode_z_all(wire_a, wire_b, alpha_a, alpha_b, ramp_time, p):
    """Decode Z_a and Z_b from wire values for B parallel channels.

    All decode work is vectorized across B channels per exchange step.

    Parameters
    ----------
    wire_a : list of (B,) arrays, length n_ex + 1
    wire_b : list of (B,) arrays, length n_ex
    alpha_a : (B,) array of signed alpha values
    alpha_b : (B,) array of signed alpha values
    ramp_time : float
    p : float

    Returns
    -------
    z_a : (B, n_a), z_b : (B, n_b), rel_a : (B, n_a), rel_b : (B, n_b)
    """
    n_ex = len(wire_b)
    n_a = n_ex + 1
    B = len(wire_a[0])

    z_a = np.empty((B, n_a))
    rel_a = np.empty((B, n_a))

    # Z_a[0]: center = 0 (ramp(0) = 0)
    z_a[:, 0], rel_a[:, 0] = _batch_wire_decode_step(
        wire_a[0], np.zeros(B), p)

    for k in range(1, n_a):
        ramp_k = 1.0 - _math.exp(-float(k) / float(ramp_time))
        centers = alpha_a * ramp_k * wire_b[k - 1]
        z_a[:, k], rel_a[:, k] = _batch_wire_decode_step(wire_a[k], centers, p)

    z_b = np.empty((B, n_ex))
    rel_b = np.empty((B, n_ex))

    for i in range(n_ex):
        ramp_i = 1.0 - _math.exp(-float(i) / float(ramp_time))
        centers = alpha_b * ramp_i * wire_a[i]
        z_b[:, i], rel_b[:, i] = _batch_wire_decode_step(wire_b[i], centers, p)

    return z_a, z_b, rel_a, rel_b


def _batch_quantize_coeffs(all_z_a, all_z_b, clean_a, clean_b,
                            sigma_z, n_bits, range_sigma):
    """Vectorized quantization of B channels to packed MAC coefficients.

    Packs multiple bins into single Mersenne-61 field elements to reduce
    the number of MAC iterations.  With n_bits=4, 15 bins fit in one
    60-bit field element (15 * 4 = 60 < 61).

    Parameters
    ----------
    all_z_a : (B, n_a)
    all_z_b : (B, n_b)
    clean_a : (n_a,) bool
    clean_b : (n_b,) bool

    Returns
    -------
    coeffs : list of int
    """
    R = range_sigma * sigma_z
    n_bins = 2 ** n_bits
    delta_q = 2.0 * R / n_bins
    z_all = np.concatenate([all_z_a[:, clean_a], all_z_b[:, clean_b]], axis=1)
    bins = np.clip(((z_all + R) / delta_q).astype(np.int64), 0, n_bins - 1)
    # bins shape: (B, clean_steps)
    # Pack bins_per_pack bins into one coefficient using base n_bins encoding
    bins_per_pack = 61 // n_bits  # 15 for n_bits=4
    flat = bins.ravel()
    n_total = len(flat)
    base = int(n_bins)

    # Pad to multiple of bins_per_pack
    pad = (-n_total) % bins_per_pack
    if pad:
        flat = np.concatenate([flat, np.zeros(pad, dtype=np.int64)])

    # Reshape into groups and dot with powers: [base^(k-1), base^(k-2), ..., 1]
    groups = flat.reshape(-1, bins_per_pack)
    powers = np.array([base ** (bins_per_pack - 1 - i)
                       for i in range(bins_per_pack)], dtype=np.int64)
    packed = groups @ powers  # (n_groups,) int64
    return packed.tolist()


def _batch_search_decode_deltas(all_z_a, all_z_b, all_rel_a, all_rel_b,
                                 clean_a, clean_b, sigma_z, p,
                                 n_bits, range_sigma, max_flip):
    """Vectorized computation of search decoder inputs for packed coefficients.

    Returns coefficient-level indices and deltas suitable for the packed
    MAC coefficient array produced by ``_batch_quantize_coeffs``.

    Returns
    -------
    borderline_idx : list of int  (indices into packed coeffs array)
    borderline_deltas : list of int  (delta to packed coefficient value)
    """
    R = range_sigma * sigma_z
    n_bins = 2 ** n_bits
    delta_q = 2.0 * R / n_bins
    bins_per_pack = 61 // n_bits  # 15 for n_bits=4
    base = int(n_bins)

    z_all = np.concatenate([all_z_a[:, clean_a], all_z_b[:, clean_b]], axis=1)
    rel_all = np.concatenate([all_rel_a[:, clean_a], all_rel_b[:, clean_b]], axis=1)

    z_flat = z_all.ravel()
    rel_flat = rel_all.ravel()

    bin_orig = np.clip(((z_flat + R) / delta_q).astype(int), 0, n_bins - 1)
    bin_plus = np.clip(((z_flat + p + R) / delta_q).astype(int), 0, n_bins - 1)
    bin_minus = np.clip(((z_flat - p + R) / delta_q).astype(int), 0, n_bins - 1)

    d_plus = bin_plus - bin_orig
    d_minus = bin_minus - bin_orig

    both = (d_plus != 0) & (d_minus != 0)
    only_plus = (d_plus != 0) & (d_minus == 0)
    only_minus = (d_plus == 0) & (d_minus != 0)
    prefer_plus = np.abs(d_plus) <= np.abs(d_minus)

    delta_bins = np.zeros(len(z_flat), dtype=int)
    delta_bins[both & prefer_plus] = d_plus[both & prefer_plus]
    delta_bins[both & ~prefer_plus] = d_minus[both & ~prefer_plus]
    delta_bins[only_plus] = d_plus[only_plus]
    delta_bins[only_minus] = d_minus[only_minus]

    order = np.argsort(rel_flat)
    nonzero_mask = delta_bins[order] != 0
    nonzero_positions = np.where(nonzero_mask)[0][:max_flip]
    selected = order[nonzero_positions]

    # Translate bin-level corrections to packed coefficient corrections.
    # Bin at flat index i is in packed coefficient i // bins_per_pack,
    # at position (bins_per_pack - 1 - i % bins_per_pack) within that pack
    # (because packing uses big-endian: val = b0*base^(k-1) + ... + b_{k-1}).
    borderline_idx = []
    borderline_deltas = []
    for idx in selected:
        pack_idx = int(idx) // bins_per_pack
        pos_in_pack = bins_per_pack - 1 - (int(idx) % bins_per_pack)
        delta_coeff = int(delta_bins[idx]) * (base ** pos_in_pack)
        borderline_idx.append(pack_idx)
        borderline_deltas.append(delta_coeff)
    return borderline_idx, borderline_deltas


class InternalLink(object):
    """A link controller for two endpoints in the same process.

    Example: Run 100 iterations of the protocol and return the results

    >>> link = InternalLink(physics, storage)
    >>> results = [link.run_proto() for i in range(100)]"""
    def __init__(self, physics, storage=None):

        self.physics_config = physics.to_json()

        self.physics_A = physics
        self.physics_B = endpoint.Physics.from_json(self.physics_config)
        self.physics_B._is_second_mover = True
        # Propagate true random flag: physics_B must use the same RNG
        # mode so that reset() generates i.i.d. noise for ITS.
        if physics.rng_is_true_random:
            self.physics_B.rng_is_true_random = True
        self.messages = []
        self.storage = storage

        self.run_count = 0

    def run_proto(self):
        """Run a single iteration of the protocol."""

        self.physics_A.reset()
        self.physics_B.reset()

        if self.storage is not None:
            this_run = storage.Run(
                self.run_count,
                storage.Endpoint('Alice', self.physics_A),
                storage.Endpoint('Bob', self.physics_B))

            self.run_count += 1

        self.messages = []
        its_mode = self.physics_A.rng_is_true_random

        self.messages.append(self.physics_A.exchange(0.0))
        if self.storage is not None:
            this_run.add_message(
                storage.Message('Alice', 'Bob', self.messages[-1]))

        for i in range(self.physics_A.number_of_exchanges):
            if its_mode:
                # ITS mode: share true M_prev_real via the authenticated
                # channel so the receiver avoids unwrapping.  Eve still
                # only sees the wrapped wire values in self.messages.
                real_A = self.physics_A._last_real_sent
                self.messages.append(
                    self.physics_B.exchange(self.messages[-1],
                                           incoming_real=real_A))
                real_B = self.physics_B._last_real_sent
                self.messages.append(
                    self.physics_A.exchange(self.messages[-1],
                                           incoming_real=real_B))
            else:
                self.messages.append(
                    self.physics_B.exchange(self.messages[-1]))
                self.messages.append(
                    self.physics_A.exchange(self.messages[-1]))

            if self.storage is not None:
                this_run.add_message(
                    storage.Message('Bob', 'Alice', self.messages[-2]))
                this_run.add_message(
                    storage.Message('Alice', 'Bob', self.messages[-1]))

        if not (self.physics_A.estimate_other()
                    ^ (self.physics_A.reflection_coefficient > 0)):
            result = (None,None)

        elif not (self.physics_B.estimate_other()
                    ^ (self.physics_B.reflection_coefficient > 0)):
            result = (None,None)

        else:
            result = (not self.physics_A.estimate_other(),
                    self.physics_B.estimate_other())

        if self.storage is not None:
            this_run.add_result(storage.Result('Alice', result[0]))
            this_run.add_result(storage.Result('Bob', result[1]))
            self.storage.add_run(this_run)

        return result

    def run_proto_multibit(self):
        """Run a single protocol iteration, returning Z sequences.

        This method is for ITS multi-bit extraction.  It stores the full
        M_real history during the protocol and reconstructs both parties'
        Z sequences afterward.

        Unlike ``run_proto()``, this method **never erases**.  The sign
        bit was only needed for the 1-bit sign secret; for Z-sequence
        extraction, both parties can determine each other's sign from
        ``estimate_other()`` and their own sign, regardless of whether
        signs match or differ.  This doubles throughput.

        Requires ``rng_is_true_random=True`` on the physics objects
        (ITS mode), which ensures i.i.d. noise matching the HMM model.

        Returns
        -------
        dict
            'z_a': numpy array of Alice's Z values (n_ex + 1),
            'z_b': numpy array of Bob's Z values (n_ex),
            'clean_a': boolean array, True where masking noise is zero (Alice),
            'clean_b': boolean array, True where masking noise is zero (Bob),
            'signs_differ': bool, True if signs were different,
            'wire_a': list of Alice's wire (mod-p) values,
            'wire_b': list of Bob's wire (mod-p) values.
        """
        if not self.physics_A.rng_is_true_random:
            raise RuntimeError("run_proto_multibit requires ITS mode "
                               "(rng_is_true_random=True)")

        self.physics_A.reset()
        self.physics_B.reset()

        n_ex = self.physics_A.number_of_exchanges
        wire_a = []
        wire_b = []
        m_real_a = []
        m_real_b = []

        # Alice exchange 0
        w = self.physics_A.exchange(0.0)
        wire_a.append(w)
        m_real_a.append(self.physics_A._last_real_sent)

        for i in range(n_ex):
            # Bob exchange i: share Alice's real value via auth channel
            real_A = self.physics_A._last_real_sent
            w = self.physics_B.exchange(wire_a[-1], incoming_real=real_A)
            wire_b.append(w)
            m_real_b.append(self.physics_B._last_real_sent)

            # Alice exchange i+1: share Bob's real value via auth channel
            real_B = self.physics_B._last_real_sent
            w = self.physics_A.exchange(wire_b[-1], incoming_real=real_B)
            wire_a.append(w)
            m_real_a.append(self.physics_A._last_real_sent)

        # No erasure: both parties can determine each other's sign.
        # estimate_other() reliably determines the product sign; combined
        # with one's own sign, the other party's sign is determined.
        signs_differ = bool(
            self.physics_A.estimate_other()
            ^ (self.physics_A.reflection_coefficient > 0))

        # Reconstruct Z sequences from M_real history
        # M_A[k] = Z_A[k] + alpha_A * ramp(k) * M_B[k-1]  (for k > 0)
        # M_A[0] = Z_A[0]  (ramp(0) = 0)
        # M_B[i] = Z_B[i] + alpha_B * ramp(i) * M_A[i]
        alpha_a = self.physics_A.reflection_coefficient
        alpha_b = self.physics_B.reflection_coefficient

        z_a = np.empty(n_ex + 1)
        z_a[0] = m_real_a[0]  # ramp(0) = 0
        for i in range(n_ex):
            ramp_k = self.physics_A._ramp_function([i + 1])[0]
            z_a[i + 1] = m_real_a[i + 1] - alpha_a * ramp_k * m_real_b[i]

        z_b = np.empty(n_ex)
        for i in range(n_ex):
            ramp_k = self.physics_B._ramp_function([i])[0]
            z_b[i] = m_real_b[i] - alpha_b * ramp_k * m_real_a[i]

        # Compute clean masks: identify samples not affected by masking noise.
        # In endpoint.py exchange(), exchange index k reads
        # masking_noise[k] (line 291 increments current_exchange, then
        # line 292-294 access masking_noise[current_exchange - 1] = [k]).
        # The masking_noise array is nonzero at indices
        # [ramp_time - masking_time, ramp_time - 1] (endpoint.py lines
        # 138-140: zeroes [:ramp_time-masking_time] and [ramp_time:]).
        # Therefore masking affects exchange indices k in
        # [ramp_time - masking_time, ramp_time - 1].
        ramp_time = self.physics_A.ramp_time
        masking_time = self.physics_A.masking_time

        mask_start = ramp_time - masking_time   # first dirty index
        mask_end = ramp_time - 1                # last dirty index (inclusive)

        # Alice's exchange indices are 0, 1, ..., n_ex.
        clean_a = np.ones(n_ex + 1, dtype=bool)
        for k in range(max(0, mask_start), min(mask_end + 1, n_ex + 1)):
            clean_a[k] = False

        # Bob's exchange indices are 0, 1, ..., n_ex-1.
        clean_b = np.ones(n_ex, dtype=bool)
        for k in range(max(0, mask_start), min(mask_end + 1, n_ex)):
            clean_b[k] = False

        return {
            'z_a': z_a,
            'z_b': z_b,
            'clean_a': clean_a,
            'clean_b': clean_b,
            'signs_differ': signs_differ,
            'wire_a': wire_a,
            'wire_b': wire_b,
        }

    @staticmethod
    def quantize_z(z_values, sigma_z, n_bits=4, range_sigma=4.0):
        """Quantize continuous Z values to a bit string.

        Maps each Z sample to an n_bits integer index over the range
        [-range_sigma*sigma_z, +range_sigma*sigma_z], then packs indices
        into a flat bit array.

        Parameters
        ----------
        z_values : array-like
            Continuous Z samples.
        sigma_z : float
            Standard deviation of the noise process.
        n_bits : int
            Bits per sample (default 4).
        range_sigma : float
            Quantization range in sigma_z units (default 4.0).

        Returns
        -------
        numpy.ndarray of uint8
            Flat bit array of length len(z_values) * n_bits.
        """
        R = range_sigma * sigma_z
        n_bins = 2 ** n_bits
        delta = 2.0 * R / n_bins
        z = np.asarray(z_values)
        # Clip to range and compute bin indices
        indices = np.clip(((z + R) / delta).astype(int), 0, n_bins - 1)
        # Pack each index into n_bits
        bits = []
        for idx in indices:
            for b in range(n_bits - 1, -1, -1):
                bits.append((idx >> b) & 1)
        return np.array(bits, dtype=np.uint8)

    def run_batch_multibit(self, n_runs, n_bits=4, range_sigma=4.0,
                           target_epsilon=0.01):
        """Run a batch with multi-bit extraction from Z sequences.

        Instead of extracting 1 sign bit per run, this extracts many
        secure bits from the shared noise sequences Z_A and Z_B.

        Requires ITS mode (rng_is_true_random=True).

        The pipeline is:
        1. Run protocol to collect Z sequences (with sign agreement)
        2. Quantize Z values to discrete bits
        3. Compute security bound (per-step H_min from lattice analysis)
        4. Privacy amplification (Toeplitz hash)

        No reconciliation is needed: in ITS mode both parties reconstruct
        Z sequences exactly from the authenticated M_real values.

        Parameters
        ----------
        n_runs : int
            Number of protocol runs.
        n_bits : int
            Quantization bits per Z sample (default 4).
        range_sigma : float
            Quantization range in sigma_z units (default 4.0).
        target_epsilon : float
            Target security parameter (default 0.01).

        Returns
        -------
        dict
            'secure_bits_a': secure key array (numpy uint8),
            'secure_bits_b': secure key array (numpy uint8),
            'n_raw_bits': total raw quantized bits,
            'n_secure': secure bits after privacy amplification,
            'n_runs_used': successful (non-erased) runs,
            'n_runs_total': total runs attempted,
            'security': security analysis dict from
                ``security_proof.multibit_security_analysis``,
            'achieved_epsilon': actual security parameter.
        """
        if not self.physics_A.rng_is_true_random:
            raise RuntimeError("run_batch_multibit requires ITS mode "
                               "(rng_is_true_random=True)")

        sigma_z = self.physics_A.sigma_z
        n_ex = self.physics_A.number_of_exchanges
        modulus = self.physics_A.modulus

        # Collect Z sequences from ALL runs (no erasure in multi-bit mode).
        # Both parties know both Z_A and Z_B (reconstructed from
        # authenticated M_real values), so we concatenate them into
        # a single shared raw bit string.
        # Masking-affected samples are excluded to ensure the ITS
        # security model holds (masking noise is not i.i.d. Gaussian).
        all_raw = []
        n_used = 0
        clean_steps_per_run = None
        n_masking_excluded_per_run = 0

        for _ in range(n_runs):
            result = self.run_proto_multibit()
            n_used += 1
            # Filter out masking-affected samples
            z_a_clean = result['z_a'][result['clean_a']]
            z_b_clean = result['z_b'][result['clean_b']]
            z_combined = np.concatenate([z_a_clean, z_b_clean])

            if clean_steps_per_run is None:
                total_steps = len(result['z_a']) + len(result['z_b'])
                clean_steps_per_run = len(z_combined)
                n_masking_excluded_per_run = total_steps - clean_steps_per_run

            bits = self.quantize_z(z_combined, sigma_z,
                                   n_bits=n_bits, range_sigma=range_sigma)
            all_raw.append(bits)

        if n_used == 0:
            return {
                'secure_bits_a': np.array([], dtype=np.uint8),
                'secure_bits_b': np.array([], dtype=np.uint8),
                'n_raw_bits': 0,
                'n_secure': 0,
                'n_runs_used': 0,
                'n_runs_total': n_runs,
                'security': None,
                'achieved_epsilon': 1.0,
                'n_masking_excluded_per_run': 0,
                'clean_steps_per_run': 0,
            }

        raw_bits = np.concatenate(all_raw)
        n_raw = len(raw_bits)

        # Security analysis: sign-based min-entropy for decoded Z
        alpha_mag = abs(self.physics_A.reflection_coefficient)
        ramp_time = self.physics_A.ramp_time
        security = _sec_mod.multibit_security_analysis(
            sigma_z, modulus, n_ex,
            alpha=alpha_mag, ramp_time=ramp_time,
            n_bits=n_bits, range_sigma=range_sigma,
            target_epsilon=target_epsilon)

        # Total channels across all used runs
        n_channels_total = n_used
        h_min_per_channel = security['h_min_per_channel']

        # No composition correction needed: independent runs with
        # sign-based entropy (each run's sign is independent).
        composition_correction = 0.0

        secure_result = _sec_mod.compute_multibit_secure_length(
            n_channels_total, h_min_per_channel,
            target_epsilon=target_epsilon,
            composition_correction_bits=composition_correction)
        n_secure = secure_result['n_secure']

        if n_secure == 0 or n_secure > n_raw:
            return {
                'secure_bits_a': np.array([], dtype=np.uint8),
                'secure_bits_b': np.array([], dtype=np.uint8),
                'n_raw_bits': n_raw,
                'n_secure': 0,
                'n_runs_used': n_used,
                'n_runs_total': n_runs,
                'security': security,
                'achieved_epsilon': 1.0,
                'n_masking_excluded_per_run': n_masking_excluded_per_run,
                'clean_steps_per_run': clean_steps_per_run,
            }

        # Both parties hash the identical shared raw bit string.
        # In a real deployment, both independently compute the same
        # quantized Z concatenation and apply the same Toeplitz hash.
        pa = _privacy_mod.PrivacyAmplification(n_raw, n_secure, seed=42)
        secure_key = pa.hash(raw_bits.tolist())

        return {
            'secure_bits_a': secure_key,
            'secure_bits_b': secure_key,  # identical: both parties hash same input
            'n_raw_bits': n_raw,
            'n_secure': n_secure,
            'n_runs_used': n_used,
            'n_runs_total': n_runs,
            'security': security,
            'achieved_epsilon': secure_result['achieved_epsilon'],
            'n_masking_excluded_per_run': n_masking_excluded_per_run,
            'clean_steps_per_run': clean_steps_per_run,
        }

    def run_batch_with_privacy(self, n_runs, eve_info_per_bit=None,
                               safety_margin=10):
        """Run a batch of protocol iterations and apply privacy amplification.

        The pipeline is:
        1. Run protocol to collect raw bits (with possible errors)
        2. Information reconciliation (cascade) to correct errors
        3. Privacy amplification (Toeplitz hash) to remove Eve's info

        Parameters
        ----------
        n_runs : int
            Number of protocol runs to execute.
        eve_info_per_bit : float or None
            Upper bound on Eve's information per raw bit from the wire.
            If None, it is estimated from the endpoint's leakage report.
        safety_margin : int
            Extra bits subtracted during privacy amplification (default 10).

        Returns
        -------
        tuple
            (secure_bits_a, secure_bits_b, n_raw, n_secure) where the
            secure bit arrays are numpy uint8 arrays.
        """
        raw_a = []
        raw_b = []
        for _ in range(n_runs):
            result = self.run_proto()
            if result[0] is not None and result[1] is not None:
                raw_a.append(int(result[0]))
                raw_b.append(int(result[1]))

        n_raw = len(raw_a)
        if n_raw == 0:
            return (np.array([], dtype=np.uint8),
                    np.array([], dtype=np.uint8), 0, 0)

        # Step 1: Estimate Eve's information from wire observations
        if eve_info_per_bit is not None:
            eve_wire = eve_info_per_bit * n_raw
        else:
            report = self.physics_A.leakage_report()
            eve_wire = report['total_eve_information_bits'] * n_raw

        # Step 2: Information reconciliation (correct errors)
        arr_a = np.array(raw_a, dtype=np.int8)
        arr_b = np.array(raw_b, dtype=np.int8)
        recon_leaked = _recon_mod.cascade_reconcile(arr_a, arr_b)

        # Total Eve information = wire leakage + reconciliation leakage
        eve_total = eve_wire + recon_leaked

        # Step 3: Privacy amplification
        n_secure = _privacy_mod.PrivacyAmplification.compute_secure_length(
            n_raw, eve_total, safety_margin)

        if n_secure == 0:
            return (np.array([], dtype=np.uint8),
                    np.array([], dtype=np.uint8), n_raw, 0)

        pa = _privacy_mod.PrivacyAmplification(n_raw, n_secure, seed=42)
        secure_a = pa.hash(arr_a.tolist())
        secure_b = pa.hash(arr_b.tolist())

        return (secure_a, secure_b, n_raw, n_secure)

    def run_batch_with_security_proof(self, n_runs, eve_info_per_bit=None,
                                      target_epsilon=0.01, mi_samples=500,
                                      mi_confidence=0.99, mi_seed=42):
        """Run a batch with full composable security analysis.

        Like ``run_batch_with_privacy`` but uses the rigorous HMM MI
        bound and returns a complete security report including the
        composable epsilon parameter.

        Parameters
        ----------
        n_runs : int
            Number of protocol runs.
        eve_info_per_bit : float or None
            If provided, use this as the per-bit MI bound instead of
            computing it via the rigorous estimator.
        target_epsilon : float
            Target security parameter (default 0.01).
        mi_samples : int
            Monte Carlo samples for MI estimation (default 500).
        mi_confidence : float
            Confidence level for MI bound (default 0.99).
        mi_seed : int
            Random seed for MI estimation.

        Returns
        -------
        dict
            'secure_bits_a', 'secure_bits_b': secure key arrays,
            'n_raw': raw bits count,
            'n_secure': secure bits count,
            'security': full security analysis report from
            ``security_proof.full_security_analysis``.
        """
        raw_a = []
        raw_b = []
        for _ in range(n_runs):
            result = self.run_proto()
            if result[0] is not None and result[1] is not None:
                raw_a.append(int(result[0]))
                raw_b.append(int(result[1]))

        n_raw = len(raw_a)
        if n_raw == 0:
            return {
                'secure_bits_a': np.array([], dtype=np.uint8),
                'secure_bits_b': np.array([], dtype=np.uint8),
                'n_raw': 0, 'n_secure': 0, 'security': None,
            }

        # Reconciliation
        arr_a = np.array(raw_a, dtype=np.int8)
        arr_b = np.array(raw_b, dtype=np.int8)
        recon_leaked = _recon_mod.cascade_reconcile(arr_a, arr_b)

        # Get protocol parameters for security analysis
        report = self.physics_A.leakage_report()
        sigma_z = report['sigma_z']
        alpha = report['alpha']
        ramp_time = report['ramp_time']
        modulus = report['modulus']
        n_exchanges = report['number_of_exchanges']

        if eve_info_per_bit is not None:
            mi_bound = eve_info_per_bit
            wire_total = mi_bound * n_raw
            eve_total = wire_total + recon_leaked
            n_secure = _sec_mod.compute_secure_length_from_epsilon(
                n_raw, eve_total, target_epsilon)
            security = _sec_mod.verify_security(
                n_raw, max(n_secure, 1), mi_bound, recon_leaked,
                confidence=mi_confidence)
            if n_secure == 0:
                security['is_secure'] = False
        else:
            security = _sec_mod.full_security_analysis(
                sigma_z, alpha, ramp_time, modulus, n_exchanges,
                n_raw, recon_leaked,
                target_epsilon=target_epsilon,
                mi_samples=mi_samples,
                mi_confidence=mi_confidence,
                mi_seed=mi_seed)
            n_secure = security['n_secure_for_target']

        if n_secure == 0:
            return {
                'secure_bits_a': np.array([], dtype=np.uint8),
                'secure_bits_b': np.array([], dtype=np.uint8),
                'n_raw': n_raw, 'n_secure': 0,
                'security': security,
            }

        pa = _privacy_mod.PrivacyAmplification(n_raw, n_secure, seed=42)
        secure_a = pa.hash(arr_a.tolist())
        secure_b = pa.hash(arr_b.tolist())

        return {
            'secure_bits_a': secure_a,
            'secure_bits_b': secure_b,
            'n_raw': n_raw, 'n_secure': n_secure,
            'security': security,
        }


class NetworkLinkRequestHandler(socketserver.BaseRequestHandler):
    """A server implementing the Liu protocol over the network"""

    def handle(self):
        self.server.physics = []

        run_number = 0
        while True:
            config = self.__read_json_string()

            if config is None or config == '{}':
                return

            # Check for multibit mode
            config_dict = json.loads(config)
            psk = self.server.pre_shared_key

            is_signbit_nopa = (psk is not None
                               and config_dict.get('signbit_nopa', False))
            if is_signbit_nopa:
                self._handle_signbit_nopa(config_dict)
                return

            is_signbit_its = (psk is not None
                              and config_dict.get('signbit_its', False))
            if is_signbit_its:
                self._handle_signbit_its(config_dict)
                return

            is_parallel_its = (psk is not None
                               and config_dict.get('parallel_its', False))
            if is_parallel_its:
                self._handle_parallel_its(config, config_dict, run_number)
                return

            is_multibit_its = (psk is not None
                               and config_dict.get('multibit_its', False))
            if is_multibit_its:
                self._handle_multibit_its(config, config_dict, run_number)
                return

            is_multibit = (psk is not None
                           and config_dict.get('multibit', False))

            if is_multibit:
                self._handle_multibit(config, config_dict, run_number)
                return
            else:
                self._handle_legacy(config, run_number)

            run_number += 1

    def _handle_legacy(self, config, run_number):
        """Handle legacy sign-bit protocol (unchanged behaviour)."""
        # Send a response to the configuration string.
        self.request.send('{}'.encode('utf-8'))

        # Now that we have a valid configuration string, produce our
        # endpoint.
        physics = endpoint.Physics.from_json(config)
        physics._is_second_mover = True
        if self.server.storage is not None:
            this_run = storage.Run(
                run_number,
                storage.Endpoint('Bob', physics))

        # Finally, run the protocol.
        for i in range(physics.number_of_exchanges):
            message = json.loads(self.__read_json_string())
            result = physics.exchange(message['message'])

            if self.server.storage is not None:
                this_run.add_message(storage.Message('Alice', 'Bob', message['message']))
                this_run.add_message(storage.Message('Bob', 'Alice', result))

            message_out = json.dumps({'message': result})
            self.request.send(message_out.encode('utf-8'))

        message = json.loads(self.__read_json_string())
        physics.exchange(message['message'])

        if self.server.storage is not None:
            this_run.add_message(storage.Message('Alice', 'Bob', message['message']))

        # We may now decide on whether to declare a zero, one, or erasure.
        if physics.estimate_other() != (physics.reflection_coefficient > 0):
            result = physics.estimate_other()
        else:
            result = None

        # Now that we have have decided whether or not to declare a bit,
        # we must agree this with the client.
        if result is None:
            self.request.send('{"decision":"discard"}'.encode('utf-8'))
        else:
            self.request.send('{"decision":"declare"}'.encode('utf-8'))

        message = json.loads(self.__read_json_string())

        if message['decision'] == 'discard':
            result = None

        self.server.physics.append(result)
        if self.server.storage is not None:
            this_run.add_result(storage.Result('Bob', result))
            self.server.storage.add_run(this_run)

        # Send the final response.
        self.request.send('{}'.encode('utf-8'))

    def _handle_multibit(self, config, config_dict, run_number):
        """Handle multibit Z-extraction protocol."""
        psk = self.server.pre_shared_key

        # Parse batch parameters from config
        n_runs = config_dict.get('n_runs', 1)
        n_bits = config_dict.get('n_bits', 4)
        range_sigma = config_dict.get('range_sigma', 4.0)
        target_epsilon = config_dict.get('target_epsilon', 0.01)
        is_batch = config_dict.get('batch', False)

        # Send ack
        self.request.send('{}'.encode('utf-8'))

        # Create physics endpoint from the config (strip extra keys)
        physics = endpoint.Physics.from_json(config)
        physics._is_second_mover = True
        physics.rng_is_true_random = True

        n_ex = physics.number_of_exchanges

        # Create directional ciphers for alpha exchange
        alpha_enc = AuthCipher(psk + b'S-alpha')
        alpha_dec = AuthCipher(psk + b'C-alpha')

        # Receive Alice's alpha (encrypted)
        alpha_msg = json.loads(self.__read_json_string())
        alpha_a = _decode_real(alpha_msg['alpha'], alpha_dec)

        # Send Bob's alpha (encrypted)
        alpha_b = physics.reflection_coefficient
        self.request.send(json.dumps({
            'alpha': _encode_real(alpha_b, alpha_enc)
        }).encode('utf-8'))

        # Create directional ciphers for exchange data
        enc_cipher = AuthCipher(psk + b'S')
        dec_cipher = AuthCipher(psk + b'C')

        all_results = []

        for run_idx in range(n_runs):
            if run_idx > 0:
                physics.reset()
                # After reset, alpha sign may change — exchange again
                alpha_enc_r = AuthCipher(psk + b'S-alpha' + struct.pack('>I', run_idx))
                alpha_dec_r = AuthCipher(psk + b'C-alpha' + struct.pack('>I', run_idx))
                alpha_msg = json.loads(self.__read_json_string())
                alpha_a = _decode_real(alpha_msg['alpha'], alpha_dec_r)
                alpha_b = physics.reflection_coefficient
                self.request.send(json.dumps({
                    'alpha': _encode_real(alpha_b, alpha_enc_r)
                }).encode('utf-8'))

                # Fresh ciphers per run for synchronization
                enc_cipher = AuthCipher(psk + b'S' + struct.pack('>I', run_idx))
                dec_cipher = AuthCipher(psk + b'C' + struct.pack('>I', run_idx))

            wire_a = []
            wire_b = []
            m_real_a = []
            m_real_b = []

            # Receive Alice's exchange 0
            message = json.loads(self.__read_json_string())
            wire_a.append(message['message'])
            incoming_real = _decode_real(message['auth'], dec_cipher)
            m_real_a.append(incoming_real)

            # Exchange loop
            for i in range(n_ex):
                # Bob exchange i
                result = physics.exchange(wire_a[-1],
                                          incoming_real=m_real_a[-1])
                wire_b.append(result)
                m_real_b.append(physics._last_real_sent)

                # Send Bob's response with auth
                msg_out = json.dumps({
                    'message': result,
                    'auth': _encode_real(physics._last_real_sent, enc_cipher)
                })
                self.request.send(msg_out.encode('utf-8'))

                # Receive Alice's next exchange
                message = json.loads(self.__read_json_string())
                wire_a.append(message['message'])
                incoming_real = _decode_real(message['auth'], dec_cipher)
                m_real_a.append(incoming_real)

            # Final Alice exchange (n_ex + 1 total from Alice)
            physics.exchange(wire_a[-1], incoming_real=m_real_a[-1])

            # Send multibit done ack
            self.request.send(json.dumps({'multibit': 'done'}).encode('utf-8'))

            # Read client sync
            self.__read_json_string()

            # Reconstruct Z sequences (same logic as InternalLink)
            # alpha_a was received via the encrypted auth channel
            # alpha_b is our own physics.reflection_coefficient

            z_a = np.empty(n_ex + 1)
            z_a[0] = m_real_a[0]  # ramp(0) = 0
            for i in range(n_ex):
                ramp_k = physics._ramp_function([i + 1])[0]
                z_a[i + 1] = m_real_a[i + 1] - alpha_a * ramp_k * m_real_b[i]

            z_b = np.empty(n_ex)
            for i in range(n_ex):
                ramp_k = physics._ramp_function([i])[0]
                z_b[i] = m_real_b[i] - alpha_b * ramp_k * m_real_a[i]

            # Compute clean masks
            ramp_time = physics.ramp_time
            masking_time = physics.masking_time
            mask_start = ramp_time - masking_time
            mask_end = ramp_time - 1

            clean_a = np.ones(n_ex + 1, dtype=bool)
            for k in range(max(0, mask_start), min(mask_end + 1, n_ex + 1)):
                clean_a[k] = False

            clean_b = np.ones(n_ex, dtype=bool)
            for k in range(max(0, mask_start), min(mask_end + 1, n_ex)):
                clean_b[k] = False

            signs_differ = bool(
                physics.estimate_other()
                ^ (physics.reflection_coefficient > 0))

            result_dict = {
                'z_a': z_a,
                'z_b': z_b,
                'clean_a': clean_a,
                'clean_b': clean_b,
                'signs_differ': signs_differ,
                'wire_a': wire_a,
                'wire_b': wire_b,
            }
            all_results.append(result_dict)

        self.server.multibit_results = all_results

        # If batch mode, perform PA on accumulated Z sequences
        if is_batch:
            sigma_z = physics.sigma_z
            modulus = physics.modulus
            all_raw = []
            n_used = 0
            clean_steps_per_run = None
            n_masking_excluded_per_run = 0

            for res in all_results:
                n_used += 1
                z_a_clean = res['z_a'][res['clean_a']]
                z_b_clean = res['z_b'][res['clean_b']]
                z_combined = np.concatenate([z_a_clean, z_b_clean])

                if clean_steps_per_run is None:
                    total_steps = len(res['z_a']) + len(res['z_b'])
                    clean_steps_per_run = len(z_combined)
                    n_masking_excluded_per_run = total_steps - clean_steps_per_run

                bits = InternalLink.quantize_z(z_combined, sigma_z,
                                               n_bits=n_bits,
                                               range_sigma=range_sigma)
                all_raw.append(bits)

            if n_used == 0:
                self.server.multibit_batch_result = {
                    'secure_bits_a': np.array([], dtype=np.uint8),
                    'secure_bits_b': np.array([], dtype=np.uint8),
                    'n_raw_bits': 0, 'n_secure': 0,
                    'n_runs_used': 0, 'n_runs_total': n_runs,
                    'security': None, 'achieved_epsilon': 1.0,
                    'n_masking_excluded_per_run': 0,
                    'clean_steps_per_run': 0,
                }
                return

            raw_bits = np.concatenate(all_raw)
            n_raw = len(raw_bits)

            alpha_mag = abs(physics.reflection_coefficient)
            security = _sec_mod.multibit_security_analysis(
                sigma_z, modulus, n_ex,
                alpha=alpha_mag, ramp_time=physics.ramp_time,
                n_bits=n_bits, range_sigma=range_sigma,
                target_epsilon=target_epsilon)

            n_channels_total = n_used
            h_min_per_channel = security['h_min_per_channel']

            composition_correction = 0.0

            secure_result = _sec_mod.compute_multibit_secure_length(
                n_channels_total, h_min_per_channel,
                target_epsilon=target_epsilon,
                composition_correction_bits=composition_correction)
            n_secure = secure_result['n_secure']

            if n_secure == 0 or n_secure > n_raw:
                self.server.multibit_batch_result = {
                    'secure_bits_a': np.array([], dtype=np.uint8),
                    'secure_bits_b': np.array([], dtype=np.uint8),
                    'n_raw_bits': n_raw, 'n_secure': 0,
                    'n_runs_used': n_used, 'n_runs_total': n_runs,
                    'security': security, 'achieved_epsilon': 1.0,
                    'n_masking_excluded_per_run': n_masking_excluded_per_run,
                    'clean_steps_per_run': clean_steps_per_run,
                }
                return

            pa = _privacy_mod.PrivacyAmplification(n_raw, n_secure, seed=42)
            secure_key = pa.hash(raw_bits.tolist())

            self.server.multibit_batch_result = {
                'secure_bits_a': secure_key,
                'secure_bits_b': secure_key,
                'n_raw_bits': n_raw, 'n_secure': n_secure,
                'n_runs_used': n_used, 'n_runs_total': n_runs,
                'security': security,
                'achieved_epsilon': secure_result['achieved_epsilon'],
                'n_masking_excluded_per_run': n_masking_excluded_per_run,
                'clean_steps_per_run': clean_steps_per_run,
            }

    def _handle_multibit_its(self, config, config_dict, run_number):
        """Handle ITS multibit Z-extraction protocol (no M_real on wire).

        Uses wire-value exchange: both parties feed wire values (not
        unwrapped M_real) into exchange(), making per-step decode errors
        independent.  Post-exchange, Z is decoded using known-alpha
        centers and verified with a Wegman-Carter MAC.  A search decoder
        flips borderline wrapping counts if the initial decode fails.
        """
        psk = self.server.pre_shared_key

        n_runs = config_dict.get('n_runs', 1)
        n_bits = config_dict.get('n_bits', 4)
        range_sigma = config_dict.get('range_sigma', 4.0)
        target_epsilon = config_dict.get('target_epsilon', 0.01)
        is_batch = config_dict.get('batch', False)
        max_flip = config_dict.get('max_flip', 8)

        _validate_its_psk(psk, n_runs)

        # Send ack
        self.request.send('{}'.encode('utf-8'))

        physics = endpoint.Physics.from_json(config)
        physics._is_second_mover = True
        # ITS mode: use IID noise (no band-limiting correlations).
        # With wire-value exchange, protocol dynamics are independent of
        # noise correlations, and IID gives composition_correction = 0.
        physics.rng_is_true_random = True
        physics.no_reset = True          # prevent sign flip on first reset
        physics.reset()                  # regenerate noise as IID
        physics.no_reset = False

        n_ex = physics.number_of_exchanges
        sigma_z = physics.sigma_z

        all_results = []

        for run_idx in range(n_runs):
            if run_idx > 0:
                physics.reset()

            # Receive Alice's OTP-encrypted sign bit
            sign_msg = json.loads(self.__read_json_string())
            alice_otp = _psk_alpha_otp(psk, run_idx, 0)
            alice_sign_positive = (sign_msg['sign'] ^ alice_otp) == 0

            # Send Bob's OTP-encrypted sign bit
            bob_sign_positive = physics.reflection_coefficient > 0
            bob_otp = _psk_alpha_otp(psk, run_idx, 1)
            bob_sign_enc = (0 if bob_sign_positive else 1) ^ bob_otp
            self.request.send(json.dumps({'sign': bob_sign_enc}).encode('utf-8'))

            # Reconstruct Alice's alpha from sign
            alpha_a_sign = 1.0 if alice_sign_positive else -1.0
            alpha_a = alpha_a_sign * abs(physics.reflection_coefficient)
            alpha_b = physics.reflection_coefficient

            wire_a = []
            wire_b = []

            # Receive Alice's exchange 0 wire value
            message = json.loads(self.__read_json_string())
            wire_a_last = message['message']
            wire_a.append(wire_a_last)

            # Exchange loop: feed wire values as incoming_real
            for i in range(n_ex):
                result = physics.exchange(wire_a_last,
                                          incoming_real=wire_a_last)
                wire_b.append(result)

                self.request.send(json.dumps({
                    'message': result
                }).encode('utf-8'))

                message = json.loads(self.__read_json_string())
                wire_a_last = message['message']
                wire_a.append(wire_a_last)

            # Absorb final Alice wire value
            physics.exchange(wire_a_last, incoming_real=wire_a_last)

            # Send done signal
            self.request.send(json.dumps({'its': 'done'}).encode('utf-8'))

            # Post-exchange decode using known-alpha centers
            z_a, z_b, rel_a, rel_b, wrap_a, wrap_b = \
                _wire_decode_z_all(wire_a, wire_b, alpha_a, alpha_b,
                                   physics._ramp_function, physics.modulus)

            # Compute clean masks
            ramp_time = physics.ramp_time
            masking_time = physics.masking_time
            mask_start = ramp_time - masking_time
            mask_end = ramp_time - 1

            clean_a = np.ones(n_ex + 1, dtype=bool)
            for k in range(max(0, mask_start), min(mask_end + 1, n_ex + 1)):
                clean_a[k] = False

            clean_b = np.ones(n_ex, dtype=bool)
            for k in range(max(0, mask_start), min(mask_end + 1, n_ex)):
                clean_b[k] = False

            # Compute MAC coefficients and tag
            coeffs = _z_to_mac_coeffs(z_a, z_b, clean_a, clean_b, sigma_z,
                                       n_bits=n_bits, range_sigma=range_sigma)
            r, s = _psk_mac_keys(psk, run_idx)
            bob_tag = _its_mac_tag(coeffs, r, s)

            # Receive Alice's tag, send Bob's tag
            tag_msg = json.loads(self.__read_json_string())
            alice_tag = tag_msg['tag']

            # If initial decode disagrees, try search decoder
            if bob_tag != alice_tag:
                bob_tag, coeffs = self._its_search_correct(
                    coeffs, z_a, z_b, rel_a, rel_b, clean_a, clean_b,
                    wire_a, wire_b, alpha_a, alpha_b, physics,
                    sigma_z, r, s, alice_tag, n_bits, range_sigma,
                    max_flip)

            self.request.send(json.dumps({'tag': bob_tag}).encode('utf-8'))

            # Sync
            self.__read_json_string()

            if alice_tag == bob_tag:
                all_results.append({
                    'z_a': z_a,
                    'z_b': z_b,
                    'clean_a': clean_a,
                    'clean_b': clean_b,
                    'signs_differ': (alpha_a * alpha_b) < 0,
                })
            else:
                all_results.append(None)

        self.server.multibit_results = all_results

        # Batch mode: PA on successful results
        if is_batch:
            self._its_batch_pa(all_results, physics, n_runs, n_bits,
                               range_sigma, target_epsilon)

    def _its_search_correct(self, coeffs, z_a, z_b, rel_a, rel_b,
                            clean_a, clean_b, wire_a, wire_b,
                            alpha_a, alpha_b, physics, sigma_z,
                            r, s, target_tag, n_bits, range_sigma,
                            max_flip):
        """Attempt search-decode correction to match the other party's tag.

        Returns (corrected_tag, corrected_coeffs).  If no match found,
        returns the original tag and coeffs unchanged.
        """
        p = physics.modulus
        R = range_sigma * sigma_z
        n_bins = 2 ** n_bits
        delta = 2.0 * R / n_bins

        # Build flat reliability array and delta-bins for clean steps
        rel_flat = np.concatenate([rel_a[clean_a], rel_b[clean_b]])
        z_flat = np.concatenate([z_a[clean_a], z_b[clean_b]])

        # For each clean step, compute the bin change if wrap flipped
        # Flip direction: toward the ambiguous side
        # If z flipped by +p → new_z = z + p, if by -p → new_z = z - p
        # We pick the direction that moves toward the boundary
        # (i.e. the candidate with lower reliability)
        # For simplicity, try ±p and compute which gives a different bin
        delta_bins = []
        for i in range(len(z_flat)):
            z_orig = z_flat[i]
            bin_orig = int(np.clip((z_orig + R) / delta, 0, n_bins - 1))
            # Try z + p
            bin_plus = int(np.clip((z_orig + p + R) / delta, 0, n_bins - 1))
            # Try z - p
            bin_minus = int(np.clip((z_orig - p + R) / delta, 0, n_bins - 1))
            # Pick whichever direction gives a bin change and is closer
            # to the true value (lower reliability = more ambiguous)
            if bin_plus != bin_orig and bin_minus != bin_orig:
                # Both change — pick the one closer (smaller |Δbin|)
                if abs(bin_plus - bin_orig) <= abs(bin_minus - bin_orig):
                    delta_bins.append(bin_plus - bin_orig)
                else:
                    delta_bins.append(bin_minus - bin_orig)
            elif bin_plus != bin_orig:
                delta_bins.append(bin_plus - bin_orig)
            elif bin_minus != bin_orig:
                delta_bins.append(bin_minus - bin_orig)
            else:
                delta_bins.append(0)

        # Sort by reliability ascending (most ambiguous first)
        order = np.argsort(rel_flat)
        borderline_idx = []
        borderline_deltas = []
        for idx in order:
            if delta_bins[idx] != 0:
                borderline_idx.append(int(idx))
                borderline_deltas.append(delta_bins[idx])
            if len(borderline_idx) >= max_flip:
                break

        if not borderline_idx:
            return _its_mac_tag(coeffs, r, s), coeffs

        r_powers = _compute_r_powers(len(coeffs), r)
        corrected = _search_decode(coeffs, r, s, target_tag,
                                   borderline_idx, borderline_deltas,
                                   r_powers, max_flip)
        if corrected is not None:
            return _its_mac_tag(corrected, r, s), corrected
        return _its_mac_tag(coeffs, r, s), coeffs

    def _its_batch_pa(self, all_results, physics, n_runs, n_bits,
                      range_sigma, target_epsilon):
        """Run privacy amplification on successful ITS results.

        ITS mode uses IID noise (``rng_is_true_random``), so per-step
        observations are independent and min-entropy is additive.
        Composition correction is therefore zero.
        """
        successful = [r for r in all_results if r is not None]
        sigma_z = physics.sigma_z
        n_ex = physics.number_of_exchanges
        modulus = physics.modulus

        if not successful:
            self.server.multibit_batch_result = {
                'secure_bits_a': np.array([], dtype=np.uint8),
                'secure_bits_b': np.array([], dtype=np.uint8),
                'n_raw_bits': 0, 'n_secure': 0,
                'n_runs_used': 0, 'n_runs_total': n_runs,
                'security': None, 'achieved_epsilon': 1.0,
                'n_masking_excluded_per_run': 0,
                'clean_steps_per_run': 0,
            }
            return

        all_raw = []
        n_used = 0
        clean_steps_per_run = None
        n_masking_excluded_per_run = 0

        for res in successful:
            n_used += 1
            z_a_clean = res['z_a'][res['clean_a']]
            z_b_clean = res['z_b'][res['clean_b']]
            z_combined = np.concatenate([z_a_clean, z_b_clean])

            if clean_steps_per_run is None:
                total_steps = len(res['z_a']) + len(res['z_b'])
                clean_steps_per_run = len(z_combined)
                n_masking_excluded_per_run = total_steps - clean_steps_per_run

            bits = InternalLink.quantize_z(z_combined, sigma_z,
                                           n_bits=n_bits,
                                           range_sigma=range_sigma)
            all_raw.append(bits)

        raw_bits = np.concatenate(all_raw)
        n_raw = len(raw_bits)

        alpha_mag = abs(physics.reflection_coefficient)
        security = _sec_mod.multibit_security_analysis(
            sigma_z, modulus, n_ex,
            alpha=alpha_mag, ramp_time=physics.ramp_time,
            n_bits=n_bits, range_sigma=range_sigma,
            target_epsilon=target_epsilon)

        n_channels_total = n_used
        h_min_per_channel = security['h_min_per_channel']

        composition_correction = 0.0

        secure_result = _sec_mod.compute_multibit_secure_length(
            n_channels_total, h_min_per_channel,
            target_epsilon=target_epsilon,
            composition_correction_bits=composition_correction)
        n_secure = secure_result['n_secure']

        if n_secure == 0 or n_secure > n_raw:
            self.server.multibit_batch_result = {
                'secure_bits_a': np.array([], dtype=np.uint8),
                'secure_bits_b': np.array([], dtype=np.uint8),
                'n_raw_bits': n_raw, 'n_secure': 0,
                'n_runs_used': n_used, 'n_runs_total': n_runs,
                'security': security, 'achieved_epsilon': 1.0,
                'n_masking_excluded_per_run': n_masking_excluded_per_run,
                'clean_steps_per_run': clean_steps_per_run,
            }
            return

        pa = _privacy_mod.PrivacyAmplification(n_raw, n_secure, seed=42)
        secure_key = pa.hash(raw_bits.tolist())

        self.server.multibit_batch_result = {
            'secure_bits_a': secure_key,
            'secure_bits_b': secure_key,
            'n_raw_bits': n_raw, 'n_secure': n_secure,
            'n_runs_used': n_used, 'n_runs_total': n_runs,
            'security': security,
            'achieved_epsilon': secure_result['achieved_epsilon'],
            'n_masking_excluded_per_run': n_masking_excluded_per_run,
            'clean_steps_per_run': clean_steps_per_run,
        }

    def _handle_signbit_nopa(self, config_dict):
        """Handle sign-bit no-PA protocol (B channels, n_ex=1, no PA).

        Raw sign bits are the key — no privacy amplification needed when
        TV distance per channel is negligible (exp(-79) at sigma/p=2).
        Uses _SignbitPool for OTP management; pool stays flat (withdraw B
        bits, deposit B bits per run).

        Batched message flow per batch (1.5 RTTs for n_runs):
        1. Recv: all wire_a[0] concatenated (n_runs × B float64)
        2. Send: all (bob_sign_enc | wire_b[0] | bob_mac_tag) concatenated
        3. Recv: all alice_mac_tags concatenated (n_runs × 8 bytes)

        Pool operations are sequential locally — run N's MAC key comes
        from run N-1's deposited sign bits.  If no tampering, both sides
        deposit identical bits and pools stay in sync.  If Eve tampers
        with encrypted signs, pools desync, but the MAC fails and the
        run is discarded.  Subsequent runs will also fail (wrong MAC
        keys), but no wrong keys are ever accepted — this is a DoS, not
        a security break.
        """
        psk = self.server.pre_shared_key
        config_dict, session_nonce = _verify_config_mac(config_dict, psk)
        B = config_dict.get('B', 100000)
        n_runs = config_dict.get('n_runs', 10)
        n_batches = config_dict.get('n_batches', 1)
        cutoff = config_dict.get('cutoff', 0.1)
        mod_mult = config_dict.get('mod_mult', 0.5)
        n_bits = config_dict.get('n_bits', 4)
        range_sigma = config_dict.get('range_sigma', 4.0)
        n_test_rounds = config_dict.get('n_test_rounds', 0)
        rng_mode = config_dict.get('rng_mode', 'urandom')

        _validate_signbit_nopa_psk(psk, B, rng_mode=rng_mode)

        # Extract Toeplitz seed from PSK if rdseed mode
        toeplitz_seed = None
        if rng_mode == 'rdseed':
            toeplitz_offset = 32 + _math.ceil(B / 8)
            toeplitz_seed = psk[toeplitz_offset:toeplitz_offset + 96]

        sigma_z = _leakage_mod.estimate_sigma_z(cutoff)
        p = mod_mult * sigma_z

        self.request.send('{}'.encode('utf-8'))  # ack

        # Committed σ/p verification (before pool init)
        sigma_verified = False
        empirical_sigma_over_p = 0.0
        if n_test_rounds > 0:
            empirical_sigma_over_p = self._signbit_nopa_committed_verify(
                sigma_z, p, B, n_test_rounds)
            sigma_verified = True

        # Initialize or reuse pool (nonce XOR ensures unique MAC keys per session)
        if not hasattr(self.server, '_signbit_pool') or self.server._signbit_pool is None:
            self.server._signbit_pool = _SignbitPool(psk, session_nonce=session_nonce)
        pool = self.server._signbit_pool

        # Per-run frame sizes
        resp_per_run = B + B * 8 + 8  # sign_enc + wire_b + tag

        all_sign_bits = []
        n_runs_used = 0
        max_chi2 = 0.0

        for batch_idx in range(n_batches):
            # --- Message 1: Recv all wire_a (n_runs × B float64) ---
            all_wa_frame = _recv_frame(self.request)
            wa_stride = B * 8

            # Process all runs locally (sequential pool ops), build response
            bob_signs_list = []
            bob_tags = []
            resp_parts = []

            for run_idx in range(n_runs):
                wa0 = np.frombuffer(
                    all_wa_frame[run_idx * wa_stride:(run_idx + 1) * wa_stride],
                    dtype=np.float64)

                # Generate Bob's noise and sign bits
                Z_b = sigma_z * _batch_true_random_gaussian(1, B,
                          rng_mode=rng_mode, toeplitz_seed=toeplitz_seed)
                bob_sign_raw = np.frombuffer(
                    _rng_bytes(B, rng_mode=rng_mode, toeplitz_seed=toeplitz_seed),
                    dtype=np.uint8) & 1

                # Encrypt Bob's signs with OTP from pool
                bob_otps = pool.withdraw_otp(B)
                bob_sign_enc = bob_sign_raw ^ bob_otps

                # wire_b[0] = mod_reduce(Z_b[0])
                wb0 = _parallel_mod_reduce(Z_b[:, 0], p)

                # Wire uniformity monitor
                chi2_a = _check_wire_uniformity(wa0, p)
                chi2_b = _check_wire_uniformity(wb0, p)
                max_chi2 = max(max_chi2, chi2_a, chi2_b)

                # Compute MAC (includes encrypted signs for active MITM protection)
                coeffs = _signbit_mac_coeffs(wa0, wb0, sigma_z, n_bits, range_sigma,
                                             sign_enc=bob_sign_enc)
                r, s = pool.get_mac_keys()
                bob_tag = _its_mac_tag_tree(coeffs, r, s)

                # Always deposit — both sides recover identical sign bits
                pool.deposit(bob_sign_raw, B)

                bob_signs_list.append(bob_sign_raw)
                bob_tags.append(bob_tag)
                resp_parts.append(
                    bob_sign_enc.astype(np.uint8).tobytes()
                    + np.ascontiguousarray(wb0).tobytes()
                    + int(bob_tag).to_bytes(8, 'big'))

            # --- Message 2: Send all responses ---
            _send_frame(self.request, b''.join(resp_parts))

            # --- Message 3: Recv all alice_mac_tags ---
            all_tags_frame = _recv_frame(self.request)

            for run_idx in range(n_runs):
                alice_tag = int.from_bytes(
                    all_tags_frame[run_idx * 8:(run_idx + 1) * 8], 'big')
                if alice_tag == bob_tags[run_idx]:
                    all_sign_bits.append(bob_signs_list[run_idx].copy())
                    n_runs_used += 1

            pool.compact()

        # Combine all sign bits as the key (no PA)
        if all_sign_bits:
            combined_key = np.concatenate(all_sign_bits)
        else:
            combined_key = np.array([], dtype=np.uint8)

        self.server.multibit_batch_result = {
            'secure_bits': combined_key,
            'n_raw_bits': len(combined_key),
            'n_secure': len(combined_key),
            'n_runs_used': n_runs_used,
            'n_runs_total': n_batches * n_runs,
            'n_batches': n_batches,
            'achieved_epsilon': 0.0,
            'pool_available_bits': pool.available_bits(),
            'psk_recycled': True,
            'sigma_verified': sigma_verified,
            'empirical_sigma_over_p': empirical_sigma_over_p,
            'monitor_chi2_max': max_chi2,
        }

    def _signbit_nopa_committed_verify(self, sigma_z, p, B, n_test):
        """Committed σ/p verification (Bob/server side).

        Both sides generate test noise, exchange commitments, then reveal.
        Checks: commitment integrity, wire consistency, empirical σ/p.

        Returns empirical σ/p ratio.
        Raises SigmaDriftError if any check fails.
        """
        # Generate test data: shape (B, n_test), mod-reduce all values
        Z_test_b = sigma_z * _batch_true_random_gaussian(n_test, B)
        wire_test_b = _parallel_mod_reduce(Z_test_b.ravel(), p)
        Z_test_b_bytes = np.ascontiguousarray(Z_test_b).tobytes()
        nonce_b = os.urandom(32)
        commit_b = hashlib.sha256(Z_test_b_bytes + nonce_b).digest()

        # Step 1: Recv commit_a, send commit_b
        commit_a = _recv_frame(self.request)
        _send_frame(self.request, commit_b)

        # Step 2: Recv wire_test_a, send wire_test_b
        wire_test_a_bytes = _recv_frame(self.request)
        _send_frame(self.request, np.ascontiguousarray(wire_test_b).tobytes())
        wire_test_a = np.frombuffer(wire_test_a_bytes, dtype=np.float64)

        # Step 3: Recv reveal_a, send reveal_b
        reveal_a = _recv_frame(self.request)
        _send_frame(self.request, Z_test_b_bytes + nonce_b)

        # Verify commitment integrity
        if hashlib.sha256(reveal_a).digest() != commit_a:
            _send_frame(self.request, b'\x00')
            _recv_frame(self.request)
            raise SigmaDriftError("Committed verification: Alice commitment mismatch")

        # Extract Alice's revealed Z and verify wire consistency
        Z_test_a_bytes = reveal_a[:-32]
        Z_test_a = np.frombuffer(Z_test_a_bytes, dtype=np.float64).reshape(B, n_test)
        wire_test_a_check = _parallel_mod_reduce(Z_test_a.ravel(), p)
        if not np.allclose(wire_test_a_check, wire_test_a, atol=1e-12):
            _send_frame(self.request, b'\x00')
            _recv_frame(self.request)
            raise SigmaDriftError("Committed verification: Alice wire inconsistency")

        # Check empirical σ/p
        all_Z = np.concatenate([Z_test_a.ravel(), Z_test_b.ravel()])
        empirical_sigma = float(np.std(all_Z))
        ratio = empirical_sigma / p
        if ratio < _SIGMA_P_MIN_THRESHOLD:
            _send_frame(self.request, b'\x00')
            _recv_frame(self.request)
            raise SigmaDriftError(
                "Committed verification: sigma/p=%.2f < %.1f"
                % (ratio, _SIGMA_P_MIN_THRESHOLD))

        # Step 4: Exchange pass/fail
        _send_frame(self.request, b'\x01')
        peer_result = _recv_frame(self.request)
        if peer_result != b'\x01':
            raise SigmaDriftError("Committed verification: Alice reported failure")

        return ratio

    def _handle_signbit_its(self, config_dict):
        """Handle sign-bit-only ITS protocol (B channels, n_ex=1).

        Only Bob's sign bits are extracted as key material.  With n_ex=1,
        wire_a[0] has center=0 (no sign dependence), so only Bob's sign
        contributes entropy (1 bit per channel).

        Batched message flow (1.5 RTTs for n_runs):
        1. Recv: all wire_a[0] concatenated (n_runs × B float64)
        2. Send: all (bob_sign_enc | wire_b[0] | bob_mac_tag) concatenated
        3. Recv: all alice_mac_tags concatenated (n_runs × 8 bytes)

        Runs are fully independent (MAC keys from static PSK offsets).
        """
        psk = self.server.pre_shared_key
        B = config_dict.get('B', 100000)
        n_runs = config_dict.get('n_runs', 10)
        target_epsilon = config_dict.get('target_epsilon', 0.01)
        ramp_time = config_dict.get('ramp_time', 5)
        cutoff = config_dict.get('cutoff', 0.1)
        mod_mult = config_dict.get('mod_mult', 0.5)
        alpha_mag = config_dict.get('alpha_mag', 0.9)
        recycle_psk = config_dict.get('recycle_psk', False)
        n_bits = config_dict.get('n_bits', 4)
        range_sigma = config_dict.get('range_sigma', 4.0)

        _validate_signbit_psk(psk, n_runs, B)

        sigma_z = _leakage_mod.estimate_sigma_z(cutoff)
        p = mod_mult * sigma_z

        self.request.send('{}'.encode('utf-8'))  # ack

        # Per-run frame sizes
        resp_per_run = B + B * 8 + 8  # sign_enc + wire_b + tag

        # --- Message 1: Recv all wire_a (n_runs × B float64) ---
        all_wa_frame = _recv_frame(self.request)
        wa_stride = B * 8

        # Process all runs, build response
        bob_signs_list = []
        bob_tags = []
        resp_parts = []

        for run_idx in range(n_runs):
            wa0 = np.frombuffer(
                all_wa_frame[run_idx * wa_stride:(run_idx + 1) * wa_stride],
                dtype=np.float64)

            Z_b = sigma_z * _batch_true_random_gaussian(1, B)
            bob_sign_raw = np.frombuffer(os.urandom(B), dtype=np.uint8) & 1

            bob_otps = _psk_signbit_bob_otp(psk, run_idx, B)
            bob_sign_enc = bob_sign_raw ^ bob_otps

            wb0 = _parallel_mod_reduce(Z_b[:, 0], p)

            coeffs = _signbit_mac_coeffs(wa0, wb0, sigma_z, n_bits, range_sigma,
                                         sign_enc=bob_sign_enc)
            r, s = _psk_signbit_mac_keys(psk, run_idx, B)
            bob_tag = _its_mac_tag_tree(coeffs, r, s)

            bob_signs_list.append(bob_sign_raw)
            bob_tags.append(bob_tag)
            resp_parts.append(
                bob_sign_enc.astype(np.uint8).tobytes()
                + np.ascontiguousarray(wb0).tobytes()
                + int(bob_tag).to_bytes(8, 'big'))

        # --- Message 2: Send all responses ---
        _send_frame(self.request, b''.join(resp_parts))

        # --- Message 3: Recv all alice_mac_tags ---
        all_tags_frame = _recv_frame(self.request)

        all_results = []
        for run_idx in range(n_runs):
            alice_tag = int.from_bytes(
                all_tags_frame[run_idx * 8:(run_idx + 1) * 8], 'big')
            if alice_tag == bob_tags[run_idx]:
                all_results.append({
                    'bob_signs_raw': bob_signs_list[run_idx],
                })
            else:
                all_results.append(None)

        self.server.multibit_results = all_results

        if config_dict.get('batch', False):
            self._signbit_batch_pa(all_results, n_runs, B, sigma_z, p,
                                    n_bits, range_sigma, target_epsilon,
                                    alpha_mag=alpha_mag, ramp_time=ramp_time,
                                    recycle_psk=recycle_psk)

    def _signbit_batch_pa(self, all_results, n_runs, B, sigma_z, modulus,
                           n_bits, range_sigma, target_epsilon,
                           alpha_mag=0.9, ramp_time=5, recycle_psk=False):
        """Privacy amplification for sign-bit extraction."""
        successful = [r for r in all_results if r is not None]

        if not successful:
            self.server.multibit_batch_result = {
                'secure_bits': np.array([], dtype=np.uint8),
                'n_raw_bits': 0, 'n_secure': 0,
                'n_runs_used': 0, 'n_runs_total': n_runs,
                'security': None, 'achieved_epsilon': 1.0,
                'psk_recycled': False,
            }
            return

        # Collect sign bits from all successful runs
        all_sign_bits = []
        for res in successful:
            all_sign_bits.append(res['bob_signs_raw'])
        raw_bits = np.concatenate(all_sign_bits).astype(np.uint8)
        n_raw = len(raw_bits)

        # Security analysis (sign-based h_min with n_ex=1)
        security = _sec_mod.multibit_security_analysis(
            sigma_z, modulus, 1,  # n_ex=1 fixed
            alpha=alpha_mag, ramp_time=ramp_time,
            n_bits=n_bits, range_sigma=range_sigma,
            target_epsilon=target_epsilon)

        n_channels_total = len(successful) * B
        h_min_per_channel = security['h_min_per_channel']

        secure_result = _sec_mod.compute_multibit_secure_length(
            n_channels_total, h_min_per_channel,
            target_epsilon=target_epsilon)
        n_secure = secure_result['n_secure']

        if n_secure == 0 or n_secure > n_raw:
            self.server.multibit_batch_result = {
                'secure_bits': np.array([], dtype=np.uint8),
                'n_raw_bits': n_raw, 'n_secure': 0,
                'n_runs_used': len(successful), 'n_runs_total': n_runs,
                'security': security, 'achieved_epsilon': 1.0,
                'psk_recycled': False,
            }
            return

        # GF(2) block PA
        secure_key = _privacy_mod.PrivacyAmplification.hash_gf2_block(
            raw_bits, n_secure, block_raw=64, seed=42)

        result = {
            'secure_bits': secure_key,
            'n_raw_bits': n_raw, 'n_secure': n_secure,
            'n_runs_used': len(successful), 'n_runs_total': n_runs,
            'security': security,
            'achieved_epsilon': secure_result['achieved_epsilon'],
        }

        # Key recycling
        if recycle_psk and n_secure > 0:
            next_psk, usable = _derive_next_signbit_psk(secure_key, n_runs, B)
            if next_psk is not None:
                self.server.pre_shared_key = next_psk
                result['next_psk'] = next_psk
                result['secure_bits'] = usable
                result['n_secure'] = len(usable)
                result['psk_recycled'] = True
            else:
                result['psk_recycled'] = False
        else:
            result['psk_recycled'] = False

        self.server.multibit_batch_result = result

    def _handle_parallel_its(self, config, config_dict, run_number):
        """Handle parallel-channel ITS protocol (B channels per round trip)."""
        psk = self.server.pre_shared_key
        B = config_dict.get('B', 100)
        n_ex = config_dict.get('n_ex', 10)
        n_runs = config_dict.get('n_runs', 1)
        n_bits = config_dict.get('n_bits', 4)
        range_sigma = config_dict.get('range_sigma', 4.0)
        target_epsilon = config_dict.get('target_epsilon', 0.01)
        is_batch = config_dict.get('batch', False)
        max_flip = config_dict.get('max_flip', 8)
        ramp_time = config_dict.get('ramp_time', 5)
        cutoff = config_dict.get('cutoff', 0.1)
        mod_mult = config_dict.get('mod_mult', 0.5)
        masking_time = config_dict.get('masking_time', 0)
        alpha_mag = config_dict.get('alpha_mag', 0.9)
        recycle_psk = config_dict.get('recycle_psk', False)

        _validate_parallel_psk(psk, n_runs, B)

        sigma_z = _leakage_mod.estimate_sigma_z(cutoff)
        p = mod_mult * sigma_z

        self.request.send('{}'.encode('utf-8'))  # ack

        all_results = []

        for run_idx in range(n_runs):
            # Generate Bob's noise: B channels x n_ex steps
            Z_b = sigma_z * _batch_true_random_gaussian(n_ex, B)  # (B, n_ex)

            # Generate Bob's alpha signs from PSK
            alice_otps, bob_otps = _psk_parallel_alpha_otps(psk, run_idx, B)

            # Random alpha signs for Bob (vectorized, single urandom call)
            bob_sign_raw = np.frombuffer(os.urandom(B), dtype=np.uint8) & 1
            bob_signs = np.where(bob_sign_raw == 0, 1.0, -1.0)
            bob_sign_enc = (bob_sign_raw ^ bob_otps).tolist()

            # Receive Alice's {signs, wire_a[0]} as binary frame
            frame = _recv_frame(self.request)
            alice_sign_enc, wa0 = _unpack_signs_wire(frame, B)
            alice_sign_raw = alice_sign_enc ^ alice_otps
            alice_signs = np.where(alice_sign_raw == 0, 1.0, -1.0)
            wire_a = [wa0]

            # Bob exchange step 0: compute wire_b[0]
            wire_b = []
            ramp_0 = _parallel_ramp(0, ramp_time)
            wb0 = _parallel_exchange_step_bob(Z_b[:, 0], bob_signs, ramp_0,
                                              wa0, p)
            wire_b.append(wb0)

            # Send Bob's {signs, wire_b[0]} as binary frame
            _send_frame(self.request,
                        _pack_signs_wire(bob_sign_enc, wb0))

            # Exchange loop: steps 1..n_ex-1
            for i in range(1, n_ex):
                # Receive wire_a[i] as binary frame
                wire_a.append(_unpack_wire(_recv_frame(self.request)))

                ramp_i = _parallel_ramp(i, ramp_time)
                wb = _parallel_exchange_step_bob(Z_b[:, i], bob_signs, ramp_i,
                                                  wire_a[-1], p)
                wire_b.append(wb)

                # Send wire_b[i] as binary frame
                _send_frame(self.request, _pack_wire(wb))

            # Receive final {wire_a[n_ex], tag} as binary frame
            frame = _recv_frame(self.request)
            wa_last, alice_tag = _unpack_wire_tag(frame)
            wire_a.append(wa_last)

            # Post-exchange decode for all B channels (vectorized)
            alpha_a_vec = alice_signs * alpha_mag
            alpha_b_vec = bob_signs * alpha_mag
            all_z_a, all_z_b, all_rel_a, all_rel_b = \
                _batch_wire_decode_z_all(wire_a, wire_b,
                                         alpha_a_vec, alpha_b_vec,
                                         ramp_time, p)

            n_a = n_ex + 1
            n_b = n_ex

            # Compute clean masks
            mask_start = ramp_time - masking_time
            mask_end = ramp_time - 1
            clean_a = np.ones(n_a, dtype=bool)
            for k in range(max(0, mask_start), min(mask_end + 1, n_a)):
                clean_a[k] = False
            clean_b = np.ones(n_b, dtype=bool)
            for k in range(max(0, mask_start), min(mask_end + 1, n_b)):
                clean_b[k] = False

            # Quantize all B channels to MAC coefficients (vectorized)
            coeffs = _batch_quantize_coeffs(all_z_a, all_z_b, clean_a, clean_b,
                                             sigma_z, n_bits, range_sigma)

            r, s = _psk_parallel_mac_keys(psk, run_idx, B)
            bob_tag = _its_mac_tag_tree(coeffs, r, s)

            # Search decoder if mismatch (vectorized)
            if bob_tag != alice_tag:
                borderline_idx, borderline_deltas = _batch_search_decode_deltas(
                    all_z_a, all_z_b, all_rel_a, all_rel_b,
                    clean_a, clean_b, sigma_z, p, n_bits, range_sigma, max_flip)

                if borderline_idx:
                    r_powers = _compute_r_powers(len(coeffs), r)
                    corrected = _search_decode(coeffs, r, s, alice_tag,
                                               borderline_idx, borderline_deltas,
                                               r_powers, max_flip)
                    if corrected is not None:
                        bob_tag = _its_mac_tag_tree(corrected, r, s)
                        coeffs = corrected

            # Send Bob's tag as binary frame
            _send_frame(self.request, _pack_tag(bob_tag))

            if alice_tag == bob_tag:
                all_results.append({
                    'z_a': all_z_a,        # (B, n_a)
                    'z_b': all_z_b,        # (B, n_b)
                    'clean_a': clean_a,    # (n_a,)
                    'clean_b': clean_b,    # (n_b,)
                    'coeffs': coeffs,
                })
            else:
                all_results.append(None)

        self.server.multibit_results = all_results

        if is_batch:
            self._parallel_its_batch_pa(all_results, n_runs, n_ex, B,
                                         sigma_z, p, n_bits, range_sigma,
                                         target_epsilon,
                                         alpha_mag=alpha_mag,
                                         ramp_time=ramp_time,
                                         recycle_psk=recycle_psk)

    def _parallel_its_batch_pa(self, all_results, n_runs, n_ex, B,
                                sigma_z, modulus, n_bits, range_sigma,
                                target_epsilon, alpha_mag=0.9,
                                ramp_time=5, recycle_psk=False):
        """Privacy amplification for parallel ITS results."""
        successful = [r for r in all_results if r is not None]

        if not successful:
            self.server.multibit_batch_result = {
                'secure_bits_a': np.array([], dtype=np.uint8),
                'secure_bits_b': np.array([], dtype=np.uint8),
                'n_raw_bits': 0, 'n_secure': 0,
                'n_runs_used': 0, 'n_runs_total': n_runs,
                'security': None, 'achieved_epsilon': 1.0,
                'psk_recycled': False,
            }
            return

        # Collect all raw bits from successful runs (vectorized)
        R = range_sigma * sigma_z
        n_bins = 2 ** n_bits
        delta_q = 2.0 * R / n_bins
        all_raw = []
        clean_steps_per_channel = None

        for res in successful:
            z_all = np.concatenate([res['z_a'][:, res['clean_a']],
                                     res['z_b'][:, res['clean_b']]], axis=1)
            if clean_steps_per_channel is None:
                clean_steps_per_channel = z_all.shape[1]
            bins = np.clip(((z_all + R) / delta_q).astype(int),
                            0, n_bins - 1).astype(np.uint8)
            # bins shape: (B, clean_steps) -> unpack each to n_bits
            bit_array = np.unpackbits(bins.reshape(-1, 1), axis=1,
                                       count=n_bits, bitorder='big')
            all_raw.append(bit_array.ravel())

        raw_bits = np.concatenate(all_raw)
        n_raw = len(raw_bits)

        security = _sec_mod.multibit_security_analysis(
            sigma_z, modulus, n_ex,
            alpha=alpha_mag, ramp_time=ramp_time,
            n_bits=n_bits, range_sigma=range_sigma,
            target_epsilon=target_epsilon)

        n_used = len(successful)
        n_channels_total = n_used * B
        h_min_per_channel = security['h_min_per_channel']

        composition_correction = 0.0

        secure_result = _sec_mod.compute_multibit_secure_length(
            n_channels_total, h_min_per_channel,
            target_epsilon=target_epsilon,
            composition_correction_bits=composition_correction)
        n_secure = secure_result['n_secure']

        if n_secure == 0 or n_secure > n_raw:
            self.server.multibit_batch_result = {
                'secure_bits_a': np.array([], dtype=np.uint8),
                'secure_bits_b': np.array([], dtype=np.uint8),
                'n_raw_bits': n_raw, 'n_secure': 0,
                'n_runs_used': n_used, 'n_runs_total': n_runs,
                'security': security, 'achieved_epsilon': 1.0,
                'psk_recycled': False,
            }
            return

        secure_key = _privacy_mod.PrivacyAmplification.hash_gf2_block(
            raw_bits, n_secure, block_raw=64, seed=42)

        result = {
            'secure_bits_a': secure_key,
            'secure_bits_b': secure_key,
            'n_raw_bits': n_raw, 'n_secure': n_secure,
            'n_runs_used': n_used, 'n_runs_total': n_runs,
            'security': security,
            'achieved_epsilon': secure_result['achieved_epsilon'],
        }

        if recycle_psk and n_secure > 0:
            next_psk, usable_bits = _derive_next_psk(secure_key, n_runs, B)
            if next_psk is not None:
                self.server.pre_shared_key = next_psk
                result['next_psk'] = next_psk
                result['secure_bits_a'] = usable_bits
                result['secure_bits_b'] = usable_bits
                result['n_secure'] = len(usable_bits)
                result['psk_recycled'] = True
            else:
                result['psk_recycled'] = False
        else:
            result['psk_recycled'] = False

        self.server.multibit_batch_result = result

    def __read_json_string(self):
        json_string = ''

        # Keep reading until we have a valid JSON string.
        while True:
            chunk = self.request.recv(1048576).decode('utf-8')
            if not chunk:
                return None
            json_string += chunk
            try:
                json.loads(json_string)
                break
            except ValueError:
                pass

        return json_string

class NetworkServerLink(object):
    """ A link class for a network-accessible server.

        Example: Wait for a connection and then return the session results:

        >>> link = NetworkServerLink(address, storage)
        >>> bits = link.run_proto()
    """
    def __init__(self, address, storage=None, pre_shared_key=None):
        self.server = socketserver.TCPServer(address, NetworkLinkRequestHandler)
        self.server.physics = []
        self.server.storage = storage
        self.server.pre_shared_key = pre_shared_key
        self.server.multibit_results = []
        self.server.multibit_batch_result = None

    def run_proto(self):
        self.server.handle_request()
        return self.server.physics

    def run_proto_multibit(self):
        """Handle one multibit protocol run. Returns multibit result dict."""
        self.server.multibit_results = []
        self.server.handle_request()
        return self.server.multibit_results

    def run_batch_multibit(self):
        """Handle one multibit batch session. Returns secure key + metadata."""
        self.server.handle_request()
        return self.server.multibit_batch_result

    def run_proto_multibit_its(self):
        """Handle one ITS multibit protocol run. Returns multibit result list."""
        self.server.multibit_results = []
        self.server.handle_request()
        return self.server.multibit_results

    def run_batch_multibit_its(self):
        """Handle one ITS multibit batch session. Returns secure key + metadata."""
        self.server.handle_request()
        return self.server.multibit_batch_result

    def run_batch_signbit_its(self):
        """Handle one signbit ITS batch session. Returns secure key + metadata."""
        self.server.handle_request()
        return self.server.multibit_batch_result

    def run_batch_signbit_nopa(self):
        """Handle one signbit no-PA batch session. Returns raw key + metadata."""
        self.server.handle_request()
        return self.server.multibit_batch_result

    def run_proto_parallel_its(self):
        """Handle one parallel ITS protocol run. Returns multibit result list."""
        self.server.multibit_results = []
        self.server.handle_request()
        return self.server.multibit_results

    def run_batch_parallel_its(self):
        """Handle one parallel ITS batch session. Returns secure key + metadata."""
        self.server.handle_request()
        return self.server.multibit_batch_result

    def close(self):
        self.server.server_close()




class NetworkClientLink(object):
    """A client-side link class.

    Example: Run the protocol 100 times

    >>> link = NetworkClientLink(address, endpoint, storage)
    >>> bits = [link.run_proto() for i in range(100)]"""
    def __init__(self, address, physics, storage=None, pre_shared_key=None):
        self.address = address
        self.physics = physics
        self.storage = storage
        self.run_number = 0
        self.pre_shared_key = pre_shared_key

        self.client_socket = socket.socket()
        self.client_socket.connect(self.address)

    def run_proto(self):
        self.physics.reset()

        if self.storage is not None:
            this_run = storage.Run(
                self.run_number,
                storage.Endpoint('Alice', self.physics))

            self.run_number += 1

        self.client_socket.send(self.physics.to_json().encode('utf-8'))
        self.__read_json_string(self.client_socket)

        message = self.physics.exchange(0.0)
        self.client_socket.send(json.dumps({'message': message}).encode('utf-8'))

        if self.storage is not None:
            this_run.add_message(storage.Message('Alice', 'Bob', message))

        for i in range(self.physics.number_of_exchanges):
            message = json.loads(self.__read_json_string(self.client_socket))
            response = self.physics.exchange(message['message'])

            self.client_socket.send(json.dumps({'message': response}).encode('utf-8'))

            if self.storage is not None:
                this_run.add_message(storage.Message('Bob', 'Alice', message['message']))
                this_run.add_message(storage.Message('Alice', 'Bob', response))

        if self.physics.estimate_other() \
                == (self.physics.reflection_coefficient > 0):
            result = None
        else:
            result = self.physics.reflection_coefficient > 0

        # Now that we have decided whether or not to declare a bit,
        # we must agree this with the client.
        message = json.loads(self.__read_json_string(self.client_socket))

        if result is None:
            self.client_socket.send('{"decision":"discard"}'.encode('utf-8'))
        else:
            self.client_socket.send('{"decision":"declare"}'.encode('utf-8'))

        if message['decision'] == 'discard':
            result = None

        if self.storage is not None:
            this_run.add_result(storage.Result('Alice', result))
            self.storage.add_run(this_run)

        # Read the final "resynchronising" response.
        self.__read_json_string(self.client_socket)

        return result

    def run_proto_multibit(self):
        """Run a single multibit protocol iteration over the network.

        Requires ``pre_shared_key`` to be set. Sends M_real values
        encrypted via AuthCipher alongside wire values.

        Returns
        -------
        dict
            Same format as ``InternalLink.run_proto_multibit()``.
        """
        if self.pre_shared_key is None:
            raise RuntimeError("run_proto_multibit requires pre_shared_key")

        return self._run_multibit_runs(n_runs=1)[0]

    def run_batch_multibit(self, n_runs, n_bits=4, range_sigma=4.0,
                           target_epsilon=0.01):
        """Run a batch with multi-bit extraction over the network.

        Same pipeline as ``InternalLink.run_batch_multibit()`` but
        uses the network protocol with encrypted auth channel.

        Parameters
        ----------
        n_runs : int
            Number of protocol runs.
        n_bits : int
            Quantization bits per Z sample (default 4).
        range_sigma : float
            Quantization range in sigma_z units (default 4.0).
        target_epsilon : float
            Target security parameter (default 0.01).

        Returns
        -------
        dict
            Same format as ``InternalLink.run_batch_multibit()``.
        """
        if self.pre_shared_key is None:
            raise RuntimeError("run_batch_multibit requires pre_shared_key")

        all_results = self._run_multibit_runs(
            n_runs=n_runs, n_bits=n_bits, range_sigma=range_sigma,
            target_epsilon=target_epsilon, batch=True)

        sigma_z = self.physics.sigma_z
        n_ex = self.physics.number_of_exchanges
        modulus = self.physics.modulus

        all_raw = []
        n_used = 0
        clean_steps_per_run = None
        n_masking_excluded_per_run = 0

        for res in all_results:
            n_used += 1
            z_a_clean = res['z_a'][res['clean_a']]
            z_b_clean = res['z_b'][res['clean_b']]
            z_combined = np.concatenate([z_a_clean, z_b_clean])

            if clean_steps_per_run is None:
                total_steps = len(res['z_a']) + len(res['z_b'])
                clean_steps_per_run = len(z_combined)
                n_masking_excluded_per_run = total_steps - clean_steps_per_run

            bits = InternalLink.quantize_z(z_combined, sigma_z,
                                           n_bits=n_bits,
                                           range_sigma=range_sigma)
            all_raw.append(bits)

        if n_used == 0:
            return {
                'secure_bits_a': np.array([], dtype=np.uint8),
                'secure_bits_b': np.array([], dtype=np.uint8),
                'n_raw_bits': 0, 'n_secure': 0,
                'n_runs_used': 0, 'n_runs_total': n_runs,
                'security': None, 'achieved_epsilon': 1.0,
                'n_masking_excluded_per_run': 0,
                'clean_steps_per_run': 0,
            }

        raw_bits = np.concatenate(all_raw)
        n_raw = len(raw_bits)

        alpha_mag = abs(self.physics.reflection_coefficient)
        security = _sec_mod.multibit_security_analysis(
            sigma_z, modulus, n_ex,
            alpha=alpha_mag, ramp_time=self.physics.ramp_time,
            n_bits=n_bits, range_sigma=range_sigma,
            target_epsilon=target_epsilon)

        n_channels_total = n_used
        h_min_per_channel = security['h_min_per_channel']

        composition_correction = 0.0

        secure_result = _sec_mod.compute_multibit_secure_length(
            n_channels_total, h_min_per_channel,
            target_epsilon=target_epsilon,
            composition_correction_bits=composition_correction)
        n_secure = secure_result['n_secure']

        if n_secure == 0 or n_secure > n_raw:
            return {
                'secure_bits_a': np.array([], dtype=np.uint8),
                'secure_bits_b': np.array([], dtype=np.uint8),
                'n_raw_bits': n_raw, 'n_secure': 0,
                'n_runs_used': n_used, 'n_runs_total': n_runs,
                'security': security, 'achieved_epsilon': 1.0,
                'n_masking_excluded_per_run': n_masking_excluded_per_run,
                'clean_steps_per_run': clean_steps_per_run,
            }

        pa = _privacy_mod.PrivacyAmplification(n_raw, n_secure, seed=42)
        secure_key = pa.hash(raw_bits.tolist())

        return {
            'secure_bits_a': secure_key,
            'secure_bits_b': secure_key,
            'n_raw_bits': n_raw, 'n_secure': n_secure,
            'n_runs_used': n_used, 'n_runs_total': n_runs,
            'security': security,
            'achieved_epsilon': secure_result['achieved_epsilon'],
            'n_masking_excluded_per_run': n_masking_excluded_per_run,
            'clean_steps_per_run': clean_steps_per_run,
        }

    def _run_multibit_runs(self, n_runs=1, n_bits=4, range_sigma=4.0,
                           target_epsilon=0.01, batch=False):
        """Execute multibit protocol runs over the network.

        Returns list of result dicts (one per run).
        """
        psk = self.pre_shared_key
        self.physics.reset()
        self.physics.rng_is_true_random = True

        n_ex = self.physics.number_of_exchanges

        # Send config with multibit flag
        config_dict = json.loads(self.physics.to_json())
        config_dict['multibit'] = True
        config_dict['n_runs'] = n_runs
        config_dict['n_bits'] = n_bits
        config_dict['range_sigma'] = range_sigma
        config_dict['target_epsilon'] = target_epsilon
        config_dict['batch'] = batch
        self.client_socket.send(json.dumps(config_dict).encode('utf-8'))

        # Wait for ack
        self.__read_json_string(self.client_socket)

        # Exchange actual reflection coefficients via encrypted auth channel
        alpha_enc = AuthCipher(psk + b'C-alpha')
        alpha_dec = AuthCipher(psk + b'S-alpha')

        alpha_a = self.physics.reflection_coefficient
        self.client_socket.send(json.dumps({
            'alpha': _encode_real(alpha_a, alpha_enc)
        }).encode('utf-8'))

        alpha_msg = json.loads(
            self.__read_json_string(self.client_socket))
        alpha_b = _decode_real(alpha_msg['alpha'], alpha_dec)

        # Create directional ciphers
        enc_cipher = AuthCipher(psk + b'C')
        dec_cipher = AuthCipher(psk + b'S')

        all_results = []

        for run_idx in range(n_runs):
            if run_idx > 0:
                self.physics.reset()
                # Re-exchange alphas (sign may change on reset)
                alpha_enc_r = AuthCipher(psk + b'C-alpha' + struct.pack('>I', run_idx))
                alpha_dec_r = AuthCipher(psk + b'S-alpha' + struct.pack('>I', run_idx))
                alpha_a = self.physics.reflection_coefficient
                self.client_socket.send(json.dumps({
                    'alpha': _encode_real(alpha_a, alpha_enc_r)
                }).encode('utf-8'))
                alpha_msg = json.loads(
                    self.__read_json_string(self.client_socket))
                alpha_b = _decode_real(alpha_msg['alpha'], alpha_dec_r)

                enc_cipher = AuthCipher(psk + b'C' + struct.pack('>I', run_idx))
                dec_cipher = AuthCipher(psk + b'S' + struct.pack('>I', run_idx))

            wire_a = []
            wire_b = []
            m_real_a = []
            m_real_b = []

            # Alice exchange 0
            w = self.physics.exchange(0.0)
            wire_a.append(w)
            m_real_a.append(self.physics._last_real_sent)

            # Send exchange 0 with auth
            msg = json.dumps({
                'message': w,
                'auth': _encode_real(self.physics._last_real_sent, enc_cipher)
            })
            self.client_socket.send(msg.encode('utf-8'))

            for i in range(n_ex):
                # Receive Bob's response
                response = json.loads(
                    self.__read_json_string(self.client_socket))
                wire_b.append(response['message'])
                incoming_real = _decode_real(response['auth'], dec_cipher)
                m_real_b.append(incoming_real)

                # Alice exchange i+1
                w = self.physics.exchange(response['message'],
                                          incoming_real=incoming_real)
                wire_a.append(w)
                m_real_a.append(self.physics._last_real_sent)

                # Send Alice's response
                msg = json.dumps({
                    'message': w,
                    'auth': _encode_real(self.physics._last_real_sent,
                                         enc_cipher)
                })
                self.client_socket.send(msg.encode('utf-8'))

            # Receive multibit done ack
            done_msg = json.loads(
                self.__read_json_string(self.client_socket))
            assert done_msg.get('multibit') == 'done'

            # Send sync
            self.client_socket.send('{}'.encode('utf-8'))

            # Reconstruct Z sequences
            # alpha_a and alpha_b were exchanged via the encrypted channel

            z_a = np.empty(n_ex + 1)
            z_a[0] = m_real_a[0]  # ramp(0) = 0
            for i in range(n_ex):
                ramp_k = self.physics._ramp_function([i + 1])[0]
                z_a[i + 1] = m_real_a[i + 1] - alpha_a * ramp_k * m_real_b[i]

            z_b = np.empty(n_ex)
            for i in range(n_ex):
                ramp_k = self.physics._ramp_function([i])[0]
                z_b[i] = m_real_b[i] - alpha_b * ramp_k * m_real_a[i]

            # Compute clean masks
            ramp_time = self.physics.ramp_time
            masking_time = self.physics.masking_time
            mask_start = ramp_time - masking_time
            mask_end = ramp_time - 1

            clean_a = np.ones(n_ex + 1, dtype=bool)
            for k in range(max(0, mask_start), min(mask_end + 1, n_ex + 1)):
                clean_a[k] = False

            clean_b = np.ones(n_ex, dtype=bool)
            for k in range(max(0, mask_start), min(mask_end + 1, n_ex)):
                clean_b[k] = False

            signs_differ = bool(
                self.physics.estimate_other()
                ^ (self.physics.reflection_coefficient > 0))

            all_results.append({
                'z_a': z_a,
                'z_b': z_b,
                'clean_a': clean_a,
                'clean_b': clean_b,
                'signs_differ': signs_differ,
                'wire_a': wire_a,
                'wire_b': wire_b,
            })

        return all_results

    def run_proto_multibit_its(self):
        """Run a single ITS multibit protocol iteration over the network.

        No M_real is transmitted. Agreement is verified via Wegman-Carter
        polynomial MAC keyed from the PSK.

        Returns
        -------
        dict or None
            Same format as ``InternalLink.run_proto_multibit()``, or None
            if MAC verification failed (Z mismatch).
        """
        if self.pre_shared_key is None:
            raise RuntimeError("run_proto_multibit_its requires pre_shared_key")

        results = self._run_multibit_runs_its(n_runs=1)
        return results[0]

    def run_batch_multibit_its(self, n_runs, n_bits=4, range_sigma=4.0,
                                target_epsilon=0.01):
        """Run a batch with ITS multi-bit extraction over the network.

        Same pipeline as ``run_batch_multibit()`` but uses the ITS protocol
        where M_real is never transmitted.

        Parameters
        ----------
        n_runs : int
            Number of protocol runs.
        n_bits : int
            Quantization bits per Z sample (default 4).
        range_sigma : float
            Quantization range in sigma_z units (default 4.0).
        target_epsilon : float
            Target security parameter (default 0.01).

        Returns
        -------
        dict
            Same format as ``InternalLink.run_batch_multibit()``.
        """
        if self.pre_shared_key is None:
            raise RuntimeError("run_batch_multibit_its requires pre_shared_key")

        all_results = self._run_multibit_runs_its(
            n_runs=n_runs, n_bits=n_bits, range_sigma=range_sigma,
            target_epsilon=target_epsilon, batch=True)

        # Filter successful results
        successful = [r for r in all_results if r is not None]

        sigma_z = self.physics.sigma_z
        n_ex = self.physics.number_of_exchanges
        modulus = self.physics.modulus

        all_raw = []
        n_used = 0
        clean_steps_per_run = None
        n_masking_excluded_per_run = 0

        for res in successful:
            n_used += 1
            z_a_clean = res['z_a'][res['clean_a']]
            z_b_clean = res['z_b'][res['clean_b']]
            z_combined = np.concatenate([z_a_clean, z_b_clean])

            if clean_steps_per_run is None:
                total_steps = len(res['z_a']) + len(res['z_b'])
                clean_steps_per_run = len(z_combined)
                n_masking_excluded_per_run = total_steps - clean_steps_per_run

            bits = InternalLink.quantize_z(z_combined, sigma_z,
                                           n_bits=n_bits,
                                           range_sigma=range_sigma)
            all_raw.append(bits)

        if n_used == 0:
            return {
                'secure_bits_a': np.array([], dtype=np.uint8),
                'secure_bits_b': np.array([], dtype=np.uint8),
                'n_raw_bits': 0, 'n_secure': 0,
                'n_runs_used': 0, 'n_runs_total': n_runs,
                'security': None, 'achieved_epsilon': 1.0,
                'n_masking_excluded_per_run': 0,
                'clean_steps_per_run': 0,
            }

        raw_bits = np.concatenate(all_raw)
        n_raw = len(raw_bits)

        alpha_mag = abs(self.physics.reflection_coefficient)
        security = _sec_mod.multibit_security_analysis(
            sigma_z, modulus, n_ex,
            alpha=alpha_mag, ramp_time=self.physics.ramp_time,
            n_bits=n_bits, range_sigma=range_sigma,
            target_epsilon=target_epsilon)

        n_channels_total = n_used
        h_min_per_channel = security['h_min_per_channel']

        composition_correction = 0.0

        secure_result = _sec_mod.compute_multibit_secure_length(
            n_channels_total, h_min_per_channel,
            target_epsilon=target_epsilon,
            composition_correction_bits=composition_correction)
        n_secure = secure_result['n_secure']

        if n_secure == 0 or n_secure > n_raw:
            return {
                'secure_bits_a': np.array([], dtype=np.uint8),
                'secure_bits_b': np.array([], dtype=np.uint8),
                'n_raw_bits': n_raw, 'n_secure': 0,
                'n_runs_used': n_used, 'n_runs_total': n_runs,
                'security': security, 'achieved_epsilon': 1.0,
                'n_masking_excluded_per_run': n_masking_excluded_per_run,
                'clean_steps_per_run': clean_steps_per_run,
            }

        pa = _privacy_mod.PrivacyAmplification(n_raw, n_secure, seed=42)
        secure_key = pa.hash(raw_bits.tolist())

        return {
            'secure_bits_a': secure_key,
            'secure_bits_b': secure_key,
            'n_raw_bits': n_raw, 'n_secure': n_secure,
            'n_runs_used': n_used, 'n_runs_total': n_runs,
            'security': security,
            'achieved_epsilon': secure_result['achieved_epsilon'],
            'n_masking_excluded_per_run': n_masking_excluded_per_run,
            'clean_steps_per_run': clean_steps_per_run,
        }

    def _run_multibit_runs_its(self, n_runs=1, n_bits=4, range_sigma=4.0,
                                target_epsilon=0.01, batch=False):
        """Execute ITS multibit protocol runs over the network.

        Uses wire-value exchange: both parties feed wire values into
        exchange(), making per-step decode errors independent.
        Post-exchange Z decode uses known-alpha centres and a search
        decoder for borderline wrapping counts.

        Returns list of result dicts (one per run), with None for
        runs where MAC verification failed.
        """
        psk = self.pre_shared_key
        _validate_its_psk(psk, n_runs)

        # ITS mode: use IID noise for zero composition correction.
        self.physics.rng_is_true_random = True
        self.physics.no_reset = True
        self.physics.reset()
        self.physics.no_reset = False

        n_ex = self.physics.number_of_exchanges
        sigma_z = self.physics.sigma_z
        max_flip = 8

        # Send config with multibit_its flag
        config_dict = json.loads(self.physics.to_json())
        config_dict['multibit_its'] = True
        config_dict['n_runs'] = n_runs
        config_dict['n_bits'] = n_bits
        config_dict['range_sigma'] = range_sigma
        config_dict['target_epsilon'] = target_epsilon
        config_dict['batch'] = batch
        config_dict['max_flip'] = max_flip
        self.client_socket.send(json.dumps(config_dict).encode('utf-8'))

        # Wait for ack
        self.__read_json_string(self.client_socket)

        all_results = []

        for run_idx in range(n_runs):
            if run_idx > 0:
                self.physics.reset()

            # Send Alice's OTP-encrypted sign bit
            alice_sign_positive = self.physics.reflection_coefficient > 0
            alice_otp = _psk_alpha_otp(psk, run_idx, 0)
            alice_sign_enc = (0 if alice_sign_positive else 1) ^ alice_otp
            self.client_socket.send(json.dumps({'sign': alice_sign_enc}).encode('utf-8'))

            # Receive Bob's OTP-encrypted sign bit
            sign_msg = json.loads(self.__read_json_string(self.client_socket))
            bob_otp = _psk_alpha_otp(psk, run_idx, 1)
            bob_sign_positive = (sign_msg['sign'] ^ bob_otp) == 0

            alpha_a = self.physics.reflection_coefficient
            alpha_b_sign = 1.0 if bob_sign_positive else -1.0
            alpha_b = alpha_b_sign * abs(self.physics.reflection_coefficient)

            wire_a = []
            wire_b = []

            # Alice exchange 0
            w = self.physics.exchange(0.0)
            wire_a.append(w)

            # Send wire value only (no auth)
            self.client_socket.send(json.dumps({
                'message': w
            }).encode('utf-8'))

            for i in range(n_ex):
                # Receive Bob's wire value
                response = json.loads(
                    self.__read_json_string(self.client_socket))
                wire_b_val = response['message']
                wire_b.append(wire_b_val)

                # Alice exchange i+1: wire-value mode
                w = self.physics.exchange(wire_b_val,
                                          incoming_real=wire_b_val)
                wire_a.append(w)

                # Send Alice's wire value (no auth)
                self.client_socket.send(json.dumps({
                    'message': w
                }).encode('utf-8'))

            # Receive done signal
            done_msg = json.loads(
                self.__read_json_string(self.client_socket))
            assert done_msg.get('its') == 'done'

            # Post-exchange decode using known-alpha centers
            z_a, z_b, rel_a, rel_b, wrap_a, wrap_b = \
                _wire_decode_z_all(wire_a, wire_b, alpha_a, alpha_b,
                                   self.physics._ramp_function,
                                   self.physics.modulus)

            # Compute clean masks
            ramp_time = self.physics.ramp_time
            masking_time = self.physics.masking_time
            mask_start = ramp_time - masking_time
            mask_end = ramp_time - 1

            clean_a = np.ones(n_ex + 1, dtype=bool)
            for k in range(max(0, mask_start), min(mask_end + 1, n_ex + 1)):
                clean_a[k] = False

            clean_b = np.ones(n_ex, dtype=bool)
            for k in range(max(0, mask_start), min(mask_end + 1, n_ex)):
                clean_b[k] = False

            # Compute MAC tag
            coeffs = _z_to_mac_coeffs(z_a, z_b, clean_a, clean_b, sigma_z,
                                       n_bits=n_bits, range_sigma=range_sigma)
            r, s = _psk_mac_keys(psk, run_idx)
            alice_tag = _its_mac_tag(coeffs, r, s)

            # Send Alice's tag, receive Bob's tag
            self.client_socket.send(json.dumps({'tag': alice_tag}).encode('utf-8'))
            tag_msg = json.loads(self.__read_json_string(self.client_socket))
            bob_tag = tag_msg['tag']

            # If Bob corrected his decode to match ours, bob_tag == alice_tag.
            # If not, try search-correcting our decode to match Bob's.
            if alice_tag != bob_tag:
                alice_tag, coeffs = self._its_search_correct_client(
                    coeffs, z_a, z_b, rel_a, rel_b, clean_a, clean_b,
                    wire_a, wire_b, alpha_a, alpha_b,
                    sigma_z, r, s, bob_tag, n_bits, range_sigma,
                    max_flip)

            # Sync
            self.client_socket.send('{}'.encode('utf-8'))

            if alice_tag == bob_tag:
                all_results.append({
                    'z_a': z_a,
                    'z_b': z_b,
                    'clean_a': clean_a,
                    'clean_b': clean_b,
                    'signs_differ': (alpha_a * alpha_b) < 0,
                })
            else:
                all_results.append(None)

        return all_results

    def _its_search_correct_client(self, coeffs, z_a, z_b, rel_a, rel_b,
                                   clean_a, clean_b, wire_a, wire_b,
                                   alpha_a, alpha_b, sigma_z,
                                   r, s, target_tag, n_bits, range_sigma,
                                   max_flip):
        """Client-side search decoder (same logic as server's)."""
        p = self.physics.modulus
        R = range_sigma * sigma_z
        n_bins = 2 ** n_bits
        delta = 2.0 * R / n_bins

        rel_flat = np.concatenate([rel_a[clean_a], rel_b[clean_b]])
        z_flat = np.concatenate([z_a[clean_a], z_b[clean_b]])

        delta_bins = []
        for i in range(len(z_flat)):
            z_orig = z_flat[i]
            bin_orig = int(np.clip((z_orig + R) / delta, 0, n_bins - 1))
            bin_plus = int(np.clip((z_orig + p + R) / delta, 0, n_bins - 1))
            bin_minus = int(np.clip((z_orig - p + R) / delta, 0, n_bins - 1))
            if bin_plus != bin_orig and bin_minus != bin_orig:
                if abs(bin_plus - bin_orig) <= abs(bin_minus - bin_orig):
                    delta_bins.append(bin_plus - bin_orig)
                else:
                    delta_bins.append(bin_minus - bin_orig)
            elif bin_plus != bin_orig:
                delta_bins.append(bin_plus - bin_orig)
            elif bin_minus != bin_orig:
                delta_bins.append(bin_minus - bin_orig)
            else:
                delta_bins.append(0)

        order = np.argsort(rel_flat)
        borderline_idx = []
        borderline_deltas = []
        for idx in order:
            if delta_bins[idx] != 0:
                borderline_idx.append(int(idx))
                borderline_deltas.append(delta_bins[idx])
            if len(borderline_idx) >= max_flip:
                break

        if not borderline_idx:
            return _its_mac_tag(coeffs, r, s), coeffs

        r_powers = _compute_r_powers(len(coeffs), r)
        corrected = _search_decode(coeffs, r, s, target_tag,
                                   borderline_idx, borderline_deltas,
                                   r_powers, max_flip)
        if corrected is not None:
            return _its_mac_tag(corrected, r, s), corrected
        return _its_mac_tag(coeffs, r, s), coeffs

    def run_signbit_batch(self, B=100000, n_runs=10, cutoff=0.1,
                          mod_mult=0.5, alpha_mag=0.9, ramp_time=5,
                          target_epsilon=0.01, recycle_psk=False,
                          n_bits=4, range_sigma=4.0):
        """Run sign-bit-only ITS batch over the network.

        With n_ex=1, only Bob's sign contributes entropy (1 bit per channel).
        Net PSK cost per run is ~143 bits (128 MAC + 15 LHL slack).

        Parameters
        ----------
        B : int
            Number of parallel channels (default 100000).
        n_runs : int
            Number of runs per batch (default 10).
        cutoff : float
            Noise cutoff frequency (default 0.1).
        mod_mult : float
            Modulus multiplier (p = mod_mult * sigma_z, default 0.5).
        alpha_mag : float
            Magnitude of reflection coefficient (default 0.9).
        ramp_time : float
            Ramp time constant (default 5).
        target_epsilon : float
            Target security parameter (default 0.01).
        recycle_psk : bool
            If True, feed output back as next PSK (default False).
        n_bits : int
            Quantization bits for MAC verification (default 4).
        range_sigma : float
            Quantization range for MAC (default 4.0).

        Returns
        -------
        dict
            'secure_bits': usable key bits (numpy uint8),
            'n_secure': number of secure bits,
            'n_raw_bits': raw sign bits collected,
            'n_runs_used': successful runs,
            'n_runs_total': total runs,
            'security': security analysis dict,
            'achieved_epsilon': actual epsilon,
            'psk_recycled': True if PSK was recycled,
            'throughput_bps': estimated throughput (bits per second).
        """
        if self.pre_shared_key is None:
            raise RuntimeError("run_signbit_batch requires pre_shared_key")

        import time
        t_start = time.time()

        result = self._run_signbit_its(
            B=B, n_runs=n_runs, cutoff=cutoff, mod_mult=mod_mult,
            alpha_mag=alpha_mag, ramp_time=ramp_time,
            target_epsilon=target_epsilon, recycle_psk=recycle_psk,
            n_bits=n_bits, range_sigma=range_sigma)

        t_elapsed = time.time() - t_start
        n_secure = result.get('n_secure', 0)
        result['throughput_bps'] = n_secure / t_elapsed if t_elapsed > 0 else 0
        result['elapsed_seconds'] = t_elapsed

        return result

    def _run_signbit_its(self, B=100000, n_runs=10, cutoff=0.1,
                          mod_mult=0.5, alpha_mag=0.9, ramp_time=5,
                          target_epsilon=0.01, recycle_psk=False,
                          n_bits=4, range_sigma=4.0):
        """Execute sign-bit ITS protocol runs over the network (Alice side).

        Batched message flow (1.5 RTTs for n_runs):
        1. Send: all wire_a[0] concatenated (n_runs × B float64)
        2. Recv: all (bob_sign_enc | wire_b[0] | bob_mac_tag) concatenated
        3. Send: all alice_mac_tags concatenated (n_runs × 8 bytes)

        Runs are fully independent (MAC keys from static PSK offsets).
        """
        psk = self.pre_shared_key
        _validate_signbit_psk(psk, n_runs, B)

        sigma_z = _leakage_mod.estimate_sigma_z(cutoff)
        p = mod_mult * sigma_z

        # Send config
        config_dict = {
            'signbit_its': True,
            'B': B,
            'n_runs': n_runs,
            'target_epsilon': target_epsilon,
            'batch': True,
            'ramp_time': ramp_time,
            'cutoff': cutoff,
            'mod_mult': mod_mult,
            'alpha_mag': alpha_mag,
            'recycle_psk': recycle_psk,
            'n_bits': n_bits,
            'range_sigma': range_sigma,
        }
        self.client_socket.send(json.dumps(config_dict).encode('utf-8'))

        # Wait for ack
        self.__read_json_string(self.client_socket)

        # Per-run frame sizes
        resp_per_run = B + B * 8 + 8  # sign_enc + wire_b + tag

        # --- Message 1: Generate and send all wire_a ---
        wa_parts = []
        wa_list = []
        for run_idx in range(n_runs):
            Z_a = sigma_z * _batch_true_random_gaussian(1, B)
            wa0 = _parallel_mod_reduce(Z_a[:, 0], p)
            wa_list.append(wa0)
            wa_parts.append(np.ascontiguousarray(wa0).tobytes())
        _send_frame(self.client_socket, b''.join(wa_parts))

        # --- Message 2: Recv all responses ---
        all_resp_frame = _recv_frame(self.client_socket)

        # Process all runs
        bob_tags = []
        alice_tags = []
        bob_signs_list = []

        for run_idx in range(n_runs):
            off = run_idx * resp_per_run
            bob_sign_enc = np.frombuffer(
                all_resp_frame[off:off + B], dtype=np.uint8)
            wb0 = np.frombuffer(
                all_resp_frame[off + B:off + B + B * 8], dtype=np.float64)
            bob_tag = int.from_bytes(
                all_resp_frame[off + B + B * 8:off + resp_per_run], 'big')

            bob_otps = _psk_signbit_bob_otp(psk, run_idx, B)
            bob_sign_raw = bob_sign_enc ^ bob_otps

            coeffs = _signbit_mac_coeffs(wa_list[run_idx], wb0, sigma_z,
                                         n_bits, range_sigma,
                                         sign_enc=bob_sign_enc)
            r, s = _psk_signbit_mac_keys(psk, run_idx, B)
            alice_tag = _its_mac_tag_tree(coeffs, r, s)

            bob_signs_list.append(bob_sign_raw)
            bob_tags.append(bob_tag)
            alice_tags.append(alice_tag)

        # --- Message 3: Send all alice_mac_tags ---
        tag_frame = b''.join(int(t).to_bytes(8, 'big') for t in alice_tags)
        _send_frame(self.client_socket, tag_frame)

        # Collect results
        all_results = []
        for run_idx in range(n_runs):
            if alice_tags[run_idx] == bob_tags[run_idx]:
                all_results.append({
                    'bob_signs_raw': bob_signs_list[run_idx].copy(),
                })
            else:
                all_results.append(None)

        # Client-side PA (mirrors server)
        successful = [r for r in all_results if r is not None]

        if not successful:
            return {
                'secure_bits': np.array([], dtype=np.uint8),
                'n_raw_bits': 0, 'n_secure': 0,
                'n_runs_used': 0, 'n_runs_total': n_runs,
                'security': None, 'achieved_epsilon': 1.0,
                'psk_recycled': False,
            }

        all_sign_bits = []
        for res in successful:
            all_sign_bits.append(res['bob_signs_raw'])
        raw_bits = np.concatenate(all_sign_bits).astype(np.uint8)
        n_raw = len(raw_bits)

        security = _sec_mod.multibit_security_analysis(
            sigma_z, p, 1,
            alpha=alpha_mag, ramp_time=ramp_time,
            n_bits=n_bits, range_sigma=range_sigma,
            target_epsilon=target_epsilon)

        n_channels_total = len(successful) * B
        h_min_per_channel = security['h_min_per_channel']

        secure_result = _sec_mod.compute_multibit_secure_length(
            n_channels_total, h_min_per_channel,
            target_epsilon=target_epsilon)
        n_secure = secure_result['n_secure']

        if n_secure == 0 or n_secure > n_raw:
            return {
                'secure_bits': np.array([], dtype=np.uint8),
                'n_raw_bits': n_raw, 'n_secure': 0,
                'n_runs_used': len(successful), 'n_runs_total': n_runs,
                'security': security, 'achieved_epsilon': 1.0,
                'psk_recycled': False,
            }

        secure_key = _privacy_mod.PrivacyAmplification.hash_gf2_block(
            raw_bits, n_secure, block_raw=64, seed=42)

        result = {
            'secure_bits': secure_key,
            'n_raw_bits': n_raw, 'n_secure': n_secure,
            'n_runs_used': len(successful), 'n_runs_total': n_runs,
            'security': security,
            'achieved_epsilon': secure_result['achieved_epsilon'],
        }

        if recycle_psk and n_secure > 0:
            next_psk, usable = _derive_next_signbit_psk(secure_key, n_runs, B)
            if next_psk is not None:
                self.pre_shared_key = next_psk
                result['next_psk'] = next_psk
                result['secure_bits'] = usable
                result['n_secure'] = len(usable)
                result['psk_recycled'] = True
            else:
                result['psk_recycled'] = False
        else:
            result['psk_recycled'] = False

        return result

    def run_signbit_nopa(self, B=100000, n_runs=10, n_batches=1,
                         cutoff=0.1, mod_mult=0.5,
                         n_bits=4, range_sigma=4.0,
                         n_test_rounds=_DEFAULT_N_TEST_ROUNDS,
                         rng_mode='urandom'):
        """Run sign-bit no-PA protocol over the network.

        No privacy amplification — raw sign bits are the key.  Pool stays
        flat: each run withdraws and deposits B/8 bytes.  Infinite operation
        from finite PSK.

        Parameters
        ----------
        B : int
            Number of parallel channels (default 100000).
        n_runs : int
            Number of runs per batch (default 10).
        n_batches : int
            Number of batches within single connection (default 1).
        cutoff : float
            Noise cutoff frequency (default 0.1).
        mod_mult : float
            Modulus multiplier (p = mod_mult * sigma_z, default 0.5).
        n_bits : int
            Quantization bits for MAC verification (default 4).
        range_sigma : float
            Quantization range for MAC (default 4.0).
        n_test_rounds : int
            Number of committed test rounds at session start (default 2).
            Set to 0 to skip committed verification.
        rng_mode : str
            Randomness source: 'urandom' (default) or 'rdseed'.
            'rdseed' uses Intel RDSEED + Toeplitz extraction for near-ITS
            randomness.  Requires CPU with RDSEED support and 96 extra
            bytes in PSK for the Toeplitz seed.

        Returns
        -------
        dict
            'secure_bits': raw key bits (numpy uint8),
            'n_secure': number of key bits,
            'n_runs_used': successful runs,
            'n_runs_total': total runs,
            'n_batches': number of batches,
            'pool_available_bits': pool size after completion,
            'throughput_bps': estimated throughput (bits per second).
        """
        if self.pre_shared_key is None:
            raise RuntimeError("run_signbit_nopa requires pre_shared_key")

        import time
        t_start = time.time()

        result = self._run_signbit_nopa(
            B=B, n_runs=n_runs, n_batches=n_batches,
            cutoff=cutoff, mod_mult=mod_mult,
            n_bits=n_bits, range_sigma=range_sigma,
            n_test_rounds=n_test_rounds,
            rng_mode=rng_mode)

        t_elapsed = time.time() - t_start
        n_secure = result.get('n_secure', 0)
        result['throughput_bps'] = n_secure / t_elapsed if t_elapsed > 0 else 0
        result['elapsed_seconds'] = t_elapsed

        return result

    def _run_signbit_nopa(self, B=100000, n_runs=10, n_batches=1,
                           cutoff=0.1, mod_mult=0.5,
                           n_bits=4, range_sigma=4.0,
                           n_test_rounds=_DEFAULT_N_TEST_ROUNDS,
                           rng_mode='urandom'):
        """Execute sign-bit no-PA protocol runs over the network (Alice side).

        Batched message flow per batch (1.5 RTTs for n_runs):
        1. Send: all wire_a[0] concatenated (n_runs × B float64)
        2. Recv: all (bob_sign_enc | wire_b[0] | bob_mac_tag) concatenated
        3. Send: all alice_mac_tags concatenated (n_runs × 8 bytes)

        Pool operations are sequential locally — run N's MAC key comes
        from run N-1's deposited sign bits.  If no tampering, both sides
        deposit identical bits and pools stay in sync.  If Eve tampers
        with encrypted signs, pools desync, but the MAC fails and the
        run is discarded.  Subsequent runs will also fail (wrong MAC
        keys), but no wrong keys are ever accepted — this is a DoS, not
        a security break.
        """
        psk = self.pre_shared_key
        _validate_signbit_nopa_psk(psk, B, rng_mode=rng_mode)

        # Extract Toeplitz seed from PSK (last 96 bytes) if rdseed mode
        toeplitz_seed = None
        if rng_mode == 'rdseed':
            toeplitz_offset = 32 + _math.ceil(B / 8)
            toeplitz_seed = psk[toeplitz_offset:toeplitz_offset + 96]

        sigma_z = _leakage_mod.estimate_sigma_z(cutoff)
        p = mod_mult * sigma_z

        # Send config with session nonce (prevents replay across TCP connections)
        config_nonce = _rng_bytes(16, rng_mode=rng_mode, toeplitz_seed=toeplitz_seed)
        config_dict = {
            'signbit_nopa': True,
            'B': B,
            'n_runs': n_runs,
            'n_batches': n_batches,
            'cutoff': cutoff,
            'mod_mult': mod_mult,
            'n_bits': n_bits,
            'range_sigma': range_sigma,
            'n_test_rounds': n_test_rounds,
            'rng_mode': rng_mode,
        }
        # MAC computed over config_dict before adding nonce/tag to it
        config_tag = _config_mac_tag(config_dict, psk, config_nonce)
        config_dict['config_nonce'] = config_nonce.hex()
        config_dict['config_tag'] = config_tag
        self.client_socket.send(json.dumps(config_dict).encode('utf-8'))

        # Wait for ack
        self.__read_json_string(self.client_socket)

        # Committed σ/p verification (before pool init)
        sigma_verified = False
        empirical_sigma_over_p = 0.0
        if n_test_rounds > 0:
            empirical_sigma_over_p = self._signbit_nopa_committed_verify(
                sigma_z, p, B, n_test_rounds)
            sigma_verified = True

        # Initialize or reuse pool (nonce XOR ensures unique MAC keys per session)
        if not hasattr(self, '_signbit_pool') or self._signbit_pool is None:
            self._signbit_pool = _SignbitPool(psk, session_nonce=config_nonce)
        pool = self._signbit_pool

        # Per-run frame sizes
        resp_per_run = B + B * 8 + 8  # sign_enc + wire_b + tag

        all_sign_bits = []
        n_runs_used = 0
        max_chi2 = 0.0

        for batch_idx in range(n_batches):
            # --- Message 1: Generate and send all wire_a ---
            wa_parts = []
            wa_list = []
            for run_idx in range(n_runs):
                Z_a = sigma_z * _batch_true_random_gaussian(1, B,
                          rng_mode=rng_mode, toeplitz_seed=toeplitz_seed)
                wa0 = _parallel_mod_reduce(Z_a[:, 0], p)
                wa_list.append(wa0)
                wa_parts.append(np.ascontiguousarray(wa0).tobytes())
            _send_frame(self.client_socket, b''.join(wa_parts))

            # --- Message 2: Recv all responses ---
            all_resp_frame = _recv_frame(self.client_socket)

            # Process all runs locally (sequential pool ops)
            bob_signs_list = []
            bob_tags = []
            alice_tags = []

            for run_idx in range(n_runs):
                off = run_idx * resp_per_run
                bob_sign_enc = np.frombuffer(
                    all_resp_frame[off:off + B], dtype=np.uint8)
                wb0 = np.frombuffer(
                    all_resp_frame[off + B:off + B + B * 8], dtype=np.float64)
                bob_tag = int.from_bytes(
                    all_resp_frame[off + B + B * 8:off + resp_per_run], 'big')

                # Wire uniformity monitor
                chi2_a = _check_wire_uniformity(wa_list[run_idx], p)
                chi2_b = _check_wire_uniformity(wb0, p)
                max_chi2 = max(max_chi2, chi2_a, chi2_b)

                # Decrypt Bob's signs using OTP from pool
                bob_otps = pool.withdraw_otp(B)
                bob_sign_raw = bob_sign_enc ^ bob_otps

                # Compute MAC (includes encrypted signs for active MITM protection)
                coeffs = _signbit_mac_coeffs(wa_list[run_idx], wb0, sigma_z,
                                             n_bits, range_sigma,
                                             sign_enc=bob_sign_enc)
                r, s = pool.get_mac_keys()
                alice_tag = _its_mac_tag_tree(coeffs, r, s)

                # Always deposit — both sides recover identical sign bits
                pool.deposit(bob_sign_raw, B)

                bob_signs_list.append(bob_sign_raw)
                bob_tags.append(bob_tag)
                alice_tags.append(alice_tag)

            # --- Message 3: Send all alice_mac_tags ---
            tag_frame = b''.join(int(t).to_bytes(8, 'big') for t in alice_tags)
            _send_frame(self.client_socket, tag_frame)

            # Collect successful runs
            for run_idx in range(n_runs):
                if alice_tags[run_idx] == bob_tags[run_idx]:
                    all_sign_bits.append(bob_signs_list[run_idx].copy())
                    n_runs_used += 1

            pool.compact()

        # Raw sign bits are the key (no PA)
        if all_sign_bits:
            combined_key = np.concatenate(all_sign_bits)
        else:
            combined_key = np.array([], dtype=np.uint8)

        return {
            'secure_bits': combined_key,
            'n_raw_bits': len(combined_key),
            'n_secure': len(combined_key),
            'n_runs_used': n_runs_used,
            'n_runs_total': n_batches * n_runs,
            'n_batches': n_batches,
            'achieved_epsilon': 0.0,
            'pool_available_bits': pool.available_bits(),
            'psk_recycled': True,
            'sigma_verified': sigma_verified,
            'empirical_sigma_over_p': empirical_sigma_over_p,
            'monitor_chi2_max': max_chi2,
        }

    def _signbit_nopa_committed_verify(self, sigma_z, p, B, n_test):
        """Committed σ/p verification (Alice/client side).

        Both sides generate test noise, exchange commitments, then reveal.
        Checks: commitment integrity, wire consistency, empirical σ/p.

        Returns empirical σ/p ratio.
        Raises SigmaDriftError if any check fails.
        """
        # Generate test data: shape (B, n_test), mod-reduce all values
        Z_test_a = sigma_z * _batch_true_random_gaussian(n_test, B)
        wire_test_a = _parallel_mod_reduce(Z_test_a.ravel(), p)
        Z_test_a_bytes = np.ascontiguousarray(Z_test_a).tobytes()
        nonce_a = os.urandom(32)
        commit_a = hashlib.sha256(Z_test_a_bytes + nonce_a).digest()

        # Step 1: Send commit_a, recv commit_b
        _send_frame(self.client_socket, commit_a)
        commit_b = _recv_frame(self.client_socket)

        # Step 2: Send wire_test_a, recv wire_test_b
        _send_frame(self.client_socket,
                     np.ascontiguousarray(wire_test_a).tobytes())
        wire_test_b_bytes = _recv_frame(self.client_socket)
        wire_test_b = np.frombuffer(wire_test_b_bytes, dtype=np.float64)

        # Step 3: Send reveal_a, recv reveal_b
        _send_frame(self.client_socket, Z_test_a_bytes + nonce_a)
        reveal_b = _recv_frame(self.client_socket)

        # Verify commitment integrity
        if hashlib.sha256(reveal_b).digest() != commit_b:
            _send_frame(self.client_socket, b'\x00')
            _recv_frame(self.client_socket)
            raise SigmaDriftError("Committed verification: Bob commitment mismatch")

        # Extract Bob's revealed Z and verify wire consistency
        Z_test_b_bytes = reveal_b[:-32]
        Z_test_b = np.frombuffer(Z_test_b_bytes, dtype=np.float64).reshape(
            B, n_test)
        wire_test_b_check = _parallel_mod_reduce(Z_test_b.ravel(), p)
        if not np.allclose(wire_test_b_check, wire_test_b, atol=1e-12):
            _send_frame(self.client_socket, b'\x00')
            _recv_frame(self.client_socket)
            raise SigmaDriftError("Committed verification: Bob wire inconsistency")

        # Check empirical σ/p
        all_Z = np.concatenate([Z_test_a.ravel(), Z_test_b.ravel()])
        empirical_sigma = float(np.std(all_Z))
        ratio = empirical_sigma / p
        if ratio < _SIGMA_P_MIN_THRESHOLD:
            _send_frame(self.client_socket, b'\x00')
            _recv_frame(self.client_socket)
            raise SigmaDriftError(
                "Committed verification: sigma/p=%.2f < %.1f"
                % (ratio, _SIGMA_P_MIN_THRESHOLD))

        # Step 4: Exchange pass/fail
        peer_result = _recv_frame(self.client_socket)
        _send_frame(self.client_socket, b'\x01')
        if peer_result != b'\x01':
            raise SigmaDriftError("Committed verification: Bob reported failure")

        return ratio

    def run_proto_parallel_its(self, B=100, n_ex=10, n_bits=4,
                                range_sigma=4.0, ramp_time=5, cutoff=0.1,
                                mod_mult=0.5, alpha_mag=0.9,
                                masking_time=0, max_flip=8):
        """Single parallel ITS run with B channels."""
        if self.pre_shared_key is None:
            raise RuntimeError("run_proto_parallel_its requires pre_shared_key")
        results = self._run_parallel_its(
            n_runs=1, B=B, n_ex=n_ex, n_bits=n_bits,
            range_sigma=range_sigma, ramp_time=ramp_time, cutoff=cutoff,
            mod_mult=mod_mult, alpha_mag=alpha_mag,
            masking_time=masking_time, max_flip=max_flip)
        return results[0]

    def run_batch_parallel_its(self, n_runs=1, B=100, n_ex=10, n_bits=4,
                                range_sigma=4.0, target_epsilon=0.01,
                                ramp_time=5, cutoff=0.1, mod_mult=0.5,
                                alpha_mag=0.9, masking_time=0, max_flip=8,
                                recycle_psk=False):
        """Batch parallel ITS with PA."""
        if self.pre_shared_key is None:
            raise RuntimeError("run_batch_parallel_its requires pre_shared_key")

        all_results = self._run_parallel_its(
            n_runs=n_runs, B=B, n_ex=n_ex, n_bits=n_bits,
            range_sigma=range_sigma, target_epsilon=target_epsilon,
            ramp_time=ramp_time, cutoff=cutoff, mod_mult=mod_mult,
            alpha_mag=alpha_mag, masking_time=masking_time,
            max_flip=max_flip, batch=True, recycle_psk=recycle_psk)

        # Filter successful results
        successful = [r for r in all_results if r is not None]

        sigma_z = _leakage_mod.estimate_sigma_z(cutoff)
        p = mod_mult * sigma_z

        R = range_sigma * sigma_z
        n_bins = 2 ** n_bits
        delta_q = 2.0 * R / n_bins
        all_raw = []
        clean_steps_per_channel = None

        for res in successful:
            z_all = np.concatenate([res['z_a'][:, res['clean_a']],
                                     res['z_b'][:, res['clean_b']]], axis=1)
            if clean_steps_per_channel is None:
                clean_steps_per_channel = z_all.shape[1]
            bins = np.clip(((z_all + R) / delta_q).astype(int),
                            0, n_bins - 1).astype(np.uint8)
            bit_array = np.unpackbits(bins.reshape(-1, 1), axis=1,
                                       count=n_bits, bitorder='big')
            all_raw.append(bit_array.ravel())

        n_used = len(successful)

        if n_used == 0:
            return {
                'secure_bits_a': np.array([], dtype=np.uint8),
                'secure_bits_b': np.array([], dtype=np.uint8),
                'n_raw_bits': 0, 'n_secure': 0,
                'n_runs_used': 0, 'n_runs_total': n_runs,
                'security': None, 'achieved_epsilon': 1.0,
                'psk_recycled': False,
            }

        raw_bits = np.concatenate(all_raw)
        n_raw = len(raw_bits)

        security = _sec_mod.multibit_security_analysis(
            sigma_z, p, n_ex,
            alpha=alpha_mag, ramp_time=ramp_time,
            n_bits=n_bits, range_sigma=range_sigma,
            target_epsilon=target_epsilon)

        n_channels_total = n_used * B
        h_min_per_channel = security['h_min_per_channel']

        composition_correction = 0.0

        secure_result = _sec_mod.compute_multibit_secure_length(
            n_channels_total, h_min_per_channel,
            target_epsilon=target_epsilon,
            composition_correction_bits=composition_correction)
        n_secure = secure_result['n_secure']

        if n_secure == 0 or n_secure > n_raw:
            return {
                'secure_bits_a': np.array([], dtype=np.uint8),
                'secure_bits_b': np.array([], dtype=np.uint8),
                'n_raw_bits': n_raw, 'n_secure': 0,
                'n_runs_used': n_used, 'n_runs_total': n_runs,
                'security': security, 'achieved_epsilon': 1.0,
                'psk_recycled': False,
            }

        secure_key = _privacy_mod.PrivacyAmplification.hash_gf2_block(
            raw_bits, n_secure, block_raw=64, seed=42)

        result = {
            'secure_bits_a': secure_key,
            'secure_bits_b': secure_key,
            'n_raw_bits': n_raw, 'n_secure': n_secure,
            'n_runs_used': n_used, 'n_runs_total': n_runs,
            'security': security,
            'achieved_epsilon': secure_result['achieved_epsilon'],
        }

        if recycle_psk and n_secure > 0:
            next_psk, usable_bits = _derive_next_psk(secure_key, n_runs, B)
            if next_psk is not None:
                self.pre_shared_key = next_psk
                result['next_psk'] = next_psk
                result['secure_bits_a'] = usable_bits
                result['secure_bits_b'] = usable_bits
                result['n_secure'] = len(usable_bits)
                result['psk_recycled'] = True
            else:
                result['psk_recycled'] = False
        else:
            result['psk_recycled'] = False

        return result

    def _run_parallel_its(self, n_runs=1, B=100, n_ex=10, n_bits=4,
                           range_sigma=4.0, target_epsilon=0.01,
                           ramp_time=5, cutoff=0.1, mod_mult=0.5,
                           alpha_mag=0.9, masking_time=0, max_flip=8,
                           batch=False, recycle_psk=False):
        """Execute parallel ITS protocol runs over the network (Alice side)."""
        psk = self.pre_shared_key
        _validate_parallel_psk(psk, n_runs, B)

        sigma_z = _leakage_mod.estimate_sigma_z(cutoff)
        p = mod_mult * sigma_z

        # Send config
        config_dict = {
            'parallel_its': True,
            'B': B,
            'n_ex': n_ex,
            'n_runs': n_runs,
            'n_bits': n_bits,
            'range_sigma': range_sigma,
            'target_epsilon': target_epsilon,
            'batch': batch,
            'max_flip': max_flip,
            'ramp_time': ramp_time,
            'cutoff': cutoff,
            'mod_mult': mod_mult,
            'masking_time': masking_time,
            'alpha_mag': alpha_mag,
            'recycle_psk': recycle_psk,
        }
        self.client_socket.send(json.dumps(config_dict).encode('utf-8'))

        # Wait for ack
        self.__read_json_string(self.client_socket)

        all_results = []

        for run_idx in range(n_runs):
            # Generate Alice's noise: B channels x (n_ex+1) steps
            Z_a = sigma_z * _batch_true_random_gaussian(n_ex + 1, B)  # (B, n_ex+1)

            # Generate Alice's alpha signs from PSK
            alice_otps, bob_otps = _psk_parallel_alpha_otps(psk, run_idx, B)

            # Random alpha signs for Alice (vectorized, single urandom call)
            alice_sign_raw = np.frombuffer(os.urandom(B), dtype=np.uint8) & 1
            alice_signs = np.where(alice_sign_raw == 0, 1.0, -1.0)
            alice_sign_enc = (alice_sign_raw ^ alice_otps).tolist()

            # Alice exchange 0: wire_a[0] = mod_reduce(Z_a[0])
            wire_a_0 = _parallel_mod_reduce(Z_a[:, 0], p)
            wire_a = [wire_a_0]

            # Send {signs, wire_a[0]} as binary frame
            _send_frame(self.client_socket,
                        _pack_signs_wire(alice_sign_enc, wire_a_0))

            # Receive {signs, wire_b[0]} as binary frame
            frame = _recv_frame(self.client_socket)
            bob_sign_enc, wb0 = _unpack_signs_wire(frame, B)
            bob_sign_raw = bob_sign_enc ^ bob_otps
            bob_signs = np.where(bob_sign_raw == 0, 1.0, -1.0)

            wire_b = [wb0]

            # Alice exchange 1: depends on wire_b[0]
            ramp_1 = _parallel_ramp(1, ramp_time)
            wa1 = _parallel_exchange_step_alice(Z_a[:, 1], alice_signs,
                                                ramp_1, wb0, p)
            wire_a.append(wa1)

            # Exchange loop: steps 1..n_ex-1
            for i in range(1, n_ex):
                # Send wire_a[i] as binary frame
                _send_frame(self.client_socket, _pack_wire(wire_a[-1]))

                # Receive wire_b[i] as binary frame
                wb = _unpack_wire(_recv_frame(self.client_socket))
                wire_b.append(wb)

                # Alice exchange i+1
                ramp_k = _parallel_ramp(i + 1, ramp_time)
                wa = _parallel_exchange_step_alice(Z_a[:, i + 1], alice_signs,
                                                    ramp_k, wb, p)
                wire_a.append(wa)

            # Post-exchange decode for all B channels (vectorized)
            alpha_a_vec = alice_signs * alpha_mag
            alpha_b_vec = bob_signs * alpha_mag
            all_z_a, all_z_b, all_rel_a, all_rel_b = \
                _batch_wire_decode_z_all(wire_a, wire_b,
                                         alpha_a_vec, alpha_b_vec,
                                         ramp_time, p)

            n_a = n_ex + 1
            n_b = n_ex

            # Compute clean masks
            mask_start = ramp_time - masking_time
            mask_end = ramp_time - 1
            clean_a = np.ones(n_a, dtype=bool)
            for k in range(max(0, mask_start), min(mask_end + 1, n_a)):
                clean_a[k] = False
            clean_b = np.ones(n_b, dtype=bool)
            for k in range(max(0, mask_start), min(mask_end + 1, n_b)):
                clean_b[k] = False

            # Quantize all B channels to MAC coefficients (vectorized)
            coeffs = _batch_quantize_coeffs(all_z_a, all_z_b, clean_a, clean_b,
                                             sigma_z, n_bits, range_sigma)

            r, s = _psk_parallel_mac_keys(psk, run_idx, B)
            alice_tag = _its_mac_tag_tree(coeffs, r, s)

            # Send {wire_a[n_ex], tag} as binary frame
            _send_frame(self.client_socket,
                        _pack_wire_tag(wire_a[-1], alice_tag))

            # Receive Bob's tag as binary frame
            bob_tag = _unpack_tag(_recv_frame(self.client_socket))

            # Search decoder if mismatch (vectorized)
            if alice_tag != bob_tag:
                borderline_idx, borderline_deltas = _batch_search_decode_deltas(
                    all_z_a, all_z_b, all_rel_a, all_rel_b,
                    clean_a, clean_b, sigma_z, p, n_bits, range_sigma, max_flip)

                if borderline_idx:
                    r_powers = _compute_r_powers(len(coeffs), r)
                    corrected = _search_decode(coeffs, r, s, bob_tag,
                                               borderline_idx, borderline_deltas,
                                               r_powers, max_flip)
                    if corrected is not None:
                        alice_tag = _its_mac_tag_tree(corrected, r, s)
                        coeffs = corrected

            if alice_tag == bob_tag:
                all_results.append({
                    'z_a': all_z_a,
                    'z_b': all_z_b,
                    'clean_a': clean_a,
                    'clean_b': clean_b,
                    'coeffs': coeffs,
                })
            else:
                all_results.append(None)

        return all_results

    def close(self):
        self.client_socket.send('{}'.encode('utf-8'))
        self.client_socket.close()

    def __read_json_string(self, client_socket):
        json_string = ''

        # Keep reading until we have a valid JSON string.
        while True:
            chunk = client_socket.recv(1048576).decode('utf-8')
            if not chunk:
                return json_string
            json_string += chunk
            try:
                json.loads(json_string)
                break
            except ValueError:
                pass

        return json_string
