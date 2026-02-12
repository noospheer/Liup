#!/usr/bin/env python

"""Privacy amplification via Toeplitz-matrix universal hashing.

Standard technique from quantum key distribution (QKD): a Toeplitz
matrix is defined by n_raw + n_secure - 1 random seed bits and maps
n_raw raw key bits to n_secure secure key bits via GF(2) matrix-vector
multiplication.

The secure key length is chosen so that Eve's remaining information
about the output is negligible:

    n_secure = n_raw - ceil(eve_info_bits) - safety_margin
"""

import math
import numpy as np


class PrivacyAmplification:
    """Toeplitz-matrix universal hashing for privacy amplification.

    Parameters
    ----------
    n_raw : int
        Length of the raw key (number of input bits).
    n_secure : int
        Length of the secure key (number of output bits).
    seed : int or None
        Random seed for generating the Toeplitz matrix.
    """

    def __init__(self, n_raw, n_secure, seed=None, precompute=False):
        if n_secure > n_raw:
            raise ValueError("n_secure (%d) must not exceed n_raw (%d)" %
                             (n_secure, n_raw))
        if n_secure < 1:
            raise ValueError("n_secure must be at least 1, got %d" % n_secure)
        self.n_raw = n_raw
        self.n_secure = n_secure
        self.seed = seed

        # Generate the Toeplitz defining sequence: n_raw + n_secure - 1 bits
        rng = np.random.default_rng(seed)
        self._toeplitz_seq = rng.integers(0, 2,
                                          size=n_raw + n_secure - 1,
                                          dtype=np.uint8)

        # Optionally precompute the full Toeplitz matrix for fast hashing.
        # Safe to reuse across independent chunks (standard QKD result:
        # the same Toeplitz matrix is 2-universal for each application).
        self._matrix = None
        if precompute:
            self._matrix = np.array(
                [self._toeplitz_row(i) for i in range(n_secure)],
                dtype=np.uint16)

    def _toeplitz_row(self, i):
        """Return row i of the Toeplitz matrix (length n_raw)."""
        # Row i uses elements [n_secure - 1 - i .. n_secure - 1 - i + n_raw - 1]
        start = self.n_secure - 1 - i
        return self._toeplitz_seq[start:start + self.n_raw]

    def hash(self, raw_bits):
        """Apply the Toeplitz hash to a raw bit string.

        Uses FFT-based O(n log n) convolution for large inputs, or
        precomputed matrix multiplication for small inputs.

        Parameters
        ----------
        raw_bits : array-like of int/bool
            The raw key bits (length n_raw).

        Returns
        -------
        numpy.ndarray of uint8
            The hashed (secure) key bits (length n_secure).
        """
        raw = np.asarray(raw_bits, dtype=np.uint8)
        if len(raw) != self.n_raw:
            raise ValueError("Expected %d raw bits, got %d" %
                             (self.n_raw, len(raw)))
        if self._matrix is not None:
            return ((self._matrix @ raw) % 2).astype(np.uint8)
        return self._hash_fft(raw)

    def hash_fast(self, raw_bits):
        """Fast Toeplitz hash.

        Uses precomputed matrix if available (best for repeated calls
        with the same dimensions, e.g. streaming chunks), otherwise
        falls back to FFT-based convolution.

        Parameters
        ----------
        raw_bits : array-like of int/bool
            The raw key bits (length n_raw).

        Returns
        -------
        numpy.ndarray of uint8
            The hashed (secure) key bits (length n_secure).
        """
        raw = np.asarray(raw_bits, dtype=np.uint8)
        if len(raw) != self.n_raw:
            raise ValueError("Expected %d raw bits, got %d" %
                             (self.n_raw, len(raw)))
        if self._matrix is None:
            # For small enough matrices, precompute; otherwise use FFT.
            mem_bytes = self.n_secure * self.n_raw
            if mem_bytes <= 100_000_000:  # ~100 MB threshold
                self._matrix = np.array(
                    [self._toeplitz_row(i) for i in range(self.n_secure)],
                    dtype=np.uint16)
                return ((self._matrix @ raw) % 2).astype(np.uint8)
            return self._hash_fft(raw)
        return ((self._matrix @ raw) % 2).astype(np.uint8)

    def _hash_fft(self, raw):
        """Toeplitz hash via FFT-based convolution in O(n log n).

        The Toeplitz matrix-vector product result[i] =
        sum_j seq[n_secure-1-i+j] * raw[j] is a cross-correlation,
        equivalent to a convolution of seq with reversed raw.
        Since all inputs are binary (0/1), the integer sums fit in
        int64 for any practical input size, and we take mod 2 at the
        end.
        """
        # Convolve seq with reversed raw using FFT
        # result_full[k] = sum_j seq[k+j] * raw[j] for valid indices
        # We need result[i] = sum_j seq[n_secure-1-i+j] * raw[j]
        # = result_full[n_secure-1-i]
        n_fft = 1
        n_total = len(self._toeplitz_seq) + self.n_raw - 1
        while n_fft < n_total:
            n_fft <<= 1

        seq_f = np.fft.rfft(self._toeplitz_seq.astype(np.float64), n=n_fft)

        # Correlation: convolve(seq, reversed(raw))
        # correlate[k] = sum_j seq[k+j]*raw[j] for the valid range
        # So result[i] = correlate[n_secure-1-i]
        raw_rev = raw[::-1].copy()
        raw_rev_f = np.fft.rfft(raw_rev.astype(np.float64), n=n_fft)
        corr = np.fft.irfft(seq_f * raw_rev_f, n=n_fft)

        # corr[k] = sum_j seq[j] * raw_rev[k-j] = sum_j seq[j] * raw[n_raw-1-(k-j)]
        # Let m = k - j, then j = k - m:
        # = sum_m seq[k-m] * raw[n_raw-1-m]
        # We want: result[i] = sum_j seq[n_secure-1-i+j] * raw[j]
        # Let j' = n_raw - 1 - j: = sum_j' seq[n_secure-1-i + n_raw-1-j'] * raw[n_raw-1-j']
        # This is corr at index (n_secure-1-i + n_raw - 1) = (n_secure + n_raw - 2 - i)
        # So result[i] = corr[n_secure + n_raw - 2 - i]

        indices = np.arange(self.n_secure - 1 + self.n_raw - 1,
                            self.n_raw - 2, -1)
        result = np.rint(corr[indices]).astype(np.int64) % 2
        return result.astype(np.uint8)

    @staticmethod
    def hash_gf2_block(raw_bits, n_secure, block_raw=512, seed=42):
        """Block-diagonal GF(2) PA using packed bitwise numpy operations.

        Splits raw_bits into blocks of ``block_raw`` bits and applies the
        same random binary matrix to each block.  The GF(2) matrix-vector
        product is computed entirely with uint64 AND + XOR operations,
        replacing O(n log n) FFT with O(n) bitwise work.

        Security: A random binary matrix over GF(2) is 2-universal.
        For IID input blocks the Leftover Hash Lemma applies per block,
        and the concatenated output is (n_blocks * epsilon)-close to
        uniform by the union bound.

        Parameters
        ----------
        raw_bits : array-like of uint8
            Raw key bits (values 0 or 1).
        n_secure : int
            Total number of secure output bits.
        block_raw : int
            Bits per block.  Must be a multiple of 64.  Default 512.
        seed : int
            RNG seed for generating the hash matrix.

        Returns
        -------
        numpy.ndarray of uint8
            Secure key bits (length n_secure).
        """
        raw = np.asarray(raw_bits, dtype=np.uint8)
        n_raw = len(raw)
        if n_secure < 1 or n_secure > n_raw:
            raise ValueError("n_secure=%d invalid for n_raw=%d"
                             % (n_secure, n_raw))
        if block_raw % 64 != 0:
            raise ValueError("block_raw must be a multiple of 64")

        # --- pad to a whole number of blocks ---
        n_blocks = (n_raw + block_raw - 1) // block_raw
        pad = n_blocks * block_raw - n_raw
        if pad:
            raw = np.concatenate([raw, np.zeros(pad, dtype=np.uint8)])

        # secure bits per block (ceil so we produce >= n_secure, then trim)
        sec_per_blk = (n_secure + n_blocks - 1) // n_blocks
        if sec_per_blk > block_raw:
            sec_per_blk = block_raw

        words_per_blk = block_raw // 64

        # --- pack bits into uint64 words ---
        packed_bytes = np.packbits(raw.reshape(n_blocks, block_raw), axis=1)
        packed = np.ascontiguousarray(packed_bytes).view(np.uint64)
        # packed shape: (n_blocks, words_per_blk)

        # --- random GF(2) matrix: (sec_per_blk, words_per_blk) uint64 ---
        rng = np.random.default_rng(seed)
        matrix = rng.integers(
            np.uint64(0), np.iinfo(np.uint64).max,
            size=(sec_per_blk, words_per_blk),
            dtype=np.uint64, endpoint=True)

        # --- process in cache-friendly batches ---
        # Target ~4 MB working set per batch (fits L3 comfortably)
        max_batch = max(1, 4_000_000 // (sec_per_blk * 8))
        parts = []

        for b_start in range(0, n_blocks, max_batch):
            b_end = min(b_start + max_batch, n_blocks)
            p_batch = packed[b_start:b_end]  # (batch, words_per_blk)
            batch_sz = b_end - b_start

            temp = np.zeros((batch_sz, sec_per_blk), dtype=np.uint64)
            for w in range(words_per_blk):
                temp ^= p_batch[:, w:w+1] & matrix[:, w]

            # parity extraction: fold uint64 down to bit 0
            temp ^= temp >> np.uint64(32)
            temp ^= temp >> np.uint64(16)
            temp ^= temp >> np.uint64(8)
            temp ^= temp >> np.uint64(4)
            temp ^= temp >> np.uint64(2)
            temp ^= temp >> np.uint64(1)
            parts.append((temp & np.uint64(1)).astype(np.uint8))

        result = np.concatenate(parts, axis=0)
        return result.ravel()[:n_secure]

    @staticmethod
    def hash_chunked(raw_bits, n_secure, chunk_raw=8192, seed=42):
        """Chunked Toeplitz hash for large inputs.

        Splits raw_bits into independent chunks and applies a separate
        small Toeplitz hash to each.  For IID input bits this preserves
        the security guarantee (each chunk is independent) while
        replacing one O(N log N) FFT with many O(c log c) FFTs where
        c = chunk_raw << N, giving a large constant-factor speedup.

        Parameters
        ----------
        raw_bits : numpy.ndarray of uint8
            All raw key bits.
        n_secure : int
            Total number of secure bits to produce.
        chunk_raw : int
            Raw bits per chunk (default 8192).
        seed : int
            Base seed; chunk i uses seed + i.

        Returns
        -------
        numpy.ndarray of uint8
            The secure key bits (length n_secure).
        """
        raw = np.asarray(raw_bits, dtype=np.uint8)
        n_raw = len(raw)
        if n_secure < 1 or n_secure > n_raw:
            raise ValueError("n_secure=%d invalid for n_raw=%d" %
                             (n_secure, n_raw))

        # Compute number of full chunks and remainder
        n_chunks = n_raw // chunk_raw
        remainder = n_raw % chunk_raw
        if n_chunks == 0:
            # Input smaller than chunk size — single hash
            pa = PrivacyAmplification(n_raw, n_secure, seed=seed)
            return pa.hash(raw)

        # Distribute secure bits proportionally across chunks
        ratio = n_secure / n_raw
        secure_per_chunk = max(1, int(ratio * chunk_raw))
        # Last chunk handles the remainder (if any) plus leftover secure bits
        n_secure_assigned = secure_per_chunk * n_chunks
        if remainder > 0:
            last_secure = n_secure - n_secure_assigned
            if last_secure < 1:
                # Redistribute: fewer bits from regular chunks
                n_chunks_eff = n_chunks + 1
                secure_per_chunk = n_secure // n_chunks_eff
                if secure_per_chunk < 1:
                    secure_per_chunk = 1
                n_secure_assigned = secure_per_chunk * n_chunks
                last_secure = n_secure - n_secure_assigned
        else:
            last_secure = 0
            # Adjust last regular chunk to absorb rounding
            diff = n_secure - n_secure_assigned
            if diff != 0:
                n_secure_assigned = secure_per_chunk * (n_chunks - 1)
                last_chunk_secure = n_secure - n_secure_assigned
            else:
                last_chunk_secure = None

        parts = []
        rng = np.random.default_rng(seed)
        chunk_seeds = rng.integers(0, 2**31, size=n_chunks + (1 if remainder > 0 else 0))

        for i in range(n_chunks):
            start = i * chunk_raw
            chunk = raw[start:start + chunk_raw]
            if i == n_chunks - 1 and remainder == 0 and 'last_chunk_secure' in dir():
                # Last regular chunk absorbs rounding difference
                if last_chunk_secure is not None and last_chunk_secure >= 1:
                    ns = last_chunk_secure
                else:
                    ns = secure_per_chunk
            else:
                ns = secure_per_chunk
            if ns > len(chunk):
                ns = len(chunk)
            if ns < 1:
                continue
            pa = PrivacyAmplification(len(chunk), ns, seed=int(chunk_seeds[i]))
            parts.append(pa.hash(chunk))

        if remainder > 0 and last_secure >= 1:
            chunk = raw[n_chunks * chunk_raw:]
            ns = min(last_secure, len(chunk))
            if ns >= 1:
                pa = PrivacyAmplification(len(chunk), ns,
                                          seed=int(chunk_seeds[n_chunks]))
                parts.append(pa.hash(chunk))

        result = np.concatenate(parts)
        # Trim or pad to exact n_secure (should be exact by construction)
        return result[:n_secure]

    @staticmethod
    def compute_secure_length(n_raw, eve_info_bits, safety_margin=10):
        """Compute the secure key length after privacy amplification.

        Note: For correct application of the Leftover Hash Lemma,
        ``eve_info_bits`` should represent the min-entropy deficit
        (i.e., ``n_raw - H_min(K|Eve)``), not Shannon mutual information.
        Shannon entropy H >= H_min, so using Shannon MI here
        underestimates Eve's advantage.  For rigorous min-entropy
        accounting, use ``security_proof.compute_secure_length_minentropy``.

        Parameters
        ----------
        n_raw : int
            Number of raw key bits.
        eve_info_bits : float
            Upper bound on Eve's total information (bits).
        safety_margin : int
            Additional bits subtracted for security (default 10).

        Returns
        -------
        int
            The number of secure bits, or 0 if not enough raw bits.
        """
        n_secure = n_raw - int(math.ceil(eve_info_bits)) - safety_margin
        return max(0, n_secure)
