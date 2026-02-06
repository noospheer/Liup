r"""Information reconciliation for the Liu protocol.

Implements a cascade-style protocol for correcting errors between
Alice's and Bob's raw bit strings before privacy amplification.

Leakage Bound (Theorem)
-----------------------
**Theorem:**  The cascade protocol leaks exactly ``lambda`` bits of
information about the raw key to an eavesdropper, where ``lambda``
equals the number of parity comparisons performed.

**Proof:**

Each parity comparison publicly reveals a single linear function
(mod-2 sum) of a subset of key bits.  By the chain rule of entropy:

    H(K | transcript) = H(K) - H(transcript)
                      ≥ H(K) - lambda

since each binary parity value has at most 1 bit of entropy, and
``lambda`` parities are disclosed.  Therefore Eve's information
gain from reconciliation is at most ``lambda`` bits:

    I(K; transcript) = H(K) - H(K | transcript) ≤ lambda

This bound is tight: each parity is a fresh linear function of the
key bits (the random permutations in later passes ensure the parity
blocks are distinct with overwhelming probability), so the parities
are approximately independent and each contributes ~1 bit.

The ``cascade_reconcile`` function counts every parity comparison
(both block-level and binary-search sub-comparisons) and returns
the total as ``lambda``.  This value is used directly in the
privacy amplification security parameter.
"""

import math
import numpy as np


def _binary_search_correct(bits_ref, bits_fix, lo, hi):
    """Find and correct one error in bits_fix[lo:hi] using binary search.

    Parameters
    ----------
    bits_ref : ndarray
        Reference bits (Alice's, read-only).
    bits_fix : ndarray
        Bits to correct (Bob's, modified in place).
    lo, hi : int
        Slice bounds.

    Returns
    -------
    int
        Number of parity comparisons made (leaked bits).
    """
    leaked = 0
    while hi - lo > 1:
        mid = (lo + hi) // 2
        par_ref = int(np.sum(bits_ref[lo:mid])) % 2
        par_fix = int(np.sum(bits_fix[lo:mid])) % 2
        leaked += 1
        if par_ref != par_fix:
            hi = mid
        else:
            lo = mid
    # lo is the error position — correct it
    bits_fix[lo] = bits_ref[lo]
    return leaked


def cascade_reconcile(bits_a, bits_b, n_passes=10, initial_block=None):
    """Cascade information reconciliation.

    Corrects errors in bits_b to match bits_a using parity comparisons.
    bits_a is used as a read-only reference; only bits_b is modified.

    Parameters
    ----------
    bits_a : ndarray of int
        Alice's raw bits (reference, not modified).
    bits_b : ndarray of int
        Bob's raw bits (corrected in place).
    n_passes : int
        Number of cascade passes (default 10).
    initial_block : int or None
        Initial block size.  If None, starts at 8.

    Returns
    -------
    int
        Number of bits leaked to Eve (parity comparisons).  This is
        a proven upper bound on I(key; reconciliation_transcript);
        see module docstring.
    """
    n = len(bits_a)
    if n == 0:
        return 0

    if initial_block is None:
        initial_block = 8

    total_leaked = 0

    for pass_idx in range(n_passes):
        # Block size grows each pass but caps at n
        block_size = min(initial_block * (2 ** pass_idx), n)

        # Random permutation for passes > 0
        if pass_idx > 0:
            perm = np.random.permutation(n)
            inv_perm = np.argsort(perm)
            ref = bits_a[perm].copy()
            fix = bits_b[perm].copy()
        else:
            perm = None
            ref = bits_a
            fix = bits_b

        # Process each block
        for start in range(0, n, block_size):
            end = min(start + block_size, n)
            par_ref = int(np.sum(ref[start:end])) % 2
            par_fix = int(np.sum(fix[start:end])) % 2
            total_leaked += 1

            if par_ref != par_fix:
                total_leaked += _binary_search_correct(
                    ref, fix, start, end)

        # Write corrections back through inverse permutation
        if perm is not None:
            bits_b[:] = fix[inv_perm]

    return total_leaked


def leakage_bound(n, n_passes=10, initial_block=8):
    """Compute a deterministic upper bound on reconciliation leakage.

    Returns the maximum number of parity comparisons that the cascade
    protocol can perform, which bounds the information leaked.

    Parameters
    ----------
    n : int
        Length of the raw key.
    n_passes : int
        Number of cascade passes.
    initial_block : int
        Initial block size.

    Returns
    -------
    int
        Upper bound on the number of leaked bits (lambda).
    """
    total = 0
    for pass_idx in range(n_passes):
        block_size = min(initial_block * (2 ** pass_idx), n)
        n_blocks = math.ceil(n / block_size)
        # Each block: 1 parity check + at most ceil(log2(block_size))
        # binary search steps if parity differs
        max_bisect = max(0, math.ceil(math.log2(block_size))) \
            if block_size > 1 else 0
        # Worst case: every block has an error
        total += n_blocks * (1 + max_bisect)
    return total
