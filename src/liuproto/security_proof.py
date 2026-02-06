r"""Composable security proof for the Liu protocol.

TCP Security Model — Information-Theoretic Security (ITS)
=========================================================

This module provides a composable ITS proof against **passive TCP
eavesdroppers**.  The security model is:

**Eve's observation model.**  Eve observes all values transmitted over
the TCP channel.  These are the mod-p wrapped wire values
W_k ∈ (-p/2, p/2].  The wrapping happens *before* transmission:
``endpoint.Physics.exchange()`` applies ``_mod_reduce(real_output)``
(endpoint.py, line 218) before returning the value that goes over TCP
as JSON.  Eve never sees the unwrapped real-valued signal.

**Receiver unwrapping.**  The receiver recovers the real-valued signal
locally via hypothesis tracking (endpoint.py, lines 189-202), using
its private noise realisations.  This unwrapping is a local computation
that does not leak information to Eve.

**Why the HMM analysis matches Eve's view.**  The ``_forward_log_likelihood``
function in ``leakage.py`` computes P(W | s_A, s_B) using wrapped wire
values as input — exactly the observations available to an optimal
passive TCP eavesdropper.  The proof chain:

    HMM forward on wrapped W → P_guess → Hoeffding → H_min → LHL

is therefore a valid ITS proof for passive TCP eavesdroppers.

**ITS Assumptions** (see ``ITS_ASSUMPTIONS`` constant):

1. Endpoint noise Z_k is true randomness (hardware RNG, not PRNG)
2. Modular reduction is implemented correctly (centered mod-p)
3. Eve is passive (observes TCP traffic only, no active injection)
4. Protocol runs are independent (fresh randomness each run)

Theorem (Composable Security via Leftover Hash Lemma)
=====================================================

**Statement.**  Let Alice and Bob share a raw key K of n_raw bits after
the protocol.  Let Eve observe (1) the wire transcript W and (2) the
information-reconciliation transcript C.  Then:

    H_min(K | W, C) >= n_raw * h_min - lambda

where:

    h_min = proven per-run min-entropy bound (bits)
    lambda = number of reconciliation parity bits leaked

The min-entropy bound h_min is obtained via the HMM-based chain:

    1. Exact HMM forward: compute P(W | s_A, s_B) for all 4 sign configs
       using _forward_log_likelihood (exact posterior tracking on lattice)
    2. Product-sign marginals: P(W|S=+) = 0.5[P(W|++)+P(W|--)]
    3. Guessing probability: P_guess(W) = max(P(S=+|W), P(S=-|W))
    4. Hoeffding on P_guess in [0.5,1]: E[P_guess] <= mean + t
    5. Min-entropy: h_min = -log2(E[P_guess])
    6. IID composition: H_min(K|W_all) = n_raw * h_min

Every step is a proven theorem.  No Shannon-to-min-entropy conversion
(which would be invalid: H >= H_min, not the reverse).  No analytic
convexity-over-posteriors arguments (which have an unresolved
posterior-divergence gap).  The HMM forward absorbs all posterior
effects automatically.

Note: The Leftover Hash Lemma requires **min-entropy**, not Shannon
entropy.  Shannon MI bounds are insufficient for the LHL.

The Leftover Hash Lemma (Impagliazzo, Levin, Luby 1989; Renner 2005
for quantum-proof version) states:

**Leftover Hash Lemma.**  Let F be a family of 2-universal hash
functions from {0,1}^n_raw to {0,1}^n_secure.  Let X be a random
variable with H_min(X | E) >= k.  Then:

    d(F(X), U_{n_secure} | F, E) <= epsilon

where

    epsilon = 2^{-(k - n_secure)/2 - 1}

and d denotes the trace distance (= total variation distance in the
classical case).

**Application.**  Toeplitz matrices form a 2-universal hash family.
Setting k = n_raw - I_wire - lambda:

    epsilon = 2^{-(n_raw - I_wire - lambda - n_secure)/2 - 1}

To achieve a target epsilon, we need:

    n_secure <= n_raw - I_wire - lambda - 2*log2(1/epsilon) - 2

Equivalently, the ``compute_secure_length`` function in ``privacy.py``
sets:

    n_secure = n_raw - ceil(I_wire + lambda) - safety_margin

where ``safety_margin`` controls the residual epsilon:

    epsilon = 2^{-(safety_margin - 2)/2 - 1} = 2^{-safety_margin/2}

For the default safety_margin = 10:  epsilon = 2^{-5} approx 0.031.
For safety_margin = 20:  epsilon = 2^{-10} approx 0.001.
For safety_margin = 40:  epsilon = 2^{-20} approx 10^{-6}.

Proof of Condition (A): Wire Leakage Bound
-------------------------------------------

The ``estimate_mi_rigorous`` method in ``leakage.py`` computes a
(1 - delta)-confidence upper bound on I(S; W_1, ..., W_n) using:

1.  **Exact HMM forward algorithm** — ``_forward_log_likelihood``
    tracks the full posterior on hidden state M_{k-1} through the
    forward recursion on the lattice {W_k + j*p}, giving exact
    log P(wire | s_A, s_B).

2.  **Product sign marginalisation** — The joint likelihood under
    product sign S = sign(alpha_A * alpha_B) is:

        P(W | S=+) = 0.5 * P(W|+,+) + 0.5 * P(W|-,-)
        P(W | S=-) = 0.5 * P(W|+,-) + 0.5 * P(W|-,+)

3.  **Hoeffding concentration** — MI samples X_i = max(0, log2(P_true/P_avg))
    satisfy X_i in [0, 1] and E[X_i] >= I(S; W).  By Hoeffding's bound:

        P(X_bar_n > E[X_i] + t) <= exp(-2*n*t^2)

    Setting t = sqrt(ln(1/delta) / (2*n)):

        I(S; W) <= X_bar_n + t  with probability >= 1 - delta.

For n_raw protocol runs, the total wire leakage is bounded by:

    I_wire = n_raw * mi_upper_bound

(Each run is independent, so MI adds across runs.)

Proof of Condition (B): Reconciliation Leakage Bound
-----------------------------------------------------

See ``reconciliation.py`` module docstring.  Each parity comparison
reveals one linear function (mod-2 sum) of key bits.  By the chain
rule:

    I(K; C) = H(C) <= lambda

where lambda is the total number of parity comparisons (block-level
plus binary-search sub-comparisons).  The ``cascade_reconcile``
function counts and returns this value exactly.

Composability
-------------

The above proof is composable in the Abstract Cryptography / Universally
Composable (UC) framework because:

1.  The Leftover Hash Lemma gives a bound on trace distance, which
    composes under arbitrary post-processing (data-processing inequality).

2.  The security parameter epsilon is an additive error: if the key is
    used in any application that is secure against uniform keys, the
    composed system is secure up to additional epsilon.

3.  The Toeplitz hash is a one-time computation that Alice and Bob
    perform independently using a shared public seed.  No additional
    communication is needed.

Multi-Bit Extraction: Decoded Z vs Original Z
----------------------------------------------

The multi-bit extraction mode quantizes the shared noise Z sequences
into multiple bits per step.  The key material is the **decoded Z**:

    decoded_Z = wire + round((center - wire) / p) * p - center

This equals Z mod p (centered).  Crucially, decoded Z is **deterministic**
given (wire_value, center).  Eve observes the wire values.  Her only
uncertainty is which of 2 candidate centers is correct (one per sign
hypothesis ±alpha).  All steps within a channel share the same sign,
so Eve has exactly 2 candidate full decoded-Z sequences.

Therefore, the min-entropy of the decoded-Z key material equals the
sign-bit min-entropy:

    H_min(decoded_Z_all | Wire_all) = H_min(sign | Wire_all)

This is computed by the TV-based analytical bound in ``leakage.py``
(``per_run_min_entropy_bound``).

The per-step lattice analysis (``compute_z_pguess_per_step``) models
the **original** (pre-wrapping) Z, which has genuine lattice ambiguity
even when Eve knows the sign.  But the protocol uses decoded Z (which
both parties can agree on), not original Z (known only to the generator).
The lattice analysis is retained as a diagnostic tool only.

Current Implementation Status
-----------------------------

The default implementation achieves **computational security** (CSPRNG-
seeded PRNG), not information-theoretic security.  Specifically:

-  Endpoint noise is generated by ``np.random.default_rng`` seeded from
   ``os.urandom(32)`` — a cryptographically secure PRNG, but still a
   PRNG.  ITS assumption (1) requires *true* randomness.

-  Successive protocol runs share the same PRNG state, so they are
   deterministically correlated given the seed.  ITS assumption (4)
   requires independent runs.

To achieve ITS, replace the PRNG with a hardware (true) random number
generator and set ``physics.rng_is_true_random = True`` on each
endpoint.  The ``validate_assumptions()`` function and the
``proven_security_analysis()`` return dict report the actual security
level based on this flag.
"""

import math
import numpy as np
from . import leakage as _leakage_mod
from . import reconciliation as _recon_mod


ITS_ASSUMPTIONS = {
    "true_randomness": "Endpoint noise Z_k is true randomness (hardware RNG, not PRNG)",
    "modular_reduction": "Modular reduction is implemented correctly (centered mod-p into (-p/2, p/2])",
    "passive_eve": "Eve is passive (observes TCP traffic only, no active injection)",
    "run_independence": "Protocol runs are independent (fresh randomness each run)",
}
"""Assumptions required for the ITS proof against passive TCP eavesdroppers.

The security guarantee (composable ITS via Leftover Hash Lemma) holds
provided all four assumptions are satisfied.  See the module docstring
for the full security model.
"""


def validate_assumptions(rng_is_true_random=False, modulus=0.0):
    """Validate ITS assumptions against actual protocol configuration.

    Parameters
    ----------
    rng_is_true_random : bool
        Whether the endpoint RNG is a true (hardware) random source.
    modulus : float
        The modular reduction parameter.  When > 0, modular reduction
        is in use and assumption (2) is considered satisfied.

    Returns
    -------
    dict
        ``assumption_status``: dict mapping assumption name to one of
        ``'satisfied'``, ``'violated'``, or ``'unchecked'``.

        ``its_valid``: bool — True only when every checkable assumption
        is satisfied.

        ``security_level``: ``'its'`` or ``'computational'``.

        ``its_caveats``: list of strings explaining why ITS does not hold
        (empty when ``its_valid`` is True).
    """
    status = {}
    caveats = []

    # (1) True randomness
    if rng_is_true_random:
        status['true_randomness'] = 'satisfied'
    else:
        status['true_randomness'] = 'violated'
        caveats.append(
            "Endpoint noise uses a PRNG (np.random.default_rng), not a "
            "hardware RNG.  Security is computational (CSPRNG), not "
            "information-theoretic.")

    # (2) Modular reduction — code-level correctness; we check that
    # modulus > 0 (modular mode is enabled).
    if modulus > 0:
        status['modular_reduction'] = 'satisfied'
    else:
        status['modular_reduction'] = 'violated'
        caveats.append(
            "Modular reduction is disabled (modulus=0).  Without "
            "mod-p wrapping, wire values leak the full real-valued signal.")

    # (3) Passive Eve — cannot be verified programmatically.
    status['passive_eve'] = 'unchecked'

    # (4) Run independence — cannot be fully verified, but we can flag
    # that a shared PRNG across runs makes them deterministically
    # correlated given the seed.  True independence requires fresh
    # hardware randomness per run.
    if rng_is_true_random:
        status['run_independence'] = 'satisfied'
    else:
        status['run_independence'] = 'violated'
        caveats.append(
            "Successive protocol runs share a single PRNG state.  Given "
            "the seed, all Z_k sequences are deterministic — runs are "
            "not independent.  Use a hardware RNG for true independence.")

    its_valid = all(
        v in ('satisfied', 'unchecked')
        for v in status.values()
    )
    security_level = 'its' if its_valid else 'computational'

    return {
        'assumption_status': status,
        'its_valid': its_valid,
        'security_level': security_level,
        'its_caveats': caveats,
    }


def compute_epsilon(n_raw, eve_total_bits, n_secure):
    r"""Compute the security parameter epsilon from the leftover hash lemma.

    Given Toeplitz 2-universal hashing from n_raw to n_secure bits,
    with Eve's total information = eve_total_bits:

        epsilon = 2^{-(n_raw - eve_total_bits - n_secure)/2 - 1}

    Parameters
    ----------
    n_raw : int
        Number of raw key bits.
    eve_total_bits : float
        Upper bound on Eve's total information in bits
        (wire leakage + reconciliation leakage).
    n_secure : int
        Number of secure output bits.

    Returns
    -------
    float
        The security parameter epsilon (trace distance from uniform).
        Returns 1.0 if the exponent is non-negative (insecure).
    """
    exponent = -(n_raw - eve_total_bits - n_secure) / 2.0 - 1.0
    if exponent >= 0:
        return 1.0
    return 2.0 ** exponent


def compute_secure_length_from_epsilon(n_raw, eve_total_bits, target_epsilon):
    r"""Compute maximum n_secure achieving a target epsilon.

    From the LHL:
        epsilon = 2^{-(n_raw - I_total - n_secure)/2 - 1}

    Solving for n_secure:
        n_secure <= n_raw - I_total - 2*log2(1/epsilon) - 2

    Parameters
    ----------
    n_raw : int
        Number of raw key bits.
    eve_total_bits : float
        Upper bound on Eve's total information in bits.
    target_epsilon : float
        Target security parameter (0 < epsilon < 1).

    Returns
    -------
    int
        Maximum secure key length, or 0 if not achievable.
    """
    if target_epsilon <= 0 or target_epsilon >= 1:
        raise ValueError("target_epsilon must be in (0, 1), got %s"
                         % target_epsilon)
    slack = 2.0 * math.log2(1.0 / target_epsilon) + 2.0
    n_secure = n_raw - math.ceil(eve_total_bits) - int(math.ceil(slack))
    return max(0, n_secure)


def compute_epsilon_minentropy(n_raw, h_min_per_bit, recon_leaked, n_secure):
    r"""Compute epsilon using proven min-entropy accounting.

    The min-entropy of the raw key given Eve's observations is:

        H_min(K | W, C) >= n_raw * h_min_per_bit - recon_leaked

    where h_min_per_bit is the proven per-run min-entropy bound from
    the coupling -> TV -> guessing probability chain (see leakage.py
    ``per_run_min_entropy_bound``).

    By the Leftover Hash Lemma:

        epsilon = 2^{-(H_min(K|W,C) - n_secure)/2 - 1}

    Parameters
    ----------
    n_raw : int
        Number of raw key bits (= number of protocol runs).
    h_min_per_bit : float
        Proven per-run min-entropy bound (bits), from
        ``LeakageEstimator.per_run_min_entropy_bound()['h_min_per_bit']``.
    recon_leaked : int
        Number of parity bits leaked during reconciliation.
    n_secure : int
        Number of secure output bits.

    Returns
    -------
    float
        The security parameter epsilon.  Returns 1.0 if insecure.
    """
    h_min_total = n_raw * h_min_per_bit - recon_leaked
    if h_min_total <= n_secure:
        return 1.0
    exponent = -(h_min_total - n_secure) / 2.0 - 1.0
    if exponent >= 0:
        return 1.0
    return 2.0 ** exponent


def compute_secure_length_minentropy(n_raw, h_min_per_bit, recon_leaked,
                                     target_epsilon):
    r"""Compute maximum secure key length using min-entropy accounting.

    From the LHL with min-entropy:

        epsilon = 2^{-(H_min - n_secure)/2 - 1}
        H_min = n_raw * h_min_per_bit - recon_leaked

    Solving for n_secure:

        n_secure <= H_min - 2*log2(1/epsilon) - 2

    Parameters
    ----------
    n_raw : int
        Number of raw key bits.
    h_min_per_bit : float
        Proven per-run min-entropy bound (bits).
    recon_leaked : int
        Parity bits leaked during reconciliation.
    target_epsilon : float
        Target security parameter (0 < epsilon < 1).

    Returns
    -------
    int
        Maximum secure key length, or 0 if not achievable.
    """
    if target_epsilon <= 0 or target_epsilon >= 1:
        raise ValueError("target_epsilon must be in (0, 1), got %s"
                         % target_epsilon)
    h_min_total = n_raw * h_min_per_bit - recon_leaked
    slack = 2.0 * math.log2(1.0 / target_epsilon) + 2.0
    n_secure = int(math.floor(h_min_total - slack))
    return max(0, n_secure)


def verify_security(n_raw, n_secure, wire_leakage_per_bit, recon_leaked,
                    confidence=0.99, h_min_per_bit=None):
    r"""Verify the composable security of a completed protocol run.

    Combines the wire leakage bound, reconciliation leakage, and the
    leftover hash lemma to compute the security parameter epsilon.

    When ``h_min_per_bit`` is provided, uses the correct min-entropy
    accounting (coupling -> TV -> guessing probability -> H_min) for
    the LHL instead of Shannon MI.

    Parameters
    ----------
    n_raw : int
        Number of raw key bits.
    n_secure : int
        Number of secure key bits produced.
    wire_leakage_per_bit : float
        Upper bound on I(S; W) per protocol run (bits).
        Typically from ``LeakageEstimator.estimate_mi_rigorous()['mi_upper_bound']``.
    recon_leaked : int
        Number of parity bits leaked during reconciliation.
    confidence : float
        Confidence level of the wire leakage bound (default 0.99).
    h_min_per_bit : float or None
        If provided, use min-entropy accounting instead of Shannon MI.
        Typically from ``LeakageEstimator.per_run_min_entropy_bound()['h_min_per_bit']``.

    Returns
    -------
    dict
        'epsilon': security parameter (trace distance from uniform),
        'n_raw': number of raw bits,
        'n_secure': number of secure bits,
        'wire_leakage_total': total wire leakage bound (bits),
        'recon_leakage': reconciliation leakage (bits),
        'eve_total_bits': total Eve information bound (bits),
        'min_entropy_bound': lower bound on H_min(K|Eve),
        'confidence': statistical confidence of the wire bound,
        'is_secure': True if epsilon < 1 (meaningful security guarantee),
        'safety_margin_bits': effective safety margin in bits,
        'accounting': 'min_entropy' or 'shannon' depending on method used,
        'h_min_total': total min-entropy (only when h_min_per_bit provided).
    """
    wire_total = wire_leakage_per_bit * n_raw
    eve_total = wire_total + recon_leaked

    if h_min_per_bit is not None:
        # Correct min-entropy accounting for the LHL
        h_min_total = n_raw * h_min_per_bit - recon_leaked
        min_entropy = max(0.0, h_min_total)
        epsilon = compute_epsilon_minentropy(
            n_raw, h_min_per_bit, recon_leaked, n_secure)
        safety_bits = h_min_total - n_secure
        accounting = 'min_entropy'
    else:
        # Legacy Shannon MI accounting (not rigorous for LHL)
        min_entropy = max(0.0, n_raw - eve_total)
        epsilon = compute_epsilon(n_raw, eve_total, n_secure)
        safety_bits = n_raw - eve_total - n_secure
        h_min_total = min_entropy
        accounting = 'shannon'

    return {
        'epsilon': epsilon,
        'n_raw': n_raw,
        'n_secure': n_secure,
        'wire_leakage_total': wire_total,
        'recon_leakage': recon_leaked,
        'eve_total_bits': eve_total,
        'min_entropy_bound': min_entropy,
        'confidence': confidence,
        'is_secure': epsilon < 1.0,
        'safety_margin_bits': safety_bits,
        'accounting': accounting,
        'h_min_total': h_min_total,
    }


def full_security_analysis(sigma_z, alpha, ramp_time, modulus,
                           number_of_exchanges, n_raw, recon_leaked,
                           target_epsilon=0.01, mi_samples=500,
                           mi_confidence=0.99, mi_seed=42):
    r"""Run a complete security analysis for given protocol parameters.

    Combines the rigorous HMM MI bound with reconciliation leakage
    and the leftover hash lemma to determine achievable secure key
    length and security parameter.

    Parameters
    ----------
    sigma_z : float
        Standard deviation of the noise process.
    alpha : float
        Magnitude of reflection coefficient.
    ramp_time : float
        Ramp time constant.
    modulus : float
        Modular reduction parameter p.
    number_of_exchanges : int
        Exchanges per protocol run.
    n_raw : int
        Number of raw key bits collected.
    recon_leaked : int
        Parity bits leaked during reconciliation.
    target_epsilon : float
        Target security parameter (default 0.01).
    mi_samples : int
        Monte Carlo samples for MI bound (default 500).
    mi_confidence : float
        Confidence for MI bound (default 0.99).
    mi_seed : int
        Random seed for MI estimation.

    Returns
    -------
    dict
        'mi_bound': rigorous per-run MI upper bound,
        'mi_estimate': per-run MI point estimate,
        'mi_confidence': confidence level,
        'wire_leakage_total': n_raw * mi_bound,
        'recon_leakage': parity bits leaked,
        'eve_total_bits': total Eve information,
        'n_secure_for_target': max n_secure achieving target_epsilon,
        'target_epsilon': the target,
        'achieved_epsilon': actual epsilon at n_secure_for_target,
        'recon_leakage_bound': deterministic worst-case recon bound,
        'is_secure': whether a secure key can be extracted.
    """
    estimator = _leakage_mod.LeakageEstimator(
        sigma_z, alpha, ramp_time, modulus, number_of_exchanges)

    # Rigorous MI bound via HMM forward + Hoeffding
    mi_result = estimator.estimate_mi_rigorous(
        n_samples=mi_samples, seed=mi_seed, confidence=mi_confidence)
    mi_bound = mi_result['mi_upper_bound']

    wire_total = mi_bound * n_raw
    eve_total = wire_total + recon_leaked

    # Deterministic worst-case reconciliation bound
    recon_bound = _recon_mod.leakage_bound(n_raw)

    # Max secure length for target epsilon
    n_secure = compute_secure_length_from_epsilon(
        n_raw, eve_total, target_epsilon)

    # Actual epsilon at that length
    if n_secure > 0:
        achieved_eps = compute_epsilon(n_raw, eve_total, n_secure)
    else:
        achieved_eps = 1.0

    return {
        'mi_bound': mi_bound,
        'mi_estimate': mi_result['mi_estimate'],
        'mi_confidence': mi_confidence,
        'hoeffding_correction': mi_result['hoeffding_correction'],
        'wire_leakage_total': wire_total,
        'recon_leakage': recon_leaked,
        'recon_leakage_bound': recon_bound,
        'eve_total_bits': eve_total,
        'n_secure_for_target': n_secure,
        'target_epsilon': target_epsilon,
        'achieved_epsilon': achieved_eps,
        'n_raw': n_raw,
        'is_secure': n_secure > 0,
        'proof_type': 'statistical',
    }


def proven_security_analysis(sigma_z, alpha, ramp_time, modulus,
                              number_of_exchanges, n_raw, recon_leaked,
                              target_epsilon=0.01, hmin_samples=500,
                              hmin_confidence=0.99, hmin_seed=42,
                              rng_is_true_random=False):
    r"""Fully proven security analysis using HMM-based min-entropy.

    Security Model
    --------------
    This proves ITS against a **passive TCP eavesdropper** who observes
    all mod-p wrapped wire values transmitted over the channel.  The
    wrapping is applied by ``endpoint.Physics.exchange()`` before
    transmission (via ``_mod_reduce``), so Eve never sees unwrapped
    real-valued signals.

    The proof is valid under the assumptions listed in
    ``ITS_ASSUMPTIONS``:
    (1) true randomness for endpoint noise,
    (2) correct modular reduction,
    (3) passive Eve,
    (4) independent protocol runs.

    Uses the rigorous proof chain:

        1. HMM forward: exact P(W|s_A,s_B)
        2. Product-sign marginals: P(W|S=±)
        3. Guessing probability: P_guess = max(P(S=+|W), P(S=-|W))
        4. Hoeffding on P_guess: E[P_guess] ≤ mean + t
        5. Min-entropy: h_min = -log₂(E[P_guess])
        6. IID composition: H_min(K|W) = n_raw · h_min
        7. Reconciliation: H_min(K|W,C) ≥ H_min(K|W) - λ
        8. LHL: ε = 2^{-(H_min(K|W,C) - n_secure)/2 - 1}

    Every step is a proven theorem.  The security guarantee is:
    the extracted key is ε-close to uniform, except with failure
    probability (1 - hmin_confidence) in the Hoeffding bound.

    Parameters
    ----------
    sigma_z : float
        Standard deviation of the noise process.
    alpha : float
        Magnitude of reflection coefficient.
    ramp_time : float
        Ramp time constant.
    modulus : float
        Modular reduction parameter p.
    number_of_exchanges : int
        Exchanges per protocol run.
    n_raw : int
        Number of raw key bits collected.
    recon_leaked : int
        Parity bits leaked during reconciliation.
    target_epsilon : float
        Target security parameter (default 0.01).
    hmin_samples : int
        Monte Carlo samples for H_min estimation (default 500).
    hmin_confidence : float
        Confidence for Hoeffding bound (default 0.99).
    hmin_seed : int
        Random seed for H_min estimation.
    rng_is_true_random : bool
        Whether the endpoint RNG is a true (hardware) random source.
        When False (default), the analysis reports ``security_level``
        as ``'computational'`` and ``its_valid`` as False.

    Returns
    -------
    dict
        'h_min_per_run': proven per-run min-entropy bound,
        'h_min_total': total min-entropy after reconciliation,
        'pguess_mean': sample mean of P_guess,
        'pguess_upper_bound': Hoeffding upper bound on E[P_guess],
        'recon_leakage': parity bits leaked,
        'recon_leakage_bound': deterministic worst-case recon bound,
        'n_secure_for_target': max n_secure for target epsilon,
        'target_epsilon': the target,
        'achieved_epsilon': actual epsilon,
        'n_raw': number of raw bits,
        'is_secure': True if extractable key,
        'proof_type': 'proven_statistical' (rigorous with confidence),
        'confidence': Hoeffding confidence level,
        'accounting': 'min_entropy',
        'assumption_status': per-assumption validation dict,
        'its_valid': True only when all checkable assumptions pass,
        'security_level': 'its' or 'computational',
        'its_caveats': list of strings explaining ITS gaps (if any).
    """
    estimator = _leakage_mod.LeakageEstimator(
        sigma_z, alpha, ramp_time, modulus, number_of_exchanges)

    # Rigorous min-entropy via HMM forward + Hoeffding
    hmin_result = estimator.estimate_hmin_rigorous(
        n_samples=hmin_samples, seed=hmin_seed, confidence=hmin_confidence)
    h_min_per_run = hmin_result['h_min']

    recon_bound = _recon_mod.leakage_bound(n_raw)

    assumption_result = validate_assumptions(
        rng_is_true_random=rng_is_true_random, modulus=modulus)

    if h_min_per_run <= 0.0:
        return {
            'h_min_per_run': 0.0,
            'h_min_total': 0.0,
            'pguess_mean': hmin_result['pguess_mean'],
            'pguess_upper_bound': hmin_result['pguess_upper_bound'],
            'recon_leakage': recon_leaked,
            'recon_leakage_bound': recon_bound,
            'n_secure_for_target': 0,
            'target_epsilon': target_epsilon,
            'achieved_epsilon': 1.0,
            'n_raw': n_raw,
            'is_secure': False,
            'proof_type': 'proven_statistical',
            'confidence': hmin_confidence,
            'accounting': 'min_entropy',
            'assumption_status': assumption_result['assumption_status'],
            'its_valid': assumption_result['its_valid'],
            'security_level': assumption_result['security_level'],
            'its_caveats': assumption_result['its_caveats'],
        }

    h_min_total = n_raw * h_min_per_run - recon_leaked

    n_secure = compute_secure_length_minentropy(
        n_raw, h_min_per_run, recon_leaked, target_epsilon)

    if n_secure > 0:
        achieved_eps = compute_epsilon_minentropy(
            n_raw, h_min_per_run, recon_leaked, n_secure)
    else:
        achieved_eps = 1.0

    return {
        'h_min_per_run': h_min_per_run,
        'h_min_total': h_min_total,
        'pguess_mean': hmin_result['pguess_mean'],
        'pguess_upper_bound': hmin_result['pguess_upper_bound'],
        'recon_leakage': recon_leaked,
        'recon_leakage_bound': recon_bound,
        'n_secure_for_target': n_secure,
        'target_epsilon': target_epsilon,
        'achieved_epsilon': achieved_eps,
        'n_raw': n_raw,
        'is_secure': n_secure > 0,
        'proof_type': 'proven_statistical',
        'confidence': hmin_confidence,
        'accounting': 'min_entropy',
        'assumption_status': assumption_result['assumption_status'],
        'its_valid': assumption_result['its_valid'],
        'security_level': assumption_result['security_level'],
        'its_caveats': assumption_result['its_caveats'],
    }


# ======================================================================
# Multi-bit extraction from Z sequences
# ======================================================================

def compute_z_pguess_per_step(sigma_z, modulus, n_bits=4, range_sigma=4.0,
                               n_grid=500, n_branches=20):
    r"""Compute Eve's guessing probability for one quantized Z sample.

    .. warning::

        This function models the **original** (pre-wrapping) Z on the
        lattice, NOT the **decoded** Z = Z mod p used as key material.
        The decoded Z is deterministic given (wire, center), so this
        per-step analysis does NOT apply to the protocol's actual
        security.  Use ``multibit_security_analysis()`` with the
        ``alpha`` and ``ramp_time`` parameters for the correct
        sign-based security bound.  This function is retained for
        diagnostic purposes only.

    In ITS mode, each protocol step produces a noise sample Z_k drawn
    from N(0, sigma_z^2).  Eve observes W_k = (Z_k + c_k) mod p, where
    c_k depends on the message history.  In the worst case (for security),
    Eve knows c_k perfectly.

    Given W_k, Eve knows Z_k lies on the lattice {W_k - c_k + j*p}.
    Quantizing Z_k to n_bits over [-range_sigma*sigma_z, +range_sigma*sigma_z]
    maps each lattice point to a bin.  Eve's guessing probability is
    the maximum bin probability.

    This function computes E_W[max_bin P(bin | W)] averaged over the
    (nearly uniform) distribution of W, as well as a proven upper bound
    ``pguess_proven`` that accounts for grid discretization error.

    Parameters
    ----------
    sigma_z : float
        Standard deviation of the noise process.
    modulus : float
        The modular reduction parameter p.
    n_bits : int
        Quantization bits per sample (default 4).
    range_sigma : float
        Quantization range in units of sigma_z (default 4.0).
    n_grid : int
        Grid points for averaging over W (default 500).
    n_branches : int
        Lattice branches to consider (default 20).

    Returns
    -------
    dict
        'pguess': E[P_guess(Z_q | W)] (worst-case over c_k),
        'pguess_max': max over W grid of P_guess(Z_q | W),
        'pguess_proven': pguess_max + grid_error (proven upper bound),
        'h_min_per_step': -log2(pguess) = per-step min-entropy (bits),
        'h_min_per_step_proven': -log2(pguess_proven) (proven bound),
        'grid_error': proven analytical bound on max pguess variation from grid,
        'truncation_error': bound on probability mass outside lattice range,
        'n_bits': quantization bits,
        'n_bins': number of quantization bins,
        'range': quantization range [-R, R].
    """
    p = modulus
    R = range_sigma * sigma_z
    n_bins = 2 ** n_bits
    delta = 2.0 * R / n_bins

    # Auto-adjust n_branches so all lattice points within [-R, R] are
    # enumerated for any W in (-p/2, p/2].  The furthest lattice point
    # is |W| + n_branches*p; we need this >= R.
    min_branches = int(math.ceil(R / p)) + 1
    n_branches = max(n_branches, min_branches)

    # Truncation error: total Gaussian probability mass beyond the
    # enumerated lattice range.  The furthest enumerated point is at
    # |W| + n_branches*p <= p/2 + n_branches*p.  Probability mass
    # beyond this is bounded by the Gaussian tail.
    max_lattice_reach = p / 2.0 + n_branches * p
    truncation_error = 2.0 * _gaussian_tail_bound(max_lattice_reach, sigma_z)

    # Average P_guess over W uniformly on (-p/2, p/2]
    dw = p / n_grid
    w_grid = np.linspace(-p / 2, p / 2, n_grid, endpoint=False)
    w_grid += dw / 2.0

    def _eval_pguess_at(w_val):
        """Compute pguess and mu_1 at a single W value.

        Returns (pguess, mu_1) where mu_1 = sum_j |z_j|*phi_j / g(W)
        is the first absolute moment used in the Lipschitz bound.
        """
        bin_probs = np.zeros(n_bins)
        total_weight = 0.0
        abs_moment = 0.0
        for j in range(-n_branches, n_branches + 1):
            z = w_val + j * p
            if abs(z) > R:
                continue
            weight = math.exp(-0.5 * (z / sigma_z) ** 2)
            total_weight += weight
            abs_moment += abs(z) * weight
            bin_idx = int((z + R) / delta)
            bin_idx = max(0, min(n_bins - 1, bin_idx))
            bin_probs[bin_idx] += weight
        if total_weight > 0:
            bin_probs /= total_weight
            mu_1 = abs_moment / total_weight
        else:
            mu_1 = 0.0
        return float(np.max(bin_probs)), mu_1

    # Evaluate pguess on primary grid
    pguess_sum = 0.0
    pguess_max = 0.0
    mu_1_max_grid = 0.0
    pg_primary = np.empty(n_grid)
    for i, w in enumerate(w_grid):
        pg, mu_1 = _eval_pguess_at(w)
        pg_primary[i] = pg
        pguess_sum += pg
        if pg > pguess_max:
            pguess_max = pg
        if mu_1 > mu_1_max_grid:
            mu_1_max_grid = mu_1

    pguess = pguess_sum / n_grid

    # Evaluate pguess on a half-shifted grid to capture peaks near
    # bin-boundary crossings that the primary grid may miss.
    w_grid_half = w_grid + dw / 2.0
    for w in w_grid_half:
        pg, mu_1 = _eval_pguess_at(w)
        if pg > pguess_max:
            pguess_max = pg
        if mu_1 > mu_1_max_grid:
            mu_1_max_grid = mu_1

    # --- Proven grid error bound ---
    #
    # The computed pguess is an approximation of the true pguess:
    #
    # (A) Grid discretization: pguess(W) is evaluated at discrete W
    #     points, so the true max_W pguess(W) may exceed pguess_max.
    #
    # (B) Range truncation: lattice points with |z| > R are skipped
    #     (line 836), so the computed bin probabilities condition on
    #     Z in [-R, R].  The true pguess includes tail weight.
    #
    # === Part (A): Grid error ===
    #
    # pguess(W) = max_b q_b(W), where q_b = f_b/g is a bin probability.
    # q_b is smooth EXCEPT at bin-boundary crossings where a lattice
    # point moves between adjacent bins.
    #
    # STRUCTURAL FACT: For a fixed bin b, consecutive crossings are
    # spaced >= min(p, delta_bin) apart.
    # Proof: crossings at W = (-R + b*delta_bin) - j*p; consecutive j
    # values differ by p; adjacent boundaries within same j differ by
    # delta_bin = 2R/n_bins.
    #
    # LIPSCHITZ BOUND between crossings: Within a crossing-free
    # segment of bin b, the branch set S_b is fixed.  By quotient rule:
    #   q_b'(W) = (1/g) * sum_j [-(W+jp)/sigma^2 * phi(W+jp)]
    #             * (1_{j in S_b} - q_b)
    # Since |1_{j in S_b} - q_b| <= 1:
    #   |q_b'| <= mu_1(W)/sigma^2
    # where mu_1(W) = sum_j |W+jp|*phi(W+jp) / g(W).
    #
    # --- Two-tier mu_1 bound (tight) ---
    #
    # OLD elementary bound (kept for context and used in correction term):
    #   Each |W+jp|*phi(W+jp) <= sigma/sqrt(e)  [max at |x|=sigma]
    #   Numerator <= (2*n_branches + 1) * sigma/sqrt(e)
    #   Denominator >= g_min = sqrt(2*pi)*sigma*(1-delta)/p
    #   So mu_1_old = (2*n_branches+1)*p / (sqrt(2*pi*e)*(1-delta))
    #
    # NEW tight approach: Compute mu_1(w) exactly at each of the 2*n_grid
    # evaluation points (primary + half-shifted).  Set
    #   mu_1_max_grid = max over all evaluation points.
    #
    # To bound mu_1 between grid points, bound |mu_1'(W)| via quotient
    # rule on mu_1 = N/D:
    #   |mu_1'| <= |N'|/D + mu_1 * |D'|/D
    # For numerator derivative:
    #   |d/dW [|z_j|*phi_j]| <= (1 + z_j^2/sigma^2)*phi_j
    #   max_t (1+t^2)*exp(-t^2/2) = 2/sqrt(e) (at t=1)
    #   => |N'| <= (2/sqrt(e)) * n_lattice
    #   |D'| <= N/sigma^2  [since |d/dW phi_j| = |z_j|/sigma^2 * phi_j]
    # Using D >= g_min and mu_1_old for the correction:
    #   M := |mu_1'| <= (2/sqrt(e))*n_lattice/g_min + mu_1_old^2/sigma^2
    #
    # Final tight bound:
    #   mu_1_tight = mu_1_max_grid + M * dw/2
    #   L_tight = mu_1_tight / sigma^2
    #   grid_error = L_tight * dw/2
    #
    # Since M*dw/2 is typically negligible vs mu_1_max_grid, the
    # improvement factor is roughly mu_1_old / mu_1_max_grid ≈ 10-1000x.
    #
    # SAME-SEGMENT ARGUMENT: For any W, let b* be the bin achieving
    # pguess(W) = q_{b*}(W).  Since dw/2 < min(p, delta_bin) (checked
    # below), there exists an evaluation point w_eval in the same
    # crossing-free segment of b* as W, with |W - w_eval| <= dw/2.
    # (Worst case: W is within dw/4 of a crossing of b*, and the
    # nearest same-side point is dw/2 away.)
    # Then: pguess(W) = q_{b*}(W) <= q_{b*}(w_eval) + L * dw/2
    #                              <= pguess(w_eval) + L * dw/2
    #                              <= pguess_max + L * dw/2.  QED.
    #
    # === Part (B): Truncation correction ===
    #
    # The code skips lattice points with |z| > R, computing pguess
    # for the distribution conditioned on Z in [-R, R].  The true
    # (unconditional) bin probability for bin b satisfies:
    #   q_b_true = (f_b + eps_b) / (g + eps_abs)
    # where eps_abs = sum_{|z|>R} phi(z) and eps_b <= eps_abs.
    # Since f_b <= g and eps_b <= eps_abs:
    #   q_b_true <= (f_b + eps_abs) / (g + eps_abs)
    #            <= f_b/g + eps_abs/g  =  q_b_computed + eps_abs/g
    #
    # PROVEN BOUND on eps_abs/g (no lattice-integral approximation):
    #
    # (i) Upper bound on eps_abs: Each out-of-range lattice point
    #     has |z_j| > R, so phi(z_j) = exp(-z_j^2/(2*sigma^2))
    #     <= exp(-R^2/(2*sigma^2)).  There are at most n_lattice
    #     = 2*n_branches+1 lattice points total, so:
    #       eps_abs(W) <= n_lattice * exp(-R^2/(2*sigma^2))  =: A
    #
    # (ii) Lower bound on g (the in-range sum): The total lattice
    #      sum g_total(W) = g(W) + eps_abs(W) satisfies the Fourier
    #      lower bound (same as Part A):
    #        g_total(W) >= sqrt(2*pi)*sigma*(1-delta)/p  =: G
    #      Therefore:
    #        g(W) = g_total(W) - eps_abs(W) >= G - A
    #
    # (iii) Combining: eps_abs/g <= A / (G - A), provided G > A.
    #       This is proven from (i) and (ii) with no approximation.

    tv_delta_for_grid = wrapped_gaussian_tv_bound(sigma_z, p)
    one_minus_delta = max(1e-30, 1.0 - tv_delta_for_grid)
    n_lattice = 2 * n_branches + 1

    # Tight Lipschitz bound: grid-evaluated mu_1 + second-order correction.
    #
    # mu_1(W) = sum_j |W+jp|*phi_j / g(W) was computed exactly at each
    # of the 2*n_grid evaluation points.  To bound mu_1 between grid
    # points, we bound |mu_1'(W)| via quotient rule on N/D:
    #   |mu_1'| <= |N'|/D + mu_1 * |D'|/D
    # where |d/dW [|z_j|*phi_j]| <= (1 + z_j^2/sigma^2)*phi_j
    # and max_t (1+t^2)*exp(-t^2/2) = 2/sqrt(e) (at t=1).
    # So |N'| <= (2/sqrt(e)) * n_lattice, and |D'| <= N/sigma^2.
    # Using D >= g_min and the old elementary mu_1 bound for the
    # correction term only:
    g_min = math.sqrt(2.0 * math.pi) * sigma_z * one_minus_delta / p
    C1 = 2.0 / math.sqrt(math.e)
    mu_1_old = n_lattice * sigma_z / math.sqrt(math.e) / g_min
    M_mu1prime = C1 * n_lattice / g_min + mu_1_old ** 2 / sigma_z ** 2
    mu_1_tight = mu_1_max_grid + M_mu1prime * dw / 2.0
    lipschitz_const = mu_1_tight / sigma_z ** 2
    grid_error = lipschitz_const * dw / 2.0

    # Truncation correction: proven bound A / (G - A)
    # A = n_lattice * exp(-R^2 / (2*sigma^2))
    t = R / sigma_z
    if t > 38:  # underflow guard
        A = 0.0
    else:
        A = n_lattice * math.exp(-0.5 * t * t)
    # G = sqrt(2*pi) * sigma * (1 - delta) / p  (Fourier lower bound on g_total)
    G = math.sqrt(2.0 * math.pi) * sigma_z * one_minus_delta / p
    if A <= 0.0:
        truncation_correction = 0.0
    elif G > A:
        truncation_correction = A / (G - A)
    else:
        truncation_correction = 1.0

    # Verify grid resolution: the double grid (spacing dw/2) must be
    # finer than the minimum same-bin crossing spacing.
    min_crossing_spacing = min(p, delta)
    assert dw / 2.0 < min_crossing_spacing, (
        "Grid too coarse to resolve bin-boundary crossings: "
        "dw/2 = %.2e >= min crossing spacing = %.2e.  "
        "Increase n_grid." % (dw / 2.0, min_crossing_spacing))

    # Proven upper bound: observed max + grid residual + truncation
    pguess_proven = min(1.0, pguess_max + grid_error + truncation_correction)

    h_min = -math.log2(pguess) if pguess > 0 and pguess < 1.0 else 0.0
    h_min_proven = (-math.log2(pguess_proven)
                    if pguess_proven > 0 and pguess_proven < 1.0 else 0.0)

    return {
        'pguess': pguess,
        'pguess_max': pguess_max,
        'pguess_proven': pguess_proven,
        'h_min_per_step': h_min,
        'h_min_per_step_proven': h_min_proven,
        'grid_error': grid_error,
        'truncation_error': truncation_error,
        'n_bits': n_bits,
        'n_bins': n_bins,
        'range': R,
    }


def _gaussian_tail_bound(x, sigma):
    """Upper bound on P(|Z| > x) for Z ~ N(0, sigma^2).

    Uses the standard Mill's ratio bound: P(Z > x) <= phi(x/sigma) * sigma/x.
    """
    if x <= 0:
        return 1.0
    t = x / sigma
    if t > 38:  # underflow guard
        return 0.0
    return 2.0 * math.exp(-0.5 * t * t) / (math.sqrt(2.0 * math.pi) * t)


def wrapped_gaussian_tv_bound(sigma_z, modulus, n_terms=20):
    r"""TV distance between a wrapped Gaussian and uniform on (-p/2, p/2].

    The wrapped Gaussian with variance sigma^2 on a circle of circumference p
    has TV distance from uniform bounded by:

        delta = 2 * sum_{m=1}^{n_terms} exp(-2*pi^2*m^2*sigma^2/p^2)

    For sigma >> p, this is exponentially small.

    Parameters
    ----------
    sigma_z : float
        Standard deviation of the Gaussian.
    modulus : float
        The modular reduction parameter p.
    n_terms : int
        Number of Fourier terms in the bound (default 20).

    Returns
    -------
    float
        Upper bound delta on the TV distance.
    """
    p = modulus
    total = 0.0
    for m in range(1, n_terms + 1):
        exponent = -2.0 * math.pi ** 2 * m ** 2 * sigma_z ** 2 / (p ** 2)
        if exponent < -700:  # underflow guard
            break
        total += math.exp(exponent)
    return 2.0 * total


def compute_multibit_secure_length(n_channels, h_min_per_channel,
                                    target_epsilon=0.01,
                                    composition_correction_bits=0.0):
    r"""Compute secure key length for multi-bit Z extraction.

    Uses the Leftover Hash Lemma with total min-entropy:

        H_min(decoded_Z_all | W) >= n_channels * h_min_per_channel
                                     - composition_correction_bits

    Each "channel" is an independent protocol run (or parallel channel).
    The per-channel min-entropy ``h_min_per_channel`` is the sign-bit
    min-entropy: Eve's uncertainty about the alpha sign product, which
    is the only source of uncertainty in the decoded Z values (see
    ``multibit_security_analysis`` docstring for the full argument).

    No reconciliation leakage is needed because in ITS mode both
    parties reconstruct each other's Z sequences exactly from the
    authenticated M_real values.

    Parameters
    ----------
    n_channels : int
        Total number of independent channels (runs or parallel channels).
    h_min_per_channel : float
        Per-channel min-entropy bound (sign-bit entropy), from
        ``multibit_security_analysis()['h_min_per_channel']``.
    target_epsilon : float
        Target security parameter (default 0.01).
    composition_correction_bits : float
        Correction term from the composition proof (default 0.0).
        Accounts for the TV distance between real and ideal protocols.

    Returns
    -------
    dict
        'n_secure': maximum secure key bits,
        'h_min_total': total min-entropy,
        'target_epsilon': the target,
        'achieved_epsilon': actual epsilon at n_secure.
    """
    if target_epsilon <= 0 or target_epsilon >= 1:
        raise ValueError("target_epsilon must be in (0, 1)")

    h_min_total = n_channels * h_min_per_channel - composition_correction_bits
    slack = 2.0 * math.log2(1.0 / target_epsilon) + 2.0
    n_secure = int(math.floor(h_min_total - slack))
    n_secure = max(0, n_secure)

    if n_secure > 0:
        exponent = -(h_min_total - n_secure) / 2.0 - 1.0
        achieved_eps = 2.0 ** exponent if exponent < 0 else 1.0
    else:
        achieved_eps = 1.0

    return {
        'n_secure': n_secure,
        'h_min_total': h_min_total,
        'target_epsilon': target_epsilon,
        'achieved_epsilon': achieved_eps,
    }


def multibit_security_analysis(sigma_z, modulus, number_of_exchanges,
                                alpha=None, ramp_time=None,
                                n_bits=4, range_sigma=4.0,
                                target_epsilon=0.01):
    r"""Full security analysis for multi-bit Z extraction.

    **Correct security model: decoded Z = Z mod p (centered).**

    The protocol extracts key material from the **decoded** Z values,
    computed as ``Z_decoded = wire + n*p - center`` where
    ``n = round((center - wire) / p)``.  This is algebraically
    ``Z mod p`` (centered).

    **Decoded Z is deterministic given (wire, center).**  Eve observes
    the wire values.  Her only uncertainty is which of 2 candidate
    centers is correct (one per sign hypothesis).  All steps within a
    channel share the **same sign pair**, so Eve has exactly
    **2 candidate full sequences**.

    Therefore::

        P_guess(decoded_Z_all | Wire_all) = max(P(S=+|W), P(S=-|W))
        H_min(decoded_Z_all | Wire_all) = H_min(sign | Wire_all)

    This is exactly the sign-bit min-entropy, computed by the
    HMM-based ``estimate_hmin_rigorous`` or the analytical TV bound
    in ``leakage.py``.

    The per-step Z-lattice analysis (``compute_z_pguess_per_step``)
    models the *original* (pre-wrapping) Z, which has genuine lattice
    ambiguity.  But the protocol uses decoded Z, not original Z.
    The lattice results are retained as diagnostics only.

    Parameters
    ----------
    sigma_z : float
        Standard deviation of the noise process.
    modulus : float
        Modular reduction parameter p.
    number_of_exchanges : int
        Exchanges per protocol run.
    alpha : float or None
        Magnitude of reflection coefficient.  Required for the correct
        sign-based security bound.  When None, falls back to
        h_min_per_channel = 0 (safe but conservative).
    ramp_time : float or None
        Ramp time constant.  Required together with ``alpha``.
    n_bits : int
        Quantization bits per Z sample (default 4).
    range_sigma : float
        Quantization range in sigma_z units (default 4.0).
    target_epsilon : float
        Target security parameter (default 0.01).

    Returns
    -------
    dict
        'h_min_per_channel': per-channel min-entropy (sign entropy),
        'sign_pguess': sign guessing probability per channel,
        'sign_tv_run': per-run TV distance for sign,
        'n_secure_per_run': secure bits from 1 run (sign-based),
        'n_steps_per_run': total Z samples per run,
        'target_epsilon': the target,
        'achieved_epsilon': actual epsilon,
        'n_bits': quantization bits used,
        'tv_delta': TV distance of wrapped Gaussian from uniform,
        'z_lattice_diagnostic': dict with old per-step results
            (for reference only, NOT used for security),
        'network_security_note': note about PSK requirements.
    """
    # Total Z samples per run: Alice sends n_ex+1 messages, Bob sends n_ex
    n_steps = 2 * number_of_exchanges + 1

    # --- Z-lattice diagnostic (models original Z, NOT decoded Z) ---
    step_result = compute_z_pguess_per_step(
        sigma_z, modulus, n_bits=n_bits, range_sigma=range_sigma)

    tv_delta = wrapped_gaussian_tv_bound(sigma_z, modulus)

    # --- Sign-based min-entropy (correct bound for decoded-Z key material) ---
    if alpha is not None and ramp_time is not None:
        estimator = _leakage_mod.LeakageEstimator(
            sigma_z, abs(alpha), ramp_time, modulus, number_of_exchanges)
        sign_result = estimator.per_run_min_entropy_bound()
        h_min_per_channel = sign_result['h_min_per_bit']
        sign_pguess = sign_result['p_guess']
        sign_tv_run = sign_result['tv_run']
    else:
        # Fallback: assume worst case (0 min-entropy) when params missing
        h_min_per_channel = 0.0
        sign_pguess = 1.0
        sign_tv_run = 1.0

    # Secure bits from a single run (1 channel)
    secure_result = compute_multibit_secure_length(
        1, h_min_per_channel,
        target_epsilon=target_epsilon,
        composition_correction_bits=0.0)

    return {
        'h_min_per_channel': h_min_per_channel,
        'sign_pguess': sign_pguess,
        'sign_tv_run': sign_tv_run,
        'n_secure_per_run': secure_result['n_secure'],
        'n_steps_per_run': n_steps,
        'h_min_total_per_run': secure_result['h_min_total'],
        'target_epsilon': target_epsilon,
        'achieved_epsilon': secure_result['achieved_epsilon'],
        'n_bits': n_bits,
        'tv_delta': tv_delta,
        'z_lattice_diagnostic': {
            'h_min_per_step': step_result['h_min_per_step'],
            'h_min_per_step_proven': step_result['h_min_per_step_proven'],
            'pguess_per_step': step_result['pguess'],
            'pguess_proven': step_result['pguess_proven'],
            'grid_error': step_result['grid_error'],
            'truncation_error': step_result['truncation_error'],
        },
        'network_security_note': (
            "Network mode requires a pre-shared key for auth channel "
            "encryption.  ITS holds if the PSK is a true-random OTP "
            "of session length; computational if the PSK seeds a "
            "stream cipher (e.g. ChaCha20 or SHAKE-256)."
        ),
    }


def signbit_security_analysis(sigma_z, modulus, alpha, ramp_time,
                               B, n_runs, psk_size_bits,
                               target_epsilon=0.01):
    r"""Security analysis for sign-bit-only ITS protocol with key recycling.

    With n_ex=1 and sign-bit extraction, the net PSK cost per run is:

        PSK consumed per run = B + 128  (B sign OTP bits + 128 MAC key bits)
        Key produced per run = B * h_min_per_channel - slack
        Net loss per run = (B + 128) - (B * h_min - slack) = B*(1-h_min) + 128 + slack

    When h_min ~ 1.0 (achievable with mod_mult=0.5, sigma/p=2):
        Net loss per run ~ 128 + slack ~ 143 bits

    Amplification ratio from initial PSK:
        total_output / psk_size ~ (psk_size / 143) * B / psk_size = B / 143

    Parameters
    ----------
    sigma_z : float
        Standard deviation of noise.
    modulus : float
        Modular reduction parameter p.
    alpha : float
        Magnitude of reflection coefficient.
    ramp_time : float
        Ramp time constant.
    B : int
        Number of parallel channels per run.
    n_runs : int
        Runs per batch.
    psk_size_bits : int
        Initial PSK size in bits.
    target_epsilon : float
        Target security parameter (default 0.01).

    Returns
    -------
    dict
        h_min_per_channel : sign-bit min-entropy per channel,
        n_secure_per_batch : secure bits per batch (n_runs runs),
        psk_consumed_per_batch : PSK bits consumed per batch,
        net_loss_per_batch : psk_consumed - n_secure (should be ~143*n_runs),
        max_batches : number of batches from psk_size_bits,
        total_output_bits : total key output from PSK,
        amplification_ratio : total_output / psk_size_bits,
        net_loss_per_run : average net PSK loss per run.
    """
    # Get sign-based h_min
    security = multibit_security_analysis(
        sigma_z, modulus, 1,  # n_ex=1
        alpha=alpha, ramp_time=ramp_time,
        target_epsilon=target_epsilon)

    h_min_per_channel = security['h_min_per_channel']

    # Per batch: n_runs runs, each with B channels
    n_channels_per_batch = n_runs * B

    secure_result = compute_multibit_secure_length(
        n_channels_per_batch, h_min_per_channel,
        target_epsilon=target_epsilon)
    n_secure_per_batch = secure_result['n_secure']

    # PSK consumed per batch: 256-bit header + n_runs * (B sign OTP + 128 MAC)
    psk_consumed_per_batch = 256 + n_runs * (B + 128)

    net_loss_per_batch = psk_consumed_per_batch - n_secure_per_batch

    # With key recycling, each batch shrinks the pool by net_loss_per_batch.
    # The first batch requires psk_consumed_per_batch bits from the pool.
    # After recycling n_secure_per_batch bits back, the pool shrinks by
    # net_loss_per_batch.  So max_batches = psk_size_bits // net_loss_per_batch
    # (provided the initial PSK is large enough for the first batch).
    if net_loss_per_batch > 0 and psk_size_bits >= psk_consumed_per_batch:
        max_batches = psk_size_bits // net_loss_per_batch
    elif net_loss_per_batch <= 0 and psk_size_bits >= psk_consumed_per_batch:
        max_batches = 10**9  # effectively unlimited
    else:
        max_batches = 0

    total_output_bits = max_batches * n_secure_per_batch
    amplification_ratio = (total_output_bits / psk_size_bits
                           if psk_size_bits > 0 else 0.0)
    net_loss_per_run = (net_loss_per_batch / n_runs
                        if n_runs > 0 else 0.0)

    return {
        'h_min_per_channel': h_min_per_channel,
        'sign_pguess': security['sign_pguess'],
        'sign_tv_run': security['sign_tv_run'],
        'n_secure_per_batch': n_secure_per_batch,
        'psk_consumed_per_batch': psk_consumed_per_batch,
        'net_loss_per_batch': net_loss_per_batch,
        'net_loss_per_run': net_loss_per_run,
        'max_batches': max_batches,
        'total_output_bits': total_output_bits,
        'amplification_ratio': amplification_ratio,
        'target_epsilon': target_epsilon,
        'achieved_epsilon': secure_result['achieved_epsilon'],
        'B': B,
        'n_runs': n_runs,
        'tv_delta': security['tv_delta'],
    }


def signbit_nopa_security_analysis(sigma_z, modulus, B, n_runs,
                                    n_batches=1):
    r"""Security analysis for sign-bit no-PA protocol (pool-flat mode).

    With sigma/p = 2, the TV distance per sign-bit channel from uniform
    is exponentially small: TV ~ exp(-2*pi^2*sigma^2/p^2) ~ exp(-79).
    Raw sign bits are already indistinguishable from uniform — no privacy
    amplification is needed.

    Security budget:
        epsilon_per_channel = TV_per_channel (from wrapped_gaussian_tv_bound)
        epsilon_per_batch = n_runs * B * epsilon_per_channel  (union bound)
        epsilon_cumulative = n_batches * epsilon_per_batch

    Pool dynamics:
        Each run withdraws ceil(B/8) bytes and deposits ceil(B/8) bytes.
        Net pool change = 0.  MAC keys recycled from output.

    Parameters
    ----------
    sigma_z : float
        Standard deviation of noise.
    modulus : float
        Modular reduction parameter p.
    B : int
        Number of parallel channels per run.
    n_runs : int
        Runs per batch.
    n_batches : int
        Number of batches (default 1).

    Returns
    -------
    dict
        tv_per_channel : TV distance per sign-bit channel,
        epsilon_per_batch : security parameter per batch,
        epsilon_cumulative : total security parameter over all batches,
        pool_net_change : 0 (flat operation),
        key_bits_per_batch : n_runs * B,
        min_psk_bytes : 32 + ceil(B/8),
        sigma_over_p : sigma_z / modulus ratio.
    """
    tv_per_channel = wrapped_gaussian_tv_bound(sigma_z, modulus)
    epsilon_per_batch = n_runs * B * tv_per_channel
    epsilon_cumulative = n_batches * epsilon_per_batch
    key_bits_per_batch = n_runs * B
    min_psk_bytes = 32 + math.ceil(B / 8)

    bins_per_pack = 61 // 4  # default n_bits=4
    # MAC covers: packed wire bins + B encrypted sign bytes
    mac_degree = math.ceil(2 * B / bins_per_pack) + B
    M61 = (1 << 61) - 1
    eps_mac_per_run = mac_degree / M61
    eps_composition = n_batches * n_runs * (4 * B * tv_per_channel
                                            + eps_mac_per_run)

    return {
        'tv_per_channel': tv_per_channel,
        'epsilon_per_batch': epsilon_per_batch,
        'epsilon_cumulative': epsilon_cumulative,
        'pool_net_change': 0,
        'key_bits_per_batch': key_bits_per_batch,
        'min_psk_bytes': min_psk_bytes,
        'sigma_over_p': sigma_z / modulus if modulus > 0 else float('inf'),
        'mac_degree': mac_degree,
        'eps_mac_per_run': eps_mac_per_run,
        'eps_composition': eps_composition,
    }


def composition_security_bound(sigma_z, modulus, B, n_runs_total,
                                n_bits=4, range_sigma=4.0):
    r"""Composition security bound for signbit_nopa with pool recycling.

    THEOREM (Pool Recycling Composition):

    The signbit_nopa protocol with pool recycling achieves eps_total-ITS
    security against passive eavesdroppers, where:

        eps_total <= N * (4*B*delta_TV + d/M61)

    with N = n_runs_total, delta_TV = wrapped Gaussian TV bound, d = MAC
    polynomial degree, M61 = 2^61-1 (Mersenne prime).

    PROOF SKETCH (hybrid game):

    Define a sequence of N+1 hybrid games:

    Game 0 (Real): Pool recycling. Run i uses run i-1's output as
        MAC/OTP keys.  Run 1 uses PSK-derived keys.

    Game k (1 <= k <= N): First k runs use truly uniform random keys
        (independent of all other randomness). Runs k+1..N use
        pool-recycled keys from previous output.

    Game N (Ideal): All runs use independent truly uniform keys.

    STEP 1 --- Per-run security in Game N (ideal):

        In Game N, each run is independent with truly random keys.
        Eve sees per run: wire_a (B values), wire_b (B values),
        encrypted signs (B bytes), MAC tag (8 bytes).

        - Wire leakage about signs: each wire reveals <= delta_TV about its
          corresponding sign bit. B channels per side, 2 sides -> 2B*delta_TV.
        - OTP encryption: with truly uniform key, reveals nothing.
        - MAC tag: deterministic function of (wires, key). Eve sees wires.
          Tag reveals info about key, not about signs.
        - Per-run confidentiality: eps_conf_run <= 2B*delta_TV
        - Per-run authenticity: eps_auth_run <= d/M61 (polynomial MAC)

    STEP 2 --- Output quality:

        In Game k, run k uses truly random keys. The output (B sign bits)
        has TV distance <= 2B*delta_TV from uniform, conditioned on Eve's
        entire view V_k = (transcripts of runs 1..k).

        Argument: Eve's information about sign bits comes only from wires
        (OTP hides signs, MAC tag depends on wires+key not signs).
        Per-channel TV <= delta_TV, union bound over B channels x 2 sides.

    STEP 3 --- Hybrid transition:

        Game k -> Game k+1: replace run k+1's pool-derived keys with
        truly uniform keys.

        The pool-derived keys are run k's output sign bits (possibly
        processed through pool withdraw/deposit). By Step 2, these are
        2B*delta_TV-close to uniform from Eve's view.

        By the data processing inequality, any function of these bits
        (MAC key derivation, OTP extraction) is also 2B*delta_TV-close to
        the same function of truly uniform bits.

        Therefore: D_TV(Game k, Game k+1) <= 2B*delta_TV

    STEP 4 --- Composition:

        By triangle inequality over N hybrid steps:
        D_TV(Game 0, Game N) <= N * 2B*delta_TV

        Security in Game N (union bound over N runs):
        eps_ideal <= N * (2B*delta_TV + d/M61)

        Total:
        eps_total <= D_TV(Game 0, Game N) + eps_ideal
                  <= N * 2B*delta_TV + N * (2B*delta_TV + d/M61)
                   = N * (4B*delta_TV + d/M61)

    DOMINANT TERM: MAC forgery (d/M61 ~ 10^-15) dominates over
    TV distance (4B*delta_TV ~ 10^-29) by 14 orders of magnitude.

    Security is limited by MAC polynomial degree, not by the
    Gaussian wrapping bound.

    Parameters
    ----------
    sigma_z : float
        Noise standard deviation.
    modulus : float
        Modular arithmetic modulus p.
    B : int
        Number of channels per run.
    n_runs_total : int
        Total number of runs (across all batches).
    n_bits : int
        Quantization bits for MAC coefficient packing (default 4).
    range_sigma : float
        Range in sigma units for quantization (default 4.0).

    Returns
    -------
    dict
        tv_per_channel, mac_degree, eps_tv_per_run, eps_mac_per_run,
        eps_per_run, eps_total, n_runs_total, sigma_over_p, dominant_term.
    """
    tv = wrapped_gaussian_tv_bound(sigma_z, modulus)
    bins_per_pack = 61 // n_bits
    # MAC covers: packed wire bins + B encrypted sign bytes
    mac_degree = math.ceil(2 * B / bins_per_pack) + B
    M61 = (1 << 61) - 1

    eps_tv = 4 * B * tv
    eps_mac = mac_degree / M61
    eps_per_run = eps_tv + eps_mac
    eps_total = n_runs_total * eps_per_run

    return {
        'tv_per_channel': tv,
        'mac_degree': mac_degree,
        'eps_tv_per_run': eps_tv,
        'eps_mac_per_run': eps_mac,
        'eps_per_run': eps_per_run,
        'eps_total': eps_total,
        'n_runs_total': n_runs_total,
        'sigma_over_p': sigma_z / modulus if modulus > 0 else float('inf'),
        'dominant_term': 'mac_forgery' if eps_mac > eps_tv else 'tv_distance',
    }
