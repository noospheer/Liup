#!/usr/bin/env python

r"""Leakage estimation for the Liu protocol.

Provides tools for computing per-exchange and total information leakage
bounds when modular reduction is used.

Two estimation methods are provided:

**Conservative (Pinsker) bound** — ``mutual_information()``

    Computes the statistical distance of the marginal wrapped distribution
    from uniform, then applies Pinsker's inequality.  This is a valid upper
    bound on I(S; W_k) but greatly overestimates leakage because the
    marginal distributions P(W_k|S=+) and P(W_k|S=-) are in fact identical
    (same variance, zero mean).  The Pinsker bound treats distance from
    uniform as a proxy, which inflates early-exchange leakage.

**Tight (conditional JSD) bound** — ``mutual_information_tight()``

    Computes the per-exchange conditional mutual information
    I(S; W_k | W_{k-1}) via numerical integration of the Jensen-Shannon
    divergence between the wrapped Gaussian distributions under the two
    sign hypotheses.  This correctly captures:

    - Exchange 0 leaks nothing (ramp = 0, no sign dependence).
    - Early exchanges leak little (small ramp → small sign-dependent shift).
    - Steady-state exchanges leak little (large M_{k-1} variance → Eve
      can't resolve the shift through mod-p wrapping).

    The total is capped at H(S) = 1 bit (fundamental limit for a binary
    secret).
"""

import math
import numpy as np


def estimate_sigma_z(cutoff):
    """Estimate the standard deviation of band-limited noise Z_k.

    By Parseval's theorem, retaining a fraction 2*cutoff of FFT
    coefficients scales the variance of unit-variance white noise
    by that fraction.

    Parameters
    ----------
    cutoff : float
        The digital cutoff frequency (fraction of Nyquist).

    Returns
    -------
    float
        Estimated standard deviation of Z_k.
    """
    return math.sqrt(2 * cutoff)


def _wrapped_gaussian_pdf(w_grid, mu, sigma, p, j_range):
    """Compute wrapped Gaussian PDF on a grid.

    Parameters
    ----------
    w_grid : ndarray, shape (n,)
        Evaluation points in (-p/2, p/2].
    mu : float or ndarray
        Mean(s) of the unwrapped Gaussian.
    sigma : float
        Standard deviation.
    p : float
        Modulus (period).
    j_range : ndarray, shape (m,)
        Integer wrapping offsets.

    Returns
    -------
    ndarray
        PDF values, same leading shape as mu, last axis = n.
    """
    mu = np.asarray(mu)
    if mu.ndim == 0:
        # scalar mu → shape (n,)
        diff = w_grid[None, :] - mu + j_range[:, None] * p  # (m, n)
        gauss = np.exp(-0.5 * (diff / sigma) ** 2)
        return np.sum(gauss, axis=0) / (sigma * math.sqrt(2 * math.pi))
    else:
        # mu has shape (L,) → result shape (L, n)
        # diff shape: (L, m, n)
        diff = (w_grid[None, None, :]
                - mu[:, None, None]
                + j_range[None, :, None] * p)
        gauss = np.exp(-0.5 * (diff / sigma) ** 2)
        return np.sum(gauss, axis=1) / (sigma * math.sqrt(2 * math.pi))


def _jsd_from_distributions(p_plus, p_minus, dw):
    """Jensen-Shannon divergence (in bits) from two PDF arrays.

    Parameters
    ----------
    p_plus, p_minus : ndarray, shape (..., n)
        PDF values on a grid with spacing dw.
    dw : float
        Grid spacing.

    Returns
    -------
    ndarray, shape (...)
        JSD values in bits.
    """
    eps = 1e-300
    p_avg = 0.5 * (p_plus + p_minus)
    # Use log2 for bits
    log_ratio_plus = np.where(
        p_plus > eps,
        np.log2(np.maximum(p_plus, eps) / np.maximum(p_avg, eps)),
        0.0)
    log_ratio_minus = np.where(
        p_minus > eps,
        np.log2(np.maximum(p_minus, eps) / np.maximum(p_avg, eps)),
        0.0)
    integrand = 0.5 * p_plus * log_ratio_plus + 0.5 * p_minus * log_ratio_minus
    # Integrate over the last axis
    return np.maximum(0.0, np.sum(integrand, axis=-1) * dw)


class LeakageEstimator:
    """Estimate information leakage for the modular Liu protocol.

    Parameters
    ----------
    sigma_z : float
        Standard deviation of the band-limited noise process Z_k.
    alpha : float
        Magnitude of the reflection coefficient.
    ramp_time : float
        Ramp time constant (exponential ramp: 1 - exp(-k/ramp_time)).
    modulus : float
        The modular reduction parameter p.
    number_of_exchanges : int
        Total number of exchanges in one protocol run.
    """

    def __init__(self, sigma_z, alpha, ramp_time, modulus, number_of_exchanges):
        self.sigma_z = sigma_z
        self.alpha = abs(alpha)
        self.ramp_time = ramp_time
        self.modulus = modulus
        self.number_of_exchanges = number_of_exchanges

    def _ramp(self, k):
        """Exponential ramp function at exchange k."""
        return 1.0 - math.exp(-k / self.ramp_time)

    def variance_sequence(self):
        """Compute the variance of M_k for each exchange.

        The recurrence is:
            var_M_0 = sigma_z^2
            var_M_k = sigma_z^2 + (alpha * ramp(k))^2 * var_M_{k-1}

        Returns
        -------
        numpy.ndarray
            Array of length number_of_exchanges with var_M_k values.
        """
        n = self.number_of_exchanges
        var = np.zeros(n)
        sz2 = self.sigma_z ** 2
        var[0] = sz2
        for k in range(1, n):
            ramped_alpha = self.alpha * self._ramp(k)
            var[k] = sz2 + (ramped_alpha ** 2) * var[k - 1]
        return var

    # ------------------------------------------------------------------
    # Conservative (Pinsker) bound — kept for backward compatibility
    # ------------------------------------------------------------------

    def statistical_distance(self):
        """Per-exchange statistical distance from uniform.

        delta_k = 2 * exp(-2 * pi^2 * var_M_k / p^2)

        Returns
        -------
        numpy.ndarray
            Array of delta_k values.
        """
        var = self.variance_sequence()
        p = self.modulus
        return 2.0 * np.exp(-2.0 * math.pi ** 2 * var / (p ** 2))

    def mutual_information(self):
        """Per-exchange upper bound on Eve's MI (conservative Pinsker).

        Uses Pinsker's inequality:
            I_k <= delta_k^2 / (2 * ln 2)

        Note: this overestimates because the marginal distributions
        under both sign hypotheses are identical.

        Returns
        -------
        numpy.ndarray
            Array of MI bounds in bits.
        """
        delta = self.statistical_distance()
        return delta ** 2 / (2.0 * math.log(2))

    def total_eve_information(self):
        """Total Eve info using conservative Pinsker bound (bits).

        Returns
        -------
        float
            Sum of per-exchange MI bounds.
        """
        return float(np.sum(self.mutual_information()))

    # ------------------------------------------------------------------
    # Tight (conditional JSD) bound
    # ------------------------------------------------------------------

    def _per_exchange_conditional_mi(self, k, var_prev,
                                     n_grid=100, n_wraps=3):
        r"""Compute I(S; W_k | W_{k-1}) numerically.

        At exchange k, the current party sends:
            M_k = Z_k + S * |alpha| * ramp(k) * M_{k-1}
        where S = +1 or -1 is the sign hypothesis.

        Eve observes W_k = M_k mod p and already knows W_{k-1}.
        Her posterior on M_{k-1} given W_{k-1} is a discrete set
        {W_{k-1} + j*p} with Gaussian weights.

        The MI is the expected JSD between the wrapped conditional
        distributions under S=+ and S=-.

        Parameters
        ----------
        k : int
            Exchange index.
        var_prev : float
            Variance of M_{k-1}.
        n_grid : int
            Number of quadrature points (default 100).
        n_wraps : int
            Number of wrapping copies on each side (default 3).

        Returns
        -------
        float
            Estimated I(S; W_k | W_{k-1}) in bits.
        """
        p = self.modulus
        sigma_z = self.sigma_z
        alpha = self.alpha
        ramp_k = self._ramp(k)

        if ramp_k < 1e-12 or var_prev < 1e-30:
            return 0.0

        sigma_prev = math.sqrt(var_prev)

        # Evaluation grid for W values
        w_grid = np.linspace(-p / 2, p / 2, n_grid, endpoint=False)
        w_grid += p / (2 * n_grid)  # cell centers
        dw = p / n_grid

        j_range = np.arange(-n_wraps, n_wraps + 1)

        # --- Eve's posterior on M_{k-1} for each w_prev ---
        # M_{k-1} candidates: w_prev + j*p, shape (n_grid, n_j)
        m_cand = w_grid[:, None] + j_range[None, :] * p

        # Log-weights ∝ N(m; 0, var_prev)
        log_w = -0.5 * m_cand ** 2 / var_prev
        log_w -= np.max(log_w, axis=1, keepdims=True)
        weights = np.exp(log_w)
        # P(W_{k-1}) ∝ sum of weights (for weighting the outer integral)
        p_w_prev = np.sum(weights, axis=1)  # (n_grid,)
        # Normalized posterior
        posterior = weights / np.sum(weights, axis=1, keepdims=True)

        # --- Conditional distributions P(W_k | S=±, W_{k-1}) ---
        # Shift: mu = alpha * ramp_k * M_{k-1}
        mu_cand = alpha * ramp_k * m_cand  # (n_grid, n_j)

        # For each (w_prev, j), wrapped Gaussian PDF at all w_grid points
        # Build: diff[i_prev, j_idx, i_w, jj] = w_grid[i_w] - mu ± ... + jj*p
        # Shape: (n_grid_prev, n_j, n_grid_w, n_jj)
        diff_base = (w_grid[None, None, :, None]
                     + j_range[None, None, None, :] * p)  # broadcast-ready
        mu_exp = mu_cand[:, :, None, None]  # (n_prev, n_j, 1, 1)

        diff_plus = diff_base - mu_exp
        diff_minus = diff_base + mu_exp

        inv_2s2 = -0.5 / (sigma_z ** 2)
        norm = 1.0 / (sigma_z * math.sqrt(2 * math.pi))

        wp_plus = np.sum(np.exp(inv_2s2 * diff_plus ** 2), axis=3) * norm
        wp_minus = np.sum(np.exp(inv_2s2 * diff_minus ** 2), axis=3) * norm
        # shapes: (n_prev, n_j, n_grid_w)

        # Marginalize over posterior:
        # p_plus[i_prev, i_w] = Σ_j posterior[i_prev,j] * wp_plus[i_prev,j,i_w]
        p_plus = np.einsum('ij,ijk->ik', posterior, wp_plus)
        p_minus = np.einsum('ij,ijk->ik', posterior, wp_minus)
        # shapes: (n_grid_prev, n_grid_w)

        # JSD per w_prev
        jsd_per_prev = _jsd_from_distributions(p_plus, p_minus, dw)
        # shape: (n_grid_prev,)

        # Weighted average over W_{k-1}
        p_w_prev_norm = p_w_prev / np.sum(p_w_prev)
        return float(np.sum(p_w_prev_norm * jsd_per_prev))

    def mutual_information_tight(self, n_grid=100, n_wraps=3):
        """Per-exchange tight MI via conditional JSD computation.

        Computes I(S; W_k | W_{k-1}) for each exchange k using
        numerical integration of wrapped Gaussian distributions.

        The protocol has two messages per round (Alice and Bob),
        so each round contributes approximately 2x the per-exchange MI.

        Parameters
        ----------
        n_grid : int
            Quadrature grid size (default 100).
        n_wraps : int
            Wrapping copies (default 3).

        Returns
        -------
        numpy.ndarray
            Array of length number_of_exchanges with MI values in bits.
        """
        n = self.number_of_exchanges
        var = self.variance_sequence()
        mi = np.zeros(n)
        # k=0: ramp=0, no sign dependence → MI=0
        for k in range(1, n):
            mi[k] = self._per_exchange_conditional_mi(
                k, var[k - 1], n_grid=n_grid, n_wraps=n_wraps)
        return mi

    def total_eve_information_tight(self, n_grid=100, n_wraps=3):
        """Total Eve info using tight conditional JSD bound (bits).

        Sums per-exchange conditional MI and accounts for both parties'
        messages (factor of 2).  Capped at H(S) = 1 bit since S is
        a single-bit secret.

        Parameters
        ----------
        n_grid : int
            Quadrature grid size (default 100).
        n_wraps : int
            Wrapping copies (default 3).

        Returns
        -------
        float
            Upper bound on I(S; all wire values) in bits.
        """
        mi = self.mutual_information_tight(n_grid=n_grid, n_wraps=n_wraps)
        # Factor of 2 for both Alice's and Bob's messages per round
        raw_total = 2.0 * float(np.sum(mi))
        # Cap at 1 bit (binary secret)
        return min(raw_total, 1.0)

    # ------------------------------------------------------------------
    # Monte Carlo MI estimation via log-likelihood ratios
    # ------------------------------------------------------------------

    def _wire_log_likelihood(self, wire, sign, n_wraps=3):
        """Compute log P(wire | S=sign) using pairwise approximation.

        For each consecutive pair (w_{k-1}, w_k), compute:
            P(w_k | w_{k-1}, S) = Σ_j posterior(j|w_{k-1}) ·
                wrapped_Gaussian(w_k; sign·α·ramp(k)·(w_{k-1}+j·p), σ_z, p)

        Parameters
        ----------
        wire : ndarray
            Sequence of mod-p wire values.
        sign : float
            +1 or -1 for the sign hypothesis.
        n_wraps : int
            Wrapping copies.

        Returns
        -------
        float
            Log-likelihood.
        """
        p = self.modulus
        sigma_z = self.sigma_z
        alpha = self.alpha
        j_range = np.arange(-n_wraps, n_wraps + 1)
        n = len(wire)
        var = self.variance_sequence()

        ll = 0.0
        for k in range(n):
            ramp_k = self._ramp(k)
            w_k = wire[k]

            if k == 0 or ramp_k < 1e-12:
                # No sign dependence: P(w_k) = wrapped N(0, sigma_z, p)
                vals = np.exp(-0.5 * ((w_k + j_range * p) / sigma_z) ** 2)
                pdf = np.sum(vals) / (sigma_z * math.sqrt(2 * math.pi))
            else:
                w_prev = wire[k - 1]
                var_prev = var[k - 1] if k - 1 < len(var) else var[-1]
                sigma_prev = math.sqrt(max(var_prev, 1e-30))

                # Posterior on M_{k-1}: candidates w_prev + j*p
                m_cand = w_prev + j_range * p
                log_w = -0.5 * m_cand ** 2 / max(var_prev, 1e-30)
                log_w -= np.max(log_w)
                weights = np.exp(log_w)
                weights /= np.sum(weights)

                # P(w_k | w_{k-1}, S) = Σ_j weight_j * wrapped_N(w_k; sign*α*r*m_j, σ_z)
                pdf = 0.0
                for m, wt in zip(m_cand, weights):
                    if wt < 1e-15:
                        continue
                    mu = sign * alpha * ramp_k * m
                    vals = np.exp(
                        -0.5 * ((w_k - mu + j_range * p) / sigma_z) ** 2)
                    pdf += wt * np.sum(vals) / (
                        sigma_z * math.sqrt(2 * math.pi))

            ll += math.log(max(pdf, 1e-300))

        return ll

    def _party_log_likelihood(self, wire_own, wire_other, sign,
                              own_exchange_indices, n_wraps=3):
        """Log-likelihood of one party's wire values given sign hypothesis.

        Parameters
        ----------
        wire_own : ndarray
            This party's mod-p wire values.
        wire_other : ndarray
            Other party's mod-p wire values (what this party received).
        sign : float
            +1 or -1 for this party's alpha sign.
        own_exchange_indices : ndarray of int
            The exchange index k for each of this party's messages.
        n_wraps : int

        Returns
        -------
        float
            Log-likelihood.
        """
        p = self.modulus
        sigma_z = self.sigma_z
        alpha = self.alpha
        j_range = np.arange(-n_wraps, n_wraps + 1)
        var = self.variance_sequence()

        ll = 0.0
        for idx in range(len(wire_own)):
            k = own_exchange_indices[idx]
            ramp_k = self._ramp(k)
            w = wire_own[idx]

            if k == 0 or ramp_k < 1e-12:
                vals = np.exp(-0.5 * ((w + j_range * p) / sigma_z) ** 2)
                pdf = np.sum(vals) / (sigma_z * math.sqrt(2 * math.pi))
            else:
                # The other party's previous wire value
                w_prev = wire_other[idx - 1] if idx > 0 else 0.0
                # Use the other party's variance at the previous exchange
                k_prev = own_exchange_indices[idx - 1] if idx > 0 else 0
                var_prev = var[min(k_prev, len(var) - 1)]
                sigma_prev = math.sqrt(max(var_prev, 1e-30))

                m_cand = w_prev + j_range * p
                log_w = -0.5 * m_cand ** 2 / max(var_prev, 1e-30)
                log_w -= np.max(log_w)
                weights = np.exp(log_w)
                weights /= np.sum(weights)

                pdf = 0.0
                for m, wt in zip(m_cand, weights):
                    if wt < 1e-15:
                        continue
                    mu = sign * alpha * ramp_k * m
                    vals = np.exp(
                        -0.5 * ((w - mu + j_range * p) / sigma_z) ** 2)
                    pdf += wt * np.sum(vals) / (
                        sigma_z * math.sqrt(2 * math.pi))

            ll += math.log(max(pdf, 1e-300))

        return ll

    def estimate_mi_monte_carlo(self, n_samples=500, seed=None, n_wraps=3):
        r"""Estimate I(S; wire) via Monte Carlo log-likelihood ratios.

        Simulates the full two-party alternating protocol and computes
        Eve's MI about the product sign S = sign(α_A · α_B).

        The correct likelihood for S marginalizes over individual signs:
            P(wire|S=+) = 0.5·L_A(+)·L_B(+) + 0.5·L_A(-)·L_B(-)
            P(wire|S=-) = 0.5·L_A(+)·L_B(-) + 0.5·L_A(-)·L_B(+)

        The protocol alternation is:
            Alice(0), Bob(0), Alice(1), Bob(1), ..., Alice(n)
        where Bob(i) responds to Alice(i) and Alice(i+1) responds to Bob(i).

        Parameters
        ----------
        n_samples : int
            Number of simulated protocol runs (default 500).
        seed : int or None
            Random seed for reproducibility.
        n_wraps : int
            Wrapping copies for likelihood computation.

        Returns
        -------
        float
            Estimated MI in bits.
        """
        rng = np.random.default_rng(seed)
        p = self.modulus
        n = self.number_of_exchanges
        alpha = self.alpha
        sigma_z = self.sigma_z
        j_range = np.arange(-n_wraps, n_wraps + 1)
        inv_norm = 1.0 / (sigma_z * math.sqrt(2 * math.pi))

        # Precompute exact per-party variances
        # Alice sends n+1 messages (exchanges 0..n)
        # Bob sends n messages (exchanges 0..n-1)
        var_A = np.zeros(n + 1)
        var_B = np.zeros(n)
        var_A[0] = sigma_z ** 2
        for i in range(n):
            ramp_i = self._ramp(i)
            var_B[i] = sigma_z ** 2 + (alpha * ramp_i) ** 2 * var_A[i]
            ramp_ip1 = self._ramp(i + 1)
            var_A[i + 1] = sigma_z ** 2 + (alpha * ramp_ip1) ** 2 * var_B[i]

        def _transition_ll(w_sent, w_recv, sign, ramp_k, var_recv):
            """Log P(w_sent | w_recv, sign) for one transition."""
            if ramp_k < 1e-12:
                vals = np.exp(-0.5 * ((w_sent + j_range * p) / sigma_z) ** 2)
                pdf = np.sum(vals) * inv_norm
                return math.log(max(pdf, 1e-300))

            # Posterior on M_recv: candidates w_recv + j*p
            m_cand = w_recv + j_range * p
            log_w = -0.5 * m_cand ** 2 / max(var_recv, 1e-30)
            log_w -= np.max(log_w)
            weights = np.exp(log_w)
            weights /= np.sum(weights)

            pdf = 0.0
            for m_val, wt in zip(m_cand, weights):
                if wt < 1e-15:
                    continue
                mu = sign * alpha * ramp_k * m_val
                vals = np.exp(
                    -0.5 * ((w_sent - mu + j_range * p) / sigma_z) ** 2)
                pdf += wt * np.sum(vals) * inv_norm

            return math.log(max(pdf, 1e-300))

        def _logsumexp(a, b):
            mx = max(a, b)
            return mx + math.log(math.exp(a - mx) + math.exp(b - mx))

        mi_samples = []

        for _ in range(n_samples):
            # Choose true individual signs
            sign_A = 1.0 if rng.random() < 0.5 else -1.0
            sign_B = 1.0 if rng.random() < 0.5 else -1.0
            true_S = sign_A * sign_B > 0  # True if product positive

            # Simulate alternating protocol
            wire_A = []
            wire_B = []
            M_A_real = []
            M_B_real = []

            # Alice exchange 0: M = Z (ramp(0)=0)
            Z = sigma_z * rng.standard_normal()
            M = Z
            wire_A.append(M - p * round(M / p))
            M_A_real.append(M)

            for i in range(n):
                # Bob exchange i: responds to Alice exchange i
                Z = sigma_z * rng.standard_normal()
                ramp_k = self._ramp(i)
                M = Z + sign_B * alpha * ramp_k * M_A_real[-1]
                wire_B.append(M - p * round(M / p))
                M_B_real.append(M)

                # Alice exchange i+1: responds to Bob exchange i
                Z = sigma_z * rng.standard_normal()
                ramp_k = self._ramp(i + 1)
                M = Z + sign_A * alpha * ramp_k * M_B_real[-1]
                wire_A.append(M - p * round(M / p))
                M_A_real.append(M)

            # Compute per-party log-likelihoods with correct indexing
            #
            # L_A(signA) = P(wA[0]) * prod_{i=0}^{n-1} P(wA[i+1] | wB[i], signA)
            #   Alice exchange i+1 responds to Bob exchange i
            #   Variance of Bob's exchange i = var_B[i]
            #   Ramp at Alice's exchange i+1 = ramp(i+1)
            #
            # L_B(signB) = prod_{i=0}^{n-1} P(wB[i] | wA[i], signB)
            #   Bob exchange i responds to Alice exchange i
            #   Variance of Alice's exchange i = var_A[i]
            #   Ramp at Bob's exchange i = ramp(i)

            # Alice log-likelihoods
            # Exchange 0: unconditional (same for both signs)
            ll0 = _transition_ll(wire_A[0], 0.0, +1.0, 0.0, sigma_z ** 2)
            ll_A_plus = ll0
            ll_A_minus = ll0
            for i in range(n):
                # Alice exchange i+1 responds to Bob exchange i
                r = self._ramp(i + 1)
                ll_A_plus += _transition_ll(
                    wire_A[i + 1], wire_B[i], +1.0, r, var_B[i])
                ll_A_minus += _transition_ll(
                    wire_A[i + 1], wire_B[i], -1.0, r, var_B[i])

            # Bob log-likelihoods
            ll_B_plus = 0.0
            ll_B_minus = 0.0
            for i in range(n):
                # Bob exchange i responds to Alice exchange i
                r = self._ramp(i)
                ll_B_plus += _transition_ll(
                    wire_B[i], wire_A[i], +1.0, r, var_A[i])
                ll_B_minus += _transition_ll(
                    wire_B[i], wire_A[i], -1.0, r, var_A[i])

            # Product sign mixture model
            log_joint_pp = ll_A_plus + ll_B_plus
            log_joint_mm = ll_A_minus + ll_B_minus
            log_joint_pm = ll_A_plus + ll_B_minus
            log_joint_mp = ll_A_minus + ll_B_plus

            log_p_S_plus = math.log(0.5) + _logsumexp(log_joint_pp,
                                                        log_joint_mm)
            log_p_S_minus = math.log(0.5) + _logsumexp(log_joint_pm,
                                                         log_joint_mp)

            if true_S:
                log_p_true = log_p_S_plus
            else:
                log_p_true = log_p_S_minus

            log_p_avg = _logsumexp(log_p_S_plus, log_p_S_minus) - math.log(2)
            mi_sample = (log_p_true - log_p_avg) / math.log(2)
            mi_samples.append(mi_sample)

        mi_est = float(np.mean(mi_samples))
        return max(0.0, mi_est)

    # ------------------------------------------------------------------
    # Rigorous MI bound via full HMM forward algorithm
    # ------------------------------------------------------------------

    def _forward_log_likelihood(self, wire_A, wire_B, s_A, s_B, n_wraps=5):
        r"""Compute log P(wire_A, wire_B | s_A, s_B) via exact HMM forward.

        Unlike the pairwise approximation, this tracks the full posterior
        on the hidden state M_{k-1} through all observations using the
        forward recursion.  The posterior at step k is a discrete
        distribution on lattice points {W_k + j·p : j ∈ Z}, truncated
        to |j| ≤ n_wraps.

        **TCP security note:** The wire values ``wire_A`` and ``wire_B``
        are the mod-p wrapped values that go over TCP (see
        ``endpoint.Physics.exchange()`` which applies ``_mod_reduce``
        before returning).  Therefore this function computes exactly the
        likelihoods an optimal TCP eavesdropper would use.

        The protocol alternation is:
            Alice(0) → Bob(0) → Alice(1) → Bob(1) → ... → Alice(n)

        At each step, the transition is:
            M_new = Z + s_sender · |α| · ramp(k) · M_prev
            W_new = M_new mod p

        Parameters
        ----------
        wire_A : array-like, length n+1
            Alice's wire values.
        wire_B : array-like, length n
            Bob's wire values.
        s_A, s_B : float
            Sign hypotheses (+1 or -1).
        n_wraps : int
            Lattice truncation (default 5).

        Returns
        -------
        float
            log P(wire_A, wire_B | s_A, s_B).
        """
        p = self.modulus
        sigma_z = self.sigma_z
        alpha = self.alpha
        j_range = np.arange(-n_wraps, n_wraps + 1)
        nj = len(j_range)
        inv_norm = 1.0 / (sigma_z * math.sqrt(2 * math.pi))
        n = len(wire_B)

        ll = 0.0

        # --- Alice exchange 0: M_A0 = Z_A0 (ramp=0, no coupling) ---
        w0 = wire_A[0]
        gauss = np.exp(-0.5 * ((w0 + j_range * p) / sigma_z) ** 2)
        pdf_0 = float(np.sum(gauss)) * inv_norm
        ll += math.log(max(pdf_0, 1e-300))

        # Posterior on M_A0: lattice {w0 + j·p}, prior N(0, σ_Z²)
        m_cand = w0 + j_range * p
        log_wt = -0.5 * m_cand ** 2 / sigma_z ** 2
        log_wt -= np.max(log_wt)
        fwd = np.exp(log_wt)
        fwd /= np.sum(fwd)
        fwd_wire = w0

        for i in range(n):
            # --- Bob exchange i: responds to Alice exchange i ---
            rk = self._ramp(i)
            w = wire_B[i]
            m_prev = fwd_wire + j_range * p          # (nj,)
            mu = s_B * alpha * rk * m_prev            # (nj,)
            new_lat = w + j_range * p                 # (nj,)
            diff = new_lat[None, :] - mu[:, None]     # (nj, nj)
            trans = np.exp(-0.5 * (diff / sigma_z) ** 2) * inv_norm

            # Likelihood: Σ_j fwd[j] · wrapped_gauss(w; mu[j])
            pdf = float(np.dot(fwd, np.sum(trans, axis=1)))
            ll += math.log(max(pdf, 1e-300))

            # Update forward posterior on M_B[i]
            new_fwd = np.dot(fwd, trans)
            s = np.sum(new_fwd)
            fwd = new_fwd / s if s > 0 else np.ones(nj) / nj
            fwd_wire = w

            # --- Alice exchange i+1: responds to Bob exchange i ---
            rk = self._ramp(i + 1)
            w = wire_A[i + 1]
            m_prev = fwd_wire + j_range * p
            mu = s_A * alpha * rk * m_prev
            new_lat = w + j_range * p
            diff = new_lat[None, :] - mu[:, None]
            trans = np.exp(-0.5 * (diff / sigma_z) ** 2) * inv_norm

            pdf = float(np.dot(fwd, np.sum(trans, axis=1)))
            ll += math.log(max(pdf, 1e-300))

            new_fwd = np.dot(fwd, trans)
            s = np.sum(new_fwd)
            fwd = new_fwd / s if s > 0 else np.ones(nj) / nj
            fwd_wire = w

        return ll

    def estimate_mi_rigorous(self, n_samples=500, seed=42, n_wraps=5,
                             confidence=0.99):
        r"""Rigorous upper bound on I(S; W) with statistical confidence.

        Combines the full HMM forward algorithm (exact posterior tracking)
        with a one-sided Hoeffding concentration bound.

        **Theorem (rigorous MI bound):**

        Let X_i = max(0, log_2(P(W_i|S_i) / P_avg(W_i))) be the clipped
        MI sample from run i.  Then:

        1. E[X_i] ≥ I(S; W)  (clipping only adds positive bias)
        2. X_i ∈ [0, 1]      (MI of a binary variable ≤ 1 bit)
        3. By Hoeffding: P(X̄_n > E[X_i] + t) ≤ exp(-2nt²)

        Setting t = √(ln(1/δ)/(2n)) with δ = 1 - confidence:

            I(S; W) ≤ E[X_i] ≤ X̄_n + t   with probability ≥ 1 - δ

        The bound is valid because E[X_i] ≥ I(S;W), so any upper bound
        on E[X_i] is also an upper bound on I(S;W).

        Parameters
        ----------
        n_samples : int
            Monte Carlo sample size (default 500).
        seed : int
            Random seed.
        n_wraps : int
            Lattice truncation.
        confidence : float
            Confidence level (default 0.99).

        Returns
        -------
        dict
            'mi_estimate': point estimate of I(S;W),
            'mi_upper_bound': rigorous upper bound at given confidence,
            'confidence': the confidence level,
            'n_samples': sample count,
            'hoeffding_correction': the additive correction term.
        """
        rng = np.random.default_rng(seed)
        p = self.modulus
        n = self.number_of_exchanges
        alpha = self.alpha
        sigma_z = self.sigma_z
        delta = 1.0 - confidence

        def _logsumexp(a, b):
            mx = max(a, b)
            return mx + math.log(math.exp(a - mx) + math.exp(b - mx))

        mi_samples = []

        for _ in range(n_samples):
            s_A = 1.0 if rng.random() < 0.5 else -1.0
            s_B = 1.0 if rng.random() < 0.5 else -1.0
            true_S_pos = (s_A * s_B > 0)

            # Simulate protocol
            wire_A = []
            wire_B = []
            M_A_real = []
            M_B_real = []

            Z = sigma_z * rng.standard_normal()
            M = Z
            wire_A.append(M - p * round(M / p))
            M_A_real.append(M)

            for i in range(n):
                Z = sigma_z * rng.standard_normal()
                rk = self._ramp(i)
                M = Z + s_B * alpha * rk * M_A_real[-1]
                wire_B.append(M - p * round(M / p))
                M_B_real.append(M)

                Z = sigma_z * rng.standard_normal()
                rk = self._ramp(i + 1)
                M = Z + s_A * alpha * rk * M_B_real[-1]
                wire_A.append(M - p * round(M / p))
                M_A_real.append(M)

            # Full forward log-likelihoods for all 4 sign configs
            ll_pp = self._forward_log_likelihood(
                wire_A, wire_B, +1, +1, n_wraps)
            ll_mm = self._forward_log_likelihood(
                wire_A, wire_B, -1, -1, n_wraps)
            ll_pm = self._forward_log_likelihood(
                wire_A, wire_B, +1, -1, n_wraps)
            ll_mp = self._forward_log_likelihood(
                wire_A, wire_B, -1, +1, n_wraps)

            log_p_S_plus = math.log(0.5) + _logsumexp(ll_pp, ll_mm)
            log_p_S_minus = math.log(0.5) + _logsumexp(ll_pm, ll_mp)

            log_p_true = log_p_S_plus if true_S_pos else log_p_S_minus
            log_p_avg = _logsumexp(log_p_S_plus, log_p_S_minus) \
                - math.log(2)

            # Clipped MI sample: max(0, ...) ensures [0, 1] range
            mi_sample = max(0.0, (log_p_true - log_p_avg) / math.log(2))
            mi_samples.append(mi_sample)

        mi_est = float(np.mean(mi_samples))
        # Hoeffding one-sided bound: P(X_bar > E[X] + t) ≤ exp(-2nt^2)
        # Solving exp(-2nt^2) = delta: t = sqrt(ln(1/delta) / (2n))
        hoeffding_t = math.sqrt(math.log(1.0 / delta) / (2 * n_samples))
        mi_upper = min(1.0, mi_est + hoeffding_t)

        return {
            'mi_estimate': mi_est,
            'mi_upper_bound': mi_upper,
            'confidence': confidence,
            'n_samples': n_samples,
            'hoeffding_correction': hoeffding_t,
        }

    # ------------------------------------------------------------------
    # Rigorous min-entropy bound via HMM forward + Hoeffding
    # ------------------------------------------------------------------

    def estimate_hmin_rigorous(self, n_samples=500, seed=42, n_wraps=5,
                                confidence=0.99):
        r"""Rigorous min-entropy bound via HMM forward + Hoeffding.

        This is the **correct** input for the Leftover Hash Lemma, which
        requires min-entropy (not Shannon MI).

        **TCP eavesdropper model:** The analysis uses wrapped (mod-p)
        wire values, which are exactly what a TCP eavesdropper observes.
        This is because ``endpoint.Physics.exchange()`` applies
        ``_mod_reduce`` before returning values for transmission.
        The unwrapped real-valued signal never leaves the endpoint.

        **Theorem (Rigorous Min-Entropy Bound).**

        The proof chain has six steps, each with a clean theorem:

        1.  **Exact HMM forward** — ``_forward_log_likelihood`` computes
            exact ``\log P(W | s_A, s_B)`` by tracking the full posterior
            on the lattice ``\{W_k + j \cdot p\}``.  No approximations
            beyond lattice truncation (controlled by ``n_wraps``).

        2.  **Product-sign marginalisation** —

            .. math::

                P(W | S{=}+) = \tfrac{1}{2}[P(W|{+}{+}) + P(W|{-}{-})]

            .. math::

                P(W | S{=}-) = \tfrac{1}{2}[P(W|{+}{-}) + P(W|{-}{+})]

        3.  **Guessing probability** — For each simulated run:

            .. math::

                P_{\mathrm{guess}}(W)
                = \max\bigl(P(S{=}+|W),\; P(S{=}-|W)\bigr)
                \in [0.5,\, 1]

            This is computable from the likelihoods via Bayes' rule.

        4.  **Hoeffding concentration** — Since
            ``P_{\mathrm{guess}} \in [0.5, 1]`` (range ``= 0.5``):

            .. math::

                P\bigl(\bar{X}_n > E[P_{\mathrm{guess}}] + t\bigr)
                \le \exp(-8 n t^2)

            Setting ``\exp(-8 n t^2) = \delta``:

            .. math::

                t = \sqrt{\ln(1/\delta) / (8n)}

            So ``E[P_{\mathrm{guess}}] \le \bar{X}_n + t`` with
            probability ``\ge 1 - \delta``.

        5.  **Min-entropy** — By definition:

            .. math::

                H_{\min}(S | W)
                = -\log_2 E_W[P_{\mathrm{guess}}(W)]
                \ge -\log_2(\bar{X}_n + t)

        6.  **IID composition** — For ``n_{\mathrm{raw}}`` independent
            protocol runs:

            .. math::

                H_{\min}(K | W_{\mathrm{all}})
                = n_{\mathrm{raw}} \cdot H_{\min}(S | W)

            (Min-entropy is additive for independent variables.)

        Every step is a proven theorem.  No convexity-over-posteriors
        arguments, no coupling, no Shannon-to-min-entropy conversion.
        The HMM forward absorbs all posterior-divergence effects
        automatically because it tracks the exact posterior.

        Parameters
        ----------
        n_samples : int
            Monte Carlo sample size (default 500).
        seed : int
            Random seed.
        n_wraps : int
            Lattice truncation (default 5).
        confidence : float
            Confidence level (default 0.99).

        Returns
        -------
        dict
            'h_min': rigorous lower bound on H_min(S|W) per run,
            'pguess_mean': sample mean of P_guess,
            'pguess_upper_bound': Hoeffding upper bound on E[P_guess],
            'hoeffding_correction': additive correction t,
            'confidence': confidence level,
            'n_samples': sample count.
        """
        rng = np.random.default_rng(seed)
        p = self.modulus
        n = self.number_of_exchanges
        alpha = self.alpha
        sigma_z = self.sigma_z
        delta = 1.0 - confidence

        def _logsumexp(a, b):
            mx = max(a, b)
            return mx + math.log(math.exp(a - mx) + math.exp(b - mx))

        pguess_samples = []

        for _ in range(n_samples):
            s_A = 1.0 if rng.random() < 0.5 else -1.0
            s_B = 1.0 if rng.random() < 0.5 else -1.0

            # Simulate protocol
            wire_A = []
            wire_B = []
            M_A_real = []
            M_B_real = []

            Z = sigma_z * rng.standard_normal()
            M = Z
            wire_A.append(M - p * round(M / p))
            M_A_real.append(M)

            for i in range(n):
                Z = sigma_z * rng.standard_normal()
                rk = self._ramp(i)
                M = Z + s_B * alpha * rk * M_A_real[-1]
                wire_B.append(M - p * round(M / p))
                M_B_real.append(M)

                Z = sigma_z * rng.standard_normal()
                rk = self._ramp(i + 1)
                M = Z + s_A * alpha * rk * M_B_real[-1]
                wire_A.append(M - p * round(M / p))
                M_A_real.append(M)

            # Full forward log-likelihoods for all 4 sign configs
            ll_pp = self._forward_log_likelihood(
                wire_A, wire_B, +1, +1, n_wraps)
            ll_mm = self._forward_log_likelihood(
                wire_A, wire_B, -1, -1, n_wraps)
            ll_pm = self._forward_log_likelihood(
                wire_A, wire_B, +1, -1, n_wraps)
            ll_mp = self._forward_log_likelihood(
                wire_A, wire_B, -1, +1, n_wraps)

            # Product-sign marginals
            log_p_S_plus = math.log(0.5) + _logsumexp(ll_pp, ll_mm)
            log_p_S_minus = math.log(0.5) + _logsumexp(ll_pm, ll_mp)

            # P_guess = max(P(S=+|W), P(S=-|W))
            # P(S=+|W) = P(W,S=+) / P(W) = exp(log_p_S_plus) / evidence
            log_evidence = _logsumexp(log_p_S_plus, log_p_S_minus)
            p_plus = math.exp(log_p_S_plus - log_evidence)
            p_minus = math.exp(log_p_S_minus - log_evidence)
            p_guess = max(p_plus, p_minus)  # in [0.5, 1]
            pguess_samples.append(p_guess)

        mean_pguess = float(np.mean(pguess_samples))

        # Hoeffding one-sided bound: P_guess in [0.5, 1], range = 0.5
        # P(mean > E[P_guess] + t) ≤ exp(-2n·t²/0.25) = exp(-8n·t²)
        # Solving exp(-8nt²) = delta: t = sqrt(ln(1/delta) / (8n))
        hoeffding_t = math.sqrt(math.log(1.0 / delta) / (8 * n_samples))
        pguess_upper = min(1.0, mean_pguess + hoeffding_t)

        h_min = -math.log2(pguess_upper) if pguess_upper < 1.0 else 0.0

        return {
            'h_min': h_min,
            'pguess_mean': mean_pguess,
            'pguess_upper_bound': pguess_upper,
            'hoeffding_correction': hoeffding_t,
            'confidence': confidence,
            'n_samples': n_samples,
        }

    # ------------------------------------------------------------------
    # Unwrapped P_guess for comparison (quantifies wrapping advantage)
    # ------------------------------------------------------------------

    def estimate_pguess_unwrapped(self, n_samples=500, seed=42):
        r"""Estimate P_guess assuming Eve sees unwrapped (real-valued) wire values.

        This serves as a comparison tool to quantify how much security
        the modular wrapping provides.  Without wrapping, each wire value
        ``M_k`` given ``M_{k-1}`` and the sign config is simply
        ``N(s · α · ramp(k) · M_{k-1}, σ_z²)``.  Eve's likelihood is a
        product of Gaussian PDFs — no lattice summation needed.

        Returns a dict comparing wrapped (HMM-based) and unwrapped
        guessing probabilities.

        Parameters
        ----------
        n_samples : int
            Monte Carlo sample size (default 500).
        seed : int
            Random seed.

        Returns
        -------
        dict
            'pguess_mean_unwrapped': mean P_guess without wrapping,
            'pguess_mean_wrapped': mean P_guess with wrapping (from HMM),
            'wrapping_advantage': ratio pguess_unwrapped / pguess_wrapped
                (>= 1 if wrapping helps security).
        """
        rng = np.random.default_rng(seed)
        p = self.modulus
        n = self.number_of_exchanges
        alpha = self.alpha
        sigma_z = self.sigma_z

        def _logsumexp(a, b):
            mx = max(a, b)
            return mx + math.log(math.exp(a - mx) + math.exp(b - mx))

        pguess_unwrapped_samples = []
        pguess_wrapped_samples = []

        for _ in range(n_samples):
            s_A = 1.0 if rng.random() < 0.5 else -1.0
            s_B = 1.0 if rng.random() < 0.5 else -1.0

            # Simulate protocol (store both real and wrapped values)
            wire_A = []
            wire_B = []
            M_A_real = []
            M_B_real = []

            Z = sigma_z * rng.standard_normal()
            M = Z
            wire_A.append(M - p * round(M / p))
            M_A_real.append(M)

            for i in range(n):
                Z = sigma_z * rng.standard_normal()
                rk = self._ramp(i)
                M = Z + s_B * alpha * rk * M_A_real[-1]
                wire_B.append(M - p * round(M / p))
                M_B_real.append(M)

                Z = sigma_z * rng.standard_normal()
                rk = self._ramp(i + 1)
                M = Z + s_A * alpha * rk * M_B_real[-1]
                wire_A.append(M - p * round(M / p))
                M_A_real.append(M)

            # --- Unwrapped likelihoods (simple Gaussian) ---
            def _unwrapped_ll(real_A, real_B, sA, sB):
                ll = 0.0
                # Alice exchange 0: N(0, sigma_z²)
                ll += -0.5 * (real_A[0] / sigma_z) ** 2 \
                      - math.log(sigma_z * math.sqrt(2 * math.pi))
                for i in range(n):
                    # Bob exchange i: N(sB*alpha*ramp(i)*real_A[i], sigma_z²)
                    rk = self._ramp(i)
                    mu = sB * alpha * rk * real_A[i]
                    diff = real_B[i] - mu
                    ll += -0.5 * (diff / sigma_z) ** 2 \
                          - math.log(sigma_z * math.sqrt(2 * math.pi))
                    # Alice exchange i+1: N(sA*alpha*ramp(i+1)*real_B[i], sigma_z²)
                    rk = self._ramp(i + 1)
                    mu = sA * alpha * rk * real_B[i]
                    diff = real_A[i + 1] - mu
                    ll += -0.5 * (diff / sigma_z) ** 2 \
                          - math.log(sigma_z * math.sqrt(2 * math.pi))
                return ll

            ull_pp = _unwrapped_ll(M_A_real, M_B_real, +1, +1)
            ull_mm = _unwrapped_ll(M_A_real, M_B_real, -1, -1)
            ull_pm = _unwrapped_ll(M_A_real, M_B_real, +1, -1)
            ull_mp = _unwrapped_ll(M_A_real, M_B_real, -1, +1)

            ulog_S_plus = math.log(0.5) + _logsumexp(ull_pp, ull_mm)
            ulog_S_minus = math.log(0.5) + _logsumexp(ull_pm, ull_mp)
            ulog_ev = _logsumexp(ulog_S_plus, ulog_S_minus)
            up_plus = math.exp(ulog_S_plus - ulog_ev)
            up_minus = math.exp(ulog_S_minus - ulog_ev)
            pguess_unwrapped_samples.append(max(up_plus, up_minus))

            # --- Wrapped likelihoods (HMM forward) ---
            ll_pp = self._forward_log_likelihood(wire_A, wire_B, +1, +1)
            ll_mm = self._forward_log_likelihood(wire_A, wire_B, -1, -1)
            ll_pm = self._forward_log_likelihood(wire_A, wire_B, +1, -1)
            ll_mp = self._forward_log_likelihood(wire_A, wire_B, -1, +1)

            wlog_S_plus = math.log(0.5) + _logsumexp(ll_pp, ll_mm)
            wlog_S_minus = math.log(0.5) + _logsumexp(ll_pm, ll_mp)
            wlog_ev = _logsumexp(wlog_S_plus, wlog_S_minus)
            wp_plus = math.exp(wlog_S_plus - wlog_ev)
            wp_minus = math.exp(wlog_S_minus - wlog_ev)
            pguess_wrapped_samples.append(max(wp_plus, wp_minus))

        mean_unwrapped = float(np.mean(pguess_unwrapped_samples))
        mean_wrapped = float(np.mean(pguess_wrapped_samples))
        advantage = mean_unwrapped / mean_wrapped if mean_wrapped > 0 else float('inf')

        return {
            'pguess_mean_unwrapped': mean_unwrapped,
            'pguess_mean_wrapped': mean_wrapped,
            'wrapping_advantage': advantage,
        }

    # ------------------------------------------------------------------
    # Analytic MI bound via Fourier analysis (CONJECTURAL — see warning)
    # ------------------------------------------------------------------

    @staticmethod
    def _binary_entropy(p):
        """Binary entropy H_b(p) in bits."""
        if p <= 0 or p >= 1:
            return 0.0
        return -p * math.log2(p) - (1 - p) * math.log2(1 - p)

    @staticmethod
    def wrapped_gaussian_tv_bound(sigma, p, n_fourier=50):
        r"""Proven upper bound on TV distance between wrapped Gaussians.

        **Lemma (Wrapped Gaussian TV Bound).**

        For two wrapped Gaussian distributions on ``(-p/2, p/2]`` with
        means ``+\mu`` and ``-\mu`` and common variance ``\sigma^2``:

        .. math::

            \mathrm{TV}(f_+, f_-) \le \frac{4}{\pi}
            \sum_{n=1}^{\infty} e^{-2\pi^2 n^2 \sigma^2 / p^2}

        **Proof.**

        The wrapped Gaussian PDF is:

        .. math::

            f_{\pm}(w) = \frac{1}{p}\Bigl[1 + 2\sum_{n \ge 1}
            e^{-2\pi^2 n^2 \sigma^2/p^2}
            \cos\bigl(\tfrac{2\pi n(w \mp \mu)}{p}\bigr)\Bigr]

        The difference is:

        .. math::

            f_+(w) - f_-(w) = \frac{4}{p}\sum_{n \ge 1}
            e^{-2\pi^2 n^2 \sigma^2/p^2}
            \sin\bigl(\tfrac{2\pi n w}{p}\bigr)
            \sin\bigl(\tfrac{2\pi n \mu}{p}\bigr)

        Taking absolute values and using
        ``|\sin(2\pi n\mu/p)| \le 1``:

        .. math::

            |f_+(w) - f_-(w)| \le \frac{4}{p}\sum_{n \ge 1}
            e^{-2\pi^2 n^2 \sigma^2/p^2}
            \bigl|\sin\bigl(\tfrac{2\pi n w}{p}\bigr)\bigr|

        Integrating over ``(-p/2, p/2]``:

        .. math::

            \int_{-p/2}^{p/2}
            \bigl|\sin\bigl(\tfrac{2\pi n w}{p}\bigr)\bigr|\,dw
            = \frac{2p}{\pi} \quad \forall\, n \ge 1

        (Each of the ``n`` complete half-periods contributes
        ``p/(n\pi)``; summing gives ``2p/\pi``.)

        Therefore:

        .. math::

            \mathrm{TV} = \tfrac{1}{2}\|f_+ - f_-\|_1
            \le \frac{4}{\pi}\sum_{n=1}^{\infty}
            e^{-2\pi^2 n^2 \sigma^2 / p^2} \qquad\square

        Note: this bound is **independent of** ``\mu``.  It holds for
        ANY shift, and therefore for ANY Eve posterior on ``M_{k-1}``.

        Parameters
        ----------
        sigma : float
            Standard deviation of the Gaussian noise.
        p : float
            Modulus (period).
        n_fourier : int
            Number of Fourier terms to sum (default 50).

        Returns
        -------
        float
            Upper bound on TV(f_+, f_-).
        """
        ratio = sigma / p
        total = 0.0
        for n in range(1, n_fourier + 1):
            term = math.exp(-2 * math.pi ** 2 * n ** 2 * ratio ** 2)
            if term < 1e-15:
                break
            total += term
        return min(1.0, (4.0 / math.pi) * total)

    def analytic_mi_bound(self):
        r"""Proven deterministic upper bound on I(S; W).

        **Theorem (Analytic MI Bound for the Liu Protocol).**

        Let the Liu protocol run with parameters ``(\alpha, p, \sigma_z,
        \text{ramp\_time}, n)``.  Let ``S = \text{sign}(\alpha_A \cdot
        \alpha_B)`` be the product sign (the one-bit secret) and
        ``W = (W_1, \ldots, W_N)`` be the complete wire transcript
        with ``N = 2n + 1`` values.  Then:

        .. math::

            I(S; W) \le \min\bigl(1,\; N \cdot C(\sigma_z, p)\bigr)

        where:

        .. math::

            C(\sigma_z, p) = 1 - H_b\!\Bigl(\frac{1 - \Delta}{2}\Bigr)

        .. math::

            \Delta = \frac{4}{\pi}\sum_{n=1}^{\infty}
            e^{-2\pi^2 n^2 \sigma_z^2/p^2}

        and ``H_b`` is the binary entropy function.

        **Proof.**

        1. **Chain rule.**
           ``I(S; W) = \sum_k I(S; W_k | W_{<k})``

        2. **Per-step MI via Fano.**  For binary ``S`` with equal
           priors and any observation ``X``:

           ``I(S; X) \le 1 - H_b((1 - \mathrm{TV})/2)``

           where ``\mathrm{TV} = \mathrm{TV}(P(X|S{=}+),\,
           P(X|S{=}-))`` and ``(1-\mathrm{TV})/2`` is the MAP
           error probability.

        3. **Conditional TV bound via Fourier coefficients.**
           Each conditional distribution is a mixture of wrapped
           Gaussians over Eve's posterior:

           ``P(W_k | S{=}\pm, W_{<k}) = E_{m \sim \pi_\pm}
           [\mathrm{wrapped\_N}(c(m), \sigma_z^2)]``

           Expand each wrapped Gaussian in Fourier series:

           ``\mathrm{wrapped\_N}(c(m))(w) = \frac{1}{p}\bigl[1
           + 2\sum_n r_n \cos(2\pi n(w - c(m))/p)\bigr]``

           where ``r_n = \exp(-2\pi^2 n^2 \sigma_z^2/p^2)``.
           Using the addition formula and integrating over the
           posterior, the difference ``P_+ - P_-`` has Fourier
           representation:

           ``P_+(w) - P_-(w) = \frac{2}{p}\sum_n r_n
           [\Delta\!A_n \cos(2\pi nw/p) + \Delta\!B_n
           \sin(2\pi nw/p)]``

           where ``\Delta\!A_n = E_+[\cos\phi_n] - E_-[\cos\phi_n]``
           and ``\Delta\!B_n = E_+[\sin\phi_n] - E_-[\sin\phi_n]``
           with ``\phi_n = 2\pi n c(m)/p``.

           **Key bound**: In complex form,
           ``\sqrt{\Delta\!A_n^2 + \Delta\!B_n^2}
           = |E_+[e^{i\phi_n}] - E_-[e^{i\phi_n}]|``.
           Since the characteristic function of any distribution
           has modulus ``\le 1``:

           ``|E_+[e^{i\phi_n}] - E_-[e^{i\phi_n}]|
           \le |E_+[e^{i\phi_n}]| + |E_-[e^{i\phi_n}]| \le 2``

           **L1 bound on trigonometric polynomial**: For each
           harmonic ``n``, ``\int_0^p |a\cos + b\sin| \, dw
           = (2p/\pi)\sqrt{a^2 + b^2}``.
           By the triangle inequality over harmonics:

           ``\mathrm{TV} = \frac{1}{p}\int|\cdots|\,dw
           \le \frac{2}{\pi}\sum_n r_n
           \sqrt{\Delta\!A_n^2 + \Delta\!B_n^2}
           \le \frac{4}{\pi}\sum_n r_n = \Delta``

           This avoids the posterior-divergence issue: the bound
           uses ``|E[e^{i\phi}]| \le 1`` for each posterior
           independently; different mixture weights ``\pi_+``
           and ``\pi_-`` pose no problem.

        4. **Per-step MI.**  Substituting ``\mathrm{TV} \le \Delta``
           into step 2:

           ``I(S; W_k | W_{<k}) \le 1 - H_b((1 - \Delta)/2)
           =: C(\sigma_z, p)``

        5. **Summation.**
           ``I(S; W) \le N \cdot C \le 1`` (capped at ``H(S)``).
           QED.

        The bound is **deterministic**: no Monte Carlo, no confidence
        parameters.  It is valid for **any** eavesdropper strategy
        (unbounded computation, optimal posterior tracking).

        Returns
        -------
        dict
            'mi_bound': proven upper bound on I(S; W) per protocol run,
            'delta_tv': worst-case per-step TV distance (from uniform),
            'per_step_mi': per-step MI bound C(sigma_z, p),
            'n_wire_values': total wire values N,
            'sigma_z': noise std dev,
            'modulus': modulus p,
            'is_useful': True if the bound is < 1 (non-trivial).
        """
        n = self.number_of_exchanges
        N = 2 * n + 1  # total wire values

        delta_tv = self.wrapped_gaussian_tv_bound(self.sigma_z, self.modulus)

        # Per-step MI: 1 - H_b((1 - delta)/2)
        p_error = (1.0 - delta_tv) / 2.0
        per_step_mi = 1.0 - self._binary_entropy(p_error)

        total_mi = min(1.0, N * per_step_mi)

        # Min-entropy bound via coupling → TV → guessing probability
        me = self.per_run_min_entropy_bound()

        return {
            'mi_bound': total_mi,
            'delta_tv': delta_tv,
            'per_step_mi': per_step_mi,
            'n_wire_values': N,
            'sigma_z': self.sigma_z,
            'modulus': self.modulus,
            'is_useful': total_mi < 1.0,
            'h_min_per_bit': me['h_min_per_bit'],
            'tv_run': me['tv_run'],
            'min_entropy_is_useful': me['is_useful'],
        }

    def per_run_tv_bound(self):
        r"""Proven upper bound on TV distance for a full protocol run.

        **Theorem (Per-Run TV Bound via Coupling).**

        Let ``\delta`` be the per-step TV bound from
        ``wrapped_gaussian_tv_bound(\sigma_z, p)`` and ``N = 2n + 1``
        be the total number of wire values.  Then:

        .. math::

            \mathrm{TV}(P(W_{1:N}|S{=}+),\; P(W_{1:N}|S{=}-))
            \le 1 - (1 - \delta)^N

        **Proof (Coupling via Fourier Coefficient Bound).**

        Construct a maximal coupling of the wire sequences under the
        two sign hypotheses ``S=+`` and ``S=-``.  At each step ``k``:

        1.  Given that the histories ``W_{<k}`` agree under both
            hypotheses, the per-step conditional TV satisfies:

            ``\mathrm{TV}(P(W_k|S{=}+, W_{<k}),
            P(W_k|S{=}-, W_{<k})) \le \delta``

            by the Fourier coefficient bound (see
            ``analytic_mi_bound`` Step 3): expand the difference
            ``P_+ - P_-`` as a trigonometric polynomial with
            coefficients ``r_n \cdot (\Delta\!A_n, \Delta\!B_n)``,
            bound each amplitude by
            ``|E[e^{i\phi}]| \le 1 \Rightarrow
            \sqrt{\Delta\!A_n^2 + \Delta\!B_n^2} \le 2``,
            then sum: ``\mathrm{TV} \le (4/\pi)\sum r_n = \delta``.

            This holds for ANY posteriors ``\pi_+, \pi_-`` on
            ``M_{k-1}`` (different weights pose no problem).

        2.  By the coupling characterization of TV, there exists a
            joint draw ``(W_k^+, W_k^-)`` such that
            ``P(W_k^+ = W_k^-) \ge 1 - \delta``.

        3.  If the coupling succeeds at every step, the full sequences
            are identical.  By independence of the coupling success at
            each step (conditional on agreement so far):

            .. math::

                P(\text{all } N \text{ steps agree})
                \ge (1 - \delta)^N

        4.  By the coupling characterization of total variation:

            .. math::

                \mathrm{TV}(P(W_{1:N}|S{=}+),\; P(W_{1:N}|S{=}-))
                \le 1 - (1 - \delta)^N \qquad\square

        Note: this is tighter than the union bound
        ``\min(1, N \cdot \delta)`` when ``\delta`` is small.

        Returns
        -------
        float
            Upper bound on TV(P(W|S=+), P(W|S=-)) for the full run.
        """
        n = self.number_of_exchanges
        N = 2 * n + 1
        delta = self.wrapped_gaussian_tv_bound(self.sigma_z, self.modulus)
        return 1.0 - (1.0 - delta) ** N

    def per_run_min_entropy_bound(self):
        r"""Proven min-entropy bound per protocol run via TV → guessing.

        **Theorem (Min-Entropy from Total Variation).**

        Let ``S \in \{+, -\}`` be the binary secret with uniform prior
        and ``W`` be Eve's observation.  Let
        ``\mathrm{TV}_{\mathrm{run}} = \mathrm{TV}(P(W|S{=}+), P(W|S{=}-))``
        be the total variation distance for the full run.  Then:

        .. math::

            H_{\min}(S | W) \ge 1 - \log_2(1 + \mathrm{TV}_{\mathrm{run}})

        **Proof.**

        1.  **Guessing probability.**  For binary uniform ``S``:

            .. math::

                P_{\mathrm{guess}}(S | W)
                = \int \max\bigl(\tfrac{1}{2} P(W|+),\;
                  \tfrac{1}{2} P(W|-)\bigr)\, dW
                = \tfrac{1}{2}(1 + \mathrm{TV}_{\mathrm{run}})

            This is a standard result: the optimal MAP decoder
            achieves success probability ``(1 + \mathrm{TV})/2``
            for equiprobable binary hypotheses.

        2.  **Min-entropy.**  By definition:

            .. math::

                H_{\min}(S | W)
                = -\log_2 P_{\mathrm{guess}}(S | W)
                = -\log_2\!\bigl(\tfrac{1 + \mathrm{TV}_{\mathrm{run}}}{2}\bigr)
                = 1 - \log_2(1 + \mathrm{TV}_{\mathrm{run}})
                \qquad\square

        Returns
        -------
        dict
            'tv_run': per-run TV bound,
            'p_guess': guessing probability bound,
            'h_min_per_bit': min-entropy per protocol run (bits),
            'is_useful': True if h_min_per_bit > 0,
            'delta_step': per-step TV bound,
            'n_wire_values': total wire values N.
        """
        n = self.number_of_exchanges
        N = 2 * n + 1
        delta_step = self.wrapped_gaussian_tv_bound(self.sigma_z, self.modulus)
        tv_run = self.per_run_tv_bound()
        p_guess = 0.5 * (1.0 + tv_run)
        h_min = 1.0 - math.log2(1.0 + tv_run) if tv_run < 1.0 else 0.0

        return {
            'tv_run': tv_run,
            'p_guess': p_guess,
            'h_min_per_bit': h_min,
            'is_useful': h_min > 0.0,
            'delta_step': delta_step,
            'n_wire_values': N,
        }

    @staticmethod
    def wrapped_gaussian_tv_bound_second_order(sigma, p, n_fourier=50):
        r"""CONJECTURAL bound on TV distance using product-sign symmetry.

        .. warning::

           This bound is NOT proven.  The Fourier coefficient technique
           that proves ``analytic_mi_bound`` gives a per-step TV of
           ``\delta = (4/\pi)\sum r_n``.  This second-order bound
           claims ``(16/\pi^2)\sum r_n^2``, which is tighter but
           requires a cancellation argument that fails at the per-step
           conditional level.

           The second-order cancellation (odd Fourier terms vanishing
           under product-sign symmetry) is valid at the **marginal**
           (unconditional) level but fails at the per-step conditional
           level because Eve's posteriors on ``M_{k-1}`` under the two
           sign hypotheses are not symmetric.  Numerical experiments
           confirm this: at ``p = 3.5\sigma_z`` with 20 exchanges, the
           actual MI (~0.20 bits) exceeds this bound (~0.12 bits).

           For proven bounds, use ``analytic_mi_bound`` (which gives
           ``\delta`` per step via the Fourier coefficient bound) or
           ``estimate_hmin_rigorous`` for statistical bounds.

        **Conjecture (Second-Order TV Bound via Product-Sign Symmetry).**

        For the Liu protocol with product sign ``S = \text{sign}(\alpha_A
        \cdot \alpha_B)``, the per-round total variation distance between
        the conditional wire distributions satisfies (approximately):

        .. math::

            \mathrm{TV}(P(W_k | S{=}+, W_{<k}),\;
            P(W_k | S{=}-, W_{<k})) \le \frac{16}{\pi^2}\, r_1^2

        where ``r_1 = \exp(-2\pi^2 \sigma_z^2 / p^2)`` is the first
        Fourier coefficient of the wrapped Gaussian.

        **Attempted proof (gap in Step 3).**

        1. **Product-sign symmetry.** Under the transformation
           ``(\alpha_A, \alpha_B) \to (-\alpha_A, -\alpha_B)``, each
           message ``M_k`` maps to ``-M_k`` (since the recursion
           ``M_k = Z_k + \alpha \cdot \text{ramp}(k) \cdot M_{k-1}``
           flips sign when ``\alpha`` flips, by induction).  Therefore
           each wire value ``W_k = M_k \bmod p`` maps to ``-W_k \bmod p``.

        2. **Symmetrization (marginal level, valid).**  The product sign
           ``S`` is invariant under
           ``(\alpha_A, \alpha_B) \to (-\alpha_A, -\alpha_B)``.  At the
           **marginal** level:

           .. math::

               P(W | S{=}+) = \tfrac{1}{2}\bigl[P_{++}(W) + P_{--}(W)\bigr]
               = \tfrac{1}{2}\bigl[P_{++}(W) + P_{++}(-W)\bigr]

           This IS symmetric under ``W \to -W``, and odd Fourier terms
           DO cancel, leaving only ``O(r_1^2)`` cross-terms.

        3. **Per-step conditional level (GAP).**  The argument requires
           the same cancellation at the per-step conditional level
           ``P(W_k | S, W_{<k})``.  But Eve's posterior on ``M_{k-1}``
           is NOT symmetric under ``M \to -M`` when conditioned on a
           specific wire history, breaking the cancellation.  The
           posterior divergence between ``\pi_+`` and ``\pi_-``
           reintroduces first-order terms.

        Parameters
        ----------
        sigma : float
            Standard deviation of the Gaussian noise.
        p : float
            Modulus (period).
        n_fourier : int
            Number of Fourier terms (default 50; only n=1 dominates).

        Returns
        -------
        float
            Upper bound on per-round TV distance.
        """
        ratio = sigma / p
        r1 = math.exp(-2 * math.pi ** 2 * ratio ** 2)
        # Second-order bound: 16/π² · r₁²
        # Also include higher-order cross-terms for completeness
        total_r_sq = 0.0
        for n in range(1, n_fourier + 1):
            rn = math.exp(-2 * math.pi ** 2 * n ** 2 * ratio ** 2)
            if rn < 1e-15:
                break
            total_r_sq += rn ** 2
        return min(1.0, (16.0 / (math.pi ** 2)) * total_r_sq)

    def analytic_mi_bound_second_order(self):
        r"""CONJECTURAL MI bound using product-sign symmetry.

        .. warning::

           This bound is NOT proven.  The product-sign symmetry
           cancellation is valid at the marginal level but fails at
           the per-step conditional level due to posterior divergence.
           Numerical experiments confirm: at ``p = 3.5\sigma_z`` with
           20 exchanges, the actual MI (~0.20 bits) exceeds this
           bound (~0.12 bits).

           The Fourier coefficient technique that proves
           ``analytic_mi_bound`` gives ``\delta`` per step, not
           the second-order ``(16/\pi^2) r_1^2`` this bound
           claims.

           For proven bounds, use ``analytic_mi_bound``.

        **Conjecture (Second-Order Analytic MI Bound).**

        Let the Liu protocol run with parameters ``(\alpha, p, \sigma_z,
        \text{ramp\_time}, n)`` and let ``S = \text{sign}(\alpha_A \cdot
        \alpha_B)`` be the product sign.  Then:

        .. math::

            I(S; W) \le \min\bigl(1,\; N \cdot C_2(\sigma_z, p)\bigr)

        where ``N = 2n + 1`` is the number of wire values and:

        .. math::

            C_2(\sigma_z, p) = 1 - H_b\!\Bigl(\frac{1 - \Delta_2}{2}\Bigr)

        .. math::

            \Delta_2 = \frac{16}{\pi^2}\sum_{n=1}^{\infty}
            e^{-4\pi^2 n^2 \sigma_z^2/p^2}

        The conjecture exploits product-sign symmetry
        (see ``wrapped_gaussian_tv_bound_second_order``).
        The key observation is that first-order Fourier terms cancel
        under the symmetrization ``P(W|S{=}+) = \frac{1}{2}[P_{++}(W)
        + P_{++}(-W)]``, leaving only second-order terms ``\sim r_1^2``.

        **This bound is NOT deterministically proven** — the
        symmetrization argument fails at the per-step conditional level
        because Eve's posterior on M_{k-1} is not symmetric.

        Returns
        -------
        dict
            'mi_bound': proven upper bound on I(S; W) per protocol run,
            'delta_tv': second-order per-round TV bound,
            'per_step_mi': per-step MI bound C_2(sigma_z, p),
            'n_wire_values': total wire values N,
            'sigma_z': noise std dev,
            'modulus': modulus p,
            'r1': first Fourier coefficient exp(-2π²σ²/p²),
            'is_useful': True if the bound is < 1 (non-trivial),
            'improvement_over_first_order': ratio of first-order to
                second-order TV bound.
        """
        n = self.number_of_exchanges
        N = 2 * n + 1

        delta_tv_1st = self.wrapped_gaussian_tv_bound(
            self.sigma_z, self.modulus)
        delta_tv_2nd = self.wrapped_gaussian_tv_bound_second_order(
            self.sigma_z, self.modulus)

        r1 = math.exp(-2 * math.pi ** 2
                       * (self.sigma_z / self.modulus) ** 2)

        # Per-step MI: 1 - H_b((1 - delta)/2)
        p_error = (1.0 - delta_tv_2nd) / 2.0
        per_step_mi = 1.0 - self._binary_entropy(p_error)

        total_mi = min(1.0, N * per_step_mi)

        improvement = (delta_tv_1st / delta_tv_2nd
                       if delta_tv_2nd > 1e-30 else float('inf'))

        return {
            'mi_bound': total_mi,
            'delta_tv': delta_tv_2nd,
            'delta_tv_first_order': delta_tv_1st,
            'per_step_mi': per_step_mi,
            'n_wire_values': N,
            'sigma_z': self.sigma_z,
            'modulus': self.modulus,
            'r1': r1,
            'is_useful': total_mi < 1.0,
            'improvement_over_first_order': improvement,
        }

    @staticmethod
    def find_proven_regime(sigma_z, n_exchanges, alpha_values=None,
                           p_range=None):
        r"""Find parameter regimes where the analytic MI bound is useful.

        Searches over modulus values to find where the proven bound
        gives I(S; W) < 1, meaning extractable secure key material.

        Parameters
        ----------
        sigma_z : float
            Noise standard deviation.
        n_exchanges : int
            Number of exchanges per run.
        alpha_values : list of float or None
            Reflection coefficients to test (default [0.3, 0.5, 0.8]).
        p_range : tuple or None
            (p_min, p_max) range for modulus search.

        Returns
        -------
        list of dict
            Each entry has 'alpha', 'modulus', 'mi_bound',
            'bob_unwrap_failure', 'is_useful'.
        """
        if alpha_values is None:
            alpha_values = [0.3, 0.5, 0.8]
        if p_range is None:
            p_range = (0.5 * sigma_z, 6.0 * sigma_z)

        from scipy.stats import norm as _norm

        results = []
        p_values = np.linspace(p_range[0], p_range[1], 100)

        for alpha in alpha_values:
            for p in p_values:
                est = LeakageEstimator(sigma_z, alpha, 10, p, n_exchanges)
                bound_1st = est.analytic_mi_bound()
                bound_2nd = est.analytic_mi_bound_second_order()

                # Bob's per-exchange unwrap failure rate
                unwrap_fail = 2 * (1 - _norm.cdf(p / (2 * sigma_z)))

                results.append({
                    'alpha': alpha,
                    'modulus': float(p),
                    'mi_bound': bound_1st['mi_bound'],
                    'mi_bound_second_order': bound_2nd['mi_bound'],
                    'delta_tv': bound_1st['delta_tv'],
                    'per_step_mi': bound_1st['per_step_mi'],
                    'bob_unwrap_failure': unwrap_fail,
                    'is_useful': bound_1st['is_useful'],
                    'is_useful_second_order': bound_2nd['is_useful'],
                })

        return results

    def report(self):
        """Generate a summary dict of leakage metrics.

        Includes conservative (Pinsker), tight (conditional JSD), and
        Monte Carlo MI estimates.

        Returns
        -------
        dict
        """
        delta = self.statistical_distance()
        mi_pinsker = self.mutual_information()
        mi_tight = self.mutual_information_tight()
        total_tight = self.total_eve_information_tight()
        mi_mc = self.estimate_mi_monte_carlo(n_samples=200, seed=42)

        analytic = self.analytic_mi_bound()
        analytic_2nd = self.analytic_mi_bound_second_order()

        return {
            'sigma_z': self.sigma_z,
            'alpha': self.alpha,
            'ramp_time': self.ramp_time,
            'modulus': self.modulus,
            'number_of_exchanges': self.number_of_exchanges,
            'worst_statistical_distance': float(np.max(delta)),
            'steady_state_statistical_distance': float(delta[-1]),
            'total_eve_information_pinsker': float(np.sum(mi_pinsker)),
            'total_eve_information_jsd': total_tight,
            'total_eve_information_mc': mi_mc,
            'total_eve_information_bits': mi_mc,
            'analytic_mi_bound': analytic['mi_bound'],
            'analytic_mi_bound_useful': analytic['is_useful'],
            'conjectural_mi_bound_2nd_order': analytic_2nd['mi_bound'],
            'conjectural_mi_bound_2nd_order_useful': analytic_2nd['is_useful'],  # still conjectural
            'h_min_per_bit': analytic['h_min_per_bit'],
            'tv_run': analytic['tv_run'],
            'min_entropy_useful': analytic['min_entropy_is_useful'],
        }
