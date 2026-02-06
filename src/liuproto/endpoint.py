#!/usr/bin/env python

r"""Liu protocol endpoint implementation.

This module implements a Liu protocol endpoint, including signal
generation.  In particular, it implements the exchange

    :math:`M_{k+1} = Z_{k+1} + \alpha M_k` ,

where :math:`{M_k}` are the messages sent across the wire, :math:`\alpha` is
the reflection coefficient, and :math:`{Z_k}` is composed of band-limited
Gaussian noise.

The noise signal :math:`Z_{k+1}` is a linear combination of
two Gaussian noise processes :math:`U_{1}` and :math:`U_{2}`,
band-limited by zeroing of FFT entries:

 :math:`{U_{i,k}}=\mathcal{F}^{-1}\left[\mathcal{F}\left[R_k\right]w[f]\right]`

where

 :math:`w[f] = u[Nf_s-k] + u[k - N(1-f_s)]`

is a weighting function that zeroes the range :math:`[fs,1-fs]`,
:math:`u[k]` the Heaviside step function, and :math:`R_k` Gaussian
white noise.

When a modulus p > 0 is set, transmitted values are reduced mod p into
(-p/2, p/2].  The receiver unwraps incoming values using hypothesis
tracking to recover the real-valued signal.
"""

import numpy as np
import os
import json
import math

from . import leakage as _leakage_mod


class Physics(object):
    """Implementation of an endpoint of the Liu key agreement protocol."""

    def __init__(self, number_of_exchanges, reflection_coefficient, cutoff,
                 ramp_time, resolution, masking_time, masking_magnitude,
                 modulus=0, seed=None, modulus_multiplier=5.0,
                 ramp_exclusion_factor=3.0, rng_is_true_random=False):
        # Initialize the physics parameters
        self.number_of_exchanges = number_of_exchanges
        self.reflection_coefficient = reflection_coefficient
        self.cutoff = cutoff
        self.ramp_time = ramp_time
        self.resolution = resolution
        self.masking_time = masking_time
        self.masking_magnitude = masking_magnitude
        self.modulus_multiplier = modulus_multiplier
        self.ramp_exclusion_factor = ramp_exclusion_factor

        # Handle auto-calibrated modulus
        if isinstance(modulus, str) and modulus == 'auto':
            self.modulus = self.calibrate_modulus(cutoff, modulus_multiplier)
        else:
            self.modulus = float(modulus)

        # Compute ramp exclusion threshold for modular mode
        self._exclusion_threshold = int(ramp_exclusion_factor * ramp_time)

        # Set up the PRNG.  When no explicit seed is given, we draw one
        # from os.urandom (CSPRNG) — computationally secure but *not*
        # information-theoretically random.  Users who integrate a hardware
        # RNG can pass ``rng_is_true_random=True`` to use per-sample
        # os.urandom() + Box-Muller for protocol randomness.
        if seed is not None:
            self.random_state = np.random.default_rng(seed)
        else:
            seed_bytes = os.urandom(32)
            seed_int = int.from_bytes(seed_bytes, 'big')
            self.random_state = np.random.default_rng(seed_int)

        # When True, protocol randomness comes from os.urandom() via
        # Box-Muller, not from the PRNG.  The PRNG is still available
        # for fallback / testing.
        self.rng_is_true_random = rng_is_true_random

        # Initialize random values and masking noise
        self.random_values = []
        self.masking_noise = []
        self.correlation_sum = 0.0
        self.current_exchange = 0
        self.no_reset = False

        # Modular-mode state
        self._last_real_sent = 0.0
        self._last_real_received = 0.0
        self._correlation_sum_plus = 0.0
        self._correlation_sum_minus = 0.0
        self._is_second_mover = False

        self.reset()

    @property
    def sigma_z(self):
        """Estimated standard deviation of band-limited noise Z_k."""
        return _leakage_mod.estimate_sigma_z(self.cutoff)

    @staticmethod
    def calibrate_modulus(cutoff, multiplier=5.0):
        """Compute auto-calibrated modulus from cutoff and multiplier.

        Parameters
        ----------
        cutoff : float
            Digital cutoff frequency.
        multiplier : float
            Multiplier for sigma_z (default 5.0).

        Returns
        -------
        float
            The calibrated modulus p = multiplier * sigma_z.
        """
        sigma_z = _leakage_mod.estimate_sigma_z(cutoff)
        return multiplier * sigma_z

    def reset(self):
        """Reset the endpoint to its initial random state."""
        if self._random_coin() < 0.5 and not self.no_reset:
            self.reflection_coefficient = -self.reflection_coefficient
        if self.rng_is_true_random:
            # ITS path: i.i.d. N(0, σ_z²) per step to match the HMM
            # security model exactly.  No FFT band-limiting, no ramped
            # blending — those introduce temporal correlations not
            # captured by the HMM forward algorithm in
            # LeakageEstimator._forward_log_likelihood().
            n = self.number_of_exchanges + 1
            self.random_values = self.sigma_z * self._true_random_gaussian(n)
        else:
            self.random_values = self._generate_ramped_random_values()
        self.masking_noise = self._generate_ramped_random_values() * self.masking_magnitude
        self.masking_noise[:self.ramp_time - self.masking_time] = 0.0
        self.masking_noise[self.ramp_time:] = 0.0
        self.correlation_sum = 0.0
        self.current_exchange = 0
        self._last_real_sent = 0.0
        self._last_real_received = 0.0
        self._correlation_sum_plus = 0.0
        self._correlation_sum_minus = 0.0

    def _true_random_uniform(self):
        """Return a single float in (0, 1) from os.urandom(8).

        Re-draws if the result is exactly 0.0 (needed for Box-Muller log).
        """
        while True:
            u = int.from_bytes(os.urandom(8), 'big') / (2**64)
            if u > 0.0:
                return u

    def _true_random_gaussian(self, n):
        """Generate *n* standard Gaussian samples via Box-Muller with os.urandom.

        Produces pairs of Gaussian samples from pairs of uniform draws.
        If *n* is odd, generates n+1 and discards one.
        """
        n_pairs = (n + 1) // 2
        samples = np.empty(2 * n_pairs)
        for i in range(n_pairs):
            u1 = self._true_random_uniform()
            u2 = self._true_random_uniform()
            r = math.sqrt(-2.0 * math.log(u1))
            theta = 2.0 * math.pi * u2
            samples[2 * i] = r * math.cos(theta)
            samples[2 * i + 1] = r * math.sin(theta)
        return samples[:n]

    def _true_random_coin(self):
        """Return a single uniform draw in (0, 1) from os.urandom."""
        return self._true_random_uniform()

    def _random_coin(self):
        """Return a uniform draw in (0, 1), dispatching based on rng_is_true_random."""
        if self.rng_is_true_random:
            return self._true_random_coin()
        return self.random_state.random()

    def _generate_random_values(self):
        """Generate band-limited white noise, returning a real numpy array."""
        if self.rng_is_true_random:
            white_noise = self._true_random_gaussian(self.number_of_exchanges + 1)
        else:
            white_noise = self.random_state.standard_normal(self.number_of_exchanges + 1)
        white_noise_frequency_domain = np.fft.fft(white_noise)
        cutoff_index = int(self.number_of_exchanges * self.cutoff)
        white_noise_frequency_domain[cutoff_index:-cutoff_index] = 0.0
        return np.real(np.fft.ifft(white_noise_frequency_domain))

    def _generate_ramped_random_values(self):
        """Generate ramped random processes, returning a numpy array."""
        u1 = self._generate_random_values()
        u2 = self._generate_random_values()
        ramp = self._ramp_function(np.arange(len(u1)))
        return u1 * np.sqrt(1 - ramp ** 2) + u2 * ramp

    def _ramp_function(self, n):
        """Compute the exponential ramp function, returning a numpy array."""
        n_array = np.array(n)
        return 1.0 - np.exp(-n_array.astype(float) / float(self.ramp_time))

    def _mod_reduce(self, x):
        """Centered symmetric modular reduction into (-p/2, p/2]."""
        return x - self.modulus * round(x / self.modulus)

    def _unwrap(self, received, expected_center):
        """Find the real value closest to expected_center whose mod-p
        reduction equals received."""
        reduced_center = self._mod_reduce(expected_center)
        diff = received - reduced_center
        diff = diff - self.modulus * round(diff / self.modulus)
        return expected_center + diff

    def exchange(self, incoming, incoming_real=None):
        """Perform a single exchange, returning a floating-point response.

        When modulus > 0, the returned value is mod-p reduced.  Internally
        the endpoint tracks the real-valued signal for correlation.

        Parameters
        ----------
        incoming : float
            The wire value received from the other party (mod-p wrapped
            when modulus > 0).
        incoming_real : float or None
            When ``rng_is_true_random=True``, the true (unwrapped) real
            value of the sender's last message, shared via the
            authenticated channel.  Bypasses hypothesis-tracking unwrap
            so that protocol dynamics exactly match the HMM security
            model in ``LeakageEstimator._forward_log_likelihood``.
        """
        k = self.current_exchange
        ramp = self._ramp_function([k])[0]
        alpha = self.reflection_coefficient
        ramped_alpha = alpha * ramp
        abs_alpha = abs(alpha)

        if self.modulus > 0:
            # --- Modular mode ---
            if k == 0:
                # First exchange: no history to unwrap against
                real_incoming = float(incoming)
            elif incoming_real is not None:
                # Wire-value / ITS mode: caller supplies the real value
                # to use as incoming (e.g. the wire value itself for
                # independent per-step decode, or the true M_real for
                # the HMM security model).
                real_incoming = incoming_real
            else:
                # Unwrap incoming using two sign hypotheses for other's alpha.
                # The sender's ramp index depends on protocol role:
                # First mover (Alice): receives second mover's exchange k-1
                #   → sender used ramp(k-1)
                # Second mover (Bob): receives first mover's exchange k
                #   → sender used ramp(k)
                if self._is_second_mover:
                    sender_ramp = self._ramp_function([k])[0]
                else:
                    sender_ramp = self._ramp_function([k - 1])[0]
                center_plus = +abs_alpha * sender_ramp * self._last_real_sent
                center_minus = -abs_alpha * sender_ramp * self._last_real_sent

                real_incoming_plus = self._unwrap(incoming, center_plus)
                real_incoming_minus = self._unwrap(incoming, center_minus)

                # Update correlation accumulators (skip ramp-up period)
                z_prev = self.random_values[k - 1]
                if k >= self._exclusion_threshold:
                    self._correlation_sum_plus += z_prev * real_incoming_plus
                    self._correlation_sum_minus += z_prev * real_incoming_minus

                # Pick best hypothesis
                if abs(self._correlation_sum_plus) >= abs(self._correlation_sum_minus):
                    real_incoming = real_incoming_plus
                else:
                    real_incoming = real_incoming_minus

            # Also maintain classic correlation_sum using chosen incoming
            if k > 0:
                self.correlation_sum += self.random_values[k - 1] * real_incoming

            self._last_real_received = real_incoming

            # Compute real output
            real_output = self.random_values[k] + real_incoming * ramped_alpha

            # Apply resolution quantisation and masking
            self.current_exchange += 1
            if self.resolution > 0 and self.masking_noise[self.current_exchange - 1] == 0.0:
                real_output = self.resolution * round(real_output / self.resolution)
            real_output += self.masking_noise[self.current_exchange - 1]

            self._last_real_sent = real_output
            # SECURITY-CRITICAL: Modular reduction before transmission ensures
            # Eve (a passive TCP eavesdropper) only observes wrapped values
            # W_k ∈ (-p/2, p/2].  The ITS proof in security_proof.py relies
            # on this: _forward_log_likelihood computes likelihoods over
            # wrapped observations, matching exactly what goes over the wire.
            return self._mod_reduce(real_output)
        else:
            # --- Classic mode ---
            if k > 0:
                self.correlation_sum += self.random_values[k - 1] * incoming
            new_message = self.random_values[k] + incoming * ramped_alpha
            self.current_exchange += 1
            if self.resolution > 0 and self.masking_noise[self.current_exchange - 1] == 0.0:
                new_message = self.resolution * round(new_message / self.resolution)
            return new_message + self.masking_noise[self.current_exchange - 1]

    def estimate_other(self):
        """Estimate the state of the other endpoint, returning a boolean."""
        if self.modulus > 0:
            if self.rng_is_true_random:
                # ITS mode bypasses hypothesis-tracking unwrap, so
                # _correlation_sum_plus/_minus are not populated.
                # Use correlation_sum which is always maintained.
                return self.correlation_sum > 0
            if abs(self._correlation_sum_plus) >= abs(self._correlation_sum_minus):
                return self._correlation_sum_plus > 0
            else:
                return self._correlation_sum_minus > 0
        return self.correlation_sum > 0

    def leakage_report(self):
        """Construct a LeakageEstimator and return the leakage report.

        Returns
        -------
        dict
            Leakage metrics from LeakageEstimator.report().
        """
        estimator = _leakage_mod.LeakageEstimator(
            self.sigma_z,
            abs(self.reflection_coefficient),
            self.ramp_time,
            self.modulus,
            self.number_of_exchanges)
        return estimator.report()

    def to_json(self, insecure=False):
        """Export a JSON representation of the endpoint parameters."""
        if insecure:
            reflection_coefficient = self.reflection_coefficient
        else:
            reflection_coefficient = abs(self.reflection_coefficient)
        d = {
            'number_of_exchanges': self.number_of_exchanges,
            'reflection_coefficient': reflection_coefficient,
            'cutoff': self.cutoff,
            'ramp_time': self.ramp_time,
            'resolution': self.resolution,
            'masking_time': self.masking_time,
            'masking_magnitude': self.masking_magnitude,
        }
        if self.modulus > 0:
            d['modulus'] = self.modulus
        if self.ramp_exclusion_factor != 3.0:
            d['ramp_exclusion_factor'] = self.ramp_exclusion_factor
        return json.dumps(d)

    @staticmethod
    def from_json(option_string):
        """Create a new Physics object from an exported JSON string.

        The returned object uses a PRNG (``rng_is_true_random = False``)
        because JSON round-tripping cannot preserve hardware RNG state.
        """
        options = json.loads(option_string)
        obj = Physics(
            options['number_of_exchanges'],
            options['reflection_coefficient'],
            options['cutoff'],
            options['ramp_time'],
            options['resolution'],
            options['masking_time'],
            options['masking_magnitude'],
            modulus=options.get('modulus', 0),
            ramp_exclusion_factor=options.get('ramp_exclusion_factor', 3.0)
        )
        # Explicitly mark as PRNG (constructor already sets this, but
        # be explicit for clarity).
        obj.rng_is_true_random = False
        return obj
