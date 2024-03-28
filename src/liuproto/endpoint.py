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
"""

import numpy as np
import os
import json

class Physics(object):
    """Implementation of an endpoint of the Liu key agreement protocol."""

    def __init__(self, number_of_exchanges, reflection_coefficient, cutoff, ramp_time, resolution, masking_time, masking_magnitude, seed=None):
        # Initialize the physics parameters
        self.number_of_exchanges = number_of_exchanges
        self.reflection_coefficient = reflection_coefficient
        self.cutoff = cutoff
        self.ramp_time = ramp_time
        self.resolution = resolution
        self.masking_time = masking_time
        self.masking_magnitude = masking_magnitude

        # Use os.urandom() to seed the NumPy PRNG
        seed_bytes = os.urandom(32)
        seed_int = int.from_bytes(seed_bytes, 'big')
        self.random_state = np.random.default_rng(seed_int)

        # Initialize random values and masking noise
        self.random_values = []
        self.masking_noise = []
        self.correlation_sum = 0.0
        self.current_exchange = 0
        self.no_reset = False
        self.reset()

    def reset(self):
        """Reset the endpoint to its initial random state."""
        if self.random_state.random() < 0.5 and not self.no_reset:
            self.reflection_coefficient = -self.reflection_coefficient
        self.random_values = self.__generate_ramped_random_values()
        self.masking_noise = self.__generate_ramped_random_values() * self.masking_magnitude
        self.masking_noise[:self.ramp_time - self.masking_time] = 0.0
        self.masking_noise[self.ramp_time:] = 0.0
        self.correlation_sum = 0.0
        self.current_exchange = 0

    def __generate_random_values(self):
        """Generate band-limited white noise, returning a real numpy array."""
        white_noise = self.random_state.standard_normal(self.number_of_exchanges + 1)
        white_noise_frequency_domain = np.fft.fft(white_noise)
        cutoff_index = int(self.number_of_exchanges * self.cutoff)
        white_noise_frequency_domain[cutoff_index:-cutoff_index] = 0.0
        return np.real(np.fft.ifft(white_noise_frequency_domain))

    def __generate_ramped_random_values(self):
        """Generate ramped random processes, returning a numpy array."""
        u1 = self.__generate_random_values()
        u2 = self.__generate_random_values()
        ramp = self.__ramp_function(np.arange(len(u1)))
        return u1 * np.sqrt(1 - ramp ** 2) + u2 * ramp

    def __ramp_function(self, n):
        """Compute the exponential ramp function, returning a numpy array."""
        n_array = np.array(n)  # Convert the list to a NumPy array
        return 1.0 - np.exp(-n_array.astype(float) / float(self.ramp_time))


    def exchange(self, incoming):
        """Perform a single exchange, returning a floating-point response."""
        ramp = self.__ramp_function([self.current_exchange])[0]
        ramped_reflection_coefficient = self.reflection_coefficient * ramp
        if self.current_exchange > 0:
            self.correlation_sum += self.random_values[self.current_exchange - 1] * incoming
        new_message = self.random_values[self.current_exchange] + incoming * ramped_reflection_coefficient
        self.current_exchange += 1
        if self.resolution > 0 and self.masking_noise[self.current_exchange - 1] == 0.0:
            new_message = self.resolution * round(new_message / self.resolution)
        else:
            new_message = new_message
        return new_message + self.masking_noise[self.current_exchange - 1]

    def estimate_other(self):
        """Estimate the state of the other endpoint, returning a boolean."""
        return self.correlation_sum > 0

    def to_json(self, insecure=False):
        """Export a JSON representation of the endpoint parameters."""
        if insecure:
            reflection_coefficient = self.reflection_coefficient
        else:
            reflection_coefficient = abs(self.reflection_coefficient)
        return json.dumps({
            'number_of_exchanges': self.number_of_exchanges,
            'reflection_coefficient': reflection_coefficient,
            'cutoff': self.cutoff,
            'ramp_time': self.ramp_time,
            'resolution': self.resolution,
            'masking_time': self.masking_time,
            'masking_magnitude': self.masking_magnitude
        })

    @staticmethod
    def from_json(option_string):
        """Create a new Physics object from an exported JSON string."""
        options = json.loads(option_string)
        return Physics(
            options['number_of_exchanges'],
            options['reflection_coefficient'],
            options['cutoff'],
            options['ramp_time'],
            options['resolution'],
            options['masking_time'],
            options['masking_magnitude']
        )
