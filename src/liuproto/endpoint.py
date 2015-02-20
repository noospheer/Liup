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

import numpy
import numpy.random
import numpy.fft
import json


class Physics(object):
    """Implementation of an endpoint of the Liu key agreement protocol."""
    def __init__(self, number_of_exchanges, reflection_coefficient, cutoff, ramp_time, resolution, seed=None):
        self.number_of_exchanges = number_of_exchanges
        self.reflection_coefficient = reflection_coefficient
        self.cutoff = cutoff
        self.ramp_time = ramp_time
        self.resolution = resolution

        self.random_state = numpy.random.RandomState(seed=seed)
        self.random_values = []
        self.correlation_sum = 0.0
        self.current_exchange = 0

        self.reset()

    def reset(self):
        """Reset the endpoint to its initial random state."""

        # First set the reflection coefficient.  We want to keep the same
        # magnitude, so flip the sign with probability 0.5.
        if self.random_state.rand() < 0.5:
            self.reflection_coefficient = -self.reflection_coefficient

        # Next generate our band-limited random signal.
        self.random_values = self.__generate_ramped_random_values()

        # Finally, re-zero the correlation accumulator and exchange counter.
        self.correlation_sum = 0.0

        self.current_exchange = 0

    def __generate_random_values(self):
        """Generate band-limited white noise, returning a real numpy array."""

        # First generate our white Gaussian noise.
        white_noise = self.random_state.randn(self.number_of_exchanges+1)

        # Next, use an FFT to convert to the frequency domain.
        white_noise_frequency_domain = numpy.fft.fft(white_noise)

        # Zero the FFT bins at frequencies above the cutoff.
        cutoff_index = self.cutoff*len(white_noise_frequency_domain)
        white_noise_frequency_domain[cutoff_index:-cutoff_index] = 0.0

        # Finally, apply an IFFT and return the result.  The use of
        # numpy.real() is necessary here because ifft returns a complex
        # result, even for a real signal.
        return numpy.real(numpy.fft.ifft(white_noise_frequency_domain))

    def __generate_ramped_random_values(self):
        """Generate ramped random processes, returning a numpy array."""
        u1 = self.__generate_random_values()
        u2 = self.__generate_random_values()

        ramp = self.__ramp_function(numpy.arange(len(u1)))

        return u1*numpy.sqrt(1-ramp**2) + u2*ramp

    def __ramp_function(self, n):
        """Compute the raised-sine ramp function, returning a numpy array."""


        ramp = numpy.ones(len(n))
        if self.ramp_time == 0:
            return ramp

        transition_values = numpy.array(n) < self.ramp_time
        if len(transition_values) == 1:
            if transition_values:
                transition_values = 0
            else:
                return ramp
        ramp[transition_values] = \
            0.5*(1+numpy.sin(
                        (numpy.array(n[transition_values]).astype(float)
                            - self.ramp_time/2.0
                            )*numpy.pi/float(self.ramp_time)
                   )
                )

        return ramp

    def exchange(self, incoming):
        """Perform a single exchange, returning a floating-point response."""

        # First calculate the reflection coefficient for this exchange.
        ramp = self.__ramp_function([self.current_exchange])[0]
        ramped_reflection_coefficient = self.reflection_coefficient*ramp

        # Next, if this incoming message is response to one of ours,
        # attempt to correlate it with our injected signal from last time.
        if self.current_exchange > 0:
            self.correlation_sum += \
                self.random_values[self.current_exchange - 1] * incoming

        # Finally, construct the response and increment the exchange counter.
        new_message = self.random_values[self.current_exchange] \
                      + incoming*ramped_reflection_coefficient
        self.current_exchange += 1

        if self.resolution > 0:
            return self.resolution*round(new_message/self.resolution)
        else:
            return new_message

    def estimate_other(self):
        """Estimate the state of the other endpoint, returning a boolean."""
        return self.correlation_sum > 0

    def to_json(self, insecure=False):
        """Export a JSON representation of the endpoint parameters."""

        # For logging purposes we need the ability to export the sign of the
        # reflection coefficient.
        if insecure:
            reflection_coefficient = self.reflection_coefficient
        else:
            reflection_coefficient = abs(self.reflection_coefficient)

        return json.dumps({
            'number_of_exchanges': self.number_of_exchanges,
            'reflection_coefficient': reflection_coefficient,
            'cutoff': self.cutoff,
            'ramp_time': self.ramp_time,
            'resolution': self.resolution
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
            options['resolution'])