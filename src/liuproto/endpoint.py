#!/usr/bin/env python

import numpy
import numpy.random
import numpy.fft


class Physics(object):
    """Implementation of an endpoint of the Liu key agreement protocol."""
    def __init__(self, number_of_exchanges, reflection_coefficient, cutoff, ramp_time, seed=None):
        self.number_of_exchanges = number_of_exchanges
        self.reflection_coefficient = reflection_coefficient
        self.cutoff = cutoff
        self.ramp_time = ramp_time

        self.random_state = numpy.random.RandomState(seed=seed)
        self.random_values = []
        self.correlation_sum = 0.0
        self.current_exchange = 0

        self.reset()

    def reset(self):
        """Reset the endpoint to its initial random state."""
        if self.random_state.rand() < 0.5:
            self.reflection_coefficient = -self.reflection_coefficient

        self.random_values = self.__generate_ramped_random_values()

        self.correlation_sum = 0.0

        self.current_exchange = 0

    def __generate_random_values(self):
        """Generate band-limited white noise, returning a real numpy array."""
        white_noise = self.random_state.randn(self.number_of_exchanges+1)
        white_noise_frequency_domain = numpy.fft.fft(white_noise)

        cutoff_index = self.cutoff*len(white_noise_frequency_domain)
        white_noise_frequency_domain[cutoff_index:-cutoff_index] = 0.0

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
        transition_values = numpy.array(n) < self.ramp_time
        if len(transition_values) == 1:
            transition_values = 0
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
        ramp = self.__ramp_function([self.current_exchange])[0]

        ramped_reflection_coefficient = self.reflection_coefficient*ramp

        if self.current_exchange > 0:
            self.correlation_sum += \
                self.random_values[self.current_exchange - 1] * incoming

        new_message = self.random_values[self.current_exchange] \
                      + incoming*ramped_reflection_coefficient
        self.current_exchange += 1

        return new_message

    def estimate_other(self):
        """Estimate the state of the other endpoint, returning a boolean."""
        return self.correlation_sum > 0