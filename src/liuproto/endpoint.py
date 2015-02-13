#!/usr/bin/env python

import numpy
import numpy.random
import numpy.fft

class Physics(object):
    """
    Implementation of the "physical" part of the Liu key agreement protocol.
    """
    def __init__(self, number_of_exchanges, reflection_coefficient, cutoff, ramp_time, seed=None):
        self.number_of_exchanges = number_of_exchanges
        self.reflection_coefficient = reflection_coefficient
        self.cutoff = cutoff
        self.ramp_time = ramp_time

        self.random_state = numpy.random.RandomState(seed=seed)
        self.U1 = self.__generate_random_values()
        self.U2 = self.__generate_random_values()

        self.current_exchange = 0

    def __generate_random_values(self):
        white_noise = self.random_state.randn(self.number_of_exchanges+1)
        white_noise_frequency_domain = numpy.fft.fft(white_noise)

        cutoff_index = self.cutoff*len(white_noise_frequency_domain)
        white_noise_frequency_domain[cutoff_index:-cutoff_index] = 0.0

        return numpy.real(numpy.fft.ifft(white_noise_frequency_domain))

    def __ramp_function(self, n):
        if n >= self.ramp_time:
            return 1.0
        else:
            return 0.5*(1+numpy.sin((float(n)-self.ramp_time/2.0)*numpy.pi/float(self.ramp_time)))

    def exchange(self, incoming):
        ramp = self.__ramp_function(self.current_exchange)
        injected_signal = self.U1[self.current_exchange]*(1-ramp) + self.U2[self.current_exchange]*ramp

        ramped_reflection_coefficient = self.reflection_coefficient*ramp

        self.current_exchange += 1

        return injected_signal + incoming*ramped_reflection_coefficient