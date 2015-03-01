#!/usr/bin/env python

"""Test the correlation coefficients of the protocol implementation.
"""

import liuproto.storage, liuproto.link, liuproto.endpoint
from pylab import *
import unittest

Gamma = 0.9


class CorrelationTestWideband(unittest.TestCase):
    def test_wideband(self):
        p = liuproto.endpoint.Physics(100000, Gamma, 0.5, 10, 0)
        storage = liuproto.storage.Session('internal')
        link = liuproto.link.InternalLink(p, storage=storage)

        link.run_proto()

        run = storage.runs[0]

        messages_ab = array([message.message
                        for message in run.messages if message.source == 'Alice'])

        messages_ba = array([message.message
                        for message in run.messages if message.source == 'Bob'])

        Z_a = run.endpoints[0].physics.random_values[:-1]
        Z_b = run.endpoints[1].physics.random_values[:-1]

        est_gamma_a = mean(messages_ab[1:]*Z_b)/var(Z_b)
        est_gamma_b = mean(messages_ba*Z_a)/var(Z_a)

        self.assertLessEqual(abs(
            est_gamma_a - link.physics_A.reflection_coefficient), 0.05)

        self.assertLessEqual(abs(
            est_gamma_b - link.physics_B.reflection_coefficient), 0.05)


class CorrelationTestNarrowband(unittest.TestCase):

    def test_narrowband(self):
        self.narrowband_test(+Gamma, -Gamma)
        self.narrowband_test(-Gamma, +Gamma)
        self.narrowband_test(+Gamma, +Gamma)
        self.narrowband_test(-Gamma, -Gamma)

    def narrowband_test(self, ga, gb):
        p = liuproto.endpoint.Physics(100000, Gamma, 0.005, 10, 0)
        storage = liuproto.storage.Session('internal')
        link = liuproto.link.InternalLink(p, storage=storage)

        link.physics_A.no_reset = True
        link.physics_B.no_reset = True

        link.physics_A.reflection_coefficient = ga
        link.physics_B.reflection_coefficient = gb

        link.run_proto()

        run = storage.runs[0]

        messages_ab = array([message.message
                             for message in run.messages if message.source == 'Alice'])

        messages_ba = array([message.message
                             for message in run.messages if message.source == 'Bob'])

        Z_a = run.endpoints[0].physics.random_values[:-1]
        Z_b = run.endpoints[1].physics.random_values[:-1]

        var_Za = var(Z_a)
        var_Zb = var(Z_b)


        est_gamma_a = mean(messages_ab[1:]*Z_b)/var_Zb*(1-ga*gb)
        est_gamma_b = mean(messages_ba*Z_a)/var_Za*(1-ga*gb)

        var_ab = var(messages_ab)
        var_ba = var(messages_ab)

        correlation_ab_ba = mean(messages_ab[1:]*messages_ba)

        print est_gamma_a, ga

        # Check the estimated reflection coefficients.
        self.assertLessEqual(abs(
            est_gamma_a - link.physics_A.reflection_coefficient), 0.1)

        self.assertLessEqual(abs(
            est_gamma_b - link.physics_B.reflection_coefficient), 0.1)

        # Check the message variances.
        self.assertLessEqual(abs(
            var_ab - (var_Za + gb**2*var_Zb)/(1-ga*gb)**2
        ), 0.1*var_ab)

        self.assertLessEqual(abs(
            var_ba - (ga**2*var_Za + var_Zb)/(1-ga*gb)**2
        ), 0.1*var_ba)

        # Check the message autocorrelation
        self.assertLessEqual(abs(
            correlation_ab_ba - (gb*var_Za + ga*var_Zb)/(1-ga*gb)**2
        ), max(1e-2, abs(0.1*(gb*var_Za + ga*var_Zb)/(1-ga*gb)**2)))



if __name__ == '__main__':
    suite = unittest.TestSuite([
        unittest.TestLoader().loadTestsFromTestCase(CorrelationTestWideband),
        unittest.TestLoader().loadTestsFromTestCase(CorrelationTestNarrowband)
        ])
    unittest.TextTestRunner(verbosity=2).run(suite)