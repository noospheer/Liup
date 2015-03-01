#!/usr/bin/env python

"""Test the correlation coefficients of the protocol implementation.
"""

import liuproto.storage, liuproto.link, liuproto.endpoint
from pylab import *
import unittest

Gamma = 0.9


class CorrelationTest(unittest.TestCase):
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

    def test_narrowband(self):
        self.narrowband_test(+Gamma, -Gamma)
        self.narrowband_test(-Gamma, +Gamma)
        self.narrowband_test(+Gamma, +Gamma)
        self.narrowband_test(-Gamma, -Gamma)

    def narrowband_test(self, ga, gb):
        p = liuproto.endpoint.Physics(50000, Gamma, 0.005, 10, 0)
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

        est_gamma_a = mean(messages_ab[1:]*Z_b)/var(Z_b)*(1-ga*gb)
        est_gamma_b = mean(messages_ba*Z_a)/var(Z_a)*(1-ga*gb)

        self.assertLessEqual(abs(
            est_gamma_a - link.physics_A.reflection_coefficient), 0.1)

        self.assertLessEqual(abs(
            est_gamma_b - link.physics_B.reflection_coefficient), 0.1)

if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(CorrelationTest)
    unittest.TextTestRunner(verbosity=2).run(suite)