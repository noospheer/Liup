#!/usr/bin/env python3

"""Test the correlation coefficients of the protocol implementation.
"""

import liuproto.storage, liuproto.link, liuproto.endpoint
import numpy as np
import unittest

Gamma = 0.9


class CorrelationTestWideband(unittest.TestCase):
    def test_wideband(self):
        p = liuproto.endpoint.Physics(100000, Gamma, 0.5, 10, 0, 3, 1.0/4096)
        storage = liuproto.storage.Session('internal')
        link = liuproto.link.InternalLink(p, storage=storage)

        link.run_proto()

        run = storage.runs[0]

        messages_ab = np.array([message.message
                        for message in run.messages if message.source == 'Alice'])

        messages_ba = np.array([message.message
                        for message in run.messages if message.source == 'Bob'])

        Z_a = run.endpoints[0].physics.random_values[:-1]
        Z_b = run.endpoints[1].physics.random_values[:-1]

        est_gamma_a = np.mean(messages_ab[1:]*Z_b)/np.var(Z_b)
        est_gamma_b = np.mean(messages_ba*Z_a)/np.var(Z_a)

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
        p = liuproto.endpoint.Physics(100000, Gamma, 0.005, 10, 0, 3, 1.0/4096)
        storage = liuproto.storage.Session('internal')
        link = liuproto.link.InternalLink(p, storage=storage)

        link.physics_A.no_reset = True
        link.physics_B.no_reset = True

        link.physics_A.reflection_coefficient = ga
        link.physics_B.reflection_coefficient = gb

        link.run_proto()

        run = storage.runs[0]

        messages_ab = np.array([message.message
                             for message in run.messages if message.source == 'Alice'])

        messages_ba = np.array([message.message
                             for message in run.messages if message.source == 'Bob'])

        Z_a = run.endpoints[0].physics.random_values[:-1]
        Z_b = run.endpoints[1].physics.random_values[:-1]

        var_Za = np.var(Z_a)
        var_Zb = np.var(Z_b)


        est_gamma_a = np.mean(messages_ab[1:]*Z_b)/var_Zb*(1-ga*gb)
        est_gamma_b = np.mean(messages_ba*Z_a)/var_Za*(1-ga*gb)

        var_ab = np.var(messages_ab)
        var_ba = np.var(messages_ab)

        correlation_ab_ba = np.mean(messages_ab[1:]*messages_ba)

        print(est_gamma_a, ga)

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


class ModularProtocolTest(unittest.TestCase):
    """Test the modular reduction protocol."""

    def test_modular_ber(self):
        """Verify BER is reasonable with modulus enabled."""
        p = liuproto.endpoint.Physics(
            100, 0.8, 0.5, 10, 0, 3, 1.0/4096, modulus=5.0)
        link = liuproto.link.InternalLink(p)

        results = [link.run_proto() for _ in range(200)]
        errors = sum(1 for r in results if r is not None and r[0] != r[1])
        ber = float(errors) / len(results)
        print("Modular BER: %e" % ber)
        self.assertLess(ber, 0.15,
            "BER too high with modulus: %e" % ber)

    def test_classic_backward_compat(self):
        """Verify that modulus=0 gives same behavior as classic mode."""
        p = liuproto.endpoint.Physics(
            100, 0.5, 0.5, 10, 0, 3, 1.0/4096, modulus=0)
        link = liuproto.link.InternalLink(p)

        results = [link.run_proto() for _ in range(200)]
        errors = sum(1 for r in results if r is not None and r[0] != r[1])
        ber = float(errors) / len(results)
        print("Classic BER (modulus=0): %e" % ber)
        self.assertLess(ber, 0.15,
            "Classic mode BER too high: %e" % ber)

    def test_eve_crosscorrelation_fails(self):
        """Simulate Eve's cross-correlation attack; modulus should defeat it.

        Eve observes the mod-p reduced messages on the wire and tries to
        estimate the sign of alpha via cross-correlation of consecutive
        messages. With modulus, her accuracy should be near 50% (random).
        """
        n_exchanges = 100
        modulus = 5.0
        n_trials = 200
        eve_correct = 0

        for _ in range(n_trials):
            p = liuproto.endpoint.Physics(
                n_exchanges, 0.8, 0.5, 10, 0, 3, 1.0/4096, modulus=modulus)
            link = liuproto.link.InternalLink(p)

            # Record sign of alpha before reset
            link.physics_A.no_reset = True
            link.physics_B.no_reset = True
            link.physics_A.reset()
            link.physics_B.reset()

            true_sign_a = link.physics_A.reflection_coefficient > 0

            # Run the protocol, collecting wire messages (mod-p values)
            messages = []
            messages.append(link.physics_A.exchange(0.0))
            for i in range(n_exchanges):
                messages.append(link.physics_B.exchange(messages[-1]))
                messages.append(link.physics_A.exchange(messages[-1]))

            # Eve's attack: cross-correlate consecutive messages
            wire = np.array(messages)
            eve_corr = np.mean(wire[1:] * wire[:-1])

            # Eve guesses sign based on correlation
            eve_guess = eve_corr > 0

            # Check against the actual product of signs
            actual_product_positive = (
                link.physics_A.reflection_coefficient *
                link.physics_B.reflection_coefficient) > 0

            if eve_guess == actual_product_positive:
                eve_correct += 1

        eve_accuracy = float(eve_correct) / n_trials
        print("Eve accuracy with modulus: %.3f" % eve_accuracy)
        # Eve should be near chance (0.5). Allow generous margin.
        self.assertLess(eve_accuracy, 0.7,
            "Eve's accuracy too high (%.3f) — modulus not providing security" % eve_accuracy)

    def test_auto_modulus_ber(self):
        """Verify BER is reasonable with auto-calibrated modulus."""
        p = liuproto.endpoint.Physics(
            100, 0.8, 0.5, 10, 0, 3, 1.0/4096, modulus='auto')
        # Verify modulus was computed (not the string 'auto')
        self.assertIsInstance(p.modulus, float)
        self.assertGreater(p.modulus, 0)
        print("Auto-calibrated modulus: %.4f" % p.modulus)

        link = liuproto.link.InternalLink(p)
        results = [link.run_proto() for _ in range(200)]
        errors = sum(1 for r in results if r is not None and r[0] != r[1])
        ber = float(errors) / len(results)
        print("Auto-modulus BER: %e" % ber)
        self.assertLess(ber, 0.15,
            "BER too high with auto modulus: %e" % ber)

    def test_auto_modulus_json_roundtrip(self):
        """Auto-calibrated modulus should serialize as numeric in JSON."""
        p = liuproto.endpoint.Physics(
            100, 0.8, 0.5, 10, 0, 3, 1.0/4096, modulus='auto')
        json_str = p.to_json()
        p2 = liuproto.endpoint.Physics.from_json(json_str)
        self.assertAlmostEqual(p.modulus, p2.modulus, places=10)

    def test_ramp_exclusion_present(self):
        """Verify ramp exclusion threshold is computed."""
        p = liuproto.endpoint.Physics(
            100, 0.8, 0.5, 10, 0, 3, 1.0/4096, modulus=5.0,
            ramp_exclusion_factor=3.0)
        self.assertEqual(p._exclusion_threshold, 30)

    def test_leakage_report_available(self):
        """Verify leakage_report() works on a modular endpoint."""
        p = liuproto.endpoint.Physics(
            100, 0.8, 0.5, 10, 0, 3, 1.0/4096, modulus='auto')
        report = p.leakage_report()
        self.assertIn('total_eve_information_bits', report)
        self.assertGreater(report['modulus'], 0)


if __name__ == '__main__':
    suite = unittest.TestSuite([
        unittest.TestLoader().loadTestsFromTestCase(CorrelationTestWideband),
        unittest.TestLoader().loadTestsFromTestCase(CorrelationTestNarrowband),
        unittest.TestLoader().loadTestsFromTestCase(ModularProtocolTest),
        ])
    unittest.TextTestRunner(verbosity=2).run(suite)
