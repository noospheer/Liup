#!/usr/bin/env python3

import argparse
import json

import liuproto.endpoint
import liuproto.link
import liuproto.storage


def parse_modulus(value):
    """Parse modulus argument: '0', 'auto', or a positive float."""
    if value.lower() == 'auto':
        return 'auto'
    f = float(value)
    if f < 0:
        raise argparse.ArgumentTypeError("modulus must be >= 0 or 'auto'")
    return f


class Range(object):
    def __init__(self, start, end, precision=None):
        self.start = start
        self.end = end
        if precision is None:
            self.format = '%f--%f'
        else:
            self.format = '%%.%df--%%.%df' % (precision, precision)

    def __eq__(self, other):
        return self.start <= other <= self.end

    def __str__(self):
        return (self.format % (self.start, self.end)) + ' inclusive'

    def __repr__(self):
        return (self.format % (self.start, self.end))


class Positives(object):
    def __init__(self, type='integer', zero=False):
        self.type = type
        self.zero = zero
        if self.zero:
            self.desc = 'non-negative'
        else:
            self.desc = 'positive'

    def __eq__(self, other):
        if self.zero:
            return other >= 0
        else:
            return other > 0

    def __str__(self):
        return '%s %s' % (self.desc, self.type)

    def __repr__(self):
        return '%s %ss' % (self.desc, self.type)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument(
        '-n', '--exchanges',
        type=int,
        help="The number of exchanges to simulate.",
        default=10,
        choices=[Positives()])

    parser.add_argument(
        '-rc', '--reflection-coefficient',
        type=float,
        help="The magnitude of the reflection coefficient.",
        default=0.5,
        choices=[Range(0, 1, precision=1)])

    parser.add_argument(
        '-fs', '--cutoff',
        type=float,
        help="The digital cutoff frequency of the input processes.",
        default=0.5,
        choices=[Range(0, 0.5, precision=1)])

    parser.add_argument(
        '-tr', '--ramptime',
        type=float,
        help="The length of time over which the parameters are ramped up.",
        default=1,
        choices=[Positives()])

    parser.add_argument(
        '-R', '--resolution',
        type=float,
        help="The message quantisation resolution.",
        default=0,
        choices=[Positives('float', True)])

    parser.add_argument(
        '-r', '--repetitions',
        type=int,
        help="The number of times to run the protocol.",
        default=1,
        choices=[Positives()])

    parser.add_argument(
        '-x', '--xml',
        help="Produce output in XML format.",
        action='store_true'
    )

    parser.add_argument(
        '-t', '--masking-time',
        help="Add masking noise at the last N samples of the ramp.",
        type=float,
        default=0
    )

    parser.add_argument(
        '-M', '--masking-magnitude',
        help="The magnitude of the masking noise added with -mt.",
        type=float,
        default=1.0/4096
    )

    parser.add_argument(
        '-m', '--modulus',
        help="Modular reduction modulus p (0 = classic, 'auto' = calibrated).",
        type=parse_modulus,
        default=0
    )

    parser.add_argument(
        '--leakage-report',
        help="Print leakage analysis after run.",
        action='store_true'
    )

    parser.add_argument(
        '--privacy-amplification',
        help="Apply privacy amplification to batch and report key lengths.",
        action='store_true'
    )

    args = parser.parse_args()

    if args.xml:
        storage = liuproto.storage.Session('internal')
    else:
        storage = None

    physics = liuproto.endpoint.Physics(
        args.exchanges, args.reflection_coefficient, args.cutoff,
        args.ramptime, args.resolution, args.masking_time,
        args.masking_magnitude, modulus=args.modulus)
    link = liuproto.link.InternalLink(physics, storage=storage)

    if args.privacy_amplification:
        secure_a, secure_b, n_raw, n_secure = \
            link.run_batch_with_privacy(args.repetitions)
        errors = sum(1 for a, b in zip(secure_a, secure_b) if a != b)
        print('Raw bits: %d' % n_raw)
        print('Secure bits: %d' % n_secure)
        if n_secure > 0:
            print('Secure BER: %e' % (float(errors) / n_secure))
            print('Secure key (Alice): %s' % ''.join(str(b) for b in secure_a))
            print('Secure key (Bob):   %s' % ''.join(str(b) for b in secure_b))
        else:
            print('Not enough raw bits for privacy amplification.')
    else:
        results = []
        for i in range(args.repetitions):
            results.append(link.run_proto())

        if args.xml:
            print(storage.xml)
        else:
            errors = len([1 for x in results if x is not None and x[0] != x[1]])
            if len(results) > 0:
                print('BER: %e' % (float(errors)/len(results)))
            else:
                print('No successful exchanges.')

    if args.leakage_report:
        if physics.modulus > 0:
            report = physics.leakage_report()
            print('\n--- Leakage Report ---')
            for key, val in report.items():
                print('  %s: %s' % (key, val))
        else:
            print('\nLeakage report requires modulus > 0.')
