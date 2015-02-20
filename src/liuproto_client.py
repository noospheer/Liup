#!/usr/bin/env python

import argparse
import sys

import liuproto.endpoint
import liuproto.link
import liuproto.storage


class RangeFloat(object):
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


class RangeInteger(object):
    def __init__(self, start, end):
        self.start = start
        self.end = end
        self.format = '%d--%d'

    def __eq__(self, other):
        return self.start <= other <= self.end

    def __str__(self):
        return (self.format % (self.start, self.end)) + ' inclusive'

    def __repr__(self):
        return self.format % (self.start, self.end)


class Positives(object):
    def __init__(self, type='integer'):
        self.type = type

    def __eq__(self, other):
        return other > 0

    def __str__(self):
        return 'positive %s' % self.type

    def __repr__(self):
        return 'positive %ss' % self.type

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
        choices=[RangeFloat(0, 1, precision=1)])

    parser.add_argument(
        '-fs', '--cutoff',
        type=float,
        help="The digital cutoff frequency of the input processes.",
        default=0.5,
        choices=[RangeFloat(0, 0.5, precision=1)])

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
        choices=[Positives('float')])

    parser.add_argument(
        '-r', '--repetitions',
        type=int,
        help="The number of times to run the protocol.",
        default=1,
        choices=[Positives()])

    parser.add_argument(
        '-a', '--address',
        type=str,
        help="The address to which to connect.")

    parser.add_argument(
        '-p', '--port',
        type=int,
        help="The port to which to connect.",
        default=8888,
        choices=[RangeInteger(1, 65535)])

    parser.add_argument(
        '-x', '--xml',
        help="Produce output in XML format.",
        action='store_true'
    )

    args = parser.parse_args()

    storage = liuproto.storage.Session('client')

    physics = liuproto.endpoint.Physics(args.exchanges, args.reflection_coefficient, args.cutoff, args.ramptime, args.resolution)
    link = liuproto.link.NetworkClientLink(
        (args.address, args.port),
        physics,
        storage=storage)

    results = []
    for i in range(args.repetitions):
        results.append(link.run_proto())

    link.close()

    if args.xml:
        print storage.xml
    else:
        for bit in results:
            if bit is None:
                continue

            if bit:
                sys.stdout.write('1')
            else:
                sys.stdout.write('0')

        sys.stdout.write("\n")