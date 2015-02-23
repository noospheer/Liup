#!/usr/bin/env python

import argparse

import liuproto.endpoint
import liuproto.link
import liuproto.storage


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

    args = parser.parse_args()

    storage = liuproto.storage.Session('internal')

    physics = liuproto.endpoint.Physics(args.exchanges, args.reflection_coefficient, args.cutoff, args.ramptime, args.resolution)
    link = liuproto.link.InternalLink(physics, storage=storage)

    results = []
    for i in range(args.repetitions):
        results.append(link.run_proto())

    if args.xml:
        print storage.xml
    else:
        errors = len([1 for x in results if x is not None and x[0] != x[1]])
        if len(results) > 0:
            print 'BER: %e' % (float(errors)/len(results))
        else:
            print 'No successful exchanges.'