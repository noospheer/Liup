#!/usr/bin/env python

import argparse

import liuproto.endpoint
import liuproto.internallink

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
    def __eq__(self, other):
        return other > 0

    def __str__(self):
        return 'positive integer'

    def __repr__(self):
        return 'positive integers'

if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument(
        '-n', '--exchanges',
        type=int,
        help="The number of exchanges to simulate.",
        default=1,
        choices=[Positives()])

    parser.add_argument(
        '-fs', '--cutoff',
        type=float,
        help="The cutoff digital frequency of the input processes.",
        default=0.5,
        choices=[Range(0, 0.5, precision=1)])


    args = parser.parse_args()

    print args.cutoff