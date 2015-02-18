#!/usr/bin/env python

import json
import sys


class Session(object):
    def __init__(self, linktype):
        self.runs = []
        self.linktype = linktype

    def add_run(self, run):
        self.runs.append(run)

    @property
    def xml(self):
        result = """<?xml version='1.0'?>

<session link='%s' xmlns='http://www.noosphere.org/liuproto'>
""" % self.linktype
        for run in self.runs:
            result += '\t' + '\n\t'.join(run.xml.split('\n')) + "\n"

        result += '</session>'

        return result


class Run(object):
    def __init__(self, id, alice, bob=None):
        self.id = id
        self.messages = []
        self.endpoints = [alice]
        self.results = []

        if bob is not None:
            self.endpoints.append(bob)

    def add_message(self, m):
        self.messages.append(m)

    def add_result(self, endpoint, result):
        self.results.append(Result(endpoint, result))

    @property
    def xml(self):
        result = '<run id="%d">\n' % self.id
        for endpoint in self.endpoints:
            result += "\t" + '\n\t'.join(endpoint.xml.split('\n')) + "\n"

        result += "\n"

        for message in self.messages:
            result += "\t" + '\n\t'.join(message.xml.split('\n')) + "\n"

        result += "\n"

        for this_result in self.results:
            result += "\t" + "\n\t".join(this_result.xml.split('\n')) + "\n"

        result += "</run>"

        return result


class Endpoint(object):
    def __init__(self, endpoint_id, config):
        self.id = endpoint_id
        self.config = json.loads(config)

    @property
    def xml(self):
        result = """<endpoint
    id="%s"
    reflection_coefficient="%f"
    cutoff="%f"
    ramp_time="%d" />""" % (
            self.id,
            self.config['reflection_coefficient'],
            self.config['cutoff'],
            self.config['ramp_time'])

        return result


class Message(object):
    def __init__(self, source, destination, message):
        self.source = source
        self.destination = destination
        self.message = message

    @property
    def xml(self):
        return '<message from="%s" to="%s">%f</message>' % (
            self.source,
            self.destination,
            self.message)


class Result(object):
    def __init__(self, endpoint, result):
        self.endpoint = endpoint
        self.result = result

    @property
    def xml(self):
        if self.result is not None:
            return '<result endpoint="%s">%d</result>' \
                   % (self.endpoint, self.result)
        else:
            return '<result endpoint="%s" />' % self.endpoint