#!/usr/bin/env python

import copy
from . import endpoint


try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET


class Session(object):
    def __init__(self, linktype):
        self.runs = []
        self.linktype = linktype

    def add_run(self, run):
        self.runs.append(run)

    @property
    def xml(self):
        result = """<?xml version='1.0'?>

<session link='%s' xmlns='http://www.example.org/liuproto'>
""" % self.linktype
        for run in self.runs:
            result += '\t' + '\n\t'.join(run.xml.split('\n')) + "\n"

        result += '</session>'

        return result

    @staticmethod
    def from_xml(element):
        result = Session(element.attrib['link'])
        for run in element:
            result.add_run(Run.from_xml(run))

        return result

    @staticmethod
    def from_file(filename):
        tree = ET.ElementTree(file=filename)
        return Session.from_xml(tree.getroot())


class Run(object):
    def __init__(self, id, alice=None, bob=None):
        self.id = id
        self.messages = []
        self.endpoints = []
        self.results = []

        if alice is not None:
            self.endpoints.append(alice)
        if bob is not None:
            self.endpoints.append(bob)

    def add_message(self, m):
        self.messages.append(m)

    def add_result(self, result):
        self.results.append(result)

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

    @staticmethod
    def from_xml(element):
        run = Run(int(element.attrib['id']))

        for child in element:
            if child.tag == '{http://www.example.org/liuproto}endpoint':
                run.endpoints.append(Endpoint.from_xml(child))
            elif child.tag == '{http://www.example.org/liuproto}message':
                run.add_message(Message.from_xml(child))
            elif child.tag == '{http://www.example.org/liuproto}result':
                run.add_result(Result.from_xml(child))

        return run


class Endpoint(object):
    def __init__(self, endpoint_id, physics):
        self.id = endpoint_id
        self.physics = copy.deepcopy(physics)

    @property
    def xml(self):
        result = """<endpoint
    id="%s"
    reflection_coefficient="%f"
    cutoff="%f"
    ramp_time="%d"
    resolution="%f"
    masking_time="%d"
    masking_magnitude="%f">\n\t""" % (
            self.id,
            self.physics.reflection_coefficient,
            self.physics.cutoff,
            self.physics.ramp_time,
            self.physics.resolution,
            self.physics.masking_time,
            self.physics.masking_magnitude)

        result += ' '.join([str(x) for x in self.physics.random_values])

        result += '\n</endpoint>'
        return result

    @staticmethod
    def from_xml(element):
        randomness = element.text.split()

        physics = endpoint.Physics(
            len(randomness)-1,
            float(element.attrib['reflection_coefficient']),
            float(element.attrib['cutoff']),
            int(element.attrib['ramp_time']),
            float(element.attrib['resolution']),
            int(element.attrib['masking_time']),
            float(element.attrib['masking_magnitude']))

        # These needs to be set manually, because Endpoint randomises the
        # sign of the reflection coefficient.
        physics.reflection_coefficient =\
            float(element.attrib['reflection_coefficient'])

        physics.random_values = [float(x) for x in randomness]

        return Endpoint(element.attrib['id'], physics)


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

    @staticmethod
    def from_xml(element):
        return Message(
            element.attrib['from'],
            element.attrib['to'],
            float(element.text))


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

    @staticmethod
    def from_xml(element):
        if element.text is None:
            result = None
        elif element.text.strip() in ['0','1']:
            result = int(element.text)
        elif element.text.strip().lower() in ['true', 'false']:
            result = bool(element.text)

        return Result(
            element.attrib['endpoint'],
            result
        )
