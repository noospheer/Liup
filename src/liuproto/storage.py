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
        root = ET.Element('session', attrib={
            'link': self.linktype,
            'xmlns': 'http://www.example.org/liuproto'
        })
        for run in self.runs:
            run.to_xml_element(root)
        return "<?xml version='1.0'?>\n\n" + ET.tostring(root, encoding='unicode')

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

    def to_xml_element(self, parent):
        run_elem = ET.SubElement(parent, 'run', attrib={'id': str(self.id)})
        for ep in self.endpoints:
            ep.to_xml_element(run_elem)
        for message in self.messages:
            message.to_xml_element(run_elem)
        for this_result in self.results:
            this_result.to_xml_element(run_elem)
        return run_elem

    @property
    def xml(self):
        elem = ET.Element('_dummy')
        self.to_xml_element(elem)
        return ET.tostring(list(elem)[0], encoding='unicode')

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

    def to_xml_element(self, parent):
        attribs = {
            'id': self.id,
            'reflection_coefficient': '%f' % self.physics.reflection_coefficient,
            'cutoff': '%f' % self.physics.cutoff,
            'ramp_time': '%d' % self.physics.ramp_time,
            'resolution': '%f' % self.physics.resolution,
            'masking_time': '%d' % self.physics.masking_time,
            'masking_magnitude': '%f' % self.physics.masking_magnitude,
        }
        if self.physics.modulus > 0:
            attribs['modulus'] = '%f' % self.physics.modulus
        if hasattr(self.physics, 'ramp_exclusion_factor') and \
                self.physics.ramp_exclusion_factor != 3.0:
            attribs['ramp_exclusion_factor'] = '%f' % self.physics.ramp_exclusion_factor
        elem = ET.SubElement(parent, 'endpoint', attrib=attribs)
        elem.text = ' '.join([str(x) for x in self.physics.random_values])
        return elem

    @property
    def xml(self):
        parent = ET.Element('_dummy')
        self.to_xml_element(parent)
        return ET.tostring(list(parent)[0], encoding='unicode')

    @staticmethod
    def from_xml(element):
        randomness = element.text.split()

        modulus = float(element.attrib.get('modulus', 0))
        ramp_exclusion_factor = float(
            element.attrib.get('ramp_exclusion_factor', 3.0))

        physics = endpoint.Physics(
            len(randomness)-1,
            float(element.attrib['reflection_coefficient']),
            float(element.attrib['cutoff']),
            int(element.attrib['ramp_time']),
            float(element.attrib['resolution']),
            int(element.attrib['masking_time']),
            float(element.attrib['masking_magnitude']),
            modulus=modulus,
            ramp_exclusion_factor=ramp_exclusion_factor)

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

    def to_xml_element(self, parent):
        elem = ET.SubElement(parent, 'message', attrib={
            'from': self.source,
            'to': self.destination,
        })
        elem.text = '%f' % self.message
        return elem

    @property
    def xml(self):
        parent = ET.Element('_dummy')
        self.to_xml_element(parent)
        return ET.tostring(list(parent)[0], encoding='unicode')

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

    def to_xml_element(self, parent):
        attribs = {'endpoint': self.endpoint}
        elem = ET.SubElement(parent, 'result', attrib=attribs)
        if self.result is not None:
            elem.text = '%d' % self.result
        return elem

    @property
    def xml(self):
        parent = ET.Element('_dummy')
        self.to_xml_element(parent)
        return ET.tostring(list(parent)[0], encoding='unicode')

    @staticmethod
    def from_xml(element):
        if element.text is None or not element.text.strip():
            result = None
        elif element.text.strip() in ['0', '1']:
            result = int(element.text)
        elif element.text.strip().lower() == 'true':
            result = True
        elif element.text.strip().lower() == 'false':
            result = False
        else:
            result = None

        return Result(
            element.attrib['endpoint'],
            result
        )
