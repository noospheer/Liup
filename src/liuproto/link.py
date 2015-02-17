#!/usr/bin/env python

import endpoint
import SocketServer
import socket
import json
import sys


class InternalLink(object):
    """A link controller for two endpoints in the same process."""
    def __init__(self, physics):
        self.physics_A = physics
        self.physics_B = endpoint.Physics.from_json(physics.to_json())
        self.messages = []

    def run_proto(self):
        """Run a single iteration of the protocol."""

        self.physics_A.reset()
        self.physics_B.reset()

        self.messages = []

        self.messages.append(self.physics_A.exchange(0.0))

        for i in range(self.physics_A.number_of_exchanges):
            self.messages.append(self.physics_B.exchange(self.messages[-1]))
            self.messages.append(self.physics_A.exchange(self.messages[-1]))

        if not (self.physics_A.estimate_other()
                    ^ (self.physics_A.reflection_coefficient > 0)):
            return None

        elif not (self.physics_B.estimate_other()
                    ^ (self.physics_B.reflection_coefficient > 0)):
            return None

        else:
            return (not self.physics_A.estimate_other(),
                    self.physics_B.estimate_other())


class NetworkLinkRequestHandler(SocketServer.BaseRequestHandler):
    """A server implementing the Liu protocol over the network"""

    def handle(self):
        self.server.physics = []

        while True:

            config = self.__read_json_string()

            if config == '{}':
                return

            self.request.send('{}')

            # Now that we have a valid configuration string, produce our
            # endpoint.
            physics = endpoint.Physics.from_json(config)

            # Finally, run the protocol.
            for i in range(physics.number_of_exchanges):
                message = json.loads(self.__read_json_string())
                result = physics.exchange(message['message'])
                sys.stdout.flush()
                message_out = json.dumps({'message': result})
                self.request.send(message_out)

            message = json.loads(self.__read_json_string())
            physics.exchange(message['message'])
            self.request.send('{}')

            if physics.estimate_other() != (physics.reflection_coefficient > 0):
                self.server.physics.append(physics.estimate_other())
            else:
                self.server.physics.append(None)

    def __read_json_string(self):
        json_string = ''

        # Keep reading until we have a valid JSON string.
        while True:
            try:
                json_string += self.request.recv(1024)
                json.loads(json_string)
                break
            except ValueError:
                pass

        return json_string


class NetworkServerLink(object):
    """ A link class for a network-accessible server."""
    def __init__(self, address):
        self.server = SocketServer.TCPServer(address, NetworkLinkRequestHandler)
        self.server.physics = []

    def run_proto(self):
        self.server.handle_request()

        return self.server.physics


class NetworkClientLink(object):
    """A client-side link class."""
    def __init__(self, address, physics):
        self.address = address
        self.physics = physics
        self.client_socket = socket.socket()
        self.client_socket.connect(self.address)

    def run_proto(self):
        self.physics.reset()

        self.client_socket.send(self.physics.to_json())
        self.__read_json_string(self.client_socket)

        self.client_socket.send(json.dumps({'message': self.physics.exchange(0.0)}))
        for i in range(self.physics.number_of_exchanges):
            message = json.loads(self.__read_json_string(self.client_socket))
            self.client_socket.send(json.dumps({
                'message': self.physics.exchange(message['message'])}))

        self.__read_json_string(self.client_socket)

        if self.physics.estimate_other() \
                == (self.physics.reflection_coefficient > 0):

            return None
        else:
            return self.physics.reflection_coefficient > 0

    def close(self):
        self.client_socket.send('{}')
        self.client_socket.close()

    def __read_json_string(self, client_socket):
        json_string = ''

        # Keep reading until we have a valid JSON string.
        while True:
            json_string += client_socket.recv(1024)
            try:
                json.loads(json_string)
                break
            except ValueError:
                pass

        return json_string