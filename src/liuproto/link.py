#!/usr/bin/env python

"""Implements local and networked links for the Liu protocol implementation.
"""

from . import endpoint
import liuproto.storage as storage
import socketserver
import socket
import json
import sys


class InternalLink(object):
    """A link controller for two endpoints in the same process.

    Example: Run 100 iterations of the protocol and return the results

    >>> link = InternalLink(physics, storage)
    >>> results = [link.run_proto() for i in range(100)]"""
    def __init__(self, physics, storage=None):

        self.physics_config = physics.to_json()

        self.physics_A = physics
        self.physics_B = endpoint.Physics.from_json(self.physics_config)
        self.messages = []
        self.storage = storage

        self.run_count = 0

    def run_proto(self):
        """Run a single iteration of the protocol."""

        self.physics_A.reset()
        self.physics_B.reset()

        if self.storage is not None:
            this_run = storage.Run(
                self.run_count,
                storage.Endpoint('Alice', self.physics_A),
                storage.Endpoint('Bob', self.physics_B))

            self.run_count += 1

        self.messages = []

        self.messages.append(self.physics_A.exchange(0.0))
        if self.storage is not None:
            this_run.add_message(
                storage.Message('Alice', 'Bob', self.messages[-1]))

        for i in range(self.physics_A.number_of_exchanges):
            self.messages.append(self.physics_B.exchange(self.messages[-1]))
            self.messages.append(self.physics_A.exchange(self.messages[-1]))

            if self.storage is not None:
                this_run.add_message(
                    storage.Message('Bob', 'Alice', self.messages[-2]))
                this_run.add_message(
                    storage.Message('Alice', 'Bob', self.messages[-1]))

        if not (self.physics_A.estimate_other()
                    ^ (self.physics_A.reflection_coefficient > 0)):
            result = (None,None)

        elif not (self.physics_B.estimate_other()
                    ^ (self.physics_B.reflection_coefficient > 0)):
            result = (None,None)

        else:
            result = (not self.physics_A.estimate_other(),
                    self.physics_B.estimate_other())

        if self.storage is not None:
            this_run.add_result(storage.Result('Alice', result[0]))
            this_run.add_result(storage.Result('Bob', result[1]))
            self.storage.add_run(this_run)

        return result


class NetworkLinkRequestHandler(socketserver.BaseRequestHandler):
    """A server implementing the Liu protocol over the network"""

    def handle(self):
        self.server.physics = []

        run_number = 0
        while True:
            config = self.__read_json_string()

            if config == '{}':
                return

            # Send a response to the configuration string.
            self.request.send('{}'.encode('utf-8'))

            # Now that we have a valid configuration string, produce our
            # endpoint.
            physics = endpoint.Physics.from_json(config)
            if self.server.storage is not None:
                this_run = storage.Run(
                    run_number,
                    storage.Endpoint('Bob', physics))

                run_number += 1

            # Finally, run the protocol.
            for i in range(physics.number_of_exchanges):
                message = json.loads(self.__read_json_string())
                print("Received message:", message)  # Add this line to debug
                result = physics.exchange(message['message'])

                if self.server.storage is not None:
                    this_run.add_message(storage.Message('Alice', 'Bob', message['message']))
                    this_run.add_message(storage.Message('Bob', 'Alice', result))

                message_out = json.dumps({'message': result})
                self.request.send(message_out.encode('utf-8'))

            message = json.loads(self.__read_json_string())
            physics.exchange(message['message'])

            if self.server.storage is not None:
                this_run.add_message(storage.Message('Alice', 'Bob', message['message']))

            # We may now decide on whether to declare a zero, one, or erasure.
            if physics.estimate_other() != (physics.reflection_coefficient > 0):
                result = physics.estimate_other()
            else:
                result = None

            # Now that we have have decided whether or not to declare a bit,
            # we must agree this with the client.
            if result is None:
                self.request.send('{"decision":"discard"}'.encode('utf-8'))
            else:
                self.request.send('{"decision":"declare"}'.encode('utf-8'))

            message = json.loads(self.__read_json_string())

            if message['decision'] == 'discard':
                result = None

            self.server.physics.append(result)
            if self.server.storage is not None:
                this_run.add_result(storage.Result('Bob', result))
                self.server.storage.add_run(this_run)

            # Send the final response.
            self.request.send('{}'.encode('utf-8'))

    def __read_json_string(self):
        json_string = ''

        # Keep reading until we have a valid JSON string.
        while True:
            try:
                json_string += self.request.recv(1024).decode('utf-8')
                json.loads(json_string)
                break
            except ValueError:
                pass

        return json_string

class NetworkServerLink(object):
    """ A link class for a network-accessible server.

        Example: Wait for a connection and then return the session results:

        >>> link = NetworkServerLink(address, storage)
        >>> bits = link.run_proto()
    """
    def __init__(self, address, storage=None):
        self.server = socketserver.TCPServer(address, NetworkLinkRequestHandler)
        self.server.physics = []
        self.server.storage = storage

    def run_proto(self):
        self.server.handle_request()
        return self.server.physics

    def close(self):
        self.server.server_close()




class NetworkClientLink(object):
    """A client-side link class.

    Example: Run the protocol 100 times

    >>> link = NetworkClientLink(address, endpoint, storage)
    >>> bits = [link.run_proto() for i in range(100)]"""
    def __init__(self, address, physics, storage=None):
        self.address = address
        self.physics = physics
        self.storage = storage
        self.run_number = 0

        self.client_socket = socket.socket()
        self.client_socket.connect(self.address)

    def run_proto(self):
        self.physics.reset()

        if self.storage is not None:
            this_run = storage.Run(
                self.run_number,
                storage.Endpoint('Alice', self.physics))

            self.run_number += 1

        self.client_socket.send(self.physics.to_json().encode('utf-8'))
        self.__read_json_string(self.client_socket)

        message = self.physics.exchange(0.0)
        self.client_socket.send(json.dumps({'message': message}).encode('utf-8'))

        if self.storage is not None:
            this_run.add_message(storage.Message('Alice', 'Bob', message))

        for i in range(self.physics.number_of_exchanges):
            message = json.loads(self.__read_json_string(self.client_socket))
            response = self.physics.exchange(message['message'])

            self.client_socket.send(json.dumps({'message': response}).encode('utf-8'))

            if self.storage is not None:
                this_run.add_message(storage.Message('Bob', 'Alice', message['message']))
                this_run.add_message(storage.Message('Alice', 'Bob', response))

        if self.physics.estimate_other() \
                == (self.physics.reflection_coefficient > 0):
            result = None
        else:
            result = self.physics.reflection_coefficient > 0

        # Now that we have decided whether or not to declare a bit,
        # we must agree this with the client.
        message = json.loads(self.__read_json_string(self.client_socket))

        if result is None:
            self.client_socket.send('{"decision":"discard"}'.encode('utf-8'))
        else:
            self.client_socket.send('{"decision":"declare"}'.encode('utf-8'))

        if message['decision'] == 'discard':
            result = None

        if self.storage is not None:
            this_run.add_result(storage.Result('Alice', result))
            self.storage.add_run(this_run)

        # Read the final "resynchronising" response.
        self.__read_json_string(self.client_socket)

        return result

    def close(self):
        self.client_socket.send('{}'.encode('utf-8'))
        self.client_socket.close()

    def __read_json_string(self, client_socket):
        json_string = ''

        # Keep reading until we have a valid JSON string.
        while True:
            json_string += client_socket.recv(1024).decode('utf-8')
            try:
                json.loads(json_string)
                break
            except ValueError:
                pass

        return json_string
