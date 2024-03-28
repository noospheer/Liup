#!/usr/bin/env python3

import argparse
import sys

import liuproto.endpoint
import liuproto.link
import liuproto.storage


class PortRangeAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        min_port = 1
        max_port = 65535
        if not min_port <= values <= max_port:
            raise argparse.ArgumentTypeError(f"Port number must be between {min_port} and {max_port}")
        setattr(namespace, self.dest, values)



if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument(
        '-l', '--listen-address',
        type=str,
        help="The address upon which to listen.",
        default='0.0.0.0')

    parser.add_argument(
        '-p', '--port',
        type=int,
        help="The port upon which to listen.",
        default=8888,
        action=PortRangeAction
    )


    parser.add_argument(
        '-x', '--xml',
        help="Produce output in XML format.",
        action='store_true'
    )

    args = parser.parse_args()

    storage = liuproto.storage.Session('server')

    link = liuproto.link.NetworkServerLink(
        (args.listen_address, args.port),
        storage=storage)
    results = link.run_proto()

    link.close()

    if args.xml:
        print(storage.xml)
    else:
        for bit in results:
            if bit is None:
                continue

            if bit:
                sys.stdout.write('1')
            else:
                sys.stdout.write('0')

        sys.stdout.write("\n")
