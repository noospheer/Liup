#!/usr/bin/env python

"""Compact binary wire format for streaming Liu protocol exchanges.

Replaces JSON float encoding (~20 bytes per value) with fixed-point
binary encoding (~2 bytes per value), reducing wire overhead from
~12.6 bits per secure key bit to ~3.1 bits per secure key bit.

Each exchange frame is exactly 4 bytes: 2 bytes for the mod-p wire
value and 2 bytes for the authenticated real value.
"""

import struct


class WireCodec:
    """Fixed-point binary encoder/decoder for Liu protocol wire values.

    Parameters
    ----------
    modulus : float
        The mod-p wrapping period.  Wire values lie in (-p/2, p/2].
    wire_bits : int
        Bits for encoding wire values (default 16).
    auth_bits : int
        Bits for encoding authenticated real values (default 16).
    auth_range : float
        Symmetric range for auth values: [-auth_range, auth_range]
        (default 2.0).
    """

    def __init__(self, modulus, wire_bits=16, auth_bits=16, auth_range=2.0):
        self.modulus = modulus
        self.wire_bits = wire_bits
        self.auth_bits = auth_bits
        self.auth_range = auth_range

        self._wire_max = 2 ** wire_bits - 1
        self._auth_max = 2 ** (auth_bits - 1) - 1  # signed range

    def encode(self, value):
        """Encode a mod-p wire value to bytes.

        Maps value in (-p/2, p/2] to an unsigned integer in [0, 2^wire_bits - 1].

        Parameters
        ----------
        value : float
            Wire value in (-p/2, p/2].

        Returns
        -------
        bytes
            Encoded wire value (2 bytes, big-endian unsigned).
        """
        p = self.modulus
        # Map (-p/2, p/2] -> [0, 1)
        normalized = (value + p / 2.0) / p
        # Clamp to valid range
        normalized = max(0.0, min(normalized, 1.0 - 1e-15))
        uint_val = int(normalized * (self._wire_max + 1))
        uint_val = max(0, min(self._wire_max, uint_val))
        return struct.pack('>H', uint_val)

    def decode(self, data):
        """Decode bytes back to a mod-p wire value.

        Parameters
        ----------
        data : bytes
            Encoded wire value (2 bytes, big-endian unsigned).

        Returns
        -------
        float
            Decoded wire value in (-p/2, p/2].
        """
        uint_val = struct.unpack('>H', data)[0]
        p = self.modulus
        normalized = uint_val / (self._wire_max + 1)
        return normalized * p - p / 2.0

    def encode_auth(self, real_value):
        """Encode an authenticated real value to bytes.

        Maps value in [-auth_range, auth_range] to a signed 16-bit integer.

        Parameters
        ----------
        real_value : float
            The real (unwrapped) value to encode.

        Returns
        -------
        bytes
            Encoded auth value (2 bytes, big-endian signed).
        """
        clamped = max(-self.auth_range, min(self.auth_range, real_value))
        normalized = clamped / self.auth_range  # [-1, 1]
        int_val = int(normalized * self._auth_max)
        int_val = max(-self._auth_max, min(self._auth_max, int_val))
        return struct.pack('>h', int_val)

    def decode_auth(self, data):
        """Decode bytes back to an authenticated real value.

        Parameters
        ----------
        data : bytes
            Encoded auth value (2 bytes, big-endian signed).

        Returns
        -------
        float
            Decoded real value.
        """
        int_val = struct.unpack('>h', data)[0]
        return (int_val / self._auth_max) * self.auth_range

    def encode_frame(self, wire_value, real_value):
        """Encode a complete exchange frame (wire + auth).

        Parameters
        ----------
        wire_value : float
            Mod-p wire value.
        real_value : float
            Authenticated real value.

        Returns
        -------
        bytes
            4-byte frame (2 wire + 2 auth).
        """
        return self.encode(wire_value) + self.encode_auth(real_value)

    def decode_frame(self, data):
        """Decode a complete exchange frame.

        Parameters
        ----------
        data : bytes
            4-byte frame.

        Returns
        -------
        tuple
            (wire_value, real_value)
        """
        return self.decode(data[:2]), self.decode_auth(data[2:4])

    def encode_wire(self, wire_value):
        """Encode only the wire value (2 bytes).

        Parameters
        ----------
        wire_value : float
            Mod-p wire value.

        Returns
        -------
        bytes
            2-byte encoded wire value.
        """
        return self.encode(wire_value)

    def decode_wire(self, data):
        """Decode only the wire value (2 bytes).

        Parameters
        ----------
        data : bytes
            Encoded wire value (2 bytes).

        Returns
        -------
        float
            Decoded wire value.
        """
        return self.decode(data)

    def encode_frame_encrypted(self, wire_value, real_value, cipher):
        """Encode frame with encrypted auth portion.

        The wire bytes (2 bytes) are sent in the clear.  The auth
        bytes (2 bytes) are encrypted with the provided cipher.

        Parameters
        ----------
        wire_value : float
            Mod-p wire value.
        real_value : float
            Authenticated real value.
        cipher : object
            Object with an ``encrypt(data) -> bytes`` method.

        Returns
        -------
        bytes
            4-byte frame (2 clear wire + 2 encrypted auth).
        """
        wire_bytes = self.encode(wire_value)
        auth_bytes = self.encode_auth(real_value)
        return wire_bytes + cipher.encrypt(auth_bytes)

    def decode_frame_encrypted(self, data, cipher):
        """Decode frame with encrypted auth portion.

        Parameters
        ----------
        data : bytes
            4-byte frame.
        cipher : object
            Object with a ``decrypt(data) -> bytes`` method.

        Returns
        -------
        tuple
            (wire_value, real_value)
        """
        wire_val = self.decode(data[:2])
        auth_val = self.decode_auth(cipher.decrypt(data[2:4]))
        return wire_val, auth_val

    @property
    def frame_size(self):
        """Size of one exchange frame in bytes."""
        return 4
