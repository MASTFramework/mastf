# This file is part of MAST-F's iOS API
# Copyright (c) 2024 Mobile Application Security Testing Framework
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import socket
import os

import mastf.ios.swiftsrv_format as fmt
from caterpillar.shortcuts import unpack, pack

SRV_HOST_ADDRESS = os.environ.get("SWIFTSRV_HOST", "0.0.0.0")
SRV_PORT = os.environ.get("SWIFTSRV_PORT", 1298)

class Connection:
    def __init__(self, connect=False) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.is_connected = False
        if connect:
            self.connect()

    def demangle(self, name: bytes) -> str:
        if not name:
            return "<null>"

        if not self.is_connected:
            self.connect()

        fallback = name.decode(errors="replace")
        packet = fmt.packet_t(fmt.Operation.DEMANGLE, name, fmt.get_checksum(name))
        self.sock.sendall(pack(packet))

        try:
            response = unpack(fmt.packet_t, self.sock.recv(2048))
        except Exception:
            return fallback

        if not response.is_valid():
            return fallback

        return response.payload.decode(errors="replace")

    def connect(self, address = None) -> None:
        self.sock.connect(address or (SRV_HOST_ADDRESS, SRV_PORT))
        self.is_connected = True

    def close(self) -> None:
        if not self.is_connected:
            return

        self.sock.close()
        self.is_connected = False
