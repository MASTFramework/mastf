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
import enum
import zlib

from caterpillar.shortcuts import struct
from caterpillar.fields import uint8, uint32, Prefixed


class Operation(enum.IntEnum):
    __struct__ = uint8

    NOP = 0
    DEMANGLE = 1
    # here is place for other ops

    FAIL = 0xFF


def get_checksum(content: bytes) -> int:
    return zlib.crc32(content)


@struct
class packet_t:
    operation: Operation
    payload: Prefixed(uint32)
    checksum: uint32

    def is_valid(self) -> bool:
        return self.checksum == get_checksum(self.payload)
