# This file is part of MAST-F's Core API
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
from __future__ import annotations

from typing import Generator, Any

def parse_name(full_name: str) -> tuple[str, str]:
    if not full_name:
        return None, None

    if "::" in full_name:  # group id :: artifact id
        gid, aid = full_name.split("::")
        return (gid, aid)

    if ":" in full_name:  # group id : artifact id
        gid, aid = full_name.split(":")
        return (gid, aid)

    if "-" in full_name:  # artifact id
        return None, full_name

    # only groupId
    return full_name, None


class TPL:
    def __init__(self, file_path: str) -> None:
        self.source = file_path
        self.__fp = None

    def __enter__(self) -> None:
        self.start()

    def __exit__(self, *args, **kwargs) -> None:
        if self.__fp and not self.__fp.closed:
            self.__fp.close()

    def start(self) -> None:
        if not self.__fp:
            self.__fp = open(self.source, "rb")

    def __iter__(self) -> Generator[tuple[str, str], Any, None]:
        line = self.__fp.readline()
        while line:
            if isinstance(line, (bytearray, bytes)):
                line = line.decode(errors="replace")

            # Structure of the third_party_license metadata file
            #  [start]:[end] NAME
            _, name = line.split(" ", 1)
            if any(map(lambda x: x.isupper(), name)):
                # groupid or artifactId doesn't contain upper case letters
                continue

            if " " not in name:
                gid, aid = parse_name(name)
                if gid and aid:
                    yield gid, aid
