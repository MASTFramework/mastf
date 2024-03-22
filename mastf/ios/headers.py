# This file is part of MAST-F's Frontend API
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
import pathlib

from umbrella.objc import ObjCMetadata, ObjCDumper
from umbrella.swift import ReflectionContext, SwiftDumper

from mastf.ios import swift_client


def export_objc(metadata: ObjCMetadata, dest: pathlib.Path) -> None:
    dp = ObjCDumper()
    for cls in metadata.classes:
        dest_file = dest / f"{cls.name}.m"
        if dest_file.exists():
            continue

        with open(str(dest_file), "w") as fp:
            dp.dump_class(cls, fp)


def export_swift(context: ReflectionContext, dest: pathlib.Path) -> None:
    dp = SwiftDumper()
    # This way we use our Swift server to demangle swift-related names
    conn = swift_client.Connection(connect=True)
    dp._demangle = conn.demangle
    for cls in context.classes():
        try:
            name = conn.demangle(cls.get_mangled_name().encode())
            parts = name.split(".")

            if len(parts) > 1:
                sub_path = "/".join(parts[:-1])
                dest_file = dest / sub_path / f"{parts[-1]}.swift"
            else:
                dest_file = dest / f"{parts[-1]}.swift"

            dest_file.parent.mkdir(parents=True, exist_ok=True)
            if dest_file.exists():
                continue

            with open(str(dest_file), "w") as fp:
                dp.dump_class(cls, fp)
        except Exception as e:
            continue
