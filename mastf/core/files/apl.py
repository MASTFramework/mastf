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

from io import IOBase, BytesIO, StringIO
from typing import List, Union, Optional
from dataclasses import dataclass, field

GROUP_TYPE = "group:"
UNGROUPED_TYPE = "ungrouped"
PERMISSION_TYPE = "permission:"


@dataclass
class PermissionDefItem:
    """
    Represents a permission definition item.

    :param identifier: Identifier of the permission.
    :param package: Package associated with the permission (optional).
    :param label: Label of the permission (optional).
    :param description: Description of the permission (optional).
    :param protectionLevel: List of protection levels for the permission (default: empty list).
    """

    identifier: str
    package: Optional[str] = None
    label: Optional[str] = None
    description: Optional[str] = None
    protectionLevel: List[str] = field(default_factory=list)


@dataclass
class GroupDefItem:
    """
    Represents a group definition item.

    :param identifier: Identifier of the group.
    :param package: Package associated with the group (optional).
    :param label: Label of the group (optional).
    :param description: Description of the group (optional).
    :param permissions: List of permissions in the group (default: empty list).
    """

    identifier: str
    package: Optional[str] = None
    label: Optional[str] = None
    description: Optional[str] = None
    permissions: List[PermissionDefItem] = field(default_factory=list)


@dataclass
class AppPermissionList:
    """
    Represents a list of app permissions.

    :param groups: List of group definitions (default: empty list).
    :param permissions: List of ungrouped permissions (default: empty list).
    """

    groups: List[GroupDefItem] = field(default_factory=list)
    permissions: List[PermissionDefItem] = field(default_factory=list)


def load(fp: IOBase) -> AppPermissionList:
    """
    Load app permission data from a file-like object.

    :param fp: File-like object containing the permission data.
    :return: AppPermissionList object representing the loaded data.
    """

    groups = []
    permissions = []
    current_group = None
    current = None

    for line in iter(lambda: fp.readline(), b""):
        if not line:
            break

        if isinstance(line, (bytes, bytearray)):
            line = line.decode()

        cleaned = line.strip()
        if len(cleaned) == 0:
            continue

        if cleaned[0] == "+":
            identifier = cleaned[1:].strip()

            # Check the identifier type
            if identifier.startswith(GROUP_TYPE):
                current_group = GroupDefItem(identifier.lstrip(GROUP_TYPE))
                current = None
                groups.append(current_group)
            elif identifier.startswith(UNGROUPED_TYPE):
                current = None
                current_group = UNGROUPED_TYPE
            elif identifier.startswith(PERMISSION_TYPE):
                current = PermissionDefItem(identifier.lstrip(PERMISSION_TYPE))

                # Check if the permission belongs to a group or is ungrouped
                if current_group is None or current_group == UNGROUPED_TYPE:
                    permissions.append(current)
                else:
                    current_group.permissions.append(current)

        elif (
            current_group is not None and current_group != UNGROUPED_TYPE
        ) or current is not None:
            target = current_group if current is None else current
            name, value = line.strip().split(":", 1)

            # Set attribute values on the current object
            if hasattr(target, name):
                if name.lower() == "protectionlevel":
                    setattr(target, name, value.split("|") if value != "null" else None)
                else:
                    setattr(target, name, value if value != "null" else None)

    return AppPermissionList(groups, permissions)


def parse(text: Union[str, bytes, IOBase] = None) -> AppPermissionList:
    """
    Parse app permission data from text or a file-like object.

    :param text: Input text or file-like object containing the permission data.
    :return: AppPermissionList object representing the parsed data.
    :raises TypeError: If the input text is None.
    :raises TypeError: If an invalid source type is provided.
    """

    if text is not None:
        if isinstance(text, (bytearray, bytes)):
            source = BytesIO(text)
        elif isinstance(text, str):
            source = StringIO(text)
        elif isinstance(text, IOBase):
            source = text
        else:
            raise TypeError(f"Invalid source type: {type(text)}")

        return load(source)

    raise TypeError("Got None as input text!")
