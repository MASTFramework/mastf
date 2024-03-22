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
from __future__ import annotations

import logging
import lief
import uuid
import pathlib
import io

from androguard.core import apk

from mastf.core.files.properties import Properties
from mastf.core.files.tpl import TPL

from mastf.MASTF.models import Package, Dependency
from mastf.MASTF.scanners.plugin import ScannerPluginTask

logger = logging.getLogger(__name__)


# https://github.com/lief-project/LIEF/issues/832
class BytesIO(io.BytesIO):
    @property
    def raw(self):
        return self

    def readall(self):
        return self.read()


def to_packages(class_name: str, include_class: bool = False) -> list[str]:
    """Splits a class name into individual package components.

    >>> to_packages("Ljava/lang/String;", is_internal=True)
    ['java', 'lang']
    >>> to_packages("Ljava/lang/String;", is_internal=True, include_class=True)
    ['java', 'lang', 'String']

    :param class_name: The fully qualified class name.
    :param include_class: Flag to include the class name in the result.
    :param is_internal: A flag indicating if the class is internal.
    :return: A list of package components.
    """
    delimiter = "."
    class_name = class_name.removesuffix(".class")
    result = class_name.split(delimiter)
    return result[:-1] if not include_class else result


def to_path(*elements) -> str:
    """Joins the elements into a dot-separated path.

    >>> to_path("foo", "bar")
    'foo.bar'
    >>> to_path("", "foo", "", "bar")
    'foo.bar'

    :param elements: The elements to be joined.
    :return: The dot-separated path.
    """
    values = []
    for element in map(lambda x: x.strip(), elements):
        if element:
            values.append(element)

    return ".".join(values)


def get_app_packages(task: ScannerPluginTask) -> None:
    # TODO: Use python package mastf-libscout to scan the given
    # apk file for possible dependencies. The output returns a possible
    # description, so we can add it if no template was found
    apk_file: apk.APK = task[apk.APK]
    base_dir = task.file_dir / "contents"
    dependencies: dict[Package, Dependency] = {}

    # ======================= Heuristic Approach =======================
    # Rather use lief.DEX.parse as we just want all class names. The used
    # dictionary stores the package, possible version number, type and
    # license (if found)
    for dex_content in apk_file.get_all_dex():
        dex_file = lief.DEX.parse(BytesIO(dex_content))
        if not dex_file:
            continue

        for class_def in dex_file.classes:
            # filter out any non-existend files
            if not class_def.source_filename:
                continue

            name = to_path(*to_packages(class_def.pretty_name))
            try:
                # If we have an exact match, we should add it to the matched
                # packages as we don't know the artifact id
                package = Package.objects.get(group_id=name, artifact_id=None)
                if package not in dependencies:
                    dependencies[package] = Dependency(pk=uuid.uuid4(), package=package)
            except (Package.DoesNotExist, Package.MultipleObjectsReturned):
                pass

    # Before we are going to add the packages, we try to look at other
    # places to collect version numbers:
    # 1: general ".properties" files
    for config in base_dir.rglob("*.properties"):
        properties = Properties(str(config))
        query = {}
        version = properties.get("version")
        # Only add property files with client and version as possible dependencies
        if "client" in properties:
            query["artifact_id"] = properties["client"]

        elif "groupId" in properties:
            # These special properies files are placed by maven and may contain
            # the full group+artifact ID
            query["group_id"] = properties["groupId"]
            if "artifactId" in properties:
                query["artifact_id"] = properties["artifactId"]

        try:
            package = Package.objects.get(**query)
            # If the package is already present, check if there is a version mapped to it
            if package in dependencies:
                dep = dependencies[package]
                if not dep.version and version:
                    # Set the version if not already specified
                    dep.version = version
            else:
                dependencies[package] = Dependency(
                    pk=uuid.uuid4(), package=package, version=version
                )
        except (Package.DoesNotExist, Package.MultipleObjectsReturned):
            pass

    # 2: .version files (mostly Android related frameworks)
    for config in base_dir.rglob("*.version"):
        group_id, artifact_id = config.stem.split("_", 1)

        try:
            # Limit the amount of read operations to existing packages
            package = Package.objects.get(group_id=group_id, artifact_id=artifact_id)
            # Read version
            with open(str(config), "r", encoding="utf-8") as fp:
                # These files only contain one line, so we can call .readline()
                version = fp.readline().strip()

            if package not in dependencies:
                dependencies[package] = Dependency(
                    pk=uuid.uuid4(), package=package, version=version
                )
            else:
                dep = dependencies[package]
                if version and not dep.version:
                    dep.version = version
        except (Package.DoesNotExist, Package.MultipleObjectsReturned):
            pass

    # 3: TPL metadata files (huge files with license metadata - may contain
    # group and artifact ids)
    for tpl_meta in base_dir.rglob("third_party_license_metadata"):
        # There will be only one file (if existend)
        with TPL(str(tpl_meta)) as tpl_iterator:
            # TODO: Here we have to implement a mechanism that parses
            # the ids and License name at the same time.
            for group_id, artifact_id in tpl_iterator:
                query = {}
                if group_id:
                    query["group_id"] = group_id
                if artifact_id:
                    query["artifact_id"] = artifact_id

                try:
                    package = Package.objects.get(**query)
                    # If the package is already present, check if there is a version mapped to it
                    if package not in dependencies:
                        dependencies[package] = Dependency(
                            pk=uuid.uuid4(), package=package
                        )
                except (Package.MultipleObjectsReturned, Package.DoesNotExist):
                    pass

    # 4: Cordova dependencies (TODO)
    # ...

    # Add all dependencies to the current scan if not already present
    present_packages = set(
        map(lambda x: x.package, Dependency.objects.filter(project=task.scan.project))
    )
    for package in dependencies:
        dependency = dependencies[package]
        if package in present_packages:
            dependencies.pop(package)
            continue  # just ignore duplicates

        dependency.project = task.scan.project
        dependency.scanner = task.scan_task.scanner
        # TODO: dependency.outdated = ...

    Dependency.objects.bulk_create(list(dependencies.values()))
