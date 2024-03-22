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

import uuid
import logging
import json

from mastf.ios.plist import PropertyList
from mastf.ios import cordova

from mastf.MASTF import settings
from mastf.MASTF.scanners.code import yara_code_analysis
from mastf.MASTF.tasks import (
    perform_async_sast,
    perform_semgrep_scan,
)
from mastf.MASTF.models import ScanTask, Package, Dependency
from mastf.MASTF.scanners.plugin import (
    Plugin,
    ScannerPlugin,
    Extension,
    ScannerPluginTask,
)
from mastf.MASTF.scanners.mixins import (
    DetailsMixin,
    PermissionsMixin,
    HostsMixin,
    FindingsMixins,
)

logger = logging.getLogger(__name__)


class iOSTask(ScannerPluginTask):
    def do_yara_scan(self) -> None:
        # Same as with AndroidTask
        yara_code_analysis(self.scan_task.pk, str(self.file_dir), self.observer)

    def do_app_package_scan(self) -> None:
        get_app_packages(self)

    def do_semgrep_scan(self) -> None:
        """Execute the semgrep OSS-Engine in a separate celery worker."""
        task = ScanTask.objects.create(
            task_uuid=uuid.uuid4(),
            scan=self.scan,
            scanner=self.scan_task.scanner,
            name=self.scan_task.name,
        )
        perform_semgrep_scan.delay(
            str(task.task_uuid),
            str(settings.SEMGREP_IOS_RULES_DIR),
            str(self.file_dir),
        )

    def do_code_scan(self) -> None:
        """Perform a code scan on the iOS application."""
        task = ScanTask.objects.create(
            task_uuid=uuid.uuid4(),
            scan=self.scan,
            scanner=self.scan_task.scanner,
            name=self.scan_task.name,
        )
        perform_async_sast.delay(str(task.task_uuid), str(self.file_dir))


mixins = (DetailsMixin, PermissionsMixin, HostsMixin, FindingsMixins)


@Plugin
class iOSScannerPlugin(*mixins, ScannerPlugin):
    name = "iOS Plugin"
    title = "iOS SAST Engine"
    help = "Basic security checks for iOS apps."
    task = iOSTask
    extensions = [
        Extension.DETAILS,
        Extension.PERMISSIONS,
        Extension.HOSTS,
        Extension.FINDINGS,
        Extension.EXPLORER,
    ]


# --- Task implementation ----------------------------------------------------
def get_app_packages(task: ScannerPluginTask) -> None:
    base_dir = task.file_dir / "contents"
    dependencies: dict[Package, Dependency] = {}

    # ======================= Basic Approach =======================
    # Collect all Info.plist files from framework directories and try
    # to search for Cordoca Dependencies.
    for file_path in base_dir.rglob("*"):
        if file_path.is_dir() and ".framework" in file_path.name:
            try:
                with open(str(file_path / "Info.plist"), "r", encoding="utf-8") as fp:
                    plist = PropertyList(fp=fp)
                    # package_name == group_id of our target package
                    package_name, version = (
                        plist.getBundleId(),
                        plist.getBundleVersionString(),
                    )

                package = Package.objects.get(group_id=package_name)
                if package not in dependencies:
                    dependencies[package] = Dependency(
                        pk=uuid.uuid4(), package=package, version=version
                    )
            except Exception as err:
                logger.exception(str(err))
            except Package.DoesNotExist:
                continue  # maybe create new entry

        elif file_path.name == "cordova_plugins.js":
            try:  # Cordova plugins
                metadata = cordova.get_cordova_metadata(str(file_path))
                if metadata:
                    for name, version in metadata.items():
                        package = Package.objects.get(name=name)
                        if package not in dependencies:
                            dependencies[package] = Dependency(
                                pk=uuid.uuid4(), package=package, version=version
                            )
            except Exception as err:
                logger.exception(str(err))

        elif str(file_path).endswith("public/dependencies.json"):
            try:  # Cordova dependencies
                with open(str(file_path), "r", encoding="utf-8") as fp:
                    for framework in json.load(fp):
                        package = Package.objects.get(name=framework["name"])
                        if package not in dependencies:
                            dependencies[package] = Dependency(
                                pk=uuid.uuid4(),
                                package=package,
                                version=framework["version"],
                            )
            except Exception as err:
                logger.exception(str(err))

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
