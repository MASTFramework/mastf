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
"""
In order to handle uploaded scan files and prepare them for static file
analysis, :class:`TaskFileHandler` objects are used. Once created, they
will be registered in a gobal registry and can be retrieved via
``TaskFileHandler.from_scan(...)``.

APK Files
~~~~~~~~~

To use the ``apk_handler`` function, simply import it and call it with the source
path, destination directory, and any required application settings. Optional arguments
can be passed through the ``kwargs`` parameter, including the ``observer`` argument
for progress tracking. For example:

.. code-block:: python
    :linenos:

    from mastf.core.files import TaskFileHandler
    from mastf.MASTF import settings

    src_path = "/path/to/my/app.apk"
    dest_dir = "/path/to/output/directory"
    apk_handler = TaskFileHandler.from_scan(src_path, "android")
    if apk_handler:
        apk_handler.apply(src_path, dest_dir, settings, observer=task_observer)

The ``apk_handler`` function processes the specified APK file using the settings provided, then
saves the output files to the ``dest_dir``. The function may also perform progress tracking if
an observer object is provided.

Note that the extension and scan_type parameters for :class:`TaskFileHandler` specify that this
function should only be used for files with the ``.apk`` extension and for Android scans.

IPA Files
~~~~~~~~~

Import the ``ipa_handler`` function or get the instance via the following code::

    handler = TaskFileHandler.from_scan("path/to/file.ipa", "ios")

"""

import re
import pathlib
import zipfile
import logging
import lief

from mastf.android.tools import apktool, baksmali
from mastf.ios import nib, headers
from umbrella import swift, objc

handlers = []
logger = logging.getLogger(__name__)


class TaskFileHandler:
    """A class that provides file handling functionality for tasks.

    To use the :class:`TaskFileHandler` class as a decorator on functions or classes, you can
    create an instance of the class with the desired file extension and scan type (if applicable),
    and then apply it to the target function or class using the ``@`` syntax. Here is an example
    of how this might look:

    .. code-block:: python

        task_file_handler = TaskFileHandler(r".*\\.txt")

        @task_file_handler
        def process_text_files(src_path: str, dest_dir: str, settings):
            # function body


    In the above example, the process_text_files function is decorated with an instance of the
    :class:`TaskFileHandler` class that has been configured to look for files with a ``.txt``
    extension in any scan. When ``process_text_files`` is called, the file handling logic
    provided by the :class:`TaskFileHandler` instance will be applied to the specified source
    and destination paths.


    :param extension: The file extension to look for.
    :type extension: str
    :param scan_type: The type of scan to perform (e.g. 'android' or 'ios'). Defaults to None.
    :type scan_type: str, optional
    :param private: Tells the object whether it should be added to the global handler list
    :type private: bool
    """

    def __init__(self, extension: str, scan_type: str = None, private=False) -> None:
        if isinstance(extension, type):
            raise ValueError(
                "The provided parameter is of type <class>, expected a string value. "
                "You probably used the @TaskFileHandler decorator without any arguments."
            )

        self.extension = re.compile(extension)
        self.scan_type = scan_type
        self.func = None
        if not private:
            handlers.append(self)

    def __call__(self, *args, **kwargs) -> "TaskFileHandler":
        """Enables TaskFileHandler instances to be used as decorators.

        :returns: A TaskFileHandler instance.
        :rtype: TaskFileHandler
        """
        if len(args) == 0:
            raise ValueError(
                "You called the TaskFileHandler without any arguments, "
                "expected the decorated class or method."
            )

        clazz, *_ = args
        if isinstance(clazz, type):
            clazz = clazz()

        self.func = clazz
        return self

    @staticmethod
    def from_scan(name: str, scan_type: str = None) -> "TaskFileHandler":
        """Returns the TaskFileHandler instance from the specified file name and scan type.

        :param file_name: The name of the file to look for.
        :type file_name: str
        :param scan_type: The type of scan to perform (e.g. 'android' or 'ios').
        :type scan_type: str
        :returns: A new TaskFileHandler instance.
        :rtype: TaskFileHandler
        """
        for handler in handlers:
            if handler.extension.match(name) or (
                (handler.scan_type and scan_type) and (handler.scan_type == scan_type)
            ):
                return handler

        return None

    def apply(
        self, src_path: pathlib.Path, dest_dir: pathlib.Path, settings, **kwargs
    ) -> None:
        """Applies the file handling logic to the specified source and destination paths.

        :param src_path: The path to the source directory or file.
        :type src_path: pathlib.Path
        :param dest_dir: The path to the destination directory.
        :type dest_dir: pathlib.Path
        :param settings: The settings object for the task.
        :param kwargs: Additional keyword arguments.
        :type kwargs: dict
        :returns: None
        """
        if not self.func:
            raise ValueError("Expected a callable function or class instance, got None")

        self.func(src_path, dest_dir, settings, **kwargs)


@TaskFileHandler(extension=r".*\.apk", scan_type="android")
def apk_handler(src_path: pathlib.Path, dest_dir: pathlib.Path, settings, **kwargs):
    """Handles APK files for Android scans.

    :param src_path: The path to the APK file to be processed.
    :type src_path: pathlib.Path
    :param dest_dir: The directory where the output files will be saved.
    :type dest_dir: pathlib.Path
    :param settings: A module object containing any required settings for the APK processing.
    :type settings: module
    :param kwargs: Optional keyword arguments that can be used to pass additional parameters,
                   such as observer.
    :type kwargs: dict
    :returns: This function returns nothing (``None``) as it only processes files and saves
               output to the specified directory.
    """
    src = dest_dir / "src"
    contents = dest_dir / "contents"
    if not src.exists():
        src.mkdir(parents=True, exist_ok=True)

    if not contents.exists():
        contents.mkdir(parents=True, exist_ok=True)

    logger.debug("Extracting APK file with apktool...")
    observer = kwargs.get("observer", None)
    if observer:
        observer.update("Extracting APK file with apktool...")

    # TODO: move to apkInspector as apktool may not be able to extract
    # all resources
    apktool.extractrsc(str(src_path), str(contents), settings.APKTOOL)
    smali_dir = src / "smali"
    smali_dir.mkdir(exist_ok=True)

    java_dir = src / "java"
    java_dir.mkdir(exist_ok=True)

    tool = f"{settings.D2J_TOOLSET}-dex2smali"
    java_tool = f"{settings.JADX}"
    dex_files = list(contents.glob(r"*/**/*.dex")) + list(contents.glob(r"*.dex"))
    for path in dex_files:
        logger.debug(
            "Decompiling classes with %s: classes=%s -> to=%s",
            tool,
            str(path),
            str(smali_dir),
        )
        if observer:
            observer.update("Decompiling %s with %s to /src/smali", path.name, tool)

        baksmali.decompile(str(path), str(smali_dir), tool, options=["--force"])

        if observer:
            observer.update("Decompiling %s with %s to /src/java", path.name, java_tool)
        baksmali.to_java(str(path.parent), str(path.name), str(java_dir), java_tool)


@TaskFileHandler(extension=r".*\.ipa", scan_type="ios")
def ipa_handler(
    src_path: pathlib.Path, dest_dir: pathlib.Path, settings, **kwargs
) -> None:
    """Handles IPA files for iOS scans.

    :param src_path: The path to the IPA file to be processed.
    :type src_path: pathlib.Path
    :param dest_dir: The directory where the output files will be saved.
    :type dest_dir: pathlib.Path
    :param settings: unused
    :type settings: module
    """
    observer = kwargs.get("observer", None)

    if observer:
        observer.update("Extracting files...")
    with zipfile.ZipFile(str(src_path)) as zfile:
        # Extract initial files
        zfile.extractall(str(dest_dir / "contents"))

    try:
        # Convert NIB => Swift
        if observer:
            observer.update("Converting NIB to Pseudo-Swift...")
        nib.convert_all(start_dir=src_path, recursive=True, print_empty=True)
    except RuntimeError as err:
        observer = kwargs.get("observer", None)
        if observer and observer.logger:
            observer.logger.exception("Could not convert NIB to Swift: %s", str(err))

    src_swift = dest_dir / "src" / "swift"
    src_objc = dest_dir / "src" / "objc"

    src_swift.mkdir(exist_ok=True, parents=True)
    src_objc.mkdir(exist_ok=True, parents=True)

    # export all objc and swift binaries
    if observer:
        observer.update("Searching for main binary...")
    main_binary = None
    try:
        dirs = list((dest_dir / "contents" / "Payload").iterdir())
        app_name = dirs[0].replace(".app", "")
        main_binary = dest_dir / "contents" / "Payload" / dirs[0] / app_name

        if main_binary.exists():
            binary = lief.MachO.parse(str(main_binary))

            if objc.has_objc_metadata(binary):
                if observer:
                    observer.update("Decompiling Objective-C...")
                objc_meta = objc.ObjCMetadata(binary)
                headers.export_objc(objc_meta, src_objc)

            if swift.has_swift_metadata(binary):
                if observer:
                    observer.update("Decompiling Swift...")
                swift_meta = swift.ReflectionContext(binary)
                headers.export_swift(swift_meta, src_swift)

    except Exception as e:
        if observer:
            observer.exception(e, "Could not find main binary at %s", str(main_binary))
