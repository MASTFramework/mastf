# This file is part of MAST-F's Android API
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
Support for apktool to be called within Python code. Use this module
to extract sources or resources separately or extract an APK file
completely.
"""
import subprocess


def extractrsc(apk_path: str, dest_path: str, apktool_path: str = "apktool") -> None:
    """Extracts only resources from an APK file.

    :param apk_path: The path to the APK file to decode.
    :type apk_path: str
    :param dest_path: The path to the directory where the decoded files will be placed.
    :type dest_path: str
    :param apktool_path: The path to the apktool executable. Defaults to "apktool".
    :type apktool_path: str, optional
    """
    run_apktool_decode(apk_path, dest_path, apktool_path, force=True, sources=False)


def run_apktool_decode(
    apk_path: str,
    dest_path: str,
    apktool_path: str = "apktool",
    force: bool = True,
    sources: bool = True,
    resources: bool = True,
) -> None:
    """
    Decodes the specified APK file using apktool.

    :param apk_path: The path to the APK file to decode.
    :type apk_path: str
    :param dest_path: The path to the directory where the decoded files will be placed.
    :type dest_path: str
    :param apktool_path: The path to the apktool executable. Defaults to "apktool".
    :type apktool_path: str, optional
    :param force: Whether to force overwrite existing files. Defaults to True.
    :type force: bool, optional
    :param sources: Whether to decode sources. Defaults to True.
    :type sources: bool, optional
    :param resources: Whether to decode resources. Defaults to True.
    :type resources: bool, optional
    :raises RuntimeError: If apktool fails to decode the APK file.
    """
    cmd = [f"{apktool_path} d {apk_path} -o {dest_path}"]
    if force:
        cmd.append("-f")

    if not sources:
        cmd.append("--no-src")

    if not resources:
        cmd.append("--no-res")

    try:
        subprocess.run(" ".join(cmd), shell=True, capture_output=True, check=True)
    except subprocess.CalledProcessError as err:
        # Raise a RuntimeError if apktool fails to decode the APK file
        raise RuntimeError(err.stdout.decode()) from err
