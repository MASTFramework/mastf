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
Wrapper functions for JADX decompiler and dex-tools using subprocess. Note
that these functions are designed to be used within docker containers.
"""
import pathlib
import subprocess
import sys


def getopts(options: list = None) -> str:
    opts = []
    for option in options or []:
        if isinstance(option, str):
            opts.append(option)
        elif isinstance(option, (list, tuple)):
            key, val, *_ = option
            opts.append(f"{key} {val}")

    return " ".join(opts)


def decompile(
    dex_path: str, dest_path: str, baksmali_path: str, options: list = None
) -> None:
    """Decompiles a dex file using Baksmali.

    :param dex_path: The path to the dex file to decompile.
    :type dex_path: str
    :param dest_path: The path to the directory where the decompiled files will be placed.
    :type dest_path: str
    :param baksmali_path: The path to the Baksmali executable.
    :type baksmali_path: str
    :param options: Additional command-line options to pass to Baksmali. Defaults to None.
    :type options: list, optional
    :raises RuntimeError: If Baksmali executable is not found.
    """
    if sys.platform in ("win32", "win64"):
        baksmali_path = f"{baksmali_path}.bat"
    else:
        baksmali_path = f"{baksmali_path}.sh"

    try:
        opts = getopts(options)
        cmd = f"{baksmali_path} {dex_path} -o {dest_path} {opts}"
        subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            check=True,
        )
    except subprocess.CalledProcessError as err:
        raise RuntimeError(err.stdout.decode()) from err


def to_java(dex_dir: str, dex_path: str, dest_path: str, jadx_path: str, options: list = None) -> None:
    """Converts a dex file to Java source code using jadx.

    .. note::
        The extracted files will be placed in the destination directory directly without having
        the extra ``sources/`` directory.

    :param dex_dir: The path to the directory containing the dex file.
    :type dex_dir: str
    :param dex_path: The name of the dex file to convert.
    :type dex_path: str
    :param dest_path: The path to the directory where the Java source files will be placed.
    :type dest_path: str
    :param jadx_path: The path to the jadx executable.
    :type jadx_path: str
    :param options: Additional command-line options to pass to jadx. Defaults to None.
    :type options: list, optional
    :raises RuntimeError: If jadx executable is not found.
    """
    if sys.platform in ("win32", "win64"):
        jadx_path = f"{jadx_path}.bat"

    try:
        cmd = f"cd {dex_dir} && {jadx_path} -d {dest_path} {getopts(options)} {dex_path}"
        subprocess.run(
            f"{cmd} && mv -u {dest_path}/sources/* {dest_path} && rm -rf {dest_path}/sources",
            shell=True,
            capture_output=True,
            check=False,
        )
    except subprocess.CalledProcessError as err:
        raise RuntimeError(err.stdout.decode()) from err
