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
__doc__ = """
Converters are used within URL definitions of Django. They can be used
to add additional custom path components to URLs.

New converter classes will be automatically added when Django loads the
defined URLs.To create a new string-based converter, just follow a simple
structure and add the code to the specified file.

.. code-block:: python
    :caption: converters.py

    # [...]
    class MyIDConverter(StringConverter):
        regex = r"some-value-\\d{4}"
    # [...]

In URL definitions we can access this newly defined converter by using
its class name:

.. code-block:: python
    :caption: urls.py

    urlpatterns = [
        # The name must be lower-case and without 'converter' at the end
        path("/some/path/<myid:pk>", MyModelView.as_view(), name=...),
    ]
"""
import inspect
import sys


class StringConverter:
    """Base class for string-based converters."""

    def to_python(self, value: str) -> str:
        return value

    def to_url(self, value: str) -> str:
        return value


class FindingTemplateIDConverter(StringConverter):
    regex = r"FT-[\w-]{36}-[\w-]{36}"


class VulnerabilityIDConverter(StringConverter):
    regex = r"SV-[\w-]{36}-[\w-]{36}"


class FindingIDConverter(StringConverter):
    regex = r"SF-[\w-]{36}-[\w-]{36}"


class MD5Converter(StringConverter):
    regex = r"[0-9a-fA-F]{32}"


class HostIDConverter(StringConverter):
    regex = r"hst_[\dA-Za-z-]{36}"


class ComponentIdConverter(StringConverter):
    regex = r"cpt_[\dA-Za-z-]{36}"


class DependencyIdConverter(StringConverter):
    regex = r"([0-9a-fA-F]{32}){2}"


def listconverters() -> dict:
    """Returns all converters of this module.

    The mapped name will be the class name transformed to lower
    case and with the ``"converter"`` extra removed.

    :return: a dictionary storing all registered converter classes
    :rtype: dict
    """
    mod = sys.modules[__name__]
    members = inspect.getmembers(mod, inspect.isclass)

    conv = {}
    for name, clazz in members:
        if issubclass(clazz, StringConverter) and clazz != StringConverter:
            name = name.lower().replace("converter", "")
            conv[name] = clazz

    return conv
