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
Module that stores all important database models plus utility methods
whithin each class. For details on scan related models, please view
one of the following sites:

:doc:`Project and Team related models <base_models>`
    Learn about basic database models required for the web-frontend to work.

:doc:`Basic Scan Models <scan_models>`
    Detailed overview of scan related models including :class:`ScanTask` and
    :class:`Scanner`.

:doc:`Finding Models <finding_models>`
    A list of classes that are used to represent API findings and vulnerabilities
    internally.

:doc:`Permission Models <permission_models>`
    Important app-permission models, **not** user permission models.

:doc:`Package Models <package_models>`
    Explore database models for software packages and dependencies

:doc:`Host Models <host_models>`
    Detailed overview of connection models, hosts, and other related data.

Each class will illustrate what serializers, forms and permission classes are associated
with it. In addition, most database models provide examples and detailed field explainations
in order to provide a detailed overview to them.
"""
from .base import *

from .mod_scan import *
from .mod_finding import *
from .mod_permission import *
from .mod_package import *
from .mod_host import *
from .mod_component import *
