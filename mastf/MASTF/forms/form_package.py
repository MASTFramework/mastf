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
from django import forms

from mastf.MASTF.models import Package, Project, Scanner

from .base import ModelField

__all__ = ["PackageForm", "PackageVulnerabilityForm", "DependencyForm"]


class PackageForm(forms.Form):
    name = forms.CharField(max_length=512, required=True)
    artifact_id = forms.CharField(max_length=512, required=False)
    group_id = forms.CharField(max_length=512, required=False)
    package_type = forms.CharField(max_length=256, required=True)
    platform = forms.CharField(max_length=256, required=True)


class PackageVulnerabilityForm(forms.Form):
    cve_id = forms.CharField(max_length=256, required=True)
    package = ModelField(Package, max_length=72, required=True)
    version = forms.CharField(max_length=512, required=True)
    severity = forms.CharField(max_length=32, required=False)


class DependencyForm(forms.Form):
    package = ModelField(Package, max_length=36, required=True)
    project = ModelField(Project, max_length=256, required=True)
    relation = forms.CharField(
        max_length=256, required=False
    )  # maybe add enum validator
    scanner = ModelField(Scanner, max_length=256, required=True)
    outdated = forms.CharField(max_length=512, required=False)
    version = forms.CharField(max_length=512, required=False)
    license = forms.CharField(max_length=256, required=False)
