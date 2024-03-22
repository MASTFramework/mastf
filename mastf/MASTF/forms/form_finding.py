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

from mastf.MASTF.models import Scan, FindingTemplate, Scanner, Component
from mastf.MASTF.utils.enum import ComponentCategory
from mastf.MASTF.rest.permissions import CanEditScanAsField

from .base import ModelField

__all__ = [
    "FindingTemplateForm",
    "AbstractFindingForm",
    "FindingForm",
    "VulnerabilityForm",
    "ComponentForm",
]


class FindingTemplateForm(forms.Form):
    title = forms.CharField(max_length=256, required=True)
    severity = forms.CharField(max_length=256, required=False)
    # The next two fields won't get a length maximum
    description = forms.CharField(required=False)
    risk = forms.CharField(required=False)
    mitigation = forms.CharField(required=False)


class AbstractFindingForm(forms.Form):
    scan = ModelField(Scan, max_length=256, required=True)
    language = forms.CharField(max_length=256, required=False)
    severity = forms.CharField(max_length=32, required=True)
    source_file = forms.CharField(max_length=512, required=True)
    source_line = forms.CharField(max_length=512, required=False)
    scanner = ModelField(Scanner, max_length=256, required=True)
    template = ModelField(FindingTemplate, max_length=256, required=True)

    class Meta:
        abstract = True


class FindingForm(AbstractFindingForm):
    is_custom = forms.BooleanField(required=False)


class VulnerabilityForm(AbstractFindingForm):
    state = forms.CharField(max_length=256, required=True)


class ComponentForm(forms.Form):
    scanner = ModelField(Scanner, required=True)
    name = forms.CharField(max_length=2048, required=True)
    is_protected = forms.BooleanField(required=False)
    is_exported = forms.BooleanField(required=False)
    category = forms.ChoiceField(choices=ComponentCategory.choices, required=True)
