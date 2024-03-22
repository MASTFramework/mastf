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

from mastf.MASTF.models import Host, HostTemplate, Snippet, Scanner

from .base import ModelField, ManyToManyField

__all__ = [
    "CipherSuiteForm",
    "TLSForm",
    "DataCollectionGroupForm",
    "HostForm",
    "HostTemplateForm",
]


class CipherSuiteForm(forms.Form):
    hosts = ManyToManyField(Host, max_length=256, required=False)
    name = forms.CharField(max_length=256, required=True)
    recommended = forms.BooleanField(required=False)


class TLSForm(forms.Form):
    hosts = ManyToManyField(Host, max_length=256, required=False)
    name = forms.CharField(max_length=256, required=True)
    recommended = forms.BooleanField(required=False)


class DataCollectionGroupForm(forms.Form):
    hosts = ManyToManyField(Host, max_length=256, required=False)
    group = forms.CharField(max_length=256, required=True)
    protection_level = forms.CharField(max_length=256, required=False)


class HostForm(forms.Form):
    scanner = ModelField(Scanner, required=True)
    classification = forms.CharField(max_length=256, required=False)
    snippet = ModelField(Snippet, required=False)
    template = ModelField(HostTemplate, required=False)

    url = forms.URLField(max_length=2048, required=True)
    ip = forms.CharField(max_length=32, required=True)
    port = forms.IntegerField(max_value=65535, min_value=0, required=True)
    protocol = forms.CharField(max_length=256, required=False)

    country = forms.CharField(max_length=256, required=False)
    longitude = forms.FloatField(required=False)
    langitude = forms.FloatField(required=False)


class HostTemplateForm(forms.Form):
    domain_name = forms.CharField(max_length=256, required=True)
    ip_address = forms.CharField(max_length=32, required=False)
    owner = forms.CharField(max_length=256, required=False)
    description = forms.CharField(required=False)
