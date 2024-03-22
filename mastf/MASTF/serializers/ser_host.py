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
from rest_framework import serializers

from mastf.MASTF.models import (
    Host,
    DataCollectionGroup,
    CipherSuite,
    TLS,
    HostTemplate
)

from .base import ManyToManyField, ManyToManySerializer

__all__ = [
    "DataCollectionGroupSerializer",
    "TLSSerializer",
    "CipherSuiteSerializer",
    "HostSerializer",
    "HostTemplateSerializer",
]


class DataCollectionGroupSerializer(ManyToManySerializer):
    rel_fields = ["hosts"]
    hosts = ManyToManyField(Host)

    class Meta:
        model = DataCollectionGroup
        fields = "__all__"


class TLSSerializer(ManyToManySerializer):
    rel_fields = ["hosts"]
    hosts = ManyToManyField(Host)

    class Meta:
        model = TLS
        fields = "__all__"


class CipherSuiteSerializer(ManyToManySerializer):
    rel_fields = ["hosts"]
    hosts = ManyToManyField(Host)

    class Meta:
        model = CipherSuite
        fields = "__all__"


class HostTemplateSerializer(serializers.ModelSerializer):
    class Meta:
        model = HostTemplate
        fields = "__all__"


class HostSerializer(ManyToManySerializer):
    rel_fields = ["tlsversions", "suites", "collected_data"]
    tlsversions = ManyToManyField(TLS)
    suites = ManyToManyField(CipherSuite)
    collected_data = ManyToManyField(DataCollectionGroup)
    template = HostTemplateSerializer(many=False)

    class Meta:
        model = Host
        fields = "__all__"
