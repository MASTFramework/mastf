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
from django.db import models

from mastf.MASTF.utils.enum import HostType, DataProtectionLevel
from mastf.MASTF.models import Snippet, Scan, Scanner, TimedModel


class TLS(TimedModel):
    tls_uuid = models.UUIDField(primary_key=True)
    version = models.CharField(max_length=256, null=True)
    recommended = models.BooleanField(default=False)


class CipherSuite(TimedModel):
    cipher_uuid = models.UUIDField(primary_key=True)
    name = models.CharField(max_length=256, blank=True)
    recommended = models.BooleanField(default=False)


class DataCollectionGroup(TimedModel):
    dc_uuid = models.UUIDField(primary_key=True)
    group = models.CharField(max_length=256, null=False)
    protection_level = models.CharField(
        default=DataProtectionLevel.PUBLIC,
        choices=DataProtectionLevel.choices,
        max_length=256,
    )


class HostTemplate(TimedModel):
    template_id = models.UUIDField(primary_key=True)
    domain_name = models.CharField(max_length=256, null=False)
    ip_address = models.CharField(max_length=32, null=True)
    owner = models.CharField(max_length=255, null=True)
    description = models.TextField(null=False, blank=True)


class Host(TimedModel):
    host_id = models.CharField(max_length=256, primary_key=True)
    # REVISIT: If we know the scanner we don't need the scan instance,
    # because the scanner is already mapped to the scan.
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, null=True)
    scanner = models.ForeignKey(Scanner, on_delete=models.CASCADE, null=True)

    classification = models.CharField(
        default=HostType.NOT_SET, choices=HostType.choices, max_length=256
    )
    snippet = models.ForeignKey(Snippet, on_delete=models.SET_NULL, null=True)
    template = models.ForeignKey(HostTemplate, on_delete=models.SET_NULL, null=True)

    url = models.CharField(max_length=2048, null=True, blank=True)
    ip = models.CharField(max_length=32, null=True)
    port = models.IntegerField(default=0)
    protocol = models.CharField(max_length=256, null=True)

    country = models.CharField(max_length=256, null=True)
    longitude = models.FloatField(null=True)
    latitude = models.FloatField(null=True)

    tlsversions = models.ManyToManyField(TLS, related_name="hosts")
    suites = models.ManyToManyField(CipherSuite, related_name="hosts")
    collected_data = models.ManyToManyField(DataCollectionGroup, related_name="hosts")
