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
    FindingTemplate,
    AppPermission,
    Package,
    PackageVulnerability,
    Dependency,
    Finding,
    Vulnerability,
    Snippet,
    Component,
    PermissionFinding,
)

__all__ = [
    "TemplateSerializer",
    "AppPermissionSerializer",
    "SnippetSerializer",
    "FindingSerializer",
    "VulnerabilitySerializer",
    "PackageSerializer",
    "PackageVulnerabilitySerializer",
    "DependencySerializer",
    "ComponentSerializer",
    "PermissionFindingSerializer",
]


class TemplateSerializer(serializers.ModelSerializer):
    class Meta:
        model = FindingTemplate
        fields = "__all__"


class AppPermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = AppPermission
        fields = "__all__"


class PermissionFindingSerializer(serializers.Serializer):
    permission = AppPermissionSerializer(many=False)

    class Meta:
        model = PermissionFinding
        fields = "__all__"


class SnippetSerializer(serializers.ModelSerializer):
    class Meta:
        model = Snippet
        exclude = ["sys_path"]


class FindingSerializer(serializers.ModelSerializer):
    template = TemplateSerializer(many=False)
    snippet = SnippetSerializer(many=False)

    class Meta:
        model = Finding
        fields = "__all__"


class VulnerabilitySerializer(serializers.ModelSerializer):
    template = TemplateSerializer(many=False)
    snippet = SnippetSerializer(many=False)

    class Meta:
        model = Vulnerability
        fields = "__all__"


class PackageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Package
        fields = "__all__"


class PackageVulnerabilitySerializer(serializers.ModelSerializer):
    package = PackageSerializer(many=False)

    class Meta:
        model = PackageVulnerability
        fields = "__all__"


class DependencySerializer(serializers.ModelSerializer):
    package = PackageSerializer(many=False)

    class Meta:
        model = Dependency
        fields = "__all__"


class ComponentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Component
        fields = "__all__"
