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
from django import template
from datetime import date
from time import mktime

from mastf.MASTF.models import AbstractBaseFinding, PackageVulnerability
from mastf.MASTF.mixins import VulnContextMixin
from mastf.MASTF.utils.enum import ComponentCategory

register = template.Library()


@register.filter(name="split")
def split(value: str, key: str) -> list:
    """
    Returns the value turned into a list.
    """
    return value.split(key) if value else []


@register.filter(name="vuln_stats")
def vuln_stats(value):
    mixin = VulnContextMixin()
    data = {}

    mixin.apply_vuln_context(
        data, AbstractBaseFinding.stats(PackageVulnerability, base=list(value))
    )
    return data


@register.filter(name="component_color")
def component_color(category) -> str:
    if category == ComponentCategory.ACTIVITY:
        return "green"
    elif category == ComponentCategory.PROVIDER:
        return "red"
    elif category == ComponentCategory.SERVICE:
        return "yellow"
    elif category == ComponentCategory.RECEIVER:
        return "orange"

    return "secondary"


@register.filter(name="timestamp")
def timestamp(obj: date):
    obj = obj or date.today()

    return mktime(obj.timetuple()) * 1000


@register.filter(name="render_code")
def render_code(text: str) -> str:
    output = ""
    count = 0

    for char in text:
        if char == "`":
            output = "%s<%skbd>" % (output, "/" if count % 2 != 0 else "")
            count += 1
        else:
            output = "".join([output, char])

    return output
