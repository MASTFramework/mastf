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
Additional middleware classes that intercept requests before any view
can handle them.
"""
from django.shortcuts import render

from mastf.MASTF.models import Environment


class FirstTimeMiddleware:
    """Used to redirect to the setup page when starting this framework
    for the first time.

    Note that this middleware will return a rendered setup page for all
    incoming request if the framework has not been initialized.
    """

    def __init__(self, get_response) -> None:
        self.get_response = get_response

    def __call__(self, request, *args, **kwargs):
        response = self.get_response(request)

        # If it's the first time the app is started and the request is
        # not for the setup wizard, return the setup wizard page (which
        # will guide the user through the initial configuration steps)
        env = Environment.env()
        if env.first_start and request.path != "/api/v1/setup/":
            return render(request, "setup/wizard.html")

        return response
