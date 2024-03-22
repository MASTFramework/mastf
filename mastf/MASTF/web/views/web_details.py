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
import json
import os

from django.contrib import messages

from mastf.MASTF.settings import DETAILS_DIR, ARTICLES
from mastf.MASTF.mixins import ContextMixinBase, TemplateAPIView


class DetailsView(ContextMixinBase, TemplateAPIView):
    """A view for displaying details of a specific item."""

    template_name = "details.html"

    def get_context_data(self, **kwargs):
        """
        Retrieve and prepare the context data for rendering the details view.

        :param kwargs: Additional keyword arguments.
        :return: A dictionary containing the context data.
        """
        context = super().get_context_data(**kwargs)
        context['pages'] = ARTICLES

        platform = self.kwargs['platform'].lower()
        name = self.kwargs['name'].lower()

        path = DETAILS_DIR / platform / f"{name}.jsontx"
        if not path.exists():
            messages.warning(self.request, f'Invalid details name: {path}', "FileNotFoundError")
            return context


        if not os.path.commonprefix((path, DETAILS_DIR)).startswith(str(DETAILS_DIR)):
            messages.warning(self.request, f'Invalid path name: {path}', "FileNotFoundError")
            return context

        with open(str(path), "r", encoding="utf-8") as fp:
            # Error handling will be done in dispatch() view
            context["data"] = json.load(fp)

        return context
