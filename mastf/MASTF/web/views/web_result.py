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
import logging

from django.contrib import messages

from mastf.MASTF.mixins import ContextMixinBase, UserProjectMixin, TemplateAPIView
from mastf.MASTF.rest.permissions import CanEditProject
from mastf.MASTF.scanners.plugin import ScannerPlugin
from mastf.MASTF.models import File, Scan
from mastf.MASTF.settings import FILE_TYPES, BASE_DIR

__all__ = ["ScannerResultsView", "ScanIndexView"]

logger = logging.getLogger(__name__)

RESULTS_BASE = "project/results/results-base.html"


class ScanIndexView(UserProjectMixin, ContextMixinBase, TemplateAPIView):
    """
    A view for displaying the index of scans for a user's project.
    """

    template_name = RESULTS_BASE
    permission_classes = [CanEditProject]
    default_redirect = "Project-Overview"
    keep_redirect_kwargs = False

    def get_redirect_kwargs(self) -> dict:
        return {"project_uuid": self.kwargs["project_uuid"]}

    def get_context_data(self, **kwargs):
        """
        Retrieve and prepare the context data for rendering the scan index view.

        :param kwargs: Additional keyword arguments.
        :return: A dictionary containing the context data.
        """
        context = super().get_context_data(**kwargs)
        self.apply_project_context(context)

        project = context["project"]
        # Apply scan files after permission check
        context["scan_files"] = Scan.files(project=project)
        return context


class ScannerResultsView(UserProjectMixin, ContextMixinBase, TemplateAPIView):
    """
    A view for displaying the results of a scanner for a specific file in a user's project.
    """

    permission_classes = [CanEditProject]
    default_redirect = "Project-Overview"
    keep_redirect_kwargs = False

    def get_redirect_kwargs(self) -> dict:
        return {"project_uuid": self.kwargs["project_uuid"]}

    def get_context_data(self, **kwargs):
        """
        Retrieve and prepare the context data for rendering the scanner results view.

        :param kwargs: Additional keyword arguments.
        :return: A dictionary containing the context data.
        """
        context = super().get_context_data(**kwargs)
        self.apply_project_context(context)
        self.template_name = RESULTS_BASE

        file_md5 = self.kwargs.get("file_md5", None)
        active_file = File.objects.filter(md5=file_md5).first()
        if not file_md5 or not active_file:
            messages.error(self.request, "Could not find file!", "FileNotFoundError")
            return context

        project = context["project"]
        # Apply scan files after permission check
        context["scan_files"] = Scan.files(project=project)
        context["active_file"] = active_file
        context["scan"] = Scan.objects.filter(project=project, file=active_file).first()

        plugins = ScannerPlugin.all_of(project)
        name = self.kwargs["name"]
        if name not in plugins:
            messages.error(
                self.request,
                "Invalid scanner name for selected project",
                "404NotFoundError",
            )
            return context

        plugin: ScannerPlugin = plugins[name]
        extension = self.kwargs.get("extension", plugin.extensions[0])
        if extension not in plugin.extensions and extension is not None:
            messages.error(
                self.request,
                "Invalid extension name for selected scanner",
                "404NotFoundError",
            )
            return context

        context["extensions"] = plugin.extensions
        context["scanner_name"] = name
        context["active"] = f"tabs-{extension}"
        context["data"] = plugin.context(extension, context["scan"], active_file)

        if extension == "explorer":
            context["FILE_TYPES"] = FILE_TYPES

        self.template_name = f"project/results/results-{extension}.html"
        if not (BASE_DIR / "templates" / self.template_name).exists():
            self.template_name = RESULTS_BASE

        logger.debug(f"Using result template '{self.template_name}' to display results")
        return context
