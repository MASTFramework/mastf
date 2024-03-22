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

from rest_framework import serializers
from celery.result import AsyncResult
from celery.app.task import states

from mastf.MASTF.models import Scan, namespace, ScanTask
from mastf.core.progress import PROGRESS

__all__ = ["ScanSerializer", "ScanTaskSerializer", "CeleryAsyncResultSerializer"]

logger = logging.getLogger(__name__)


class ScanSerializer(serializers.ModelSerializer):
    class Meta:
        model = Scan
        fields = "__all__"


class CeleryAsyncResultSerializer(serializers.Serializer):
    def to_representation(self, instance: AsyncResult):
        if not instance:
            return {}

        if not isinstance(instance, (AsyncResult, str)):
            raise TypeError(
                f"Invalid input type for class {self.__class__}; expected AsyncResult, "
                "got {instance.__class__}!"
            )

        if isinstance(instance, str):
            instance = AsyncResult(instance)

        data = namespace(
            id=instance.id,
            state=instance.state,
            complete=False,
            success=False,
            progress={},
        )

        meta: dict = instance._get_task_meta()
        state = meta.get("status", None)
        result = meta["result"]

        data.state = state
        if state == PROGRESS:
            data.progress = result

        elif state in (states.PENDING, states.STARTED):
            data.progress.update(
                {"pending": True, "current": 0, "total": 100, "percent": 0}
            )

        elif state in (states.SUCCESS, states.FAILURE):
            success = instance.successful()
            data.complete = True
            data.success = success
            if isinstance(result, Exception):
                data.result = str(result)
            elif isinstance(result, dict):
                data.result = result.get(
                    "description", f"Task with id={instance.id} finished!"
                )
            else:
                data.result = str(result)

            data.progress.update({"current": 0, "percent": 100})

        return data


class ScanTaskSerializer(serializers.ModelSerializer):
    celery_id = CeleryAsyncResultSerializer(many=False)

    class Meta:
        model = ScanTask
        fields = "__all__"
