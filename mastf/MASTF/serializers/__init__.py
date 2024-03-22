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
The 'serializer' module provides additional functionality to Django REST
framework's serializer classes by adding the :class:`ManyToManyField` and
:class:`ManyToManySerializer` classes.

It offers a :class:`ManyToManyField` class that allows for the serialization
and deserialization of many-to-many relationships, which are commonly used in
Django models. The :class:`ManyToManyField` class supports the full range of
many-to-many fields, including fields with intermediate models and related
objects.

In addition, this module provides a 'ManyToManySerializer' class that can be
used as a base class for serializers that handle many-to-many relationships.
It is designed to simplify the creation of custom serializers with many-to-many
fields.

Let's take a quick look at the following example:

.. code-block:: python
    :linenos:

    from mastf.MASTF.serializers import ManyToManySerializer, ManyToManyField

    # Define a new class with many-to-many relationships
    class BlogSerializer(ManyToManySerializer):
        rel_fields = ("articles", )
        articles = ManyToManyField(Article, mapper=int)

        class Meta:
            model = Blog
            fields = '__all__'

Here, we've created a new class named *BlogSerializer* that uses a
:class:`ManyToManyField` to represent a many-to-many relationships. In
addition, we delcared a ``mapper`` function that will convert incoming
data to the preferred primary key attribute.
"""
from .base import *

from .ser_finding import *
from .ser_scan import *
from .ser_host import *
