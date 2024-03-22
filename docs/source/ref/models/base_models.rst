.. _guide_models_base:

***********
Core Models
***********

Before we introduce the model classes being used the most in this project,
there is another utility class that comes with some special behaviour:

.. autoclass:: mastf.MASTF.models.namespace
    :members:

.. figure:: images/base_models.png
    :alt: Overview of basic core models

    Figure 1: Simple overview of necessary models for a MAST-F instance to work.

.. autoclass:: mastf.MASTF.models.Environment
    :members:
    :exclude-members: MultipleObjectsReturned, DoesNotExist

.. autoclass:: mastf.MASTF.models.Team
    :members:
    :exclude-members: MultipleObjectsReturned, DoesNotExist

.. autoclass:: mastf.MASTF.models.Project
    :members:
    :exclude-members: MultipleObjectsReturned, DoesNotExist

.. autoclass:: mastf.MASTF.models.File
    :members:
    :exclude-members: MultipleObjectsReturned, DoesNotExist

.. autoclass:: mastf.MASTF.models.Account
    :members:
    :exclude-members: MultipleObjectsReturned, DoesNotExist

.. autoclass:: mastf.MASTF.models.Bundle
    :members:
    :exclude-members: MultipleObjectsReturned, DoesNotExist
