.. _osal:

OSAL
====

In order to work on any Operating System (OS), the SMW library requires a
module called OSAL. The module is split in two parts:

 - The :ref:`Core library interface <core-osal-interface>` that defines the
   contract between the SMW core library and the OSAL module.
 - The OSAL user interface that allows applications to use the SMW library.
   The project delivery include a :ref:`OS-specific implementation <os-osal-implementation>`
   of the OSAL module.

The OSAL module includes a concept of object database used to store object's
information like metadata. The :ref:`Core library interface <core-osal-interface>`
gives more details.

The integrator should adapt the implementation to their specific OS
requirements and constraints.

Provided Linux implementation can be used as a reference but can also be
replaced by a custom implementation that fits the target OS architecture and
constraints.

.. toctree::
   :maxdepth: 3
   :numbered: 4
   :glob:

   osal/interface/interface
   osal/linux/linux