OSAL
====

In order to work on any Operating System (OS), the SMW library requires a
module called OSAL. This OSAL must be implemented by the SMW library integrator
to work on a specific OS.

The OSAL is the entry point of the SMW library. It's in charge of the library
initialization, load, unload.
In addition, the OSAL must implement a key database manager to convert a
subsystem key identifier to a library identifier that might be PSA compatible
or not.

The SMW source package contains an example of OSAL in the folder `osal/Linux`
running on Linux and used to validate the library. This code example can be
modified by the library integrator.

.. toctree::
   :maxdepth: 1
   :glob:

   interface
   example
