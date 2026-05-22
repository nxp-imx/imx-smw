Device management APIs
^^^^^^^^^^^^^^^^^^^^^^

The Device management APIs allow users of the library to manage device
operations such as information, configuration, and lifecycle management.


Device information
""""""""""""""""""
Functions
~~~~~~~~~
.. kernel-doc:: /public/smw_device.h
    :functions: smw_device_attestation

.. kernel-doc:: /public/smw_device.h
    :functions: smw_device_get_uuid

Structures
~~~~~~~~~~
.. kdoc-extension:: /public/smw_device.h
   :structs: smw_device_attestation_args smw_device_uuid_args

Device lifecycle
""""""""""""""""
Functions
~~~~~~~~~
.. kernel-doc:: /public/smw_device.h
    :functions: smw_device_set_lifecycle smw_device_get_lifecycle

Structures
~~~~~~~~~~
.. kdoc-extension:: /public/smw_device.h
   :structs: smw_device_lifecycle_args

Device reprovisioning
"""""""""""""""""""""
The Device reprovisioning allows clearing and reinitializing the secure
storage. This operation removes all stored keys and data objects, resetting
anti-rollback protection.

Details on the reprovisioning support and procedure are available in the
:ref:`storage_capabilities` section.

Functions
~~~~~~~~~
.. kernel-doc:: /public/smw_device.h
    :functions: smw_device_reprovision_prepare smw_device_reprovision

Structures
~~~~~~~~~~
.. kdoc-extension:: /public/smw_device.h
   :structs: smw_device_reprovision_args