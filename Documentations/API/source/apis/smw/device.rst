Device management APIs
^^^^^^^^^^^^^^^^^^^^^^

The Device management APIs allow users of the library to manage device
operations such as information, configuration, and lifecycle management.


Device information
""""""""""""""""""

.. kernel-doc:: /public/smw_device.h
    :functions: smw_device_attestation

.. kernel-doc:: /public/smw_device.h
    :functions: smw_device_get_uuid

.. kdoc-extension:: /public/smw_device.h
   :structs: smw_device_attestation_args smw_device_uuid_args


Device lifecycle
""""""""""""""""

.. kernel-doc:: /public/smw_device.h
    :functions: smw_device_set_lifecycle smw_device_get_lifecycle

.. kdoc-extension:: /public/smw_device.h
   :structs: smw_device_lifecycle_args

Device reprovisioning
"""""""""""""""""""""

The Device reprovisioning APIs allow users to create a new secure enclave
NVM Secure Storage to replace the storage that is rollback protected. It's only
possible with ELE (EdgeLock Enclave) subsystem.

The reprovisioning process consists of two steps in the **same power cycle**:

 - Step 1: If SMW database exists, it must be cleaned to ensure all ELE
   persistent objects are destroyed. The simple way is:

   - Unloading the SMW library (close all applications using NVM Secure
     Enclave storage to replace).
   - Removing the SMW's database file.
   - Reloading the SMW library (restart the application) and perform key
     provisioning (e.g. key generation, key import)

 - Step 2: Send re-provisioning request to EdgeLock Secure Enclave:

   - Generate the ELE re-provisioning signed message. The function
     :c:func:`smw_device_reprovision_prepare` can be used to prepare the message
     to be signed with signing tool like NXP `SPSDK <https://github.com/nxp-mcuxpresso/spsdk/releases>`_
     tool. The documentation is available `here <https://spsdk.readthedocs.io/en/latest/index.html>`_.
     The command used to sign is `nxpimage <https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html#nxpimage-signed-msg>`_.
   - Send the request to ELE Secure Enclave to allow re-provisioning by calling
     the :c:func:`smw_device_reprovision` function. Upon success, the SMW Library
     requests the creation of the fresh EdgeLock Secure Storage.

.. warning::
    All keys and data previously stored in the NVM Secure Storage will be
    erased during the reprovisioning process. The SMW database for persistent
    object will be un-synchronized if not erased or cleaned up.

.. kernel-doc:: /public/smw_device.h
    :functions: smw_device_reprovision_prepare smw_device_reprovision

.. kdoc-extension:: /public/smw_device.h
   :structs: smw_device_reprovision_args