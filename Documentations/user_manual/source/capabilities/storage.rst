.. _storage_capabilities:

Key and Data Storage
--------------------

Overview
^^^^^^^^

The SMW library provides storage capabilities for managing keys and data
objects across different subsystems. Each subsystem may support different
storage types and persistence models.

Storage Types
^^^^^^^^^^^^^
The library supports two main storage types:

Persistent Storage
""""""""""""""""""
Persistent storage maintains keys and data objects across system reboots and
power cycles. Objects stored persistently are saved to non-volatile memory.

Transient Storage
"""""""""""""""""
Transient storage maintains keys and data objects only during the current
session. Objects are lost when the system is powered down or the library
context is destroyed.

Subsystem Storage Support
^^^^^^^^^^^^^^^^^^^^^^^^^
The different subsystems provide varying levels of storage support as listed
in following table:

.. table:: Storage Capabilities by Subsystem
   :name: table_storage_capabilities
   :align: center
   :class: wrap-table

   +---------------+--------------+---------------+-------------------+------------------------+---------------------------------+
   | **Subsystem** | **Persistent Storage**                                                    | **Transient Storage**           |
   +               +--------------+---------------+-------------------+------------------------+                                 +
   |               | **Location** | **Shareable** | **Anti-Rollback** | **Re-Provision**       | **Location**                    |
   +===============+==============+===============+===================+========================+=================================+
   | ELE           | NVM          | Yes           | Yes               | Yes                    | Secure Enclave Volatile Memory  |
   +---------------+--------------+---------------+-------------------+------------------------+---------------------------------+
   | SECO          | NVM          | No            | Yes               | Yes                    | Secure Enclave Volatile Memory  |
   |               |              |               |                   | but not support by SMW |                                 |
   +---------------+--------------+---------------+-------------------+------------------------+---------------------------------+
   | TEE           | REE          | No            | No                | No                     | TA Volatile Memory              |
   +               +--------------+---------------+-------------------+------------------------+---------------------------------+
   |               | RPMB         | No            | Yes               | No                     | TA Volatile Memory              |
   +---------------+--------------+---------------+-------------------+------------------------+---------------------------------+


Configuration
^^^^^^^^^^^^^
Storage configuration is managed through (see :ref:`os-osal-implementation`)

ELE Subsystem
"""""""""""""
The EdgeLock Enclave (ELE) subsystem supports both persistent and transient
storage types. Persistent storage is backed by non-volatile memory (NVM) managed
by the ELE firmware, while transient storage is maintained in ELE volatile
memory during the active session.

The NVM Storage is organized in a storage master to which is linked a key
storage master. The key storage master manages the storage of both encrypted
key chunks (group of keys) and data blobs (one data per blob).

.. code-block:: text

   +-----------------+     +---------------------+
   | Storage Master* | --> | Key Storage Master* |
   +-----------------+     +---------------------+
                               /             \
                              /               \
                             /                 \
                            /                   \
                            |-- Key chunk 1*    |-- Data blob 1
                            |-- Key chunk 2*    |-- Data blob 2
                            |-- ...             |-- ...
                            |-- Key chunk N*    |-- Data blob M

   * Rollback protectable

Rollback protection
~~~~~~~~~~~~~~~~~~~
The anti-rollback feature provides protection against downgrade attacks by
maintaining version counters for stored objects. When enabled, the ELE Firmware
prevents loading of objects with lower version numbers than previously stored
versions. The anti-rollback counter is stored in secure fuses and duplicated
in the Storage Master blob of the NVM Secure Storage. By propagation, the
rollback protection extends to the Key Storage Master and all key chunks.

The data blobs even if linked to the Key Storage Master are not protected.

The rollback protection is increased when the commit operation is performed.

.. table:: Storage commit APIs Comparison
   :name: storage_commit_apis_comparison
   :align: center
   :widths: 15 85
   :width: 100%
   :class: wrap-table

   +---------+----------------------------------+
   | **API** | **Function**                     |
   +=========+==================================+
   | SMW     | :c:func:`smw_commit_key_storage` |
   +---------+----------------------------------+
   | PSA     | Not supported                    |
   +---------+----------------------------------+
   | PKCS11  | Not supported                    |
   +---------+----------------------------------+


Storage Reprovisioning
~~~~~~~~~~~~~~~~~~~~~~
The Storage reprovisioning APIs allow users to create a new secure enclave
NVM Secure Storage to replace the storage that is rollback protected.

The storage reprovisioning operation is performed through the following APIs:

.. table:: Storage Reprovisioning APIs Comparison
   :name: storage_reprovisioning_apis_comparison
   :align: center
   :widths: 15 85
   :width: 100%
   :class: wrap-table

   +---------+----------------------------------+
   | **API** | **Function**                     |
   +=========+==================================+
   | SMW     | :c:func:`smw_device_reprovision` |
   +---------+----------------------------------+
   | PSA     | Not supported                    |
   +---------+----------------------------------+
   | PKCS11  | Not supported                    |
   +---------+----------------------------------+

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

.. important::
    The new created NVM Secure Storage is empty but must not be removed as the
    anti-rollback counters are stored in the secure fuses and can't be reset.
    The new create NVM Secure Storage contains specific information that
    rollback protection is not enabled with the storage until next storage
    commitment.

Storage Capacities
~~~~~~~~~~~~~~~~~~

.. table:: ELE Key Storage Capacities
   :name: table_ele_key_storage_capacities
   :align: center
   :class: wrap-table

   +----------------+------------+----------------------+------------------+
   | **Nb Storage** | **Type**   | **Key storage**                         |
   +                +            +----------------------+------------------+
   |                |            | **max keys/storage** | **nb chunk**     |
   +================+============+======================+==================+
   | 2              | Persistent | 100                  | 50 (SMW defined) |
   +                +------------+                      +------------------+
   |                | Transient  |                      | 50 (SMW defined) |
   +----------------+------------+----------------------+------------------+

.. table:: ELE Data Storage Capacities
   :name: table_ele_data_storage_capacities
   :align: center
   :class: wrap-table

   +-------------------+-------------------------------------+
   | **max size/blob** | **nb blobs**                        |
   +===================+=====================================+
   | 2 Kbytes          | Limited by the available OS storage |
   +-------------------+-------------------------------------+

SECO Subsystem
""""""""""""""
The Security Controller (SECO) subsystem supports the same Secure Storage
concept as ELE. SECO provides both persistent and transient storage types with
similar organizational structure and anti-rollback protection capabilities.
The SECO NVM Storage follows the same master-to-key storage hierarchy as ELE,
with a Storage Master linked to a Key Storage Master that manages encrypted key
chunks and data blobs.

Rollback protection
~~~~~~~~~~~~~~~~~~~
The anti-rollback protection mechanism in SECO operates identically to ELE,
maintaining version counters in secure fuses and duplicating them in the Storage
Master blob. This ensures that key chunks and the Key Storage Master are
protected against rollback attacks, while data blobs remain unprotected by the
anti-rollback feature.

The difference between ELE and SECO subsystem is that on SECO each persistent
key creation increment the rollback protection counter up to the limit of
the max counter update define during the creation of the key storage. When
the limit of the counter is reached, rollback protection is disabled for
subsequent key creations.

Storage Reprovisioning
~~~~~~~~~~~~~~~~~~~~~~
The Storage reprovisioning is possible for SECO subsystem but not supported by
the SMW library for this subsystem.

Storage Capacities
~~~~~~~~~~~~~~~~~~

.. table:: SECO Key Storage Capacities
   :name: table_seco_key_storage_capacities
   :align: center
   :class: wrap-table

   +----------------+------------+---------------------+-------------------+
   | **Nb Storage** | **Type**   | **Key storage**                         |
   +                +            +---------------------+-------------------+
   |                |            | **max bytes/chunk** | **nb chunk**      |
   +================+============+=====================+===================+
   | 1              | Persistent | 4 Kbytes            | 512 (SMW defined) |
   +                +------------+                     +-------------------+
   |                | Transient  |                     | 512 (SMW defined) |
   +----------------+------------+---------------------+-------------------+

.. table:: SECO Data Storage Capacities
   :name: table_seco_data_storage_capacities
   :align: center
   :class: wrap-table

   +-------------------+-------------------------------------+
   | **Data storage**                                        |
   +-------------------+-------------------------------------+
   | **max size/blob** | **nb blobs**                        |
   +===================+=====================================+
   | 2 Kbytes          | Limited by the available OS storage |
   +-------------------+-------------------------------------+

TEE Subsystem
"""""""""""""
The Trusted Execution Environment (TEE) subsystem, based on TrustZone OPTEE OS,
supports persistent storage through the REE (Rich Execution Environment)
filesystem or RPMB (Replay Protected Memory Block) partition of MMC/SD card. The
REE storage is the default option, use of the RPMB is selectable at compilation
time. More details about TEE storage can be found in the
`OP-TEE documentation - Secure storage <https://optee.readthedocs.io/en/latest/architecture/secure_storage.html>`_.

The persistent storage is isolated and encrypted by OPTEE OS, ensuring data
confidentiality and integrity for each Trusted Application instance.

The transient storage is maintained in volatile memory during the active
loaded Trusted Application (TA) session and is lost when the TA is unloaded or
the system is powered down.

The persistent storage rollback protection is applicable only in case of
RPMB usage, while REE filesystem storage does not provide anti-rollback.

Key or data are stored as objects in the persistent storage. The maximum size
of a single object is limited by the available storage space.


Storage Capacities
~~~~~~~~~~~~~~~~~~

.. table:: TEE Storage Capacities
   :name: table_tee_storage_capacities
   :align: center
   :class: wrap-table

   +----------------+--------------------------+---------------------+
   | **Nb Storage** | **Key/data storage**                           |
   +                +--------------------------+---------------------+
   |                | **max keys/storage**     | **max size/object** |
   +================+==========================+=====================+
   | 1 per TA       | Limited by the available TEE Storage and       |
   |                | performance to load/unload objects             |
   +----------------+------------------------------------------------+


Bad Practice
^^^^^^^^^^^^
In OS environment where subsystem storages are files stored in the filesystem,
manually deleting these files should be avoided as it will cause
inconsistency between SMW's database and secure storage content.

The best practice is to call the :ref:`key_management_delete` and the
:ref:`data_management_delete` APIs to delete keys and data objects respectively,
ensuring database consistency and proper cleanup of secure storage resources.
