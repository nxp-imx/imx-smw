.. _smw_objects_attributes_definition:

Objects Attributes definitions
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Objects Attributes definitions provide bitmasks and macros to manage
attributes associated to keys and data objects.

Macros are provided to set, get, and test attribute values.

A key is defined by the following attributes:

  - `Permitted algorithm`_: Defines which algorithm(s) can use this key.
  - `Usage restriction`_: Defines how the key can be used.
  - `Object Attributes`_:\

    - Persistence: Defines if the key is permanent, persistent or transient.
    - Lifecycle: Defines in which device lifecycle(s) the object is usable.
    - Sensitivity: Defines if the object is sensitive (plain text retrieval
      restricted).

  - `Storage location`_: Defines where the object is stored.


A data object is defined by the following attributes:

  - `Object Attributes`_:\

    - Persistence: Defines if the data object is permanent, persistent or
      transient.
    - Lifecycle: Defines in which device lifecycle(s) the object is usable.
    - Sensitivity: Defines if the object is sensitive (plain text retrieval
      restricted).

  - `Storage location`_: Defines where the object is stored.



Permitted algorithm
"""""""""""""""""""
Definition of the key permitted algorithm restriction if supported by the
subsystem.

Refer to the :ref:`algorithm-smw_attr_algo_t-encoding`,
the 64-bit encoding is same as the cryptographic 64-bit algorithm encoding
format with some exception detailed in the notes.


Usage restriction
"""""""""""""""""
Definition of the key usage restriction if supported by the subsystem.

Typedef
~~~~~~~
.. kdoc-extension:: /public/smw/attr.h
   :typedefs: smw_attr_usage_t

.. table:: Key Usage bitmask value
   :name: table_smw_key_usage_encoding
   :align: center
   :widths: 14 46 40
   :class: wrap-table

   +------------+-------------------------------+--------------------------------------------------------+
   | **Value**  | **Define**                    | **Description**                                        |
   +============+===============================+========================================================+
   | 0x00000000 | SMW_ATTR_USAGE_NONE           | No key usage defined.                                  |
   +------------+-------------------------------+--------------------------------------------------------+
   | 0x00000001 | SMW_ATTR_USAGE_CACHE          | Permission to cache the key.                           |
   +------------+-------------------------------+--------------------------------------------------------+
   | 0x00000002 | SMW_ATTR_USAGE_COPY           | Permission to copy the key.                            |
   +------------+-------------------------------+--------------------------------------------------------+
   | 0x00000004 | SMW_ATTR_USAGE_EXPORT         | Permission to export the key.                          |
   +------------+-------------------------------+--------------------------------------------------------+
   | 0x00000008 | SMW_ATTR_USAGE_ENCRYPT        | Permission to encrypt a message with the key.          |
   +------------+-------------------------------+--------------------------------------------------------+
   | 0x00000010 | SMW_ATTR_USAGE_DECRYPT        | Permission to decrypt a message with the key.          |
   +------------+-------------------------------+--------------------------------------------------------+
   | 0x00000020 | SMW_ATTR_USAGE_SIGN_MESSAGE   | Permission to sign a message with the key.             |
   +------------+-------------------------------+--------------------------------------------------------+
   | 0x00000040 | SMW_ATTR_USAGE_VERIFY_MESSAGE | Permission to verify a message signature with the key. |
   +------------+-------------------------------+--------------------------------------------------------+
   | 0x00000080 | SMW_ATTR_USAGE_SIGN_HASH      | Permission to sign a message hash with the key.        |
   +------------+-------------------------------+--------------------------------------------------------+
   | 0x00000100 | SMW_ATTR_USAGE_VERIFY_HASH    | Permission to verify a message hash with the key.      |
   +------------+-------------------------------+--------------------------------------------------------+
   | 0x00000200 | SMW_ATTR_USAGE_DERIVE         | Permission to derive other keys from this key.         |
   +------------+-------------------------------+--------------------------------------------------------+

Macros
~~~~~~
.. kdoc-extension:: /public/smw/attr.h
   :macros: SMW_ATTR_USAGE_SET_CACHE SMW_ATTR_USAGE_IS_CACHE
            SMW_ATTR_USAGE_SET_COPY SMW_ATTR_USAGE_IS_COPY
            SMW_ATTR_USAGE_SET_EXPORT SMW_ATTR_USAGE_IS_EXPORT
            SMW_ATTR_USAGE_SET_ENCRYPT SMW_ATTR_USAGE_IS_ENCRYPT
            SMW_ATTR_USAGE_SET_DECRYPT SMW_ATTR_USAGE_IS_DECRYPT
            SMW_ATTR_USAGE_SET_SIGN_MESSAGE SMW_ATTR_USAGE_IS_SIGN_MESSAGE
            SMW_ATTR_USAGE_SET_VERIFY_MESSAGE SMW_ATTR_USAGE_IS_VERIFY_MESSAGE
            SMW_ATTR_USAGE_SET_SIGN_HASH SMW_ATTR_USAGE_IS_SIGN_HASH
            SMW_ATTR_USAGE_SET_VERIFY_HASH SMW_ATTR_USAGE_IS_VERIFY_HASH
            SMW_ATTR_USAGE_SET_DERIVE SMW_ATTR_USAGE_IS_DERIVE


Object attributes
"""""""""""""""""
Definition of the object (key or data) attributes as Persistence, Lifecycle
usage restriction (if supported by subsystem), ...

Typedef
~~~~~~~
.. kdoc-extension:: /public/smw/attr.h
   :typedefs: smw_attr_attributes_t

.. table:: Object attributes bit field
   :name: table_smw_object_attribute_encoding
   :align: center
   :widths: 10 90
   :width: 100%
   :class: wrap-table

   +-------------+--------------------------------------------------------------------------------+
   | **Bits**    | **Description**                                                                |
   +=============+================================================================================+
   | **[31:19]** | Reserved                                                                       |
   +-------------+--------------------------------------------------------------------------------+
   | **[18]**    | Sensitive, object is sensitive, plain text value can't be retrieved.           |
   +-------------+--------------------------------------------------------------------------------+
   | **[17:16]** | Read/Write data object, not applicable to a key object.                        |
   |             |                                                                                |
   |             | .. list-table::                                                                |
   |             |    :header-rows: 1                                                             |
   |             |    :widths: 9 56 35                                                            |
   |             |    :class: inner-table                                                         |
   |             |                                                                                |
   |             |    * - **Value**                                                               |
   |             |      - **Define**                                                              |
   |             |      - **Description**                                                         |
   |             |    * - 0x00                                                                    |
   |             |      - SMW_ATTR_RW_FLAG_NONE                                                   |
   |             |      - No restriction. Can be read and write.                                  |
   |             |    * - 0x01                                                                    |
   |             |      - SMW_ATTR_RW_FLAG_READ_ONLY                                              |
   |             |      - Read only. Can't be overwritten.                                        |
   |             |    * - 0x02                                                                    |
   |             |      - SMW_ATTR_RW_FLAG_READ_ONCE                                              |
   |             |      - Read only one time and it's removed after read.                         |
   +-------------+--------------------------------------------------------------------------------+
   | **[15:8]**  | Device Lifecycle when object is usable. It's a bitmask value. One or more      |
   |             | lifecycle can be selected.                                                     |
   |             |                                                                                |
   |             | .. list-table::                                                                |
   |             |    :header-rows: 1                                                             |
   |             |    :widths: 9 56 35                                                            |
   |             |    :class: inner-table                                                         |
   |             |                                                                                |
   |             |    * - **Value**                                                               |
   |             |      - **Define**                                                              |
   |             |      - **Description**                                                         |
   |             |    * - 0x01                                                                    |
   |             |      - SMW_ATTR_LIFECYCLE_CURRENT                                              |
   |             |      - Current Lifecycle                                                       |
   |             |    * - 0x02                                                                    |
   |             |      - SMW_ATTR_LIFECYCLE_OPEN                                                 |
   |             |      - OEM Open Lifecycle                                                      |
   |             |    * - 0x04                                                                    |
   |             |      - SMW_ATTR_LIFECYCLE_CLOSED                                               |
   |             |      - OEM Closed Lifecycle                                                    |
   |             |    * - 0x08                                                                    |
   |             |      - SMW_ATTR_LIFECYCLE_CLOSED_LOCKED                                        |
   |             |      - OEM Closed and Locked Lifecycle                                         |
   +-------------+--------------------------------------------------------------------------------+
   | **[7:4]**   | Reserved                                                                       |
   +-------------+--------------------------------------------------------------------------------+
   | **[3:0]**   | Object persistency.                                                            |
   |             |                                                                                |
   |             | .. list-table::                                                                |
   |             |    :header-rows: 1                                                             |
   |             |    :widths: 9 56 35                                                            |
   |             |    :class: inner-table                                                         |
   |             |                                                                                |
   |             |    * - **Value**                                                               |
   |             |      - **Define**                                                              |
   |             |      - **Description**                                                         |
   |             |    * - 0x0                                                                     |
   |             |      - SMW_ATTR_PERSISTENCE_TRANSIENT                                          |
   |             |      - Object is transient. Does not resist a device reset.                    |
   |             |    * - 0x1                                                                     |
   |             |      - SMW_ATTR_PERSISTENCE_PERSISTENT                                         |
   |             |      - Object is persistent. Resists device reset.                             |
   |             |    * - 0x2                                                                     |
   |             |      - SMW_ATTR_PERSISTENCE_PERMANENT                                          |
   |             |      - Object is permanent. Can't be deleted.                                  |
   +-------------+--------------------------------------------------------------------------------+

Macros
~~~~~~
.. kdoc-extension:: /public/smw/attr.h
   :macros: SMW_ATTR_SET_PERSISTENCE SMW_ATTR_GET_PERSISTENCE
            SMW_ATTR_SET_TRANSIENT SMW_ATTR_IS_TRANSIENT
            SMW_ATTR_SET_PERSISTENT SMW_ATTR_IS_PERSISTENT
            SMW_ATTR_SET_PERMANENT SMW_ATTR_IS_PERMANENT

.. kdoc-extension:: /public/smw/attr.h
   :macros: SMW_ATTR_SET_LC_CURRENT SMW_ATTR_IS_LC_CURRENT
            SMW_ATTR_SET_LC_OPEN SMW_ATTR_IS_LC_OPEN
            SMW_ATTR_SET_LC_CLOSED SMW_ATTR_IS_LC_CLOSED
            SMW_ATTR_SET_LC_CLOSED_LOCKED SMW_ATTR_IS_LC_CLOSED_LOCKED

.. kdoc-extension:: /public/smw/attr.h
   :macros: SMW_ATTR_SET_READ_ONLY SMW_ATTR_IS_READ_ONLY
            SMW_ATTR_SET_READ_ONCE SMW_ATTR_IS_READ_ONCE

.. kdoc-extension:: /public/smw/attr.h
   :macros: SMW_ATTR_SET_SENSITIVE SMW_ATTR_CLEAR_SENSITIVE SMW_ATTR_IS_SENSITIVE

Storage location
""""""""""""""""
Definition of the object (key or data) storage location. Giving Information
such as storage location, type of object.

The storage location attribute is used only by the ELE subsystem and only part
of the bit field is used, other bits are reserved for future use.

Typedef
~~~~~~~
.. kdoc-extension:: /public/smw/attr.h
   :typedefs: smw_attr_storage_id_t

.. table:: Object storage identifier bit field
   :name: table_smw_object_storag_encoding
   :align: center
   :widths: 10 90
   :class: wrap-table

   +-------------+---------------------------------------------------------+
   | **Bits**    | **Description**                                         |
   +=============+=========================================================+
   | **[31:24]** | Reserved                                                |
   +-------------+---------------------------------------------------------+
   | **[23]**    | Set to 1 to use this NXP vendor encoding.               |
   +-------------+---------------------------------------------------------+
   | **[22]**    | Vendor NXP Identifier.                                  |
   +-------------+---------------------------------------------------------+
   | **[21]**    | NXP's EdgeLock 2GO object.                              |
   +-------------+---------------------------------------------------------+
   | **[20:16]** | Reserved must be 0s.                                    |
   +-------------+---------------------------------------------------------+
   | **[15]**    | Object type:\                                           |
   |             |                                                         |
   |             |  - 0: Key type                                          |
   |             |  - 1: Data type                                         |
   +-------------+---------------------------------------------------------+
   | **[14:8]**  | NXP's Secure Enclave storage identifier:\               |
   |             |                                                         |
   |             |  - 0x00: default storage location                       |
   |             |  - 0x02: EdgeLock Key Import location                   |
   +-------------+---------------------------------------------------------+
   | **[7:0]**   | NXP's Secure Enclave identifier.                        |
   |             | **Defined For future use**                              |
   +-------------+---------------------------------------------------------+

Examples
~~~~~~~~
In case of *EdgeLock 2GO* object, the storage location attribute should be set
as follows:

  - Key type object: ``0x00E000__``
  - Data type object: ``0x00E080__``

where `_` means any value.

In case of *EdgeLock Key Import* object, the storage location attribute should be set
as follows:

  - Key type object: ``0x00C00200``

For other key creation operations (generate, derivation), the storage location
attribute can be any value. The ELE Subsystem is not interpreting this
attribute. Attribute is stored and returned as-is to the user. It's advice to
set it to ``0x00000000`` for compatibility with future versions.