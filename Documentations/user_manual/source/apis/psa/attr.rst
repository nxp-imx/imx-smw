
.. _psa_objects_attributes_definition:

Objects Attributes definitions
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Objects Attributes definitions provide bitmasks and functions to manage
attributes associated to keys and data objects.

Functions are provided to set and get attribute values.

A key is defined by the following attributes:

  - `Key types`_: Defines the type of the key.
  - `Permitted algorithm`_: Defines which algorithm(s) can use this key.
  - `Usage restriction`_: Defines how the key can be used.
  - `Lifetime`_:\

    - Persistence: Defines if the key is persistent or volatile (transient).
    - Location: Defines where the object is stored.

Key types
"""""""""
Definition of the key type.

Refer to the :ref:`psa_key_type_encoding`, the key type is defined as a 16-bit
encoding format.

Permitted algorithm
"""""""""""""""""""
Definition of the key permitted algorithm restriction if supported by the
subsystem.

Usage restriction
"""""""""""""""""
Definition of the key usage restriction if supported by the subsystem.

.. kdoc-extension:: /public/psa/crypto_types.h
   :typedefs: psa_key_usage_t

.. table:: Key Usage bitmask value
   :name: table_psa_key_usage_encoding
   :align: center
   :widths: 14 46 40
   :class: wrap-table

   +------------+---------------------------------+--------------------------------------------------------+
   | **Value**  | **Define**                      | **Description**                                        |
   +============+=================================+========================================================+
   | 0x00000004 | PSA_KEY_USAGE_CACHE             | Permission to cache the key.                           |
   +------------+---------------------------------+--------------------------------------------------------+
   | 0x00000002 | PSA_KEY_USAGE_COPY              | Permission to copy the key.                            |
   +------------+---------------------------------+--------------------------------------------------------+
   | 0x00000001 | PSA_KEY_USAGE_EXPORT            | Permission to export the key.                          |
   +------------+---------------------------------+--------------------------------------------------------+
   | 0x00000100 | PSA_KEY_USAGE_ENCRYPT           | Permission to encrypt a message with the key.          |
   +------------+---------------------------------+--------------------------------------------------------+
   | 0x00000200 | PSA_KEY_USAGE_DECRYPT           | Permission to decrypt a message with the key.          |
   +------------+---------------------------------+--------------------------------------------------------+
   | 0x00000400 | PSA_KEY_USAGE_SIGN_MESSAGE      | Permission to sign a message with the key.             |
   +------------+---------------------------------+--------------------------------------------------------+
   | 0x00000800 | PSA_KEY_USAGE_VERIFY_MESSAGE    | Permission to verify a message signature with the key. |
   +------------+---------------------------------+--------------------------------------------------------+
   | 0x00001000 | PSA_KEY_USAGE_SIGN_HASH         | Permission to sign a message hash with the key.        |
   +------------+---------------------------------+--------------------------------------------------------+
   | 0x00002000 | PSA_KEY_USAGE_VERIFY_HASH       | Permission to verify a message hash with the key.      |
   +------------+---------------------------------+--------------------------------------------------------+
   | 0x00004000 | PSA_KEY_USAGE_DERIVE            | Permission to derive other keys from this key.         |
   +------------+---------------------------------+--------------------------------------------------------+
   | 0x00008000 | PSA_KEY_USAGE_VERIFY_DERIVATION | Permission to verify the result of a key derivation,   |
   |            |                                 | including password hashing.                            |
   +------------+---------------------------------+--------------------------------------------------------+

Functions
~~~~~~~~~
.. kdoc-extension:: /public/psa/keymgr.h
   :functions: psa_set_key_usage_flags psa_get_key_usage_flags

Lifetime
""""""""
Definition of the key object attributes as persistence and location.

.. kdoc-extension:: /public/psa/crypto_types.h
   :typedefs: psa_key_lifetime_t

.. table:: Key lifetime bit field
   :name: table_psa_key_lifetime_encoding
   :align: center
   :widths: 10 90
   :width: 100%
   :class: wrap-table

   +-------------+---------------------------------------------------------+
   | **Bits**    | **Description**                                         |
   +=============+=========================================================+
   | **[31:8]**  | Location indicator.                                     |
   |             |                                                         |
   |             | The value indicates where the key material is stored.   |
   |             | See :c:type:`psa_key_location_t` for more information.  |
   +-------------+---------------------------------------------------------+
   | **[7:0]**   | Object persistency. See :c:type:`psa_key_persistence_t` |
   |             | for more information.                                   |
   +-------------+---------------------------------------------------------+

.. kdoc-extension:: /public/psa/crypto_types.h
   :typedefs: psa_key_location_t

It's a 24 bits encoding value and only significant for the ELE Secure Subsystem.
This encoding value is transported in the upper bytes of the key lifetime
attribute (:c:type:`psa_key_lifetime_t`).

.. table:: Key storage location bit field
   :name: table_psa_key_location_encoding
   :align: center
   :widths: 10 90
   :class: wrap-table

   +-------------+---------------------------------------------------------+
   | **Bits**    | **Description**                                         |
   +=============+=========================================================+
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

**Example**

In case of *EdgeLock 2GO* object, the storage location attribute should be set
as follows:

  - Key type object: ``0xE000__``
  - Data type object: ``0xE080__``

where `_` means any value.

In case of *EdgeLock Key Import* object, the storage location attribute should be set
as follows:

  - Key type object: ``0xC00200``

For other key creation operations (generate, derivation), the storage location
attribute can be any value. The ELE Subsystem is not interpreting this
attribute. Attribute is stored and returned as-is to the user. It's advice to
set it to ``0x00000`` for compatibility with future versions.

.. kdoc-extension:: /public/psa/crypto_types.h
   :typedefs: psa_key_persistence_t

The key persistence level is a property of a key that reflects the extent to
which the key is protected against device management events.
It's 8-bits encoding value transported in the lower byte of the key lifetime
attribute (:c:type:`psa_key_lifetime_t`).

.. table:: Key persistence bit field
   :name: table_psa_key_persistence_encoding
   :align: center
   :widths: 6 30 64
   :class: wrap-table

   +-----------+-------------------------------+------------------------------------------------------+
   | **Value** | **Define**                    | **Description**                                      |
   +===========+===============================+======================================================+
   | 0x00      | PSA_KEY_PERSISTENCE_VOLATILE  | Object is transient. Does not resist a device reset. |
   +-----------+-------------------------------+------------------------------------------------------+
   | 0x01      | PSA_KEY_PERSISTENCE_DEFAULT   | Object is persistent. Resists device reset.          |
   +-----------+-------------------------------+------------------------------------------------------+
   | 0xFF      | PSA_KEY_PERSISTENCE_READ_ONLY | Object is permanent. Can't be deleted.               |
   +-----------+-------------------------------+------------------------------------------------------+

Functions
~~~~~~~~~
.. kdoc-extension:: /public/psa/keymgr.h
   :functions: psa_set_key_lifetime psa_get_key_lifetime

Macros
~~~~~~
.. kdoc-extension:: /public/psa/crypto_values.h
   :macros: PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION

.. kdoc-extension:: /public/psa/crypto_values.h
   :macros: PSA_KEY_LIFETIME_GET_PERSISTENCE PSA_KEY_LIFETIME_IS_VOLATILE

.. kdoc-extension:: /public/psa/crypto_values.h
   :macros: PSA_KEY_LIFETIME_GET_LOCATION
