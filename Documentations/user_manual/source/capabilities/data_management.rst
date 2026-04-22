Data Management
---------------

This section documents the data management operations supported across
different security subsystems (ELE, TEE, SECO).

Supported Operations versus Subsystems
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. table:: Data Management Operations vs. subsystem
   :name: table_data_mgmt_operations_subsystem
   :align: center
   :widths: 15 20 10 10 10 35
   :width: 100%
   :class: wrap-table

   +-------------------+-------------------+---------+---------+----------+-----------------------------------------+
   | **Operations**                        | **Subsystem**                | **Notes**                               |
   +                                       +---------+---------+----------+                                         +
   |                                       | **ELE** | **TEE** | **SECO** |                                         |
   +===================+===================+=========+=========+==========+=========================================+
   | `Store Data`_     | Plaintext         |    Y    |    Y    |    Y     |                                         |
   +                   +-------------------+---------+---------+----------+-----------------------------------------+
   |                   | EdgeLock 2GO blob |  **Y*** |    N    |    N     | The :c:func:`psa_its_set` can't be used |
   |                   |                   |         |         |          | to provision a EdgeLock 2GO data, the   |
   |                   |                   |         |         |          | :c:func:`psa_import_key` function must  |
   |                   |                   |         |         |          | be used.                                |
   +                   +-------------------+---------+---------+----------+-----------------------------------------+
   |                   | Encrypt and Sign  |    Y    |    N    |    N     |                                         |
   +-------------------+-------------------+---------+---------+----------+-----------------------------------------+
   | `Retrieve Data`_                      |    Y    |    Y    |    Y     |                                         |
   +-------------------+-------------------+---------+---------+----------+-----------------------------------------+
   | `Delete Data`_                        |    Y    |    Y    |    N     |                                         |
   +-------------------+-------------------+---------+---------+----------+-----------------------------------------+
   | `Get Information`_                    |    Y    |    Y    |  **Y***  | **SECO** managed limited information.   |
   +-------------------+-------------------+---------+---------+----------+-----------------------------------------+


Data Size Limits
^^^^^^^^^^^^^^^^

.. table:: Data Size Limits vs. subsystem
   :name: table_data_size_limits_subsystem
   :align: center
   :widths: 15 20 35
   :class: wrap-table

   +---------------+---------------------------+------------------------------------------+
   | **Subsystem** | **Maximum Size (bytes)**  | **Notes**                                |
   +===============+===========================+==========================================+
   | ELE           | 2048                      | Limited by secure storage capacity       |
   +---------------+---------------------------+------------------------------------------+
   | TEE           | N/A                       | Limited by available secure filesystem   |
   +---------------+---------------------------+------------------------------------------+
   | SECO          | 2048                      | Limited by secure storage capacity       |
   +---------------+---------------------------+------------------------------------------+

Store Data
^^^^^^^^^^
The store data operation is used to securely store arbitrary data in the
secure subsystem's persistent storage.

.. table:: Store Data APIs Comparison
   :name: table_store_data_apis_comparison
   :align: center
   :widths: 15 85
   :width: 100%
   :class: wrap-table

   +---------+---------------------------+
   | **API** | **Function**              |
   +=========+===========================+
   | SMW     | :c:func:`smw_store_data`  |
   +---------+---------------------------+
   | PSA     | :c:func:`psa_its_set`     |
   +---------+---------------------------+
   | PKCS11  | C_CreateObject()          |
   +         +                           +
   |         | CKO_DATA                  |
   +---------+---------------------------+

Plaintext
"""""""""
The data stored in plaintext are retrieved also in plaintext.


EdgeLock 2GO blob
"""""""""""""""""
This service is a NXP provisioning service involving the NXP EdgeLock 2GO
server. It's only supported by the ELE subsystem.

The server allows to provision key and data embedded in blob. Visit
`EdgeLock 2GO <http://www.nxp.com/edgelock2go>`_ for more information.

The type of key blob to import is identified by the key location attribute:

  - SMW API, the key location is defined by the 'storage_id' field
    of the key attribute in the key descriptor (refer to
    the :c:type:`smw_key_descriptor`).
  - PSA API, the key location is defined by the 'lifetime' field of the
    key attribute (refer to the :c:type:`psa_key_attributes_t`). The location
    is defined by the bits[31:8] of the field.


.. table:: EdgeLock 2GO - Location
   :name: table_data_el2go_location
   :align: center
   :width: 100%
   :class: wrap-table

   +-------------------+------------------+---------------------------+
   |                   | **SMW**          | **PSA**                   |
   +                   +                  +                           +
   |                   | **'storage_id'** | **'lifetime' bits[31:8]** |
   +===================+==================+===========================+
   | EdgeLock 2GO Key  | 0x00E00000       | 0xE00000                  |
   +-------------------+------------------+---------------------------+
   | EdgeLock 2GO Data | 0x00E08000       | 0xE08000                  |
   +-------------------+------------------+---------------------------+

.. note::
   The SMW :c:func:`smw_store_data` allows to store EdgeLock 2GO blob of type
   data, but the :c:func:`psa_its_set` can't be used to store EdgeLock 2GO
   blob. The :c:func:`psa_import_key` msut be used to provision a EdgeLock
   2GO data blob identified by the PSA's `lifefime` attribute.  More
   information in the :ref:`key_management_import` chapter.

Encrypt and Sign
""""""""""""""""
The plaintext data can be encrypted and signed before being stored in the
secure subsystem's persistent storage. This feature is available by ELE
secure subsystem and using the SMW API, only.

The encryption and signature algorithms are defined in the argument structure
of the :c:func:`smw_store_data`.

Encryption of the data
~~~~~~~~~~~~~~~~~~~~~~
The encryption key is a symmetric key present in the secure subsystem storage
and identified by its key identifier. The encryption algorithm supported is
a symmetric encryption mode as defined in the
:ref:`capabilities_symmetric_encryption`.

Note that an Initialization Vector (IV) might be required depending on the
encryption mode selected. The IV can be given as input parameter or generated
by the secure subsystem. The value of the IV is returned in the resulting
data blob.

Signature of the data
~~~~~~~~~~~~~~~~~~~~~
The signature key is symmetric key present in the secure subsystem storage
and identified by its key identifier. The signature algorithm supported is
CMAC (Cipher-based Message Authentication Code) only as defined in the
:ref:`capabilities_mac`.

Data blob format
~~~~~~~~~~~~~~~~
The encrypted and signed data is retrieved through a TLV (Tag-Length-Value)
blob format. The following :numref:`table_encrypted_signed_data_tlv` describes
the structure of the encrypted and signed data blob including metadata tags
for device identification, initialization vectors, encrypted payload and
blob signature.

The encrypted and signed data is stored in a TLV blob format as detailed in the
:numref:`table_encrypted_signed_data_tlv` below.

.. table:: Encrypted and Signed Data - TLV Format
   :name: table_encrypted_signed_data_tlv
   :align: center
   :widths: 10 20 70
   :width: 100%
   :class: wrap-table

   +---------+--------------------+-----------------------------------------+
   | **Tag** | **Length (bytes)** | **Value/Description**                   |
   +=========+====================+=========================================+
   | 0x41    | 16                 | Device UUID in big endian format.       |
   +---------+--------------------+-----------------------------------------+
   | 0x45    | 16                 | Value of the IV used to encrypt data    |
   |         |                    | in case encryption algorithm use an IV. |
   |         |                    |                                         |
   |         |                    | The IV can be either:\                  |
   |         |                    |                                         |
   |         |                    |  - User input value.                    |
   |         |                    |  - Randomly generated by the secure. In |
   |         |                    |    this case, the user input IV buffer  |
   |         |                    |    address must be NULL and its length  |
   |         |                    |    equal 0.                             |
   +---------+--------------------+-----------------------------------------+
   | 0x46    | Variable           | Encrypted data. Maximum length is 2048  |
   |         |                    | bytes.                                  |
   +---------+--------------------+-----------------------------------------+
   | 0x5E    | 16                 | Signature of all previous fields of     |
   |         |                    | this blob including the signature tag   |
   |         |                    | (0x5E) and signature length fields.     |
   +---------+--------------------+-----------------------------------------+


Retrieve Data
^^^^^^^^^^^^^
The retrieve data operation is used to read previously stored data from the
secure subsystem's persistent storage.

.. table:: Retrieve Data APIs Comparison
   :name: table_retrieve_data_apis_comparison
   :align: center
   :widths: 15 85
   :width: 100%
   :class: wrap-table

   +---------+-----------------------------+
   | **API** | **Function**                |
   +=========+=============================+
   | SMW     | :c:func:`smw_retrieve_data` |
   +---------+-----------------------------+
   | PSA     | :c:func:`psa_its_get`       |
   +---------+-----------------------------+
   | PKCS11  | C_GetAttributeValue()       |
   +         +                             +
   |         | CKA_VALUE                   |
   +---------+-----------------------------+

.. _data_management_delete:

Delete Data
^^^^^^^^^^^
The delete data operation is used to permanently remove data from the
secure subsystem's persistent storage.

.. table:: Delete Data APIs Comparison
   :name: table_delete_data_apis_comparison
   :align: center
   :widths: 15 85
   :width: 100%
   :class: wrap-table

   +---------+---------------------------+
   | **API** | **Function**              |
   +=========+===========================+
   | SMW     | :c:func:`smw_delete_data` |
   +---------+---------------------------+
   | PSA     | :c:func:`psa_its_remove`  |
   +---------+---------------------------+
   | PKCS11  | C_DestroyObject()         |
   +---------+---------------------------+

.. note::
   Even if the :c:func:`psa_its_set` function can't be used to store A
   EdgeLock 2GO data blob, the :c:func:`psa_its_remove` function must be used
   to delete it.

Get Information
^^^^^^^^^^^^^^^
The get information operation is used to retrieve metadata about stored data
from the secure subsystem's persistent storage without retrieving the actual
data content.

.. table:: Get Information APIs Comparison
   :name: table_get_information_apis_comparison
   :align: center
   :widths: 15 85
   :width: 100%
   :class: wrap-table

   +---------+------------------------------+
   | **API** | **Function**                 |
   +=========+==============================+
   | SMW     | :c:func:`smw_get_data_info`  |
   +---------+------------------------------+
   | PSA     | :c:func:`psa_its_get_info`   |
   +---------+------------------------------+
   | PKCS11  | C_GetAttributeValue()        |
   +---------+------------------------------+

The metadata available for the data are described in the
:ref:`objects_attributes_definition` chapter and are:

  - **Size**: The size of the stored data in bytes.
  - **Persistence**: Indicates whether the data is persistent or volatile.
  - **Lifecycle**: Indicates the device lifecycle stage where the key is valid.
  - **Read/Write protection**: Access control policies applied to the data
    object.
  - **Storage location**: Data storage location.

.. note::
   If the data is not referenced in the SMW database, each secure subsystem
   enabled in the SMW configuration is queried to retrieve the missing data
   information within the limits of information managed by the secure subsystem.
   Some information may not be retrievable depending on subsystem capabilities.
