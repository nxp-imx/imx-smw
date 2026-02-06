Device Management
-----------------

Device management operations allow interaction with device-specific features
such as attestation, UUID, and lifecycle management.

Supported Operations versus Subsystems
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. table:: Device Management Operations vs. subsystem
   :name: table_device_mgmt_operations_subsystem
   :align: center
   :widths: 20 10 10 10
   :class: wrap-table

   +---------------------------+---------+---------+----------+
   | **Operations**            | **Subsystem**                |
   +                           +---------+---------+----------+
   |                           | **ELE** | **TEE** | **SECO** |
   +===========================+=========+=========+==========+
   | `Device Attestation`_     |    Y    |    N    |    N     |
   +---------------------------+---------+---------+----------+
   | `Get Device UUID`_        |    Y    |    N    |    N     |
   +---------------------------+---------+---------+----------+
   | `Device Lifecycle`_       |    Y    |    N    |    N     |
   +---------------------------+---------+---------+----------+


Device Attestation
^^^^^^^^^^^^^^^^^^
Device attestation provides cryptographic proof of device identity and integrity.

.. table:: Device Attestation APIs Comparison
   :name: table_device_attestation_apis_comparison
   :align: center
   :widths: 15 85
   :width: 100%
   :class: wrap-table

   +---------+----------------------------------------+
   | **API** | **Function**                           |
   +=========+========================================+
   | SMW     | :c:func:`smw_device_attestation`       |
   +---------+----------------------------------------+
   | PSA     | :c:func:`psa_initial_attest_get_token` |
   +---------+----------------------------------------+
   | PKCS11  | Not supported                          |
   +---------+----------------------------------------+

The device attestation requires a challenge value to guarantee the certificate
request. The challenge value maximum length depends of the device as listed in
the following table.

.. table:: ELE Attestation Challenge
   :name: ele_challenge
   :widths: 15 15 10 15 45
   :width: 100%
   :align: center
   :class: wrap-table

   +------------+------------------------+-------------+-------------------------------+---------------------------------+
   | **Device** | **Challenge in bytes** | **Version** | **Certificate**               | **Comment**                     |
   +============+========================+=============+===============================+=================================+
   | i.MX8ULP   |  4                     | 0x1         | :numref:`table_device_att_v1` |                                 |
   +------------+------------------------+-------------+-------------------------------+---------------------------------+
   | i.MX91     |  16                    | 0x2         | :numref:`table_device_att_v2` | OEM SRKH up to 512 bits         |
   +            +                        +             +                               +                                 +
   | i.MX93     |                        |             |                               |                                 |
   +------------+------------------------+-------------+-------------------------------+---------------------------------+
   | i.MX95     |  16                    | 0x3         | :numref:`table_device_att_v3` | Hybrid OEM SRKH up to 512 bits  |
   +            +                        +             +                               +                                 +
   | i.MX943    |                        |             |                               | and PQC 512 bits                |
   +            +                        +             +                               +                                 +
   | i.MX952    |                        |             |                               |                                 |
   +------------+------------------------+-------------+-------------------------------+---------------------------------+

The device attestation returned certificate is signed by the device manufacturer
and contains the device public key and identity information.

.. table:: Device Attestation Certificate Contents - version 1
   :name: table_device_att_v1
   :align: center
   :widths: 12 23 10 55
   :width: 100%
   :class: wrap-table

   +------------------+-----------------------+-------------+---------------------------------------+
   | **Word**         | **Certificate Field** | **Size**    | **Description**                       |
   +                  +                       +             +                                       +
   | **(32 bits)**    |                       | **(bytes)** |                                       |
   +==================+=======================+=============+=======================================+
   | 0                | Command               | 1           | 0xDB: Device Attestation              |
   +                  +-----------------------+-------------+---------------------------------------+
   |                  | Version               | 1           | Version of the certificate (0x1)      |
   +                  +-----------------------+-------------+---------------------------------------+
   |                  | Length                | 2           | Length of certificate data in bytes   |
   +------------------+-----------------------+-------------+---------------------------------------+
   | 1                | SOC ID                | 2           | System-on-Chip identifier             |
   +                  +-----------------------+-------------+---------------------------------------+
   |                  | SOC Revision          | 2           | Revision of the System-on-Chip        |
   +------------------+-----------------------+-------------+---------------------------------------+
   | 2                | Lifecycle State       | 2           | Current device lifecycle state: \     |
   |                  |                       |             |                                       |
   |                  |                       |             |  - 0x0010: OEM Open                   |
   |                  |                       |             |  - 0x0040: OEM Closed                 |
   |                  |                       |             |  - 0x0080: OEM Field Return           |
   |                  |                       |             |  - 0x0100: NXP Field Return           |
   |                  |                       |             |  - 0x0200: OEM Closed and Locked      |
   +                  +-----------------------+-------------+---------------------------------------+
   |                  | SSSM State            | 1           | Security Subsystem State machine      |
   |                  |                       |             | (internal device value)               |
   +                  +-----------------------+-------------+---------------------------------------+
   |                  | Reserved              | 1           | Reserved                              |
   +------------------+-----------------------+-------------+---------------------------------------+
   | 3                | UID                   | 16          | Unique device identifier              |
   +------------------+-----------------------+-------------+---------------------------------------+
   | 7                | ROM Patch (SHA256)    | 32          | SHA256 of ELE ROM patch fuses         |
   +------------------+-----------------------+-------------+---------------------------------------+
   | 15               | FW (SHA256)           | 32          | SHA256 of FW installed                |
   +------------------+-----------------------+-------------+---------------------------------------+
   | 23               | Nonce                 | 4           | Attestation challenge                 |
   +------------------+-----------------------+-------------+---------------------------------------+
   | 24               | Signature             | 96          | Signature of previous data.           |
   |                  |                       |             | ECC P-384 format                      |
   +------------------+-----------------------+-------------+---------------------------------------+

.. table:: Device Attestation Certificate Contents - version 2
   :name: table_device_att_v2
   :align: center
   :widths: 12 23 10 55
   :width: 100%
   :class: wrap-table

   +------------------+-----------------------+-------------+-----------------------------------------+
   | **Word**         | **Certificate Field** | **Size**    | **Description**                         |
   +                  +                       +             +                                         +
   | **(32 bits)**    |                       | **(bytes)** |                                         |
   +==================+=======================+=============+=========================================+
   | 0                | Command               | 1           | 0xDB: Device Attestation                |
   +                  +-----------------------+-------------+-----------------------------------------+
   |                  | Version               | 1           | Version of the certificate (0x2)        |
   +                  +-----------------------+-------------+-----------------------------------------+
   |                  | Length                | 2           | Length of certificate data in bytes     |
   +------------------+-----------------------+-------------+-----------------------------------------+
   | 1                | SOC ID                | 2           | System-on-Chip identifier               |
   +                  +-----------------------+-------------+-----------------------------------------+
   |                  | SOC Revision          | 2           | Revision of the System-on-Chip          |
   +------------------+-----------------------+-------------+-----------------------------------------+
   | 2                | Lifecycle State       | 2           | Current device lifecycle state:\        |
   |                  |                       |             |                                         |
   |                  |                       |             |  - 0x0010: OEM Open                     |
   |                  |                       |             |  - 0x0040: OEM Closed                   |
   |                  |                       |             |  - 0x0080: OEM Field Return             |
   |                  |                       |             |  - 0x0100: NXP Field Return             |
   |                  |                       |             |  - 0x0200: OEM Closed and Locked        |
   +                  +-----------------------+-------------+-----------------------------------------+
   |                  | SSSM State            | 1           | Security Subsystem State machine        |
   |                  |                       |             | (internal device value)                 |
   +                  +-----------------------+-------------+-----------------------------------------+
   |                  | Reserved              | 1           | Reserved                                |
   +------------------+-----------------------+-------------+-----------------------------------------+
   | 3                | UID                   | 16          | Unique device identifier                |
   +------------------+-----------------------+-------------+-----------------------------------------+
   | 7                | ROM Patch (SHA256)    | 32          | SHA256 of ELE ROM patch fuses           |
   +------------------+-----------------------+-------------+-----------------------------------------+
   | 15               | FW (SHA256)           | 32          | SHA256 of FW installed                  |
   +------------------+-----------------------+-------------+-----------------------------------------+
   | 23               | OEM SRKH              | 64          | OEM SRKH fuses                          |
   +------------------+-----------------------+-------------+-----------------------------------------+
   | 39               | TRNG State            | 1           | Current state of the TRNG:\             |
   |                  |                       |             |                                         |
   |                  |                       |             |  - 0x1: Programing mode                 |
   |                  |                       |             |  - 0x2: Generating entropy on-going     |
   |                  |                       |             |  - 0x3: Valid and ready                 |
   |                  |                       |             |  - 0x4: Generating entropy error        |
   +                  +-----------------------+-------------+-----------------------------------------+
   |                  | CSAL State            | 1           | Cryptographic library random            |
   |                  |                       |             | context initialization state:\          |
   |                  |                       |             |                                         |
   |                  |                       |             |  - 0x0: Initialization not done         |
   |                  |                       |             |  - 0x1: Initialization on-going         |
   |                  |                       |             |  - 0x2: Initialization succeed          |
   |                  |                       |             |  - 0x3: Initialization Failed           |
   |                  |                       |             |  - 0x4: Initialization in "pause" mode  |
   +                  +-----------------------+-------------+-----------------------------------------+
   |                  | IMEM State            | 1           | ELE Internal RAM State after a Real     |
   |                  |                       |             | Time Domain power down:\                |
   |                  |                       |             |                                         |
   |                  |                       |             |  - 0xCA: IMEM not lost                  |
   |                  |                       |             |  - 0xFE: IMEM lost and must be restored |
   +                  +-----------------------+-------------+-----------------------------------------+
   |                  | Reserved              | 1           | Reserved                                |
   +------------------+-----------------------+-------------+-----------------------------------------+
   | 40               | Nonce                 | 16          | Attestation challenge                   |
   +------------------+-----------------------+-------------+-----------------------------------------+
   | 56               | Signature             | 96          | Signature of previous data.             |
   |                  |                       |             | ECC P-384 format                        |
   +------------------+-----------------------+-------------+-----------------------------------------+


.. table:: Device Attestation Certificate Contents - version 3
   :name: table_device_att_v3
   :align: center
   :widths: 12 23 10 55
   :width: 100%
   :class: wrap-table

   +------------------+-----------------------+-------------+-----------------------------------------+
   | **Word**         | **Certificate Field** | **Size**    | **Description**                         |
   +                  +                       +             +                                         +
   | **(32 bits)**    |                       | **(bytes)** |                                         |
   +==================+=======================+=============+=========================================+
   | 0                | Command               | 1           | 0xDB: Device Attestation                |
   +                  +-----------------------+-------------+-----------------------------------------+
   |                  | Version               | 1           | Version of the certificate (0x3)        |
   +                  +-----------------------+-------------+-----------------------------------------+
   |                  | Length                | 2           | Length of certificate data in bytes     |
   +------------------+-----------------------+-------------+-----------------------------------------+
   | 1                | SOC ID                | 2           | System-on-Chip identifier               |
   +                  +-----------------------+-------------+-----------------------------------------+
   |                  | SOC Revision          | 2           | Revision of the System-on-Chip          |
   +------------------+-----------------------+-------------+-----------------------------------------+
   | 2                | Lifecycle State       | 2           | Current device lifecycle state:\        |
   |                  |                       |             |                                         |
   |                  |                       |             |  - 0x0010: OEM Open                     |
   |                  |                       |             |  - 0x0040: OEM Closed                   |
   |                  |                       |             |  - 0x0080: OEM Field Return             |
   |                  |                       |             |  - 0x0100: NXP Field Return             |
   |                  |                       |             |  - 0x0200: OEM Closed and Locked        |
   +                  +-----------------------+-------------+-----------------------------------------+
   |                  | SSSM State            | 1           | Security Subsystem State machine        |
   |                  |                       |             | (internal device value)                 |
   +                  +-----------------------+-------------+-----------------------------------------+
   |                  | Reserved              | 1           | Reserved                                |
   +------------------+-----------------------+-------------+-----------------------------------------+
   | 3                | UID                   | 16          | Unique device identifier                |
   +------------------+-----------------------+-------------+-----------------------------------------+
   | 7                | ROM Patch (SHA256)    | 32          | SHA256 of ELE ROM patch fuses           |
   +------------------+-----------------------+-------------+-----------------------------------------+
   | 15               | FW (SHA256)           | 32          | SHA256 of FW installed                  |
   +------------------+-----------------------+-------------+-----------------------------------------+
   | 23               | OEM SRKH              | 64          | OEM SRKH fuses                          |
   +------------------+-----------------------+-------------+-----------------------------------------+
   | 39               | TRNG State            | 1           | Current state of the TRNG:\             |
   |                  |                       |             |                                         |
   |                  |                       |             |  - 0x1: Programing mode                 |
   |                  |                       |             |  - 0x2: Generating entropy on-going     |
   |                  |                       |             |  - 0x3: Valid and ready                 |
   |                  |                       |             |  - 0x4: Generating entropy error        |
   +                  +-----------------------+-------------+-----------------------------------------+
   |                  | CSAL State            | 1           | Cryptographic library random            |
   |                  |                       |             | context initialization state:\          |
   |                  |                       |             |                                         |
   |                  |                       |             |  - 0x0: Initialization not done         |
   |                  |                       |             |  - 0x1: Initialization on-going         |
   |                  |                       |             |  - 0x2: Initialization succeed          |
   |                  |                       |             |  - 0x3: Initialization Failed           |
   |                  |                       |             |  - 0x4: Initialization in "pause" mode  |
   +                  +-----------------------+-------------+-----------------------------------------+
   |                  | Reserved              | 2           | Reserved                                |
   +------------------+-----------------------+-------------+-----------------------------------------+
   | 40               | OEM PQC SRKH          | 64          | OEM PQC SRKH fuses                      |
   +------------------+-----------------------+-------------+-----------------------------------------+
   | 56               | Reserved              | 32          | Reserved                                |
   +------------------+-----------------------+-------------+-----------------------------------------+
   | 64               | Nonce                 | 16          | Attestation challenge                   |
   +------------------+-----------------------+-------------+-----------------------------------------+
   | 68               | Signature             | 96          | Signature of previous data.             |
   |                  |                       |             | ECC P-384 format                        |
   +------------------+-----------------------+-------------+-----------------------------------------+

Get Device UUID
^^^^^^^^^^^^^^^
Retrieve the unique identifier (UUID) of the device.

.. note::
   The device UUID is a unique identifier that remains constant
   throughout the device's lifetime. The value returned by the API
   is a big-endian value.

.. table:: Get Device UUID APIs Comparison
   :name: table_device_uuid_apis_comparison
   :align: center
   :widths: 15 85
   :width: 100%
   :class: wrap-table

   +---------+----------------------------------------+
   | **API** | **Function**                           |
   +=========+========================================+
   | SMW     | :c:func:`smw_device_get_uuid`          |
   +---------+----------------------------------------+
   | PSA     | Not supported                          |
   +---------+----------------------------------------+
   | PKCS11  | Not supported                          |
   +---------+----------------------------------------+


Device Lifecycle
^^^^^^^^^^^^^^^^
Query and manage the device lifecycle state.

.. warning::
  Changing the device lifecycle (set operation) is irreversible. Refer to
  the device documentation to get more details about the lifecycle.

.. table:: Device Lifecycle APIs Comparison
   :name: table_device_lifecycle_apis_comparison
   :align: center
   :widths: 15 85
   :width: 100%
   :class: wrap-table

   +---------+----------------------------------------+
   | **API** | **Function**                           |
   +=========+========================================+
   | SMW     | :c:func:`smw_device_set_lifecycle`     |
   +         +----------------------------------------+
   |         | :c:func:`smw_device_get_lifecycle`     |
   +---------+----------------------------------------+
   | PSA     | Not supported                          |
   +---------+----------------------------------------+
   | PKCS11  | Not supported                          |
   +---------+----------------------------------------+
