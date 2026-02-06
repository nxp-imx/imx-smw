.. _subsystems-capabilities:

Secure Subsystems Capabilities
==============================

The Secure Subsystems Capabilities section provides detailed documentation of
the cryptographic and security operations supported by various subsystems
including TEE (Trusted Execution Environment), ELE (EdgeLock Enclave) and
SECO (Security Controller - First MPU Secure Enclave) subsystems.

.. table:: Subsystems vs. i.MX NPIs
   :name: table_subsystems_overview
   :align: center
   :width: 100%
   :class: wrap-table

   +-----------+------------------------------------------+
   | Subsystem | NPIs                                     |
   +===========+==========================================+
   | TEE       | TrustZone OPTEE OS supported on all i.MX |
   +-----------+------------------------------------------+
   | ELE       | i.MX8ulp, i.MX9x                         |
   +-----------+------------------------------------------+
   | SECO      | i.MX8qxp                                 |
   +-----------+------------------------------------------+



.. toctree::
   :maxdepth: 3
   :numbered: 3
   :glob:

   capabilities/storage.rst
   capabilities/key_management
   capabilities/data_management
   capabilities/digest
   capabilities/mac
   capabilities/symmetric_encryption
   capabilities/asymmetric_encryption
   capabilities/asymmetric_signature
   capabilities/aead
   capabilities/device_management
