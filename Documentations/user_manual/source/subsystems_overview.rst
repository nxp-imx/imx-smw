.. _subsystems-overview:

Subsystems Overview
===================

TEE Subsystem
-------------

The TEE subsystem provides a secure execution environment based on ARM TrustZone
technology. It uses OPTEE OS (Open Portable Trusted Execution Environment) to
isolate security-critical operations from the normal world operating system.

The TEE subsystem interfaces with the SMW Library through the OP-TEE Client
library and communicates with a Trusted Application (TA) running in the
TrustZone secure world.

**Supported Platforms:** All i.MX platforms with TrustZone support

ELE Subsystem
-------------

The ELE subsystem is NXP's dedicated security subsystem that provides
hardware-based cryptographic operations and secure key management. It offers
enhanced security features including secure boot, secure storage, and
cryptographic acceleration.

The ELE subsystem supports both standard cryptographic operations and
specialized features such as EdgeLock 2GO provisioning and NVM Secure Storage.

**Supported Platforms:** i.MX8ULP, i.MX9x series

.. _warning-ele-fw-2_0_7:

.. warning::
   **ELE FW 2.0.7 - EL2GO Key Service Limitation**

   ELE FW 2.0.7 introduces a limitation on devices where the EL2GO provisioned
   keys are missing their Key Check Values (KCV), causing certain crypto
   services to be disabled. This affects **only** i.MX952, i.MX937, i.MX94x and
   i.MX95 B1 devices that were not delivered with the KCV fix.

   The following EL2GO keys are affected:

   .. list-table:: Affected EL2GO Keys
      :widths: 28 14 18 40
      :header-rows: 1

      * - EL2GO Key Name
        - Key ID
        - Key Type
        - Description
      * - ``NXP_DIE_ID_AUTH_PRK``
        - 0x7FFF816C
        - ECDSA NIST P-384
        - Key used to identify the device when establishing the EdgeLock 2GO
          connection. Key is used to sign the EdgeLock 2GO TLS self-signed
          Certificate.
      * - ``NXP_DIE_ATTEST_AUTH_PRK``
        - 0x7FFF8173
        - ECDSA NIST P-384
        - Key used to attest the authenticity of asset exchange between Client
          and Server.
      * - ``IOT_DIE_ATTEST_AUTH_PRK``
        - 0x7FFF8174
        - ECDSA NIST P-384
        - Key used to sign the public key attestation certificate.

   Affected devices can only be identified at runtime by calling
   :c:func:`smw_device_attestation`. If it returns
   ``SMW_STATUS_OPERATION_DISABLED``, the device lacks KCV.

   .. list-table:: Disabled operations per EL2GO key
      :widths: 35 65
      :header-rows: 1

      * - EL2GO Key
        - Affected Operations
      * - ``NXP_DIE_ID_AUTH_PRK``
        - :c:func:`smw_sign`, :c:func:`smw_verify`,
          :c:func:`smw_export_key`
      * - ``NXP_DIE_ATTEST_AUTH_PRK``
        - :c:func:`smw_verify`, :c:func:`smw_export_key`
      * - ``IOT_DIE_ATTEST_AUTH_PRK``
        - :c:func:`smw_export_key`, :c:func:`smw_key_attestation`

   In addition, the device attestation service
   (:c:func:`smw_device_attestation`) is disabled on affected devices and
   returns ``SMW_STATUS_OPERATION_DISABLED``.


EdgeLock Accelerator (ELA)
^^^^^^^^^^^^^^^^^^^^^^^^^^

The ELA is a cryptographic accelerator accessible in the ELE. It provides
hardware-accelerated cryptographic operations for improved performance on
supported platforms.

ELA acceleration is enabled when all of the below mentioned conditions are met:

    - The ``USE_ELA`` tag is defined in the config file (see :ref:`use_ela`)
    - The cryptographic operation (algorithm/mode) is supported by ELA
    - Plaintext key buffers are provided (opaque keys are not supported)

**Supported Platforms:** i.MX94x (i.MX943, i.MX942, i.MX941), i.MX952, i.MX937

SECO Subsystem
--------------

SECO is NXP's first-generation secure enclave for i.MX8 platforms. It provides
hardware-based security services including cryptographic operations and secure
key storage.

**Supported Platforms:** i.MX8QXP
