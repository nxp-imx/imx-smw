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
