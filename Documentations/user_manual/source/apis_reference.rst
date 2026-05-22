.. _apis-reference:

APIs reference
==============

The SMW Library provides a unified interface to security services available
on NXP platforms.

Two sets of APIs are exposed:

- The NXP's Security Middleware APIs called :ref:`SMW APIs <smw-apis>`.
- The ARM's Platform Security Architecture APIs called :ref:`PSA APIs <psa-apis>`.

    - The key manager and cryptographic APIs are compliant with the
      `ARM PSA Certified Cryptography API v1.3.2 <https://arm-software.github.io/psa-api/crypto/1.3/>`_.
    - The attestation APIs are compliant with the
      `ARM PSA Certified Attestation API v1.0.4 <https://arm-software.github.io/psa-api/attestation/1.0/>`_.
    - The storage APIs are compliant with the
      `ARM PSA Certified Secure Storage API v1.0.4 <https://arm-software.github.io/psa-api/storage/1.0/>`_.

Both APIs set are working independently without concurrence.

.. toctree::
   :maxdepth: 4
   :numbered: 5
   :glob:

   apis/smw
   apis/psa
