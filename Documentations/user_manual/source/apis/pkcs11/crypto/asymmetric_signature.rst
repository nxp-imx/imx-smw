.. _p11_asymmetric_signature:

Asymmetric signature
""""""""""""""""""""

PKCS#11 provides two sets of functions for asymmetric signature operations
function of the PKCS#11 interface used. If the PKCS#11 3.x interface is used,
the new message-based APIs should be preferred. However, for backward
compatibility, the PKCS#11 2.x APIs are still available:

.. list-table:: PKCS#11 Asymmetric Signature APIs
   :header-rows: 1
   :widths: 20 40 40
   :class: wrap-table

   * - **Version**
     - **Signing Functions**
     - **Verification Functions**
   * - **PKCS#11 2.40**
     - :c:func:`C_SignInit`, :c:func:`C_Sign`, :c:func:`C_SignUpdate`,
       :c:func:`C_SignFinal`
     - :c:func:`C_VerifyInit`, :c:func:`C_Verify`, :c:func:`C_VerifyUpdate`,
       :c:func:`C_VerifyFinal`
   * - **PKCS#11 3.2**
     - :c:func:`C_MessageSignInit`, :c:func:`C_SignMessage`,
       :c:func:`C_SignMessageBegin`, :c:func:`C_SignMessageNext`,
       :c:func:`C_MessageSignFinal`
     - :c:func:`C_MessageVerifyInit`, :c:func:`C_VerifyMessage`,
       :c:func:`C_VerifyMessageBegin`, :c:func:`C_VerifyMessageNext`,
       :c:func:`C_MessageVerifyFinal`
       :c:func:`C_VerifySignatureInit`, :c:func:`C_VerifySignature`,
       :c:func:`C_VerifySignatureUpdate`, :c:func:`C_VerifySignatureFinal`

Regardless of the API version used, the operation must be initialized first
before performing the signature or verification operation.

PKCS#11 2.40 APIs sequences
~~~~~~~~~~~~~~~~~~~~~~~~~~~
**Asymmetric Signing**

The sequence of operations to sign a message with a single part signature is
as follows\:

   #. Initialize the operation by calling :c:func:`C_SignInit`.
   #. Sign data in a single operation with :c:func:`C_Sign`.

The sequence of operations to sign a message with a multiple part signature is
as follows\:

   #. Initialize the operation by calling :c:func:`C_SignInit`.
   #. Process one or more data parts (can be called multiple times) with
      :c:func:`C_SignUpdate`.
   #. Finish the signing operation and obtain the final signature with
      :c:func:`C_SignFinal`.

**Asymmetric Verification**

The sequence of operations to verify a signature with a single part verification
is as follows\:

   #. Initialize the operation by calling :c:func:`C_VerifyInit`.
   #. Verify signature in a single operation with :c:func:`C_Verify`.

The sequence of operations to verify a signature with a multiple part
verification is as follows\:

   #. Initialize the operation by calling :c:func:`C_VerifyInit`.
   #. Process one or more data parts (can be called multiple times) with
      :c:func:`C_VerifyUpdate`.
   #. Finish the verification operation with :c:func:`C_VerifyFinal`.

PKCS#11 3.2 APIs sequences
~~~~~~~~~~~~~~~~~~~~~~~~~~
**Message Signing**

The sequence of operations to sign a message with a single part signature is
as follows\:

   #. Initialize the operation by calling :c:func:`C_MessageSignInit`.
   #. Sign data in a single operation with :c:func:`C_SignMessage`.

The sequence of operations to sign a message with a multiple part signature is
as follows\:

   #. Initialize the operation by calling :c:func:`C_MessageSignInit`.
   #. Begin the message signing with :c:func:`C_SignMessageBegin`.
   #. Process one or more data parts (can be called multiple times) with
      :c:func:`C_SignMessageNext`.
   #. Finish the signing operation with :c:func:`C_MessageSignFinal`.

**Message Verification**

The sequence of operations to verify a signature with a single part verification
is as follows\:

   #. Initialize the operation by calling :c:func:`C_MessageVerifyInit`.
   #. Verify signature in a single operation with :c:func:`C_VerifyMessage`.

The sequence of operations to verify a signature with a multiple part
verification is as follows\:

   #. Initialize the operation by calling :c:func:`C_MessageVerifyInit`.
   #. Begin the message verification with :c:func:`C_VerifyMessageBegin`.
   #. Process one or more data parts (can be called multiple times) with
      :c:func:`C_VerifyMessageNext`.
   #. Finish the verification operation with :c:func:`C_MessageVerifyFinal`.

**Signature Verification**

The sequence of operations to verify a signature with signature provided at
initialization is as follows\:

   #. Initialize the operation by calling :c:func:`C_VerifySignatureInit`,
      providing the signature to verify.
   #. Verify data in a single operation with :c:func:`C_VerifySignature`.

The sequence of operations for multiple part verification with signature at
initialization is as follows\:

   #. Initialize the operation by calling :c:func:`C_VerifySignatureInit`,
      providing the signature to verify.
   #. Process one or more data parts (can be called multiple times) with
      :c:func:`C_VerifySignatureUpdate`.
   #. Finish the verification operation with :c:func:`C_VerifySignatureFinal`.


Initialization
~~~~~~~~~~~~~~
.. kdoc-extension:: /pkcs11/src/sign.c
   :functions: C_SignInit

.. kdoc-extension:: /pkcs11/src/verify.c
   :functions: C_VerifyInit

.. kdoc-extension:: /pkcs11/src/msg_sign.c
   :functions: C_MessageSignInit

.. kdoc-extension:: /pkcs11/src/msg_verify.c
   :functions: C_MessageVerifyInit

.. kdoc-extension:: /pkcs11/src/signature_verify.c
   :functions: C_VerifySignatureInit

Single Part
~~~~~~~~~~~
.. kdoc-extension:: /pkcs11/src/sign.c
   :functions: C_Sign

.. kdoc-extension:: /pkcs11/src/verify.c
   :functions: C_Verify

.. kdoc-extension:: /pkcs11/src/msg_sign.c
   :functions: C_SignMessage

.. kdoc-extension:: /pkcs11/src/msg_verify.c
   :functions: C_VerifyMessage

.. kdoc-extension:: /pkcs11/src/signature_verify.c
   :functions: C_VerifySignature

Multiple Part
~~~~~~~~~~~~~
.. kdoc-extension:: /pkcs11/src/sign.c
   :functions: C_SignUpdate C_SignFinal

.. kdoc-extension:: /pkcs11/src/verify.c
   :functions: C_VerifyUpdate C_VerifyFinal

.. kdoc-extension:: /pkcs11/src/msg_sign.c
   :functions: C_SignMessageBegin C_SignMessageNext C_MessageSignFinal

.. kdoc-extension:: /pkcs11/src/msg_verify.c
   :functions: C_VerifyMessageBegin C_VerifyMessageNext C_MessageVerifyFinal

.. kdoc-extension:: /pkcs11/src/signature_verify.c
   :functions: C_VerifySignatureUpdate C_VerifySignatureFinal

Examples
~~~~~~~~
PKCS#11 2.40 - Single Part Signing
**********************************
.. code-block:: c

  CK_SESSION_HANDLE hSession;
  CK_OBJECT_HANDLE hKey;
  CK_MECHANISM mechanism = { CKM_RSA_PKCS, NULL_PTR, 0 };
  CK_BYTE data[] = "Data to sign";
  CK_BYTE signature[256];
  CK_ULONG signature_len = sizeof(signature);
  CK_RV rv;

  // Initialize signing operation
  rv = C_SignInit(hSession, &mechanism, hKey);
  if (rv != CKR_OK) {
      // Handle error
  }

  // Perform single-part signing
  rv = C_Sign(hSession, data, sizeof(data), signature, &signature_len);
  if (rv != CKR_OK) {
      // Handle error
  }

PKCS#11 2.40 - Multiple Part Signing
************************************
.. code-block:: c

  CK_SESSION_HANDLE hSession;
  CK_OBJECT_HANDLE hKey;
  CK_MECHANISM mechanism = { CKM_ECDSA, NULL_PTR, 0 };
  CK_BYTE data_part1[] = "First part ";
  CK_BYTE data_part2[] = "Second part";
  CK_BYTE signature[256];
  CK_ULONG signature_len = sizeof(signature);
  CK_RV rv;

  // Initialize signing operation
  rv = C_SignInit(hSession, &mechanism, hKey);
  if (rv != CKR_OK) {
      // Handle error
  }

  // Process first part
  rv = C_SignUpdate(hSession, data_part1, sizeof(data_part1));
  if (rv != CKR_OK) {
      // Handle error
  }

  // Process second part
  rv = C_SignUpdate(hSession, data_part2, sizeof(data_part2));
  if (rv != CKR_OK) {
      // Handle error
  }

  // Finalize signing
  rv = C_SignFinal(hSession, signature, &signature_len);
  if (rv != CKR_OK) {
      // Handle error
  }

PKCS#11 2.40 - Single Part Verification
***************************************
.. code-block:: c

  CK_SESSION_HANDLE hSession;
  CK_OBJECT_HANDLE hKey;
  CK_MECHANISM mechanism = { CKM_RSA_PKCS, NULL_PTR, 0 };
  CK_BYTE data[] = "Data to verify";
  CK_BYTE signature[256];
  CK_ULONG signature_len = 256;
  CK_RV rv;

  // Initialize verification operation
  rv = C_VerifyInit(hSession, &mechanism, hKey);
  if (rv != CKR_OK) {
      // Handle error
  }

  // Perform single-part verification
  rv = C_Verify(hSession, data, sizeof(data), signature, signature_len);
  if (rv != CKR_OK) {
      // Handle error - signature invalid or other error
  }

PKCS#11 2.40 - Multiple Part Verification
*****************************************
.. code-block:: c

  CK_SESSION_HANDLE hSession;
  CK_OBJECT_HANDLE hKey;
  CK_MECHANISM mechanism = { CKM_ECDSA, NULL_PTR, 0 };
  CK_BYTE data_part1[] = "First part ";
  CK_BYTE data_part2[] = "Second part";
  CK_BYTE signature[256];
  CK_ULONG signature_len = 256;
  CK_RV rv;

  // Initialize verification operation
  rv = C_VerifyInit(hSession, &mechanism, hKey);
  if (rv != CKR_OK) {
      // Handle error
  }

  // Process first part
  rv = C_VerifyUpdate(hSession, data_part1, sizeof(data_part1));
  if (rv != CKR_OK) {
      // Handle error
  }

  // Process second part
  rv = C_VerifyUpdate(hSession, data_part2, sizeof(data_part2));
  if (rv != CKR_OK) {
      // Handle error
  }

  // Finalize verification
  rv = C_VerifyFinal(hSession, signature, signature_len);
  if (rv != CKR_OK) {
      // Handle error - signature invalid or other error
  }

PKCS#11 3.2 - Single Part Message Signing
*****************************************
.. code-block:: c

  CK_SESSION_HANDLE hSession;
  CK_OBJECT_HANDLE hKey;
  CK_MECHANISM mechanism = { CKM_RSA_PKCS, NULL_PTR, 0 };
  CK_BYTE data[] = "Message to sign";
  CK_BYTE signature[256];
  CK_ULONG signature_len = sizeof(signature);
  CK_RV rv;

  // Initialize message signing operation
  rv = C_MessageSignInit(hSession, &mechanism, hKey);
  if (rv != CKR_OK) {
      // Handle error
  }

  // Perform single-part message signing
  rv = C_SignMessage(hSession, NULL_PTR, 0, data, sizeof(data),
                     signature, &signature_len);
  if (rv != CKR_OK) {
      // Handle error
  }

PKCS#11 3.2 - Multiple Part Message Signing
*******************************************
.. code-block:: c

  CK_SESSION_HANDLE hSession;
  CK_OBJECT_HANDLE hKey;
  CK_MECHANISM mechanism = { CKM_ECDSA, NULL_PTR, 0 };
  CK_BYTE data_part1[] = "First part ";
  CK_BYTE data_part2[] = "Second part";
  CK_BYTE signature[256];
  CK_ULONG signature_len = sizeof(signature);
  CK_RV rv;

  // Initialize message signing operation
  rv = C_MessageSignInit(hSession, &mechanism, hKey);
  if (rv != CKR_OK) {
      // Handle error
  }

  // Begin message signing
  rv = C_SignMessageBegin(hSession, NULL_PTR, 0);
  if (rv != CKR_OK) {
      // Handle error
  }

  // Process first part
  rv = C_SignMessageNext(hSession, NULL_PTR, 0, data_part1,
                         sizeof(data_part1), NULL_PTR, NULL_PTR);
  if (rv != CKR_OK) {
      // Handle error
  }

  // Process second part and get signature
  rv = C_SignMessageNext(hSession, NULL_PTR, 0, data_part2,
                         sizeof(data_part2), signature, &signature_len);
  if (rv != CKR_OK) {
      // Handle error
  }

  // Finalize message signing
  rv = C_MessageSignFinal(hSession);
  if (rv != CKR_OK) {
      // Handle error
  }

PKCS#11 3.2 - Single Part Message Verification
**********************************************
.. code-block:: c

  CK_SESSION_HANDLE hSession;
  CK_OBJECT_HANDLE hKey;
  CK_MECHANISM mechanism = { CKM_RSA_PKCS, NULL_PTR, 0 };
  CK_BYTE data[] = "Message to verify";
  CK_BYTE signature[256];
  CK_ULONG signature_len = 256;
  CK_RV rv;

  // Initialize message verification operation
  rv = C_MessageVerifyInit(hSession, &mechanism, hKey);
  if (rv != CKR_OK) {
      // Handle error
  }

  // Perform single-part message verification
  rv = C_VerifyMessage(hSession, NULL_PTR, 0, data, sizeof(data),
                       signature, signature_len);
  if (rv != CKR_OK) {
      // Handle error - signature invalid or other error
  }

PKCS#11 3.2 - Multiple Part Message Verification
************************************************
.. code-block:: c

  CK_SESSION_HANDLE hSession;
  CK_OBJECT_HANDLE hKey;
  CK_MECHANISM mechanism = { CKM_ECDSA, NULL_PTR, 0 };
  CK_BYTE data_part1[] = "First part ";
  CK_BYTE data_part2[] = "Second part";
  CK_BYTE signature[256];
  CK_ULONG signature_len = 256;
  CK_RV rv;

  // Initialize message verification operation
  rv = C_MessageVerifyInit(hSession, &mechanism, hKey);
  if (rv != CKR_OK) {
      // Handle error
  }

  // Begin message verification
  rv = C_VerifyMessageBegin(hSession, NULL_PTR, 0);
  if (rv != CKR_OK) {
      // Handle error
  }

  // Process first part
  rv = C_VerifyMessageNext(hSession, NULL_PTR, 0, data_part1,
                           sizeof(data_part1), NULL_PTR, 0);
  if (rv != CKR_OK) {
      // Handle error
  }

  // Process second part with signature
  rv = C_VerifyMessageNext(hSession, NULL_PTR, 0, data_part2,
                           sizeof(data_part2), signature, signature_len);
  if (rv != CKR_OK) {
      // Handle error - signature invalid or other error
  }

  // Finalize message verification
  rv = C_MessageVerifyFinal(hSession);
  if (rv != CKR_OK) {
      // Handle error
  }
