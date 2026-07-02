Dual functions
""""""""""""""

PKCS#11 provides dual-function cryptographic operations that combine two
operations in a single call. These functions allow for efficient processing
by combining encryption/decryption with signing/verification or digest
operations.

The dual functions available are:

.. list-table:: PKCS#11 Dual Function APIs
   :header-rows: 1
   :widths: 40 60
   :class: wrap-table

   * - **Function**
     - **Description**
   * - :c:func:`C_DigestEncryptUpdate`
     - Continues a multiple-part digest and encryption operation
   * - :c:func:`C_DecryptDigestUpdate`
     - Continues a multiple-part decryption and digest operation
   * - :c:func:`C_SignEncryptUpdate`
     - Continues a multiple-part signing and encryption operation
   * - :c:func:`C_DecryptVerifyUpdate`
     - Continues a multiple-part decryption and verification operation

These functions must be used in conjunction with their respective initialization
and finalization functions. Each dual operation requires both operations to be
initialized separately before the dual function can be called.

Operation Sequences
~~~~~~~~~~~~~~~~~~~

**Digest and Encrypt**

The sequence of operations to digest and encrypt data is as follows:

   #. Initialize the digest operation by calling :c:func:`C_DigestInit`.
   #. Initialize the encryption operation by calling :c:func:`C_EncryptInit`.
   #. Process one or more data parts (can be called multiple times) with
      :c:func:`C_DigestEncryptUpdate`.
   #. Finalize the encryption operation with :c:func:`C_EncryptFinal`.
   #. Finalize the digest operation with :c:func:`C_DigestFinal`.

**Decrypt and Digest**

The sequence of operations to decrypt and digest data is as follows:

   #. Initialize the decryption operation by calling :c:func:`C_DecryptInit`.
   #. Initialize the digest operation by calling :c:func:`C_DigestInit`.
   #. Process one or more data parts (can be called multiple times) with
      :c:func:`C_DecryptDigestUpdate`.
   #. Finalize the decryption operation with :c:func:`C_DecryptFinal`.
   #. Finalize the digest operation with :c:func:`C_DigestFinal`.

**Sign and Encrypt**

The sequence of operations to sign and encrypt data is as follows:

   #. Initialize the signing operation by calling :c:func:`C_SignInit`.
   #. Initialize the encryption operation by calling :c:func:`C_EncryptInit`.
   #. Process one or more data parts (can be called multiple times) with
      :c:func:`C_SignEncryptUpdate`.
   #. Finalize the encryption operation with :c:func:`C_EncryptFinal`.
   #. Finalize the signing operation with :c:func:`C_SignFinal`.

**Decrypt and Verify**

The sequence of operations to decrypt and verify data is as follows:

   #. Initialize the decryption operation by calling :c:func:`C_DecryptInit`.
   #. Initialize the verification operation by calling :c:func:`C_VerifyInit`.
   #. Process one or more data parts (can be called multiple times) with
      :c:func:`C_DecryptVerifyUpdate`.
   #. Finalize the decryption operation with :c:func:`C_DecryptFinal`.
   #. Finalize the verification operation with :c:func:`C_VerifyFinal`.

API Reference
~~~~~~~~~~~~~

.. kdoc-extension:: /pkcs11/src/dualfunc.c
   :functions: C_DigestEncryptUpdate

.. kdoc-extension:: /pkcs11/src/dualfunc.c
   :functions: C_DecryptDigestUpdate

.. kdoc-extension:: /pkcs11/src/dualfunc.c
   :functions: C_SignEncryptUpdate

.. kdoc-extension:: /pkcs11/src/dualfunc.c
   :functions: C_DecryptVerifyUpdate

Examples
~~~~~~~~

Digest and Encrypt
******************

.. code-block:: c

  CK_SESSION_HANDLE hSession;
  CK_OBJECT_HANDLE hKey;
  CK_MECHANISM digest_mech = { CKM_SHA256, NULL_PTR, 0 };
  CK_MECHANISM encrypt_mech = { CKM_AES_CBC, iv, sizeof(iv) };
  CK_BYTE data[] = "Data to digest and encrypt";
  CK_BYTE encrypted[256];
  CK_ULONG encrypted_len = sizeof(encrypted);
  CK_BYTE digest[32];
  CK_ULONG digest_len = sizeof(digest);
  CK_RV rv;

  // Initialize digest operation
  rv = C_DigestInit(hSession, &digest_mech);
  if (rv != CKR_OK) {
      // Handle error
  }

  // Initialize encryption operation
  rv = C_EncryptInit(hSession, &encrypt_mech, hKey);
  if (rv != CKR_OK) {
      // Handle error
  }

  // Process data with dual function
  rv = C_DigestEncryptUpdate(hSession, data, sizeof(data),
                             encrypted, &encrypted_len);
  if (rv != CKR_OK) {
      // Handle error
  }

  // Finalize encryption
  rv = C_EncryptFinal(hSession, encrypted + encrypted_len, &encrypted_len);
  if (rv != CKR_OK) {
      // Handle error
  }

  // Finalize digest
  rv = C_DigestFinal(hSession, digest, &digest_len);
  if (rv != CKR_OK) {
      // Handle error
  }

Decrypt and Verify
******************

.. code-block:: c

  CK_SESSION_HANDLE hSession;
  CK_OBJECT_HANDLE hKey;
  CK_MECHANISM decrypt_mech = { CKM_AES_CBC, iv, sizeof(iv) };
  CK_MECHANISM verify_mech = { CKM_RSA_PKCS, NULL_PTR, 0 };
  CK_BYTE encrypted_data[] = "Encrypted data";
  CK_BYTE decrypted[256];
  CK_ULONG decrypted_len = sizeof(decrypted);
  CK_BYTE signature[256];
  CK_ULONG signature_len = 256;
  CK_RV rv;

  // Initialize decryption operation
  rv = C_DecryptInit(hSession, &decrypt_mech, hKey);
  if (rv != CKR_OK) {
      // Handle error
  }

  // Initialize verification operation
  rv = C_VerifyInit(hSession, &verify_mech, hKey);
  if (rv != CKR_OK) {
      // Handle error
  }

  // Process data with dual function
  rv = C_DecryptVerifyUpdate(hSession, encrypted_data, sizeof(encrypted_data),
                             decrypted, &decrypted_len);
  if (rv != CKR_OK) {
      // Handle error
  }

  // Finalize decryption
  rv = C_DecryptFinal(hSession, decrypted + decrypted_len, &decrypted_len);
  if (rv != CKR_OK) {
      // Handle error
  }

  // Finalize verification
  rv = C_VerifyFinal(hSession, signature, signature_len);
  if (rv != CKR_OK) {
      // Handle error - signature invalid or other error
  }
