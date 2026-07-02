.. _p11_symmetric_encryption:

Symmetric Encryption
""""""""""""""""""""

PKCS#11 provides two sets of functions for symmetric encryption and decryption
operations function of the PKCS#11 interface used. If the PKCS#11 3.x interface
is used, the new message-based APIs should be preferred. However, for backward
compatibility, the PKCS#11 2.x APIs are still available:

.. list-table:: PKCS#11 Symmetric Encryption APIs
   :header-rows: 1
   :widths: 20 40 40
   :class: wrap-table

   * - **Version**
     - **Encryption Functions**
     - **Decryption Functions**
   * - **PKCS#11 2.x**
     - :c:func:`C_EncryptInit`, :c:func:`C_Encrypt`, :c:func:`C_EncryptUpdate`,
       :c:func:`C_EncryptFinal`
     - :c:func:`C_DecryptInit`, :c:func:`C_Decrypt`, :c:func:`C_DecryptUpdate`,
       :c:func:`C_DecryptFinal`
   * - **PKCS#11 3.x**
     - :c:func:`C_MessageEncryptInit`, :c:func:`C_EncryptMessage`,
       :c:func:`C_EncryptMessageBegin`, :c:func:`C_EncryptMessageNext`,
       :c:func:`C_MessageEncryptFinal`
     - :c:func:`C_MessageDecryptInit`, :c:func:`C_DecryptMessage`,
       :c:func:`C_DecryptMessageBegin`, :c:func:`C_DecryptMessageNext`,
       :c:func:`C_MessageDecryptFinal`

Regardless of the API version used, the operation must be initialized first
before performing the encryption or decryption operation.

PKCS#11 2.40 APIs sequences
~~~~~~~~~~~~~~~~~~~~~~~~~~~
**Symmetric Encryption**

The sequence of operations to encrypt a message with a single part encryption is
as follows\:

     #. Initialize the operation by calling :c:func:`C_EncryptInit`.
     #. Encrypt data in a single operation with :c:func:`C_Encrypt`.

The sequence of operations to encrypt a message with a multiple part encryption
is as follows\:

     #. Initialize the operation by calling :c:func:`C_EncryptInit`.
     #. Process one or more data parts (can be called multiple times) with
        :c:func:`C_EncryptUpdate`.
     #. Finish the encryption operation and obtain the final ciphertext with
        :c:func:`C_EncryptFinal`.

**Symmetric Decryption**

The sequence of operations to decrypt a message with a single part decryption is
as follows\:

     #. Initialize the operation by calling :c:func:`C_DecryptInit`.
     #. Decrypt data in a single operation with :c:func:`C_Decrypt`.

The sequence of operations to decrypt a message with a multiple part decryption
is as follows\:

     #. Initialize the operation by calling :c:func:`C_DecryptInit`.
     #. Process one or more data parts (can be called multiple times) with
        :c:func:`C_DecryptUpdate`.
     #. Finish the decryption operation and obtain the final plaintext with
        :c:func:`C_DecryptFinal`.

PKCS#11 3.2 APIs sequences
~~~~~~~~~~~~~~~~~~~~~~~~~~
**Message Encryption**

The sequence of operations to encrypt a message with a single part encryption is
as follows\:

     #. Initialize the operation by calling :c:func:`C_MessageEncryptInit`.
     #. Encrypt data in a single operation with :c:func:`C_EncryptMessage`.

The sequence of operations to encrypt a message with a multiple part encryption
is as follows\:

     #. Initialize the operation by calling :c:func:`C_MessageEncryptInit`.
     #. Begin the message encryption with :c:func:`C_EncryptMessageBegin`.
     #. Process one or more data parts (can be called multiple times) with
        :c:func:`C_EncryptMessageNext`.
     #. Finish the encryption operation with :c:func:`C_MessageEncryptFinal`.

**Message Decryption**

The sequence of operations to decrypt a message with a single part decryption is
as follows\:

     #. Initialize the operation by calling :c:func:`C_MessageDecryptInit`.
     #. Decrypt data in a single operation with :c:func:`C_DecryptMessage`.

The sequence of operations to decrypt a message with a multiple part decryption
is as follows\:

     #. Initialize the operation by calling :c:func:`C_MessageDecryptInit`.
     #. Begin the message decryption with :c:func:`C_DecryptMessageBegin`.
     #. Process one or more data parts (can be called multiple times) with
        :c:func:`C_DecryptMessageNext`.
     #. Finish the decryption operation with :c:func:`C_MessageDecryptFinal`.



Initialization
~~~~~~~~~~~~~~
.. kdoc-extension:: /pkcs11/src/encrypt.c
     :functions: C_EncryptInit

.. kdoc-extension:: /pkcs11/src/decrypt.c
     :functions: C_DecryptInit

.. kdoc-extension:: /pkcs11/src/msg_encrypt.c
     :functions: C_MessageEncryptInit

.. kdoc-extension:: /pkcs11/src/msg_decrypt.c
     :functions: C_MessageDecryptInit

Single Part
~~~~~~~~~~~
.. kdoc-extension:: /pkcs11/src/encrypt.c
     :functions: C_Encrypt

.. kdoc-extension:: /pkcs11/src/decrypt.c
     :functions: C_Decrypt

.. kdoc-extension:: /pkcs11/src/msg_encrypt.c
     :functions: C_EncryptMessage

.. kdoc-extension:: /pkcs11/src/msg_decrypt.c
     :functions: C_DecryptMessage

Multiple Part
~~~~~~~~~~~~~
.. kdoc-extension:: /pkcs11/src/encrypt.c
     :functions: C_EncryptUpdate C_EncryptFinal

.. kdoc-extension:: /pkcs11/src/decrypt.c
     :functions: C_DecryptUpdate C_DecryptFinal

.. kdoc-extension:: /pkcs11/src/msg_encrypt.c
     :functions: C_EncryptMessageBegin C_EncryptMessageNext C_MessageEncryptFinal

.. kdoc-extension:: /pkcs11/src/msg_decrypt.c
     :functions: C_DecryptMessageBegin C_DecryptMessageNext C_MessageDecryptFinal

Examples
~~~~~~~~
PKCS#11 2.40 - Single Part Encryption
*************************************
.. code-block:: c

    CK_SESSION_HANDLE hSession;
    CK_OBJECT_HANDLE hKey;
    CK_MECHANISM mechanism = { CKM_AES_CBC, iv, sizeof(iv) };
    CK_BYTE plaintext[] = "Hello World";
    CK_BYTE ciphertext[256];
    CK_ULONG ciphertext_len = sizeof(ciphertext);
    CK_RV rv;

    // Initialize encryption operation
    rv = C_EncryptInit(hSession, &mechanism, hKey);
    if (rv != CKR_OK) {
        // Handle error
    }

    // Perform single-part encryption
    rv = C_Encrypt(hSession, plaintext, sizeof(plaintext),
                   ciphertext, &ciphertext_len);
    if (rv != CKR_OK) {
        // Handle error
    }

PKCS#11 2.40 - Multiple Part Encryption
***************************************
.. code-block:: c

    CK_SESSION_HANDLE hSession;
    CK_OBJECT_HANDLE hKey;
    CK_MECHANISM mechanism = { CKM_AES_CBC, iv, sizeof(iv) };
    CK_BYTE plaintext_part1[] = "Hello ";
    CK_BYTE plaintext_part2[] = "World";
    CK_BYTE ciphertext[256];
    CK_ULONG ciphertext_len = sizeof(ciphertext);
    CK_RV rv;

    // Initialize encryption operation
    rv = C_EncryptInit(hSession, &mechanism, hKey);
    if (rv != CKR_OK) {
        // Handle error
    }

    // Process first part
    rv = C_EncryptUpdate(hSession, plaintext_part1, sizeof(plaintext_part1),
                         ciphertext, &ciphertext_len);
    if (rv != CKR_OK) {
        // Handle error
    }

    // Process second part
    CK_ULONG remaining_len = sizeof(ciphertext) - ciphertext_len;
    rv = C_EncryptUpdate(hSession, plaintext_part2, sizeof(plaintext_part2),
                         ciphertext + ciphertext_len, &remaining_len);
    if (rv != CKR_OK) {
        // Handle error
    }
    ciphertext_len += remaining_len;

    // Finalize encryption
    remaining_len = sizeof(ciphertext) - ciphertext_len;
    rv = C_EncryptFinal(hSession, ciphertext + ciphertext_len, &remaining_len);
    if (rv != CKR_OK) {
        // Handle error
    }
    ciphertext_len += remaining_len;

PKCS#11 2.40 - Single Part Decryption
*************************************
.. code-block:: c

    CK_SESSION_HANDLE hSession;
    CK_OBJECT_HANDLE hKey;
    CK_MECHANISM mechanism = { CKM_AES_CBC, iv, sizeof(iv) };
    CK_BYTE ciphertext[256];
    CK_ULONG ciphertext_len = 256;
    CK_BYTE plaintext[256];
    CK_ULONG plaintext_len = sizeof(plaintext);
    CK_RV rv;

    // Initialize decryption operation
    rv = C_DecryptInit(hSession, &mechanism, hKey);
    if (rv != CKR_OK) {
        // Handle error
    }

    // Perform single-part decryption
    rv = C_Decrypt(hSession, ciphertext, ciphertext_len,
                   plaintext, &plaintext_len);
    if (rv != CKR_OK) {
        // Handle error
    }

PKCS#11 2.40 - Multiple Part Decryption
***************************************
.. code-block:: c

    CK_SESSION_HANDLE hSession;
    CK_OBJECT_HANDLE hKey;
    CK_MECHANISM mechanism = { CKM_AES_CBC, iv, sizeof(iv) };
    CK_BYTE ciphertext[256];
    CK_ULONG ciphertext_len = 256;
    CK_BYTE plaintext[256];
    CK_ULONG plaintext_len = sizeof(plaintext);
    CK_RV rv;

    // Initialize decryption operation
    rv = C_DecryptInit(hSession, &mechanism, hKey);
    if (rv != CKR_OK) {
        // Handle error
    }

    // Process ciphertext in parts
    rv = C_DecryptUpdate(hSession, ciphertext, ciphertext_len / 2,
                         plaintext, &plaintext_len);
    if (rv != CKR_OK) {
        // Handle error
    }

    CK_ULONG remaining_len = sizeof(plaintext) - plaintext_len;
    rv = C_DecryptUpdate(hSession, ciphertext + ciphertext_len / 2,
                         ciphertext_len - ciphertext_len / 2,
                         plaintext + plaintext_len, &remaining_len);
    if (rv != CKR_OK) {
        // Handle error
    }
    plaintext_len += remaining_len;

    // Finalize decryption
    remaining_len = sizeof(plaintext) - plaintext_len;
    rv = C_DecryptFinal(hSession, plaintext + plaintext_len, &remaining_len);
    if (rv != CKR_OK) {
        // Handle error
    }
    plaintext_len += remaining_len;

PKCS#11 3.2 - Single Part Message Encryption
********************************************
.. code-block:: c

    CK_SESSION_HANDLE hSession;
    CK_OBJECT_HANDLE hKey;
    CK_MECHANISM mechanism = { CKM_AES_GCM, &gcm_params, sizeof(gcm_params) };
    CK_BYTE plaintext[] = "Message to encrypt";
    CK_BYTE aad[] = "Additional authenticated data";
    CK_BYTE ciphertext[256];
    CK_ULONG ciphertext_len = sizeof(ciphertext);
    CK_RV rv;

    // Initialize message encryption operation
    rv = C_MessageEncryptInit(hSession, &mechanism, hKey);
    if (rv != CKR_OK) {
        // Handle error
    }

    // Perform single-part message encryption
    rv = C_EncryptMessage(hSession, NULL_PTR, 0, aad, sizeof(aad),
                          plaintext, sizeof(plaintext),
                          ciphertext, &ciphertext_len);
    if (rv != CKR_OK) {
        // Handle error
    }

PKCS#11 3.2 - Multiple Part Message Encryption
**********************************************
.. code-block:: c

    CK_SESSION_HANDLE hSession;
    CK_OBJECT_HANDLE hKey;
    CK_MECHANISM mechanism = { CKM_AES_GCM, &gcm_params, sizeof(gcm_params) };
    CK_BYTE plaintext_part1[] = "First part ";
    CK_BYTE plaintext_part2[] = "Second part";
    CK_BYTE aad[] = "Additional authenticated data";
    CK_BYTE ciphertext[256];
    CK_ULONG ciphertext_len = sizeof(ciphertext);
    CK_RV rv;

    // Initialize message encryption operation
    rv = C_MessageEncryptInit(hSession, &mechanism, hKey);
    if (rv != CKR_OK) {
        // Handle error
    }

    // Begin message encryption with AAD
    rv = C_EncryptMessageBegin(hSession, NULL_PTR, 0, aad, sizeof(aad));
    if (rv != CKR_OK) {
        // Handle error
    }

    // Process first part
    rv = C_EncryptMessageNext(hSession, NULL_PTR, 0, plaintext_part1,
                              sizeof(plaintext_part1), NULL_PTR, NULL_PTR, 0);
    if (rv != CKR_OK) {
        // Handle error
    }

    // Process second part and get ciphertext
    rv = C_EncryptMessageNext(hSession, NULL_PTR, 0, plaintext_part2,
                              sizeof(plaintext_part2), ciphertext,
                              &ciphertext_len, CKF_END_OF_MESSAGE);
    if (rv != CKR_OK) {
        // Handle error
    }

    // Finalize message encryption
    rv = C_MessageEncryptFinal(hSession);
    if (rv != CKR_OK) {
        // Handle error
    }

PKCS#11 3.2 - Single Part Message Decryption
********************************************
.. code-block:: c

    CK_SESSION_HANDLE hSession;
    CK_OBJECT_HANDLE hKey;
    CK_MECHANISM mechanism = { CKM_AES_GCM, &gcm_params, sizeof(gcm_params) };
    CK_BYTE ciphertext[256];
    CK_ULONG ciphertext_len = 256;
    CK_BYTE aad[] = "Additional authenticated data";
    CK_BYTE plaintext[256];
    CK_ULONG plaintext_len = sizeof(plaintext);
    CK_RV rv;

    // Initialize message decryption operation
    rv = C_MessageDecryptInit(hSession, &mechanism, hKey);
    if (rv != CKR_OK) {
        // Handle error
    }

    // Perform single-part message decryption
    rv = C_DecryptMessage(hSession, NULL_PTR, 0, aad, sizeof(aad),
                          ciphertext, ciphertext_len,
                          plaintext, &plaintext_len);
    if (rv != CKR_OK) {
        // Handle error
    }

PKCS#11 3.2 - Multiple Part Message Decryption
**********************************************
.. code-block:: c

    CK_SESSION_HANDLE hSession;
    CK_OBJECT_HANDLE hKey;
    CK_MECHANISM mechanism = { CKM_AES_GCM, &gcm_params, sizeof(gcm_params) };
    CK_BYTE ciphertext_part1[128];
    CK_ULONG ciphertext_part1_len = 128;
    CK_BYTE ciphertext_part2[128];
    CK_ULONG ciphertext_part2_len = 128;
    CK_BYTE aad[] = "Additional authenticated data";
    CK_BYTE plaintext[256];
    CK_ULONG plaintext_len = sizeof(plaintext);
    CK_RV rv;

    // Initialize message decryption operation
    rv = C_MessageDecryptInit(hSession, &mechanism, hKey);
    if (rv != CKR_OK) {
        // Handle error
    }

    // Begin message decryption with AAD
    rv = C_DecryptMessageBegin(hSession, NULL_PTR, 0, aad, sizeof(aad));
    if (rv != CKR_OK) {
        // Handle error
    }

    // Process first part
    rv = C_DecryptMessageNext(hSession, NULL_PTR, 0, ciphertext_part1,
                              ciphertext_part1_len, NULL_PTR, NULL_PTR, 0);
    if (rv != CKR_OK) {
        // Handle error
    }

    // Process second part and get plaintext
    rv = C_DecryptMessageNext(hSession, NULL_PTR, 0, ciphertext_part2,
                              ciphertext_part2_len, plaintext,
                              &plaintext_len, CKF_END_OF_MESSAGE);
    if (rv != CKR_OK) {
        // Handle error
    }

    // Finalize message decryption
    rv = C_MessageDecryptFinal(hSession);
    if (rv != CKR_OK) {
        // Handle error
    }
