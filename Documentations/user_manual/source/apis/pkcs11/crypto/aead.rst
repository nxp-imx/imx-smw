Authentication Encryption/Decryption with associated data (AEAD)
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

PKCS#11 provides two families of functions for authenticated encryption and
decryption with associated data (AEAD). Refer to
:ref:`Symmetric Encryption<p11_symmetric_encryption>` section for the
detailed description of the operation sequences:

- The **single-operation** family (``C_EncryptInit`` / ``C_Encrypt`` and
  ``C_DecryptInit`` / ``C_Decrypt``) embeds the IV/nonce and AAD inside the
  mechanism parameters and processes the entire message in one call.
- The **message** family (``C_MessageEncryptInit`` / ``C_EncryptMessage`` and
  ``C_MessageDecryptInit`` / ``C_DecryptMessage``) allows per-message IV/nonce
  and AAD to be supplied at encrypt/decrypt time, and supports both single-part
  and multi-part message processing.

The mechanisms are listed in the
:ref:`Authentication Encryption Mechanisms (AEAD)<p11_aead_mechanims>` section.

Examples
~~~~~~~~

Single-Operation AEAD Encryption (C_EncryptInit / C_Encrypt)
*************************************************************

The IV/nonce, AAD and tag length are all supplied through the mechanism
parameters at initialization time.

.. code-block:: c

   CK_SESSION_HANDLE hSession;
   CK_OBJECT_HANDLE  hKey;
   CK_BYTE iv[] = { /* 12-byte IV */ };
   CK_BYTE aad[] = { /* additional authenticated data */ };
   CK_BYTE plaintext[] = { /* data to encrypt */ };
   CK_BYTE ciphertext[sizeof(plaintext) + 16]; /* plaintext + 128-bit tag */
   CK_ULONG ciphertext_len = sizeof(ciphertext);
   CK_RV rv;

   CK_GCM_PARAMS gcm_params = {
       .pIv = iv,
       .ulIvLen = sizeof(iv),
       .pAAD = aad,
       .ulAADLen = sizeof(aad),
       .ulTagBits = 128
   };
   CK_MECHANISM mechanism = {
       .mechanism = CKM_AES_GCM,
       .pParameter = &gcm_params,
       .ulParameterLen = sizeof(gcm_params)
   };

   rv = C_EncryptInit(hSession, &mechanism, hKey);
   if (rv != CKR_OK) {
       /* Handle error */
   }

   rv = C_Encrypt(hSession, plaintext, sizeof(plaintext),
                  ciphertext, &ciphertext_len);
   if (rv != CKR_OK) {
       /* Handle error */
   }
   /* ciphertext_len bytes of authenticated ciphertext (data + tag) are ready */

Single-Operation AEAD Decryption (C_DecryptInit / C_Decrypt)
*************************************************************

The ciphertext buffer must include the authentication tag appended after the
encrypted data (i.e. ``ulTagBits / 8`` bytes appended).

.. code-block:: c

   CK_SESSION_HANDLE hSession;
   CK_OBJECT_HANDLE  hKey;
   CK_BYTE iv[] = { /* 12-byte IV used during encryption */ };
   CK_BYTE aad[] = { /* same additional authenticated data used during encryption */ };
   CK_BYTE ciphertext[data_len + 16]; /* encrypted data + 128-bit tag */
   CK_BYTE plaintext[data_len];
   CK_ULONG plaintext_len = sizeof(plaintext);
   CK_RV rv;

   CK_GCM_PARAMS gcm_params = {
       .pIv = iv,
       .ulIvLen = sizeof(iv),
       .pAAD = aad,
       .ulAADLen = sizeof(aad),
       .ulTagBits = 128
   };
   CK_MECHANISM mechanism = {
       .mechanism = CKM_AES_GCM,
       .pParameter = &gcm_params,
       .ulParameterLen = sizeof(gcm_params)
   };

   rv = C_DecryptInit(hSession, &mechanism, hKey);
   if (rv != CKR_OK) {
       /* Handle error */
   }

   rv = C_Decrypt(hSession, ciphertext, sizeof(ciphertext),
                  plaintext, &plaintext_len);
   if (rv != CKR_OK) {
       /* Handle error - CKR_ENCRYPTED_DATA_INVALID if authentication fails */
   }
   /* plaintext_len bytes of verified plaintext are ready */

Single-Part Message AEAD Encryption (C_MessageEncryptInit / C_EncryptMessage)
******************************************************************************

The mechanism is initialized once; per-message IV/nonce and AAD are supplied
at each ``C_EncryptMessage`` call via ``pParameter`` (a ``CK_GCM_MESSAGE_PARAMS``
for AES-GCM) and the ``pAssociatedData`` / ``ulAssociatedDataLen`` arguments.

.. code-block:: c

   CK_SESSION_HANDLE hSession;
   CK_OBJECT_HANDLE  hKey;
   CK_BYTE iv[12];    /* IV buffer - filled by the library when using CKG_GENERATE */
   CK_BYTE tag[16];   /* tag output buffer */
   CK_BYTE aad[] = { /* additional authenticated data */ };
   CK_BYTE plaintext[] = { /* data to encrypt */ };
   CK_BYTE ciphertext[sizeof(plaintext)];
   CK_ULONG ciphertext_len = sizeof(ciphertext);
   CK_RV rv;

   /* Mechanism has no per-init parameters for the message API */
   CK_MECHANISM mechanism = {
       .mechanism = CKM_AES_GCM,
       .pParameter = NULL,
       .ulParameterLen = 0
   };

   rv = C_MessageEncryptInit(hSession, &mechanism, hKey);
   if (rv != CKR_OK) {
       /* Handle error */
   }

   /* Per-message parameters: supply IV or let the library generate it */
   CK_GCM_MESSAGE_PARAMS msg_params = {
       .pIv = iv,
       .ulIvLen = sizeof(iv),
       .ulIvFixedBits = 0,
       .ivGenerator = CKG_GENERATE,    /* library generates the IV */
       .pTag = tag,
       .ulTagBits = 128
   };

   rv = C_EncryptMessage(hSession,
                         &msg_params, sizeof(msg_params),
                         aad, sizeof(aad),
                         plaintext, sizeof(plaintext),
                         ciphertext, &ciphertext_len);
   if (rv != CKR_OK) {
       /* Handle error */
   }
   /* iv[] now holds the generated IV; tag[] holds the authentication tag;
      ciphertext[] holds the encrypted data */

   /* Terminate the message encryption session */
   C_MessageEncryptFinal(hSession);

Single-Part Message AEAD Decryption (C_MessageDecryptInit / C_DecryptMessage)
******************************************************************************

.. code-block:: c

   CK_SESSION_HANDLE hSession;
   CK_OBJECT_HANDLE  hKey;
   CK_BYTE iv[12];    /* IV used during encryption */
   CK_BYTE tag[16];   /* tag produced during encryption */
   CK_BYTE aad[] = { /* same AAD used during encryption */ };
   CK_BYTE ciphertext[] = { /* encrypted data (without tag) */ };
   CK_BYTE plaintext[sizeof(ciphertext)];
   CK_ULONG plaintext_len = sizeof(plaintext);
   CK_RV rv;

   CK_MECHANISM mechanism = {
       .mechanism = CKM_AES_GCM,
       .pParameter = NULL,
       .ulParameterLen = 0
   };

   rv = C_MessageDecryptInit(hSession, &mechanism, hKey);
   if (rv != CKR_OK) {
       /* Handle error */
   }

   CK_GCM_MESSAGE_PARAMS msg_params = {
       .pIv = iv,
       .ulIvLen = sizeof(iv),
       .ulIvFixedBits = 0,
       .ivGenerator = CKG_NO_GENERATE,  /* caller supplies the IV */
       .pTag = tag,
       .ulTagBits = 128
   };

   rv = C_DecryptMessage(hSession,
                         &msg_params, sizeof(msg_params),
                         aad, sizeof(aad),
                         ciphertext, sizeof(ciphertext),
                         plaintext, &plaintext_len);
   if (rv != CKR_OK) {
       /* Handle error - CKR_ENCRYPTED_DATA_INVALID if authentication fails */
   }

   /* Terminate the message decryption session */
   C_MessageDecryptFinal(hSession);

Multi-Part Message AEAD Encryption
***********************************

``C_EncryptMessageBegin`` supplies the per-message parameters and the complete
AAD. ``C_EncryptMessageNext`` is then called for each plaintext chunk, with
``CKF_END_OF_MESSAGE`` set on the last chunk. ``C_MessageEncryptFinal``
terminates the session.

.. code-block:: c

   CK_SESSION_HANDLE hSession;
   CK_OBJECT_HANDLE  hKey;
   CK_BYTE iv[12];
   CK_BYTE tag[16];
   CK_BYTE aad[] = { /* additional authenticated data */ };
   CK_BYTE plaintext_part1[128];
   CK_BYTE plaintext_part2[128];
   CK_BYTE ciphertext[sizeof(plaintext_part1) + sizeof(plaintext_part2)];
   CK_ULONG part_len;
   CK_RV rv;

   CK_MECHANISM mechanism = {
       .mechanism = CKM_AES_GCM,
       .pParameter = NULL,
       .ulParameterLen = 0
   };

   rv = C_MessageEncryptInit(hSession, &mechanism, hKey);
   if (rv != CKR_OK) {
       /* Handle error */
   }

   CK_GCM_MESSAGE_PARAMS msg_params = {
       .pIv = iv,
       .ulIvLen = sizeof(iv),
       .ulIvFixedBits = 0,
       .ivGenerator = CKG_GENERATE,
       .pTag = tag,
       .ulTagBits = 128
   };

   /* Begin: provide per-message params and the full AAD */
   rv = C_EncryptMessageBegin(hSession,
                              &msg_params, sizeof(msg_params),
                              aad, sizeof(aad));
   if (rv != CKR_OK) {
       /* Handle error */
   }

   /* Encrypt first part */
   part_len = sizeof(plaintext_part1);
   rv = C_EncryptMessageNext(hSession,
                             &msg_params, sizeof(msg_params),
                             plaintext_part1, sizeof(plaintext_part1),
                             ciphertext, &part_len,
                             0);  /* not the last part */
   if (rv != CKR_OK) {
       /* Handle error */
   }

   /* Encrypt last part - signal end of message */
   CK_ULONG last_len = sizeof(ciphertext) - part_len;
   rv = C_EncryptMessageNext(hSession,
                             &msg_params, sizeof(msg_params),
                             plaintext_part2, sizeof(plaintext_part2),
                             ciphertext + part_len, &last_len,
                             CKF_END_OF_MESSAGE);
   if (rv != CKR_OK) {
       /* Handle error */
   }
   /* iv[] holds the generated IV; tag[] holds the authentication tag */

   /* Terminate the message encryption session */
   C_MessageEncryptFinal(hSession);

Multi-Part Message AEAD Decryption
************************************

.. code-block:: c

   CK_SESSION_HANDLE hSession;
   CK_OBJECT_HANDLE  hKey;
   CK_BYTE iv[12];
   CK_BYTE tag[16];
   CK_BYTE aad[] = { /* same AAD used during encryption */ };
   CK_BYTE ciphertext_part1[128];
   CK_BYTE ciphertext_part2[128];
   CK_BYTE plaintext[sizeof(ciphertext_part1) + sizeof(ciphertext_part2)];
   CK_ULONG part_len;
   CK_RV rv;

   CK_MECHANISM mechanism = {
       .mechanism = CKM_AES_GCM,
       .pParameter = NULL,
       .ulParameterLen = 0
   };

   rv = C_MessageDecryptInit(hSession, &mechanism, hKey);
   if (rv != CKR_OK) {
       /* Handle error */
   }

   CK_GCM_MESSAGE_PARAMS msg_params = {
       .pIv = iv,
       .ulIvLen = sizeof(iv),
       .ulIvFixedBits = 0,
       .ivGenerator = CKG_NO_GENERATE,
       .pTag = tag,
       .ulTagBits = 128
   };

   /* Begin: provide per-message params and the full AAD */
   rv = C_DecryptMessageBegin(hSession,
                              &msg_params, sizeof(msg_params),
                              aad, sizeof(aad));
   if (rv != CKR_OK) {
       /* Handle error */
   }

   /* Decrypt first part */
   part_len = sizeof(ciphertext_part1);
   rv = C_DecryptMessageNext(hSession,
                             &msg_params, sizeof(msg_params),
                             ciphertext_part1, sizeof(ciphertext_part1),
                             plaintext, &part_len,
                             0);  /* not the last part */
   if (rv != CKR_OK) {
       /* Handle error */
   }

   /* Decrypt last part - signal end of message */
   CK_ULONG last_len = sizeof(plaintext) - part_len;
   rv = C_DecryptMessageNext(hSession,
                             &msg_params, sizeof(msg_params),
                             ciphertext_part2, sizeof(ciphertext_part2),
                             plaintext + part_len, &last_len,
                             CKF_END_OF_MESSAGE);
   if (rv != CKR_OK) {
       /* Handle error - CKR_ENCRYPTED_DATA_INVALID if authentication fails */
   }

   /* Terminate the message decryption session */
   C_MessageDecryptFinal(hSession);
