Session Management
^^^^^^^^^^^^^^^^^^

Session management in PKCS#11 is fundamental for interacting with cryptographic
tokens. A session represents a logical connection between an application and a
token, providing the context for performing cryptographic operations.

SMW's PKCS#11 implementation supports session management functions that allow
applications to:

- Open and close sessions with cryptographic tokens
- Manage session state and properties
- Control access to token resources

Sessions can be opened in read-only or read-write mode, depending on the
operations that need to be performed. All cryptographic operations (key
generation, signing, encryption, etc.) must be performed within the context of
an active session.

Functions
"""""""""
Open and close sessions
~~~~~~~~~~~~~~~~~~~~~~~

.. kdoc-extension:: /pkcs11/src/session.c
   :functions: C_OpenSession C_CloseSession C_CloseAllSessions C_SessionCancel

Get session information
~~~~~~~~~~~~~~~~~~~~~~~
.. kdoc-extension:: /pkcs11/src/session.c
   :functions: C_GetSessionInfo

Operation state
~~~~~~~~~~~~~~~
.. kdoc-extension:: /pkcs11/src/session.c
   :functions: C_GetOperationState C_SetOperationState

Session login
~~~~~~~~~~~~~
.. kdoc-extension:: /pkcs11/src/session.c
   :functions: C_Login C_LoginUser C_Logout

Session flags
~~~~~~~~~~~~~
.. kdoc-extension:: /pkcs11/src/session.c
   :functions: C_GetSessionValidationFlags

Example
"""""""

The following example demonstrates how to open a session, retrieve session
information, and close the session:

.. code-block:: c
   :linenos:

   CK_RV rv;
   CK_SESSION_HANDLE hSession;
   CK_SESSION_INFO sessionInfo = { 0 };
   CK_SLOT_ID slotID = 0;
   CK_FLAGS flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

   /* Open a read-write session */
   rv = C_OpenSession(slotID, flags, NULL, NULL, &hSession);
   if (rv != CKR_OK) {
       printf("Failed to open session: 0x%lx\n", rv);
       return rv;
   }

   printf("Session opened successfully: %lu\n", hSession);

   /* Get session information */
   rv = C_GetSessionInfo(hSession, &sessionInfo);
   if (rv != CKR_OK) {
       printf("Failed to get session info: 0x%lx\n", rv);
       C_CloseSession(hSession);
       return rv;
   }

   printf("Session state: %lu\n", sessionInfo.state);
   printf("Session flags: 0x%lx\n", sessionInfo.flags);
   printf("Device error: %lu\n", sessionInfo.ulDeviceError);

   /* Perform cryptographic operations here */
   /* ... */

   /* Close the session */
   rv = C_CloseSession(hSession);
   if (rv != CKR_OK) {
       printf("Failed to close session: 0x%lx\n", rv);
       return rv;
   }

   printf("Session closed successfully\n");

   return CKR_OK;

.. note::
   SMW's PKCS#11 implementation does not require PIN authentication for session
   operations. The ``CKF_SERIAL_SESSION`` flag must always be set when opening
   a session as per PKCS#11 specification.

.. note::
   To close all sessions associated with a token at once, use
   :c:func:`C_CloseAllSessions` instead of closing each session individually.
