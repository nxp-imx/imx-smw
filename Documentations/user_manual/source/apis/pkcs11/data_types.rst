Data types definitions
^^^^^^^^^^^^^^^^^^^^^^

The purpose of this section is to document the data types used within the
PKCS#11 API.

Basic Types
~~~~~~~~~~~
The basic types are fundamental data types based on the ANSI C standard types.

CK_BYTE
*******
.. c:type:: CK_BYTE

   Single unsigned byte value.

Definition
##########
.. code-block:: c

   typedef unsigned char CK_BYTE;

Description
###########
``CK_BYTE`` is a single byte value used to represent an 8-bit unsigned integer.

CK_BYTE_PTR
***********
.. c:type:: CK_BYTE_PTR

   Pointer to a :c:type:`CK_BYTE` value.

Definition
##########
.. code-block:: c

   typedef CK_BYTE *CK_BYTE_PTR;

Description
###########
``CK_BYTE_PTR`` is a pointer type to a ``CK_BYTE`` value, used to reference
byte data in function calls and data structures within the PKCS#11 API.

CK_CHAR
*******
.. c:type:: CK_CHAR

   Single unsigned character value.

Definition
##########
.. code-block:: c

   typedef CK_BYTE CK_CHAR;

Description
###########
``CK_CHAR`` is a single character value used to represent an 8-bit unsigned
character. It's a ANSI C character as listed in the following
:ref:`p11_char_set` table.

.. list-table:: Character Set
   :header-rows: 1
   :name: p11_char_set
   :widths: 20 80
   :class: wrap-table

   * - **Category**
     - **Characters**
   * - Letters
     - A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
       a b c d e f g h i j k l m n o p q r s t u v w x y z
   * - Numbers
     - 0 1 2 3 4 5 6 7 8 9
   * - Graphic characters
     - ! “ # % & ‘ ( ) * + , - . / : ; < = > ? [ \ ] ^ _  { | } ~
   * - Blank character
     - ' '

CK_CHAR_PTR
***********
.. c:type:: CK_CHAR_PTR

   Pointer to a :c:type:`CK_CHAR` value.

Definition
##########
.. code-block:: c

   typedef CK_CHAR *CK_CHAR_PTR;

Description
###########
``CK_CHAR_PTR`` is a pointer type to a ``CK_CHAR`` value, used to reference
character data in function calls and data structures within the PKCS#11 API.

CK_UTF8CHAR
***********
.. c:type:: CK_UTF8CHAR

   Single UTF-8 character value.

Definition
##########
.. code-block:: c

   typedef CK_BYTE CK_UTF8CHAR;

Description
###########
``CK_UTF8CHAR`` is a single UTF-8 character value used to represent an 8-bit
unsigned character in UTF-8 encoding Unicode character as specified in the
:rfc:`2279`.

CK_UTF8CHAR_PTR
***************
.. c:type:: CK_UTF8CHAR_PTR

   Pointer to a :c:type:`CK_UTF8CHAR` value.

Definition
##########
.. code-block:: c

   typedef CK_UTF8CHAR *CK_UTF8CHAR_PTR;

Description
###########
``CK_UTF8CHAR_PTR`` is a pointer type to a ``CK_UTF8CHAR`` value, used to
reference UTF-8 character data in function calls and data structures within
the PKCS#11 API.

CK_BBOOL
********
.. c:type:: CK_BBOOL

   Boolean value.

Definition
##########
.. code-block:: c

   typedef unsigned char CK_BBOOL;

Description
###########
``CK_BBOOL`` is a boolean value used to represent a true `CK_TRUE` or false
`CK_FALSE` state, where a non-zero value is considered true and zero is
considered false.

CK_ULONG
********
.. c:type:: CK_ULONG

   Unsigned long integer value.

Definition
##########
.. code-block:: c

   typedef unsigned long CK_ULONG;

Description
###########
``CK_ULONG`` is an unsigned long integer value used to represent non-negative
integer values, commonly used for sizes, counts, and identifiers within the
PKCS#11 API.

CK_ULONG_PTR
************
.. c:type:: CK_ULONG_PTR

   Pointer to a :c:type:`CK_ULONG` value.

Definition
##########
.. code-block:: c

   typedef CK_ULONG *CK_ULONG_PTR;

Description
###########
``CK_ULONG_PTR`` is a pointer type to a ``CK_ULONG`` value, used to reference
unsigned long integer data in function calls and data structures within the
PKCS#11 API.

CK_LONG
*******
.. c:type:: CK_LONG

   Signed long integer value.

Definition
##########
.. code-block:: c

   typedef long CK_LONG;

Description
###########
``CK_LONG`` is a signed long integer value used to represent both positive and
negative integer values within the PKCS#11 API.

CK_FLAGS
********
.. c:type:: CK_FLAGS

   Bit flags for various purposes.

Definition
##########
.. code-block:: c

   typedef CK_ULONG CK_FLAGS;

Description
###########
``CK_FLAGS`` is a value used to provide bit flags indicating various
capabilities or states. The meaning of specific flags depends on the context
in which they are used.

CK_FLAGS_PTR
************
.. c:type:: CK_FLAGS_PTR

   Pointer to a :c:type:`CK_FLAGS`

Definition
##########
.. code-block:: c

   typedef CK_FLAGS *CK_FLAGS_PTR;

Description
###########
``CK_FLAGS_PTR`` is a pointer type to a ``CK_FLAGS`` value, used to reference
flags in function calls and data structures within the PKCS#11 API.

CK_VOID_PTR
***********
.. c:type:: CK_VOID_PTR

   Generic pointer type.

Definition
##########
.. code-block:: c

   typedef void *CK_VOID_PTR;

Description
###########
``CK_VOID_PTR`` is a generic pointer type used to reference any type of data
in function calls and data structures within the PKCS#11 API. It provides a
way to pass pointers to different data types without explicit type casting.

CK_VOID_PTR_PTR
***************
.. c:type:: CK_VOID_PTR_PTR

   Pointer to a :c:type:`CK_VOID_PTR` value.

Definition
##########
.. code-block:: c

   typedef CK_VOID_PTR *CK_VOID_PTR_PTR;

Description
###########
``CK_VOID_PTR_PTR`` is a pointer type to a ``CK_VOID_PTR`` value, used to
reference generic pointers in function calls and data structures within the
PKCS#11 API.

NULL_PTR
********
.. c:macro:: NULL_PTR

   Null pointer constant. Value is NULL.

Definition
##########
.. code-block:: c

   #define NULL_PTR NULL

Description
###########
``NULL_PTR`` is a null pointer constant used to represent a null pointer value
in function calls and data structures within the PKCS#11 API.

Constants
~~~~~~~~~
CK_TRUE
*******
.. c:macro:: CK_TRUE

   Boolean true constant. Value is 1.

CK_FALSE
********
.. c:macro:: CK_FALSE

   Boolean false constant. Value is 0.


Locking-related types
~~~~~~~~~~~~~~~~~~~~~
Cryptoki provides some special types for use in a multi-threaded environment.
These types are used to enable an application to use its own threading and
locking primitives with Cryptoki.

CK_CREATEMUTEX
**************
.. c:type:: CK_CREATEMUTEX

   Function pointer type for creating a mutex object.

Definition
##########
.. code-block:: c

   CK_CALLBACK_FUNCTION(CK_RV, CK_CREATEMUTEX)(
       CK_VOID_PTR_PTR ppMutex
   );

Parameters
##########
ppMutex
   Pointer to location to receive pointer to new mutex.

Description
###########
``CK_CREATEMUTEX`` is a pointer to a function that creates and returns a new
mutex object, storing a pointer to it in the location pointed to by ``ppMutex``.
If the function is unable to create a new mutex, it MUST return an error code
such as ``CKR_GENERAL_ERROR`` or ``CKR_HOST_MEMORY``.

CK_DESTROYMUTEX
***************
.. c:type:: CK_DESTROYMUTEX

   Function pointer type for destroying a mutex object.

Definition
##########
.. code-block:: c

   CK_CALLBACK_FUNCTION(CK_RV, CK_DESTROYMUTEX)(
       CK_VOID_PTR pMutex
   );

Parameters
##########
pMutex
   Pointer to mutex to be destroyed.

Description
###########
``CK_DESTROYMUTEX`` is a pointer to a function that destroys a mutex object.
The mutex object is specified by the ``pMutex`` parameter. If the function is
unable to destroy the mutex, it MUST return an error code such as
``CKR_GENERAL_ERROR`` or ``CKR_MUTEX_BAD``.

CK_LOCKMUTEX
************
.. c:type:: CK_LOCKMUTEX

   Function pointer type for locking a mutex.

Definition
##########
.. code-block:: c

   CK_CALLBACK_FUNCTION(CK_RV, CK_LOCKMUTEX)(
       CK_VOID_PTR pMutex
   );

Parameters
##########
pMutex
   Pointer to mutex to be locked.

Description
###########
``CK_LOCKMUTEX`` is a pointer to a function that locks a mutex. The mutex
object is specified by the ``pMutex`` parameter. If the function is unable to
lock the mutex, it MUST return an error code such as ``CKR_GENERAL_ERROR`` or
``CKR_MUTEX_BAD``.

CK_UNLOCKMUTEX
**************
.. c:type:: CK_UNLOCKMUTEX

   Function pointer type for unlocking a mutex.

Definition
##########
.. code-block:: c

   CK_CALLBACK_FUNCTION(CK_RV, CK_UNLOCKMUTEX)(
       CK_VOID_PTR pMutex
   );

Parameters
##########
pMutex
   Pointer to mutex to be unlocked.

Description
###########
``CK_UNLOCKMUTEX`` is a pointer to a function that unlocks a mutex. The mutex
object is specified by the ``pMutex`` parameter. If the function is unable to
unlock the mutex, it MUST return an error code such as ``CKR_GENERAL_ERROR`` or
``CKR_MUTEX_BAD``.

CK_C_INITIALIZE_ARGS
********************
.. c:type:: CK_C_INITIALIZE_ARGS

   Structure for C_Initialize function arguments.

Definition
##########
.. code-block:: c

   typedef struct CK_C_INITIALIZE_ARGS {
       CK_CREATEMUTEX CreateMutex;
       CK_DESTROYMUTEX DestroyMutex;
       CK_LOCKMUTEX LockMutex;
       CK_UNLOCKMUTEX UnlockMutex;
       CK_FLAGS flags;
       CK_VOID_PTR pReserved;
   } CK_C_INITIALIZE_ARGS;

Members
#######
CreateMutex
   Pointer to a function for creating a mutex.

DestroyMutex
   Pointer to a function for destroying a mutex.

LockMutex
   Pointer to a function for locking a mutex.

UnLockMutext
   Pointer to a function for unlocking a mutex.

flags
   bit flags specifying options for the :c:func:`C_Initialize` function.
   See :ref:`p11_c_initialize_parameter_flags` table for the list of flags.

pReserved
   Reserved for future use. Must be NULL_PTR.

Description
###########
``CK_C_INITIALIZE_ARGS`` is a structure used to pass initialization arguments
to the :c:func:`C_Initialize` function. It allows an application to provide
custom mutex handling functions for multi-threaded environments. All function
pointers may be set to NULL_PTR if the application does not require custom
mutex handling.

.. list-table:: C_Initialize parameter flags
   :header-rows: 1
   :name: p11_c_initialize_parameter_flags
   :align: center
   :class: wrap-table

   * - **Name**
     - **Bit Mask**
     - **Description**
   * - CKF_LIBRARY_CANT_CREATE_OS_THREADS
     - 0x00000001
     - If this bit is set, the library cannot create OS threads. The application
       must create threads on behalf of the library.
   * - CKF_OS_LOCKING_OK
     - 0x00000002
     - If this bit is set, the library can use OS-provided locking primitives.
       The application does not need to provide custom mutex handling functions.


CK_C_INITIALIZE_ARGS_PTR
************************
.. c:type:: CK_C_INITIALIZE_ARGS_PTR

   Pointer to a :c:type:`CK_C_INITIALIZE_ARGS` structure.

Definition
##########
.. code-block:: c

   typedef CK_C_INITIALIZE_ARGS CK_PTR CK_C_INITIALIZE_ARGS_PTR;

Description
###########
``CK_C_INITIALIZE_ARGS_PTR`` is a pointer type to a
:c:type:`CK_C_INITIALIZE_ARGS` structure. It is used to pass initialization
arguments to the :c:func:`C_Initialize` function.

General information
~~~~~~~~~~~~~~~~~~~
CK_VERSION
**********
.. c:struct:: CK_VERSION

   Structure that describes the version of Cryptoki.

Definition
##########
.. code-block:: c

   typedef struct CK_VERSION {
       CK_BYTE major;
       CK_BYTE minor;
   } CK_VERSION;

Members
#######
major
   Major version number (the integer portion of the version).

minor
   Minor version number (the hundredths portion of the version).

Description
###########
``CK_VERSION`` is a structure that describes the version of Cryptoki. For
version 3.2, ``major`` would be 3 and ``minor`` would be 2. The version
number is represented in binary-coded decimal format.

CK_VERSION_PTR
**************
.. c:type:: CK_VERSION_PTR

   Pointer to a :c:type:`CK_VERSION` structure.

Definition
##########
.. code-block:: c

   typedef CK_VERSION *CK_VERSION_PTR;

Description
###########
``CK_VERSION_PTR`` is a pointer type to a ``CK_VERSION`` structure, used to
reference version information in function calls and data structures within the
PKCS#11 API.

CK_INFO
*******
.. c:type:: CK_INFO

   Provides general information about Cryptoki.

Definition
##########
.. code-block:: c

   typedef struct CK_INFO {
       CK_VERSION cryptokiVersion;
       CK_UTF8CHAR manufacturerID[32];
       CK_FLAGS flags;
       CK_UTF8CHAR libraryDescription[32];
       CK_VERSION libraryVersion;
   } CK_INFO;

Members
#######
cryptokiVersion
   Cryptoki interface version number, for compatibility with future revisions.

manufacturerID
   ID of the Cryptoki library manufacturer. Padded with blank characters (' '),
   and is not null-terminated.

flags
   Bit flags reserved for future versions. Zero for this version.

libraryDescription
   Character-string description of the library. Padded with blank characters
   (' '), and is not null-terminated.

libraryVersion
   Cryptoki library version number.

Description
###########
``CK_INFO`` provides general information about the Cryptoki library. The
``manufacturerID`` and ``libraryDescription`` fields are fixed-length
character arrays that are added with space characters (0x20) without
null-terminated character. An application can use :c:func:`C_GetInfo` to obtain
this information.

CK_INFO_PTR
***********
.. c:type:: CK_INFO_PTR

   Pointer to a :c:type:`CK_INFO` structure.

Definition
##########
.. code-block:: c

   typedef CK_INFO *CK_INFO_PTR;

Description
###########
``CK_INFO_PTR`` is a pointer type to a :c:type:`CK_INFO` structure. It is
used to pass references to CK_INFO structures to Cryptoki functions.

CK_NOTIFICATION
***************
.. c:type:: CK_NOTIFICATION

   Notification event type for Cryptoki callbacks.

Definition
##########
.. code-block:: c

   typedef CK_ULONG CK_NOTIFICATION;

Description
###########
``CK_NOTIFICATION`` is a typedef for notification event types used in Cryptoki
callbacks. It is used to indicate various events that may occur during
cryptographic operations.

Current version of Cryptoki defines the following notification type:

  - ``CKN_SURRENDER``; Cryptoki is surrendering the execution of a function
    executing in a session so that the application may perform other operations.
    After performing any desired operations, the application should indicate to
    Cryptoki whether to continue or cancel the function.

Slot and token types
~~~~~~~~~~~~~~~~~~~~
CK_SLOT_ID
**********
.. c:type:: CK_SLOT_ID

   Identifier for a slot.

Definition
##########
.. code-block:: c

   typedef CK_ULONG CK_SLOT_ID;

Description
###########
``CK_SLOT_ID`` is a unique identifier for a slot within a Cryptoki library. The
list of available slots can be obtained by calling :c:func:`C_GetSlotList`. Each
slot may contain a token, and slot IDs are used to identify which slot to
perform operations on in various Cryptoki function calls.

CK_SLOT_ID_PTR
**************
.. c:type:: CK_SLOT_ID_PTR

   Pointer to a slot identifier :c:type:`CK_SLOT_ID`.

Definition
##########
.. code-block:: c

   typedef CK_SLOT_ID *CK_SLOT_ID_PTR;

Description
###########
``CK_SLOT_ID_PTR`` is a pointer type to a ``CK_SLOT_ID`` identifier, used to
reference slot identifiers in function calls and data structures within the
PKCS#11 API.

CK_SLOT_INFO
************
.. c:type:: CK_SLOT_INFO

   Provides information about a slot.

Definition
##########
.. code-block:: c

   typedef struct CK_SLOT_INFO {
       CK_UTF8CHAR slotDescription[64];
       CK_UTF8CHAR manufacturerID[32];
       CK_FLAGS flags;
       CK_VERSION hardwareVersion;
       CK_VERSION firmwareVersion;
   } CK_SLOT_INFO;

Members
#######
slotDescription
   Character-string description of the slot. Padded with blank characters
   (' '), and is not null-terminated.

manufacturerID
   ID of the slot manufacturer. Padded with blank characters (' '), and is not
   null-terminated.

flags
   Bit flags that provide information about the slot. The flags are listed in
   the :ref:`p11_slot_info_flags` table.

hardwareVersion
   Hardware version number of the slot.

firmwareVersion
   Firmware version number of the slot.

Description
###########
``CK_SLOT_INFO`` provides information about a specific slot in the Cryptoki
library. The ``slotDescription`` and ``manufacturerID`` fields are fixed-length
character arrays that are padded with space characters (0x20) without
null-terminated character. An application can use :c:func:`C_GetSlotInfo` to
obtain this information.

.. list-table:: Slot Information Flags
   :header-rows: 1
   :name: p11_slot_info_flags
   :class: wrap-table

   * - **Flag**
     - **Value**
     - **Description**
   * - CKF_TOKEN_PRESENT
     - 0x00000001
     - A token is present in the slot.
   * - CKF_REMOVABLE_DEVICE
     - 0x00000002
     - The slot is for a removable device.
   * - CKF_HW_SLOT
     - 0x00000004
     - The slot is a hardware slot.

CK_SLOT_INFO_PTR
****************
.. c:type:: CK_SLOT_INFO_PTR

   Pointer to a :c:type:`CK_SLOT_INFO` structure.

Definition
##########
.. code-block:: c

   typedef CK_SLOT_INFO *CK_SLOT_INFO_PTR;

Description
###########
``CK_SLOT_INFO_PTR`` is a pointer type to a :c:type:`CK_SLOT_INFO` structure.
It is used to pass references to CK_SLOT_INFO structures to Cryptoki functions.

CK_TOKEN_INFO
*************
.. c:type:: CK_TOKEN_INFO

   Provides information about a token.

Definition
##########
.. code-block:: c

   typedef struct CK_TOKEN_INFO {
       CK_UTF8CHAR label[32];
       CK_UTF8CHAR manufacturerID[32];
       CK_UTF8CHAR model[16];
       CK_CHAR serialNumber[16];
       CK_FLAGS flags;
       CK_ULONG ulMaxSessionCount;
       CK_ULONG ulSessionCount;
       CK_ULONG ulMaxRwSessionCount;
       CK_ULONG ulRwSessionCount;
       CK_ULONG ulMaxPinLen;
       CK_ULONG ulMinPinLen;
       CK_ULONG ulTotalPublicMemory;
       CK_ULONG ulFreePublicMemory;
       CK_ULONG ulTotalPrivateMemory;
       CK_ULONG ulFreePrivateMemory;
       CK_VERSION hardwareVersion;
       CK_VERSION firmwareVersion;
       CK_CHAR utcTime[16];
   } CK_TOKEN_INFO;

Members
#######
label
   Application-defined label for the token. Padded with blank characters
   (' '), and is not null-terminated.

manufacturerID
   ID of the device manufacturer. Padded with blank characters (' '), and is not
   null-terminated.

model
   Character-string description of the device model. Padded with blank
   characters (' '), and is not null-terminated.

serialNumber
   Character-string serial number of the device. Padded with blank characters
   (' '), and is not null-terminated.

flags
   Bit flags that provide capabilities and status of the device as defined
   in the :ref:`p11_token_info_flags` table.

ulMaxSessionCount
   Maximum number of sessions that can be opened with the token at one time
   by a single application.

ulSessionCount
   Number of sessions that application currently has open with the token.

ulMaxRwSessionCount
   Maximum number of read/write sessions that can be opened with the token at
   one time by a single application.

ulRwSessionCount
   Number of read/write sessions that application currently has open with the
   token.

ulMaxPinLen
   Maximum length in bytes for the PIN.

ulMinPinLen
   Minimum length in bytes for the PIN.

ulTotalPublicMemory
   Total amount of public memory on the token in bytes.

ulFreePublicMemory
   Amount of free public memory on the token in bytes.

ulTotalPrivateMemory
   Total amount of private memory on the token in bytes.

ulFreePrivateMemory
   Amount of free private memory on the token in bytes.

hardwareVersion
   Hardware version number.

firmwareVersion
   Firmware version number.

utcTime
   The current date and time in UTC. Formatted as a character string in the
   format YYYYMMDDhhmmss00 (year, month, day, hour, minute, second, and two
   trailing zeros). Not null-terminated.

Description
###########
``CK_TOKEN_INFO`` provides detailed information about a token in the Cryptoki
library. An application can use :c:func:`C_GetTokenInfo` to obtain this
information.

.. list-table:: Token Information Flags
   :header-rows: 1
   :name: p11_token_info_flags
   :class: wrap-table

   * - **Flag**
     - **Value**
     - **Description**
   * - CKF_RNG
     - 0x00000001
     - The token has a random number generator.
   * - CKF_WRITE_PROTECTED
     - 0x00000002
     - The token is write-protected.
   * - CKF_LOGIN_REQUIRED
     - 0x00000004
     - User must be logged to perform some cryptographic functions.
   * - CKF_USER_PIN_INITIALIZED
     - 0x00000008
     - The user PIN has been initialized.
   * - CKF_RESTORE_KEY_NOT_NEEDED
     - 0x00000020
     - Backup of session's cryptographic keys is not required.
   * - CKF_CLOCK_ON_TOKEN
     - 0x00000040
     - The token has its own hardware clock.
   * - CKF_PROTECTED_AUTHENTICATION_PATH
     - 0x00000100
     - The token has a protected authentication path. User does not need to
       login with a PIN to perform cryptographic functions.
   * - CKF_DUAL_CRYPTO_OPERATIONS
     - 0x00000200
     - The token can perform dual cryptographic operations.
   * - CKF_TOKEN_INITIALIZED
     - 0x00000400
     - The token has been initialized using the :c:func:`C_InitToken` function.
       Calling the :c:func:`C_InitToken` function with a token that is already
       initialized will cause the token to be re-initialized, clearing all
       stored objects.
   * - CKF_USER_PIN_COUNT_LOW
     - 0x00010000
     - Incorrect user login PIN has been entered at least once since the last
       successful authentication.
   * - CK_USER_PIN_FINAL_TRY
     - 0x00020000
     - Supplying an incorrect user PIN will cause it to become locked.
   * - CKF_USER_PIN_LOCKED
     - 0x00040000
     - The user PIN is locked.
   * - CKF_USER_PIN_TO_BE_CHANGED
     - 0x00080000
     - The user PIN must be changed.
   * - CKF_SO_PIN_COUNT_LOW
     - 0x00100000
     - Incorrect SO login PIN has been entered at least once since the last
       successful authentication.
   * - CKF_SO_PIN_FINAL_TRY
     - 0x00200000
     - Supplying an incorrect SO PIN will cause it to become locked.
   * - CKF_SO_PIN_LOCKED
     - 0x00400000
     - The SO PIN is locked.
   * - CKF_SO_PIN_TO_BE_CHANGED
     - 0x00800000
     - The SO PIN must be changed.
   * - CKF_ERROR_STATE
     - 0x01000000
     - The token failed a FIPS 140-2 self-test and entered an error state.
   * - CKF_SEED_RANDOM_REQUIRED
     - 0x02000000
     - The token random number generator requires seeding or re-seeding using
       :c:func:`C_SeedRandom`.
   * - CKF_ASYNC_SESSION_SUPPORTED
     - 0x04000000
     - The token supports asynchronous session operations.

CK_TOKEN_INFO_PTR
*****************
.. c:type:: CK_TOKEN_INFO_PTR

   Pointer to :c:type:`CK_TOKEN_INFO` structure.

Definition
##########
.. code-block:: c

   typedef CK_TOKEN_INFO *CK_TOKEN_INFO_PTR;

Description
###########
``CK_TOKEN_INFO_PTR`` is a pointer type to the ``CK_TOKEN_INFO`` structure.

Session types
~~~~~~~~~~~~~
CK_SESSION_HANDLE
*****************
.. c:type:: CK_SESSION_HANDLE

   Handle to a session object.

Definition
##########
.. code-block:: c

   typedef CK_ULONG CK_SESSION_HANDLE;

Description
###########
``CK_SESSION_HANDLE`` is a handle to a session object in the Cryptoki library.

CK_SESSION_HANDLE_PTR
*********************
.. c:type:: CK_SESSION_HANDLE_PTR

   Pointer to :c:type:`CK_SESSION_HANDLE`.

Definition
##########
.. code-block:: c

   typedef CK_SESSION_HANDLE *CK_SESSION_HANDLE_PTR;

Description
###########
``CK_SESSION_HANDLE_PTR`` is a pointer type to the ``CK_SESSION_HANDLE`` type.

CK_USER_TYPE
************
.. c:type:: CK_USER_TYPE

   Enumeration for user types.

Definition
##########
.. code-block::c

   typedef CK_ULONG CK_USER_TYPE;

Description
###########
``CK_USER_TYPE`` is an enumeration type for user types in the Cryptoki library.

It is used to specify the type of user logging into a token. The following
user types are defined:

 .. list-table:: User Types
    :header-rows: 1
    :name: p11_user_types
    :class: wrap-table

    * - **User Type**
      - **Value**
      - **Description**
    * - CKU_SO
      - 0x00000000
      - Security Officer user type.
    * - CKU_USER
      - 0x00000001
      - Normal user type.
    * - CKU_CONTEXT_SPECIFIC
      - 0x00000002
      - Context-specific user type.

CK_STATE
********
.. c:type:: CK_STATE

   Enumeration for session states.

Definition
##########
.. code-block:: c

   typedef CK_ULONG CK_STATE;

Description
###########
``CK_STATE`` is an enumeration type for session states in the Cryptoki library.
It is used to specify the state of a session.

.. list-table:: Session States
   :header-rows: 1
   :name: p11_session_states
   :class: wrap-table

   * - **Session State**
     - **Value**
     - **Description**
   * - CKS_RO_PUBLIC_SESSION
     - 0x00000000
     - Read-only public session state.
   * - CKS_RO_USER_FUNCTIONS
     - 0x00000001
     - Read-only user functions session state.
   * - CKS_RW_PUBLIC_SESSION
     - 0x00000002
     - Read-write public session state.
   * - CKS_RW_USER_FUNCTIONS
     - 0x00000003
     - Read-write user functions session state.
   * - CKS_RW_SO_FUNCTIONS
     - 0x00000004
     - Read-write security officer functions session state.

CK_SESSION_INFO
***************
.. c:type:: CK_SESSION_INFO

   Structure containing information about a session.

Definition
##########
.. code-block:: c

   typedef struct CK_SESSION_INFO {
       CK_SLOT_ID slotID;
       CK_STATE state;
       CK_FLAGS flags;
       CK_ULONG ulDeviceError;
   } CK_SESSION_INFO;

Members
#######
sloID
   The ID of the slot that the session is open on.

state
   The state of the session (see :ref:`p11_session_states`).

flags
   The flags set for the session (see :ref:`p11_session_flags`).

ulDeviceError
   The error code define by the device. Used for errors not covered by Cryptoki.

Description
###########
Provides information about a session.

``ulDeviceError`` is a member of the ``CK_SESSION_INFO`` structure that contains
device-specific error codes. This field is used to report errors that are not
covered by the standard Cryptoki error codes.

.. list-table:: Session Flags
   :header-rows: 1
   :name: p11_session_flags
   :class: wrap-table

   * - **Session Flag**
     - **Value**
     - **Description**
   * - CKF_RW_SESSION
     - 0x00000002
     - The session is read/write.
   * - CKF_SERIAL_SESSION
     - 0x00000004
     - This flag is provided for backward compatibility and should always be set.
   * - CKF_ASYNC_SESSION
     - 0x00000008
     - The session supports asynchronous operations.

CK_SESSION_INFO_PTR
*******************
.. c:type:: CK_SESSION_INFO_PTR

   Pointer to :c:type:`CK_SESSION_INFO` structure.

Definition
##########
.. code-block:: c

   typedef CK_SESSION_INFO *CK_SESSION_INFO_PTR;

Description
###########
``CK_SESSION_INFO_PTR`` is a pointer type to the ``CK_SESSION_INFO`` structure.

Object types
~~~~~~~~~~~~
CK_OBJECT_HANDLE
****************
.. c:type:: CK_OBJECT_HANDLE

   Handle to an object.

Definition
##########
.. code-block:: c

   typedef CK_ULONG CK_OBJECT_HANDLE;

Description
###########
``CK_OBJECT_HANDLE`` is a handle to an object in the Cryptoki library.

CK_OBJECT_HANDLE_PTR
********************
.. c:type:: CK_OBJECT_HANDLE_PTR

   Pointer to :c:type:`CK_OBJECT_HANDLE`.

Definition
##########
.. code-block:: c

   typedef CK_OBJECT_HANDLE *CK_OBJECT_HANDLE_PTR;

Description
###########
``CK_OBJECT_HANDLE_PTR`` is a pointer type to the ``CK_OBJECT_HANDLE`` type.

CK_OBJECT_CLASS
***************
.. c:type:: CK_OBJECT_CLASS

   Enumeration for object classes.

Definition
##########
.. code-block:: c

   typedef CK_ULONG CK_OBJECT_CLASS;

Description
###########
``CK_OBJECT_CLASS`` is an enumeration type for object classes in the Cryptoki
library. It is used to specify the class or type of an object stored on a token.
The following object classes are defined:

.. list-table:: Object Classes
   :header-rows: 1
   :name: p11_object_classes
   :class: wrap-table

   * - **Object Class**
     - **Bit Mask**
     - **Description**
   * - CKO_DATA
     - 0x00000000
     - Data object class
   * - CKO_CERTIFICATE
     - 0x00000001
     - Certificate object class.
   * - CKO_PUBLIC_KEY
     - 0x00000002
     - Public key object class.
   * - CKO_PRIVATE_KEY
     - 0x00000003
     - Private key object class.
   * - CKO_SECRET_KEY
     - 0x00000004
     - Secret key object class.
   * - CKO_HW_FEATURE
     - 0x00000005
     - Hardware feature object class.
   * - CKO_DOMAIN_PARAMETERS
     - 0x00000006
     - Domain parameters object class.
   * - CKO_MECHANISM
     - 0x00000007
     - Mechanism object class.
   * - CKO_OTP_KEY
     - 0x00000008
     - OTP key object class.
   * - CKO_PROFILE
     - 0x00000009
     - Profile object class describes which PKCS#11 profiles the token
       implements.
   * - CKO_VALIDATION
     - 0x0000000A
     - Validation object class describes which third party validations the
       module conforms to.
   * - CKO_TRUST
     - 0x0000000B
     - Trust object class binds trusted usages to individual certificates.
   * - CKO_VENDOR_DEFINED
     - 0x80000000
     - Vendor-defined object class.

CK_OBJECT_CLASS_PTR
*******************
.. c:type:: CK_OBJECT_CLASS_PTR

   Pointer to :c:type:`CK_OBJECT_CLASS`.

Definition
##########
.. code-block:: c

   typedef CK_OBJECT_CLASS *CK_OBJECT_CLASS_PTR;

Description
###########
``CK_OBJECT_CLASS_PTR`` is a pointer type to the ``CK_OBJECT_CLASS`` type.

CK_HW_FEATURE_TYPE
******************
.. c:type:: CK_HW_FEATURE_TYPE

   Enumeration for hardware feature types.

Definition
##########
.. code-block:: c

   typedef CK_ULONG CK_HW_FEATURE_TYPE;

Description
###########
``CK_HW_FEATURE_TYPE`` is an enumeration type for hardware feature types in the
Cryptoki library. It is used to specify the type of a hardware feature object
stored on a token. The following hardware feature types are defined:

.. list-table:: Hardware Feature Types
   :header-rows: 1
   :name: p11_hw_feature_types
   :class: wrap-table

   * - **Hardware Feature Type**
     - **Bit Mask**
     - **Description**
   * - CKH_MONOTONIC_COUNTER
     - 0x00000001
     - Monotonic counter hardware feature.
   * - CKH_CLOCK
     - 0x00000002
     - Clock hardware feature.
   * - CKH_USER_INTERFACE
     - 0x00000003
     - User interface hardware feature.
   * - CKH_VENDOR_DEFINED
     - 0x80000000
     - Vendor-defined hardware feature type.

CK_KEY_TYPE
***********
.. c:type:: CK_KEY_TYPE

   Identifies a key types.

Definition
##########
.. code-block:: c

   typedef CK_ULONG CK_KEY_TYPE;

Description
###########
``CK_KEY_TYPE`` is an enumeration type for key types in the Cryptoki library.
Key type constants are defined in the Cryptoki specification and can be
extended by vendors by setting the high bit (CKK_VENDOR_DEFINED = 0x80000000).

CK_CERTIFICATE_TYPE
*******************
.. c:type:: CK_CERTIFICATE_TYPE

   Identifies a certificate types.

Definition
##########
.. code-block:: c

   typedef CK_ULONG CK_CERTIFICATE_TYPE;

Description
###########
``CK_CERTIFICATE_TYPE`` is an enumeration type for certificate types in the
Cryptoki library. Certificate type constants are defined in the Cryptoki
specification and can be extended by vendors by setting the high bit
(CKC_VENDOR_DEFINED = 0x80000000).

CK_CERTIFICATE_CATEGORY
***********************
.. c:type:: CK_CERTIFICATE_CATEGORY

   Identifies a certificate category.

Definition
##########
.. code-block:: c

   typedef CK_ULONG CK_CERTIFICATE_CATEGORY;

Description
###########
``CK_CERTIFICATE_CATEGORY`` is an enumeration type for certificate categories
in the Cryptoki library. The following categories are defined:

.. list-table:: Certificate Categories
   :header-rows: 1
   :name: p11_certificate_categories
   :class: wrap-table

   * - **Certificate Category**
     - **Value**
     - **Description**
   * - CK_CERTIFICATE_CATEGORY_UNSPECIFIED
     - 0x00000000
     - Unspecified certificate category.
   * - CK_CERTIFICATE_CATEGORY_TOKEN_USER
     - 0x00000001
     - Token user certificate category.
   * - CK_CERTIFICATE_CATEGORY_AUTHORITY
     - 0x00000002
     - Certificate authority certificate category.
   * - CK_CERTIFICATE_CATEGORY_OTHER_ENTITY
     - 0x00000003
     - Other entity certificate category.

CK_ATTRIBUTE_TYPE
*****************
.. c:type:: CK_ATTRIBUTE_TYPE

   Identifies an attribute type.

Definition
##########
.. code-block:: c

   typedef CK_ULONG CK_ATTRIBUTE_TYPE;

Description
###########
Attributes are defined with the objects and mechanisms that use them. Attributes
are specified on an object as a list of type, length value items. These are
often specified as an attribute template. Vendors can extend attribute types by
setting the high bit (CKA_VENDOR_DEFINED = 0x80000000).

CK_ATTRIBUTE
************
.. c:type:: CK_ATTRIBUTE

   Structure for specifying an attribute.

Definition
##########
.. code-block:: c

   typedef struct CK_ATTRIBUTE {
       CK_ATTRIBUTE_TYPE type;
       CK_VOID_PTR pValue;
       CK_ULONG ulValueLen;
   } CK_ATTRIBUTE;

Members
#######
type
   Attribute type.

pValue
   Pointer to the attribute value.

ulValueLen
   Length of the attribute value in bytes.

Description
###########
``CK_ATTRIBUTE`` is a structure used to specify an attribute of an object in the
Cryptoki library. It contains the attribute type, a pointer to the attribute
value, and the length of the attribute value. Attributes are used to define
properties of objects such as keys, certificates, and other cryptographic
objects.

If an attribute has no value, then ``ulValueLen`` = 0, and the value of
``pValue`` is irrelevant. An array of ``CK_ATTRIBUTE`` is called a "template"
and is used for creating, manipulating and querying objects.

The constant ``CK_UNVALAIBLE_INFORMATION`` is used in the ``ulValueLen`` field
to indicate that the attribute value is not available or not applicable for the
object. See :c:func:`C_GetAttributeValue`.

CK_ATTRIBUTE_PTR
****************
.. c:type:: CK_ATTRIBUTE_PTR

   Pointer to :c:type:`CK_ATTRIBUTE`.

Definition
##########
.. code-block:: c

   typedef CK_ATTRIBUTE *CK_ATTRIBUTE_PTR;

Description
###########
``CK_ATTRIBUTE_PTR`` is a pointer type to the ``CK_ATTRIBUTE`` structure.

CK_DATE
*******
.. c:type:: CK_DATE

   Structure for specifying a date.

Definition
##########
.. code-block:: c

   typedef struct CK_DATE {
       CK_CHAR year[4];
       CK_CHAR month[2];
       CK_CHAR day[2];
   } CK_DATE;

Members
#######
year
   Year in YYYY format.

month
   Month in MM format (01-12).

day
   Day in DD format (01-31).

Description
###########
``CK_DATE`` is a structure used to represent a date in the Cryptoki library.
The date is represented as three separate fields for year, month, and day,
each stored as character arrays in ASCII format. This structure is commonly
used in certificate validity periods and other time-based attributes.

CK_PROFILE_ID
*************
.. c:type:: CK_PROFILE_ID

   Identifies a profile type.

Definition
##########
.. code-block:: c

   typedef CK_ULONG CK_PROFILE_ID;

Description
###########
``CK_PROFILE_ID`` is an enumeration type for profile identifiers in
Cryptoki library. Profile IDs are used to identify specific profiles or
configurations supported by a cryptographic device or token. Vendors can extend
profile IDs by setting the high bit (CKP_VENDOR_DEFINED = 0x80000000).

CK_PROFILE_ID_PTR
*****************
.. c:type:: CK_PROFILE_ID_PTR

   Pointer to :c:type:`CK_PROFILE_ID`.

Definition
##########
.. code-block:: c

   typedef CK_PROFILE_ID *CK_PROFILE_ID_PTR;

Description
###########
``CK_PROFILE_ID_PTR`` is a pointer type to the ``CK_PROFILE_ID`` structure.

Data types for mechanisms
~~~~~~~~~~~~~~~~~~~~~~~~~
CK_MECHANISM_TYPE
*****************
.. c:type:: CK_MECHANISM_TYPE

   Identifies a mechanism type.

Definition
##########
.. code-block:: c

   typedef CK_ULONG CK_MECHANISM_TYPE;

Description
###########
```CK_MECHANISM_TYPE`` is an enumeration type for the mechanism identifier in
the Cryptoki library. Mechanism types are used to identify the mechanism(s)
supported by an object. Vendors can extend mechanism types by setting the
high bit (CKM_VENDOR_DEFINED = 0x80000000).

CK_MECHANISM_TYPE_PTR
*********************
.. c:type:: CK_MECHANISM_TYPE_PTR

   Pointer to :c:type:`CK_MECHANISM_TYPE`.

Definition
##########
.. code-block:: c

   typedef CK_MECHANISM_TYPE *CK_MECHANISM_TYPE_PTR;

Description
###########
``CK_MECHANISM_TYPE_PTR`` is a pointer type to the ``CK_MECHANISM_TYPE``
structure.

CK_MECHANISM
************
.. c:type:: CK_MECHANISM

   Structure for specifying a mechanism parameters.

Definition
##########
.. code-block:: c

   typedef struct CK_MECHANISM {
       CK_MECHANISM_TYPE mechanism;
       CK_VOID_PTR pParameter;
       CK_ULONG ulParameterLen;
   } CK_MECHANISM;

Members
#######
mechanism
   Mechanism type.

pParameter
   Pointer to the mechanism parameters.

ulParameterLen
   Length of the mechanism parameters in bytes.

Description
###########
``CK_MECHANISM`` is a structure used to specify a mechanism and its parameters
in the Cryptoki library. It contains the mechanism type, a pointer to the
mechanism parameters, and the length of the parameters. Mechanisms are used to
specify cryptographic operations such as encryption, decryption, signing, and
verification.

If a mechanism has no parameters, then ``ulParameterLen`` is set to 0.

CK_MECHANISM_PTR
****************
.. c:type:: CK_MECHANISM_PTR

   Pointer to :c:type:`CK_MECHANISM`.

Definition
##########
.. code-block:: c

   typedef CK_MECHANISM *CK_MECHANISM_PTR;

Description
###########
``CK_MECHANISM_PTR`` is a pointer type to the ``CK_MECHANISM`` structure.

CK_MECHANIM_INFO
****************
.. c:type:: CK_MECHANIM_INFO

   Structure for specifying mechanism information.

Definition
##########
.. code-block:: c

   typedef struct CK_MECHANISM_INFO {
       CK_ULONG ulMinKeySize;
       CK_ULONG ulMaxKeySize;
       CK_FLAGS flags;
   } CK_MECHANISM_INFO;

Members
#######
ulMinKeySize
   Minimum key size in bits.

ulMaxKeySize
   Maximum key size in bits.

flags
   Mechanism capability flags.

Description
###########
``CK_MECHANISM_INFO`` is a structure used to specify information about a
mechanism supported by a cryptographic device or token in the Cryptoki library.
It contains the minimum and maximum key sizes supported by the mechanism, as
well as flags indicating the mechanism's capabilities such as encryption,
decryption, signing, and verification.

.. list-table:: Mechanism information flags
   :header-rows: 1
   :name: p11_mechanism_information_flags
   :class: wrap-table

   * - **Flag**
     - **Bit Mask**
     - **Description**
   * - CKF_HW
     - 0x00000001
     - Mechanism is hardware-based.
   * - CKF_MESSAGE_ENCRYPT
     - 0x00000002
     - Mechanism can be used for message encryption.
   * - CKF_MESSAGE_DECRYPT
     - 0x00000004
     - Mechanism can be used for message decryption.
   * - CKF_MESSAGE_SIGN
     - 0x00000008
     - Mechanism can be used for signing.
   * - CKF_MESSAGE_VERIFY
     - 0x00000010
     - Mechanism can be used for verification.
   * - CKF_MULTI_MESSAGE
     - 0x00000020
     - Mechanism can be used in multipart operations.
   * - CKF_FIND_OBJECTS
     - 0x00000040
     - This flag can be passed in as a parameter to :c:func:`C_SessionCancel`
       to cancel an active object search operation. Any other use of this flag
       is outside the scope of this standard.
   * - CKF_ENCRYPT
     - 0x00000100
     - Mechanism can be used for encryption.
   * - CKF_DECRYPT
     - 0x00000200
     - Mechanism can be used for decryption.
   * - CKF_DIGEST
     - 0x00000400
     - Mechanism can be used for digesting.
   * - CKF_SIGN
     - 0x00000800
     - Mechanism can be used for signing.
   * - CKF_SIGN_RECOVER
     - 0x00001000
     - Mechanism can be used for signing with message recovery.
   * - CKF_VERIFY
     - 0x00002000
     - Mechanism can be used for verification.
   * - CKF_VERIFY_RECOVER
     - 0x00004000
     - Mechanism can be used for verification with message recovery.
   * - CKF_GENERATE
     - 0x00008000
     - Mechanism can be used for key generation.
   * - CKF_GENERATE_KEY_PAIR
     - 0x00010000
     - Mechanism can be used for key pair generation.
   * - CKF_WRAP
     - 0x00020000
     - Mechanism can be used for key wrapping.
   * - CKF_UNWRAP
     - 0x00040000
     - Mechanism can be used for key unwrapping.
   * - CKF_DERIVE
     - 0x00080000
     - Mechanism can be used for key derivation.
   * - CKF_ENCAPSULATE
     - 0x10000000
     - Mechanism can be used for key encapsulation.
   * - CKF_DECAPSULATE
     - 0x20000000
     - Mechanism can be used for key decapsulation.
   * - CKF_EXTENSION
     - 0x80000000
     - There is an extension to the flags. No used in this version, must not be
       set.

CK_MECHANISM_INFO_PTR
*********************
.. c:type:: CK_MECHANISM_INFO_PTR

   Pointer to :c:type:`CK_MECHANISM_INFO`.

Definition
##########
.. code-block:: c

   typedef CK_MECHANISM_INFO *CK_MECHANISM_INFO_PTR;

Description
###########
``CK_MECHANISM_INFO_PTR`` is a pointer type to the ``CK_MECHANISM_INFO``
structure.

Function types
~~~~~~~~~~~~~~
CK_RV
*****
.. c:type:: CK_RV

   Return value type for Cryptoki functions.

Definition
##########
.. code-block:: c

   typedef CK_ULONG CK_RV;

Description
###########
``CK_RV`` is the return value type for Cryptoki functions. It is used to
indicate the success or failure of a Cryptoki function call. A return value of
``CKR_OK`` indicates successful completion. Other return values indicate
various error conditions.

CK_ASYNC_DATA
*************
.. c:type:: CK_ASYNC_DATA

   Structure for asynchronous operation data.

Definition
##########
.. code-block:: c

   typedef struct CK_ASYNC_DATA {
       CK_ULONG ulVersion;
       CK_BYTE_PTR pValue;
       CK_ULONG ulValue;
       CK_OBJECT_HANDLE hObject;
       CK_OBJECT_HANDLE hAdditionalObject:
   } CK_ASYNC_DATA;

Members
#######
ulVersion
   Version of the asynchronous data structure.

pValue
   On completion contains a pointer to the original input buffer, caller is
   responsible for this memory.

ulValue
   Size of the result.

hObject
   Handle to the object being operated on.

hAdditionalObject
   Handle to an additional object being operated on.

Description
###########
``CK_ASYNC_DATA`` is a structure used to hold asynchronous operation data in
the Cryptoki library. It contains version information, a pointer to the result
buffer, the size of the result, and handles to the objects being operated on.
This structure is used when performing asynchronous cryptographic operations,
allowing the caller to track the status and retrieve results of non-blocking
function calls.

CK_ASYNC_DATA_PTR
*****************
.. c:type:: CK_ASYNC_DATA_PTR

   Pointer to :c:type:`CK_ASYNC_DATA`.

Definition
##########
.. code-block:: c

   typedef CK_ASYNC_DATA *CK_ASYNC_DATA_PTR;

Description
###########
``CK_ASYNC_DATA_PTR`` is a pointer type to the ``CK_ASYNC_DATA``.

Library function list
~~~~~~~~~~~~~~~~~~~~~
CK_FUNCTION_LIST
****************
.. c:type:: CK_FUNCTION_LIST

   Structure containing function pointers to all Cryptoki API functions for
   PKCS#11 version 2.40. In this structure, version is the cryptoki
   specification version number. It the default function list returned by
   :c:func:`C_GetFunctionList`.

   This function list may be returned via :c:func:`C_GetInterfaceList` or
   :c:func:`C_GetInterface`.

Definition
##########
.. code-block:: c

   typedef struct CK_FUNCTION_LIST {
       CK_VERSION version;
       CK_C_Initialize C_Initialize;
       CK_C_Finalize C_Finalize;
       CK_C_GetInfo C_GetInfo;
       CK_C_GetFunctionList C_GetFunctionList;
       CK_C_GetSlotList C_GetSlotList;
       CK_C_GetSlotInfo C_GetSlotInfo;
       CK_C_GetTokenInfo C_GetTokenInfo;
       CK_C_GetMechanismList C_GetMechanismList;
       CK_C_GetMechanismInfo C_GetMechanismInfo;
       CK_C_InitToken C_InitToken;
       CK_C_InitPIN C_InitPIN;
       CK_C_SetPIN C_SetPIN;
       CK_C_OpenSession C_OpenSession;
       CK_C_CloseSession C_CloseSession;
       CK_C_CloseAllSessions C_CloseAllSessions;
       CK_C_GetSessionInfo C_GetSessionInfo;
       CK_C_GetOperationState C_GetOperationState;
       CK_C_SetOperationState C_SetOperationState;
       CK_C_Login C_Login;
       CK_C_Logout C_Logout;
       CK_C_CreateObject C_CreateObject;
       CK_C_CopyObject C_CopyObject;
       CK_C_DestroyObject C_DestroyObject;
       CK_C_GetObjectSize C_GetObjectSize;
       CK_C_GetAttributeValue C_GetAttributeValue;
       CK_C_SetAttributeValue C_SetAttributeValue;
       CK_C_FindObjectsInit C_FindObjectsInit;
       CK_C_FindObjects C_FindObjects;
       CK_C_FindObjectsFinal C_FindObjectsFinal;
       CK_C_EncryptInit C_EncryptInit;
       CK_C_Encrypt C_Encrypt;
       CK_C_EncryptUpdate C_EncryptUpdate;
       CK_C_EncryptFinal C_EncryptFinal;
       CK_C_DecryptInit C_DecryptInit;
       CK_C_Decrypt C_Decrypt;
       CK_C_DecryptUpdate C_DecryptUpdate;
       CK_C_DecryptFinal C_DecryptFinal;
       CK_C_DigestInit C_DigestInit;
       CK_C_Digest C_Digest;
       CK_C_DigestUpdate C_DigestUpdate;
       CK_C_DigestKey C_DigestKey;
       CK_C_DigestFinal C_DigestFinal;
       CK_C_SignInit C_SignInit;
       CK_C_Sign C_Sign;
       CK_C_SignUpdate C_SignUpdate;
       CK_C_SignFinal C_SignFinal;
       CK_C_SignRecoverInit C_SignRecoverInit;
       CK_C_SignRecover C_SignRecover;
       CK_C_VerifyInit C_VerifyInit;
       CK_C_Verify C_Verify;
       CK_C_VerifyUpdate C_VerifyUpdate;
       CK_C_VerifyFinal C_VerifyFinal;
       CK_C_VerifyRecoverInit C_VerifyRecoverInit;
       CK_C_VerifyRecover C_VerifyRecover;
       CK_C_DigestEncryptUpdate C_DigestEncryptUpdate;
       CK_C_DecryptDigestUpdate C_DecryptDigestUpdate;
       CK_C_SignEncryptUpdate C_SignEncryptUpdate;
       CK_C_DecryptVerifyUpdate C_DecryptVerifyUpdate;
       CK_C_GenerateKey C_GenerateKey;
       CK_C_GenerateKeyPair C_GenerateKeyPair;
       CK_C_WrapKey C_WrapKey;
       CK_C_UnwrapKey C_UnwrapKey;
       CK_C_DeriveKey C_DeriveKey;
       CK_C_SeedRandom C_SeedRandom;
       CK_C_GenerateRandom C_GenerateRandom;
       CK_C_GetFunctionStatus C_GetFunctionStatus;
       CK_C_CancelFunction C_CancelFunction;
       CK_C_WaitForSlotEvent C_WaitForSlotEvent;
   } CK_FUNCTION_LIST;

CK_FUNCTION_LIST_PTR
********************
.. c:type:: CK_FUNCTION_LIST_PTR

   Pointer to a :c:type:`CK_FUNCTION_LIST` structure.

Definition
##########
.. code-block:: c

   typedef CK_FUNCTION_LIST *CK_FUNCTION_LIST_PTR;

Description
###########
``CK_FUNCTION_LIST_PTR`` is a pointer to a :c:type:`CK_FUNCTION_LIST`
structure, which contains function pointers to all the Cryptoki API functions.
An application can obtain this pointer by calling :c:func:`C_GetFunctionList`.

CK_FUNCTION_LIST_PTR_PTR
************************
.. c:type:: CK_FUNCTION_LIST_PTR_PTR

   Pointer to a pointer to a :c:type:`CK_FUNCTION_LIST` structure.

Definition
##########
.. code-block:: c

   typedef CK_FUNCTION_LIST_PTR *CK_FUNCTION_LIST_PTR_PTR;

Description
###########
``CK_FUNCTION_LIST_PTR_PTR`` is a pointer to a pointer to a
:c:type:`CK_FUNCTION_LIST` structure. It is used to pass references to
:c:type:`CK_FUNCTION_LIST` pointers to Cryptoki functions, particularly in
the :c:func:`C_GetFunctionList` function which returns the function list
through a pointer parameter.

CK_FUNCTION_LIST_3_2
********************
.. c:type:: CK_FUNCTION_LIST_3_2

   Structure containing function pointers to all Cryptoki API functions for
   PKCS#11 version 3.2. In this structure, version is the cryptoki
   specification version number. It should match the value of cryptokiVersion
   returned in the :c:type:`CK_INFO` structure, but must be 3.2 at minimum.

   This function list may be returned via :c:func:`C_GetInterfaceList` or
   :c:func:`C_GetInterface`.


Definition
##########
.. code-block:: c

   typedef struct CK_FUNCTION_LIST_3_2 {
       CK_VERSION version;
       CK_C_Initialize C_Initialize;
       CK_C_Finalize C_Finalize;
       CK_C_GetInfo C_GetInfo;
       CK_C_GetFunctionList C_GetFunctionList;
       CK_C_GetSlotList C_GetSlotList;
       CK_C_GetSlotInfo C_GetSlotInfo;
       CK_C_GetTokenInfo C_GetTokenInfo;
       CK_C_GetMechanismList C_GetMechanismList;
       CK_C_GetMechanismInfo C_GetMechanismInfo;
       CK_C_InitToken C_InitToken;
       CK_C_InitPIN C_InitPIN;
       CK_C_SetPIN C_SetPIN;
       CK_C_OpenSession C_OpenSession;
       CK_C_CloseSession C_CloseSession;
       CK_C_CloseAllSessions C_CloseAllSessions;
       CK_C_GetSessionInfo C_GetSessionInfo;
       CK_C_GetOperationState C_GetOperationState;
       CK_C_SetOperationState C_SetOperationState;
       CK_C_Login C_Login;
       CK_C_Logout C_Logout;
       CK_C_CreateObject C_CreateObject;
       CK_C_CopyObject C_CopyObject;
       CK_C_DestroyObject C_DestroyObject;
       CK_C_GetObjectSize C_GetObjectSize;
       CK_C_GetAttributeValue C_GetAttributeValue;
       CK_C_SetAttributeValue C_SetAttributeValue;
       CK_C_FindObjectsInit C_FindObjectsInit;
       CK_C_FindObjects C_FindObjects;
       CK_C_FindObjectsFinal C_FindObjectsFinal;
       CK_C_EncryptInit C_EncryptInit;
       CK_C_Encrypt C_Encrypt;
       CK_C_EncryptUpdate C_EncryptUpdate;
       CK_C_EncryptFinal C_EncryptFinal;
       CK_C_DecryptInit C_DecryptInit;
       CK_C_Decrypt C_Decrypt;
       CK_C_DecryptUpdate C_DecryptUpdate;
       CK_C_DecryptFinal C_DecryptFinal;
       CK_C_DigestInit C_DigestInit;
       CK_C_Digest C_Digest;
       CK_C_DigestUpdate C_DigestUpdate;
       CK_C_DigestKey C_DigestKey;
       CK_C_DigestFinal C_DigestFinal;
       CK_C_SignInit C_SignInit;
       CK_C_Sign C_Sign;
       CK_C_SignUpdate C_SignUpdate;
       CK_C_SignFinal C_SignFinal;
       CK_C_SignRecoverInit C_SignRecoverInit;
       CK_C_SignRecover C_SignRecover;
       CK_C_VerifyInit C_VerifyInit;
       CK_C_Verify C_Verify;
       CK_C_VerifyUpdate C_VerifyUpdate;
       CK_C_VerifyFinal C_VerifyFinal;
       CK_C_VerifyRecoverInit C_VerifyRecoverInit;
       CK_C_VerifyRecover C_VerifyRecover;
       CK_C_DigestEncryptUpdate C_DigestEncryptUpdate;
       CK_C_DecryptDigestUpdate C_DecryptDigestUpdate;
       CK_C_SignEncryptUpdate C_SignEncryptUpdate;
       CK_C_DecryptVerifyUpdate C_DecryptVerifyUpdate;
       CK_C_GenerateKey C_GenerateKey;
       CK_C_GenerateKeyPair C_GenerateKeyPair;
       CK_C_WrapKey C_WrapKey;
       CK_C_UnwrapKey C_UnwrapKey;
       CK_C_DeriveKey C_DeriveKey;
       CK_C_SeedRandom C_SeedRandom;
       CK_C_GenerateRandom C_GenerateRandom;
       CK_C_GetFunctionStatus C_GetFunctionStatus;
       CK_C_CancelFunction C_CancelFunction;
       CK_C_WaitForSlotEvent C_WaitForSlotEvent;
       CK_C_GetInterfaceList C_GetInterfaceList;
       CK_C_GetInterface C_GetInterface;
       CK_C_LoginUser C_LoginUser;
       CK_C_SessionCancel C_SessionCancel;
       CK_C_MessageEncryptInit C_MessageEncryptInit;
       CK_C_EncryptMessage C_EncryptMessage;
       CK_C_EncryptMessageBegin C_EncryptMessageBegin;
       CK_C_EncryptMessageNext C_EncryptMessageNext;
       CK_C_MessageEncryptFinal C_MessageEncryptFinal;
       CK_C_MessageDecryptInit C_MessageDecryptInit;
       CK_C_DecryptMessage C_DecryptMessage;
       CK_C_DecryptMessageBegin C_DecryptMessageBegin;
       CK_C_DecryptMessageNext C_DecryptMessageNext;
       CK_C_MessageDecryptFinal C_MessageDecryptFinal;
       CK_C_MessageSignInit C_MessageSignInit;
       CK_C_SignMessage C_SignMessage;
       CK_C_SignMessageBegin C_SignMessageBegin;
       CK_C_SignMessageNext C_SignMessageNext;
       CK_C_MessageSignFinal C_MessageSignFinal;
       CK_C_MessageVerifyInit C_MessageVerifyInit;
       CK_C_VerifyMessage C_VerifyMessage;
       CK_C_VerifyMessageBegin C_VerifyMessageBegin;
       CK_C_VerifyMessageNext C_VerifyMessageNext;
       CK_C_MessageVerifyFinal C_MessageVerifyFinal;
       CK_C_EncapsulateKey C_EncapsulateKey;
       CK_C_DecapsulateKey C_DecapsulateKey;
       CK_C_VerifySignatureInit C_VerifySignatureInit;
       CK_C_VerifySignature C_VerifySignature;
       CK_C_VerifySignatureUpdate C_VerifySignatureUpdate;
       CK_C_VerifySignatureFinal C_VerifySignatureFinal;
       CK_C_GetSessionValidationFlags C_GetSessionValidationFlags;
       CK_C_AsyncComplete C_AsyncComplete;
       CK_C_AsyncGetID C_AsyncGetID;
       CK_C_AsyncJoin C_AsyncJoin;
       CK_C_WrapKeyAuthenticated C_WrapKeyAuthenticated;
       CK_C_UnwrapKeyAuthenticated C_UnwrapKeyAuthenticated;
     } CK_FUNCTION_LIST_3_2;

CK_FUNCTION_LIST_3_2_PTR
************************
.. c:type:: CK_FUNCTION_LIST_3_2_PTR

   Pointer to a :c:type:`CK_FUNCTION_LIST_3_2` structure.

Definition
##########
.. code-block:: c

   typedef CK_FUNCTION_LIST_3_0 *CK_FUNCTION_LIST_3_2_PTR;

Description
###########
Pointer type for accessing a :c:type:`CK_FUNCTION_LIST_3_2` structure.
This pointer type is used throughout the PKCS #11 API to reference
the function list containing all available cryptographic operations
and token management functions provided by a PKCS #11 implementation.

CK_FUNCTION_LIST_3_2_PTR_PTR
****************************
.. c:type:: CK_FUNCTION_LIST_3_2_PTR_PTR

   Pointer to a pointer to a :c:type:`CK_FUNCTION_LIST_3_2` structure.

Definition
##########
.. code-block:: c

   typedef CK_FUNCTION_LIST_3_0 **CK_FUNCTION_LIST_3_2_PTR_PTR;

Description
###########
Pointer to a pointer to a :c:type:`CK_FUNCTION_LIST_3_2` structure.
This double pointer type is used to pass references to function list pointers
through the PKCS #11 API, enabling dynamic allocation and manipulation of
function list structures at the application level.

Library interface
~~~~~~~~~~~~~~~~~
CK_INTERFACE
************
.. c:type:: CK_INTERFACE

   Describes a Cryptoki interface.

Definition
##########
.. code-block:: c

   typedef struct CK_INTERFACE {
       CK_CHAR *pInterfaceName;
       CK_VOID_PTR pFunctionList;
       CK_FLAGS flags;
   } CK_INTERFACE;

Members
#######
pInterfaceName
   Pointer to a null-terminated string identifying the interface name.
   For the default PKCS#11 interface, this is "PKCS 11".

pFunctionList
   Pointer to the function list for this interface. For the default interface,
   this points to a ``CK_FUNCTION_LIST`` structure.

flags
   Flags describing capabilities or properties of the interface. Must be zero
   for this version. See :ref:`p11_ck_interface_flags` table for details.

Description
###########
``CK_INTERFACE`` describes a Cryptoki interface. The structure is used by
:c:func:`C_GetInterface` to return information about available interfaces.
The default PKCS#11 interface has the name "PKCS 11" and provides a
``CK_FUNCTION_LIST`` structure containing function pointers to all standard
Cryptoki functions.

The ``pInterfaceName`` field points to a null-terminated string, while the
``pFunctionList`` field points to the appropriate function list structure for
the interface. Applications can use :c:func:`C_GetInterfaceList` to discover
available interfaces and :c:func:`C_GetInterface` to obtain a specific
interface.

.. list-table:: CK_INTERFACE Flags Descriptions
   :header-rows: 1
   :name: p11_ck_interface_flags
   :width: 100%
   :class: wrap-table

   * - **Bit Flag**
     - **Value**
     - **Description**
   * - CK_INTERFACE_FORK_SAFE
     - 0x00000001
     - The returned interface will have fork tolerant semantics. When the
       application forks, each process will get its own copy of all session
       objects, session states, login states, and encryption states. Each
       process will also maintain access to token objects with their previously
       supplied handles.


CK_INTERFACE_PTR
****************
.. c:type:: CK_INTERFACE_PTR

   Pointer to a :c:type:`CK_INTERFACE` structure.

Definition
##########
.. code-block:: c

   typedef CK_INTERFACE *CK_INTERFACE_PTR;

Description
###########
Pointer type for accessing a :c:type:`CK_INTERFACE` structure.

CK_INTERFACE_PTR_PTR
********************
.. c:type:: CK_INTERFACE_PTR_PTR

   Pointer to a pointer to a :c:type:`CK_INTERFACE` structure.

Definition
##########
.. code-block:: c

   typedef CK_INTERFACE **CK_INTERFACE_PTR_PTR;

Description
###########
Pointer to a pointer to a :c:type:`CK_INTERFACE` structure.

Session validation flags
~~~~~~~~~~~~~~~~~~~~~~~~
CK_SESSION_VALIDATION_FLAGS_TYPE
********************************
.. c:type:: CK_SESSION_VALIDATION_FLAGS_TYPE

   Flags for session validation operations.

Definition
##########
.. code-block:: c

   typedef CK_ULONG CK_SESSION_VALIDATION_FLAGS_TYPE;

Description
###########
``CK_SESSION_VALIDATION_FLAGS_TYPE`` is a type alias for ``CK_ULONG`` used to
represent flags that control session validation behavior in PKCS#11 operations.

These flags are used with functions like :c:func:`C_GetSessionValidationFlags`
to query and manage session validation properties.

.. list-table:: Session validation flags
   :header-rows: 1
   :name: p11_ck_session_validation_flags
   :width: 100%
   :class: wrap-table

   * - **Bit Flag**
     - **Value**
     - **Description**
   * - CKS_LAST_VALIDATION_OK
     - 0x00000001
     - Last operation that completed met all the requirements of a validated
       mechanism. This allows access to the state of operations that don't
       return a key object.
