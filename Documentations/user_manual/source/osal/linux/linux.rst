.. _os-osal-implementation:

OS-specific implementation
--------------------------

The OSAL module must be implemented for the target Operating System.
The SMW library project delivery includes a reference implementation for Linux.

The OS-specific OSAL implementation is responsible for:

 - Load and unload library in the OS environment.
 - File system operations for object database management.
 - Thread and synchronization primitives.
 - Logging.

.. note::
   This implementation can be customized by the integrator.


Library initialization methods
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In Linux, the SMW library initialization is performed by calling the
:c:func:`smw_osal_lib_init` function.

Two methods are proposed to configure the SMW library:
 - Using the linux system configuration file approach (recommended).
 - Using the programmatic approach (runtime configuration).


Linux system configuration file approach
"""""""""""""""""""""""""""""""""""""""""

The system configuration file path is `/etc/opt/smw/smw.conf`.

The file is divided into sections as shown in the template below:

.. literalinclude:: smw.conf
   :caption: SMW configuration file template
   :language: ini


The `smw_system_conf.sh` could be used to change the content of the `smw.conf`
file. It's installed on in the `/etc/opt/smw/` system folder.

.. code-block:: bash

  $ /etc/opt/smw/smw_system_conf.sh --help


To help fast integration of the SMW library, a default configuration file is
provided and installed in the `/etc/opt/smw/` system folder. This file contains
reference to the default subsystem(s) configurations, a default database file.
This file contains the configuration of the subsystem(s) included during the
build of the SMW library. It can be modified to match specific integration
requirements.

The default configuration is:

 - database file: `/usr/share/smw/smw_objects_database.dat`
 - subsystem configuration files used are in the `/usr/share/smw/config/` and
   depends on the subsystems included during the build.
 - If TEE subsystem enabled, the TA UUID is the one provided as reference
   "11b5c4aa-6d20-11ea-bc55-0242ac130003".
 - If ELE subsystem enabled, the NVM Secure Storage; identifier is 0x454C4500,
   nonce is 0x534D57 and the storage is created to be shared between
   applications (i.e., shared is yes).
 - If SECO subsystem enabled, the NVM Secure Storage; identifier is 0x454C4500,
   nonce is 0x534D57 and the replay attack counter is 3000.

.. note::
   ELE and SECO subsystems are platforms specific and can not be available
   together at the same time.
   TEE is present on all platforms.


Programmatic approach
"""""""""""""""""""""

The programmatic approach allows direct configuration of the SMW library
through OSAL APIs without relying on the configuration file. This method
provides runtime flexibility and allows applications to configure the SMW
library dynamically based on their specific requirements.

The configuration must be completed before calling the SMW library
initialization function :c:func:`smw_osal_lib_init`.

The following steps outline the programmatic configuration process:

  1. Set the `SMW_CONFIG_FILE` linux environment variable to the desired file
     path describing the subsystem(s)/operations mapping.
  2. Call :c:func:`smw_osal_set_subsystem_info` to setup the subsystem(s)
     with the desired parameters (e.g., TEE or Secure Element information).
  3. Call :c:func:`smw_osal_open_obj_db` to open and configure the object
     database file path.
  4. Call :c:func:`smw_osal_lib_init` to initialize the SMW library.
  5. The SMW library is now configured and ready to use.

You can refer the following code Example_.

OSAL APIs
^^^^^^^^^

Initialization
""""""""""""""
.. kdoc-extension:: /public/smw_osal.h
  :functions: smw_osal_lib_init

Configuration
"""""""""""""
.. kdoc-extension:: /public/smw_osal.h
  :functions: smw_osal_set_subsystem_info smw_osal_open_obj_db

.. kdoc-extension:: /public/smw_osal.h
  :structs: tee_info se_info
  :macros: TEE_TA_UUID_SIZE_MAX


Debug purpose
"""""""""""""
.. kdoc-extension:: /public/smw_osal.h
  :functions: smw_osal_latest_subsystem_name

Check capability flags
""""""""""""""""""""""

.. kdoc-extension:: /public/smw_osal.h
  :functions: smw_osal_obj_db_has_capability


Linux object database implementation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The SMW Linux OSAL reference distributed with the SMW Library manages
the object database by using the SQLite3 library. Thus, the database is
actually an SQLite3 table where each known object occupies a row. An
object could be a key or data object that is associated with a subsystem.

Since the database was introduced in SMW Library version 5.0, the database
has been versioned, and version 1 was introduced. The metadata corresponding
to each object are as follows:

- the identifier of the object in the database
- the identifier of the object as assigned by the subsystem
- the identifier as defined by the user
- the subsystem associated with the object
- object type (e.g. key or data)
- object size
- object attributes
- key type (if object is a key)
- storage identifier (if assigned by the subsystem)
- key group (if assigned by the subsystem)
- label (if assigned by the PKCS#11 API)
- key permitted algorithm (if object is a key)
- key usage (if object is a key)

SMW Library version 5.5 has modified the schema so the database version
has been increased to 2. In this version, a new column was added:

- key public data (only if object is a public key)

This column has the purpose of storing public keys for subsystems that
cannot import them, but could use them for cryptographic operations if
they are provided as plain bytes. 

.. note::
   The reference code automatically updates the database when it detects
   that the existing database version is behind the version supported by
   the SMW Library. The SMW Library distribution also includes a script
   that can be used to perform database upgrades manually. The SMW User
   Guide, section 4.3, contains examples of how the script can be used.


Example
^^^^^^^

.. caution::
   This method overwrites the configuration set in file `smw.conf`.

.. code-block:: c

   /*
    * Example of database, here database is lost at reboot because
    * it's in /var/tmp
    */
   #define DEFAULT_OBJ_DB "/var/tmp/obj_db_smw_test.dat"

   /*
    * TEE TA UUID, it's a unique identifier for the TA, here it's the
    * default TA UUID provided as a reference example.
    */
   static const struct tee_info tee_default_info = {
       { "11b5c4aa-6d20-11ea-bc55-0242ac130003" }
   };

   /*
    * Configure the Secure Element Subsystem storage parameters for ELE
    * Subsystem.
    * The storage_shared flag indicates if the storage is shared between
    * multiple applications.
    */
   static const struct se_info se_default_info = { .storage_id = 0x534d5754,
                                                   .storage_nonce =  0x444546,
                                                   .storage_shared = true };

   int main(int argc, char *argv[])
   {
       int res = ERR_CODE(FAILED);

       // Configure the TEE Subsystem: TA UUID (and so key storage)
       res = smw_osal_set_subsystem_info(SMW_SUBSYSTEM_NAME_TEE, &tee_default_info,
                                         sizeof(tee_default_info));
       if (res != SMW_STATUS_OK)
           goto exit;

       // Configure the ELE Subsystem: Key storage identifier and shared flag
       res = smw_osal_set_subsystem_info(SMW_SUBSYSTEM_NAME_ELE, &se_default_info,
                                          sizeof(se_default_info));
       if (res != SMW_STATUS_OK)
           goto exit;

       // Open/Create the application object database
       res = smw_osal_open_obj_db(DEFAULT_OBJ_DB, strlen(DEFAULT_OBJ_DB) + 1);
       if (res != SMW_STATUS_OK)
           goto exit;

       // Load and initialize the library. OSAL is loading the application
       // SMW configuration file defined by the system environment variable
       // 'SMW_CONFIG_FILE'
       res = smw_osal_lib_init();
       if (res != SMW_STATUS_OK)
           goto exit;

       // Execute the application
       ...

       exit:

       return res;
   }

