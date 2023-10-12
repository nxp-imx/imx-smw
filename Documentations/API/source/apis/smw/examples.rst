Examples
========

Authentication Encryption/Decryption (AEAD)
-------------------------------------------

Example 1: AEAD one-shot encryption operation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. code-block:: c

    #define IV_LEN 12
    #define AAD_LEN 20
    #define DATA_LEN 32
    #define CIPHER_LEN 32
    #define TAG_LEN 16

    int main(int argc, char *argv[])
    {
        int res = SMW_STATUS_OPERATION_FAILURE;
        unsigned char iv[IV_LEN] = {...};
        unsigned char aad[AAD_LEN] = {...};
        unsigned char input[DATA_LEN] = {...};
        unsigned char output[CIPHER_LEN + TAG_LEN] = {0};

        struct smw_aead_args args = {0};
        struct smw_aead_data_args data_args = {0};
        struct smw_aead_init_args init_args = {0};
        struct smw_key_descriptor key_desc = {0};

        init_args.subsystem_name = "TEE";
        init_args.operation_name = "ENCRYPT";
        init_args.mode_name = "GCM";
        init_args.aad_length = AAD_LEN;
        init_args.tag_length = TAG_LEN;
        init_args.plaintext_length = DATA_LEN;
        init_args.key_desc = &key_desc;

        data_args.input_length = DATA_LEN;
        data_args.input = input;
        data_args.output_length = CIPHER_LEN + TAG_LEN;
        data_args.output = output;

        // One-shot AE encryption operation
        args.init = init_args;
        args.data = data_args;
        args.aad = aad;
        res = smw_aead(&args);
        return res;
    }

Example 2: AEAD multi-part encryption operation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: c

    #define IV_LEN 12
    #define AAD_LEN 20
    #define DATA_LEN 32
    #define TAG_LEN 16
    #define CIPHER_LEN 32

    int main(int argc, char *argv[])
    {

        int res = SMW_STATUS_OPERATION_FAILURE;

        unsigned char iv[IV_LEN] = {...};
        unsigned char aad[AAD_LEN] = {...};
        unsigned char input[DATA_LEN] = {...};
        unsigned char output[CIPHER_LEN + TAG_LEN] = {0};

        struct smw_aead_args args = {0};
        struct smw_aead_data_args data_args = {0};
        struct smw_aead_aad_args aad_args = {0};
        struct smw_aead_final_args final_args = {0};
        struct smw_aead_init_args init_args = {0};
        struct smw_key_descriptor key_desc = {0};
        struct smw_op_context *op_ctx = 0;

        init_args.subsystem_name = "TEE";
        init_args.operation_name = "ENCRYPT";
        init_args.mode_name = "GCM";
        init_args.aad_length = AAD_LEN;
        init_args.tag_length = TAG_LEN;
        init_args.plaintext_length = DATA_LEN;

        // Allocate memory to pointer to operation context
        op_ctx = calloc(1, sizeof(*op_ctx));
        init_args.context = op_ctx;
        init_args.key_desc = &key_desc;

        // Initialize multi-part AEAD operation
        res = smw_aead_init(&init_args);
        if (res != SMW_STATUS_OK)
            goto exit;

        // Add additional data to an active AEAD operation.
        aad_args.aad = aad;
        aad_args.aad_length = AAD_LEN;
        aad_args.context = init_args.context;
        res = smw_aead_update_add(&aad_args);
        if (res != SMW_STATUS_OK)
            goto exit;

        /**
         * Encrypt 1st message fragment in an active
         * multi-part AEAD encryption operation.
         */
        data_args.input_length = 16;
        data_args.input = input;
        data_args.output_length = 16;
        data_args.output = output;
        data_args.context = init_args.context;
        res = smw_aead_update(&data_args);
        if (res != SMW_STATUS_OK)
            goto exit;

        /**
         * Encrypt 2nd message fragment in an active
         * multi-part AEAD encryption operation.
         */
        data_args.input_length = 16;
        data_args.input = &input[16];
        data_args.output_length = 16;
        data_args.output = &output[16];
        data_args.context = init_args.context;
        res = smw_aead_update(&data_args);
        if (res != SMW_STATUS_OK)
            goto exit;

        /**
         * Finish encrypting the message in an active
         * multi-part AEAD operation.
         */
        final_args.operation_name = "ENCRYPT";
        final_args.data.context = init_args.context;
        final_args.data.input = NULL;
        final_args.data.input_length = 0;
        final_args.data.output = &output[32];
        final_args.data.output_length = TAG_LEN;
        final_args.tag_length = TAG_LEN;
        res = smw_aead_final(&final_args);
        if (res != SMW_STATUS_OK)
            goto exit;

        exit:
        if (op_ctx)
            free(op_ctx);

        return res;
    }

Example 3: AEAD multi-part decryption operation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: c

    #define IV_LEN 12
    #define AAD_LEN 20
    #define DATA_LEN 32
    #define TAG_LEN 16
    #define CIPHER_LEN 32

    int main(int argc, char *argv[])
    {

        int res = SMW_STATUS_OPERATION_FAILURE;

        unsigned char iv[IV_LEN] = {...};
        unsigned char aad[AAD_LEN] = {...};
        unsigned char input[CIPHER_LEN +TAG_LEN] = {...};
        unsigned char output[DATA_LEN] = {0};

        struct smw_aead_args args = {0};
        struct smw_aead_data_args data_args = {0};
        struct smw_aead_aad_args aad_args = {0};
        struct smw_aead_final_args final_args = {0};
        struct smw_aead_init_args init_args = {0};
        struct smw_key_descriptor key_desc = {0};
        struct smw_op_context *op_ctx = 0;

        init_args.subsystem_name = "TEE";
        init_args.operation_name = "DECRYPT";
        init_args.mode_name = "GCM";
        init_args.aad_length = AAD_LEN;
        init_args.tag_length = TAG_LEN;
        init_args.plaintext_length = DATA_LEN;

        // Allocate memory to pointer to operation context
        op_ctx = calloc(1, sizeof(*op_ctx));
        init_args.context = op_ctx;
        init_args.key_desc = &key_desc;

        // Initialize multi-part AEAD operation
        res = smw_aead_init(&init_args);
        if (res != SMW_STATUS_OK)
            goto exit;

        // Add additional data to an active AEAD operation.
        aad_args.aad = aad;
        aad_args.aad_length = AAD_LEN;
        aad_args.context = init_args.context;
        res = smw_aead_update_add(&aad_args);
        if (res != SMW_STATUS_OK)
            goto exit;

        /**
         * Decrypt 1st message fragment in an active
         * multi-part AEAD decryption operation.
         */
        data_args.input_length = 16;
        data_args.input = input;
        data_args.output_length = 16;
        data_args.output = output;
        data_args.context = init_args.context;
        res = smw_aead_update(&data_args);
        if (res != SMW_STATUS_OK)
            goto exit;

        /**
         * Decrypt 2nd message fragment in an active
         * multi-part AEAD decryption operation.
         */
        data_args.input_length = 16;
        data_args.input = &input[16];
        data_args.output_length = 16;
        data_args.output = &output[16];
        data_args.context = init_args.context;
        res = smw_aead_update(&data_args);
        if (res != SMW_STATUS_OK)
            goto exit;

        /**
         * Finish authenticating and decrypting the message
         * in an active multi-part AEAD operation.
         */
        final_args.operation_name = "DECRYPT";
        final_args.data.context = init_args.context;
        // Pass the tag
        final_args.data.input = &input[32];
        final_args.data.input_length = TAG_LEN;
        final_args.data.output = NULL;
        final_args.data.output_length = 0;
        final_args.tag_length = TAG_LEN;
        res = smw_aead_final(&final_args);
        if (res != SMW_STATUS_OK)
            goto exit;

        exit:
        if (op_ctx)
            free(op_ctx);

        return res;
    }
