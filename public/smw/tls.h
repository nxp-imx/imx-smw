/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2025 NXP
 */

#ifndef __SMW_TLS_H__
#define __SMW_TLS_H__

#define SMW_TLS13_PREFIX	("tls13 ")
#define SMW_TLS13_PREFIX_LENGTH (6)

/**
 * struct smw_tls13_expand_label_args - TLS1.3 "HKDF-Expand-Label" arguments structure
 * @version: [in] Version of this structure.
 * @length: [in] Context-specific length (usually equal to Hash.Length).
 * @label: [in] Input label buffer, without the "tls13 " prefix.
 * @label_length: [in] @label length in bytes.
 * @context: [in] Input context buffer, usually the Transcript Hash.
 * @context_length: [in] @context length in bytes.
 * @expanded_label: [in/out] Buffer that holds the expanded label.
 * @expanded_label_length: [in/out] @expanded_label length in bytes.
 */
struct smw_tls13_expand_label_args {
	/* Inputs */
	unsigned char version;
	unsigned int length;
	unsigned char *label;
	unsigned int label_length;
	unsigned char *context;
	unsigned int context_length;
	/* Outputs */
	unsigned char *expanded_label;
	unsigned int expanded_label_length;
};

/**
 * SMW_TLS13_EXPANDED_LABEL_LENGTH() - Return the minimum length needed to construct
 *                                     a TLS1.3 expanded label.
 * @arg: An pointer to a &struct smw_tls13_expand_label_args.
 *
 * In order to avoid 2 calls to @smw_tls13_expand_label(), you may use this macro
 * to get the minimum required expanded label buffer length, after having filled in
 * the @arg.label_length and @arg.context_length values.
 *
 * Return:
 * Minimum length needed for @arg.expanded_label_length
 */
#define SMW_TLS13_EXPANDED_LABEL_LENGTH(arg)                                   \
	({                                                                     \
		typeof(arg) _arg = arg;                                        \
		unsigned int _ret =                                            \
			_arg ? (2 + /* length of key material */               \
				1 + /* label length */                         \
				SMW_TLS13_PREFIX_LENGTH + /* prefix bytes */   \
				_arg->label_length +	  /* label bytes */    \
				1 +			  /* context length */ \
				_arg->context_length	  /* context bytes */  \
				) :                                            \
			       0;                                              \
		_ret;                                                          \
	})

/**
 * smw_tls13_expand_label() - Helper function to construct the TLS1.3 "HkdfLabel",
 *                            used by the "HKDF-Expand-Label" function.
 * @args: Expand label arguments.
 *
 * @smw_tls13_expand_label_args.expanded_label should be a buffer that is large enough
 * to hold the expanded label; if that is not the case, this function will return
 * SMW_STATUS_OUTPUT_TOO_SHORT and set @smw_tls13_expand_label_args.expanded_label_length
 * to the minimum required length. Alternatively, you may also use the
 * SMW_TLS13_EXPANDED_LABEL_LENGTH macro to get the minimum required length.
 *
 * This function will also prepend @smw_tls13_expand_label_args.label with "tls13 ".
 *
 * Return:
 * See &enum smw_status_code
 *	- SMW_STATUS_OK:
 *		Success
 *	- SMW_STATUS_TOO_LARGE_NUMBER:
 *		One of the input length parameters is too large
 *	- SMW_STATUS_OUTPUT_TOO_SHORT:
 *		Output buffer is too short
 */
enum smw_status_code
smw_tls13_expand_label(struct smw_tls13_expand_label_args *args);

#endif // __SMW_TLS_H__
