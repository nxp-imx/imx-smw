# NXP Security Middleware CLI Tool

A command-line interface for NXP's Security Middleware (SMW) and PSA Crypto APIs.

## Overview

This CLI provides a unified interface to execute cryptographic operations using either:
- **SMW API** - NXP Security Middleware (supports subsystem selection: ELE, TEE, SECO)
- **PSA API** - ARM Platform Security Architecture Crypto API

Two separate binaries are built:
- `nxp_smw` - Uses SMW backend
- `nxp_psa` - Uses PSA backend

## Operations Usage

```bash
./nxp_smw <operation> [OPTIONS]
./nxp_psa <operation> [OPTIONS]
```
## Help Usage

### Getting Help

```bash
./nxp_smw --help
./nxp_psa --help
```

### Show operation-specific help:

```bash
./nxp_smw <operation> --help
./nxp_psa <operation> --help
```

### Get logging help:

```bash
./nxp_smw log --help
./nxp_psa log --help
```

### Show version information:

```bash
./nxp_smw --version
./nxp_psa --version
```

## File Structure

```
cli/
├── core/                               # Shared core implementation
│   ├── CMakeLists.txt
│   ├── handler.c                       # Main entry point, operation dispatcher
│   ├── logger.c                        # Logging system implementation
│   ├── opt_parser.c                    # Command-line argument parsing
│   ├── parser_device_attestation.c     # Device attestation option parsing
│   ├── parser_device_get_lifecycle.c   # Get-lifecycle-specific option parsing
│   ├── parser_device_set_lifecycle.c   # Set-lifecycle-specific option parsing
│   ├── parser_device_uuid.c            # Device UUID option parsing
│   ├── parser_encrypt.c                # Encrypt/decrypt option parsing
│   ├── parser_hash.c                   # Hash-specific option parsing
│   ├── parser_key_delete.c             # Key delete option parsing
│   ├── parser_key_export.c             # Key export option parsing
│   ├── parser_keygen_asym.c            # Asymmetric key generation option parsing
│   ├── parser_keygen_sym.c             # Symmetric key generation option parsing
│   ├── parser_mac.c                    # MAC option parsing
│   ├── parser_rng.c                    # RNG-specific option parsing
│   ├── pubkey_encode.c                 # Public key encoding (DER/PEM via Python script)
│   ├── utils.c                         # Utility functions (hex dump, program info)
│   ├── weak_asym_enc.c                 # Weak default asymmetric enc/dec implementation
│   ├── weak_cipher.c                   # Weak default cipher implementation
│   ├── weak_device_attestation.c       # Weak default dev-attestation implementation
│   ├── weak_device_get_lifecycle.c     # Weak default dev-get-lifecycle implementation
│   ├── weak_device_set_lifecycle.c     # Weak default dev-set-lifecycle implementation
│   ├── weak_device_uuid.c              # Weak default dev-get-uuid implementation
│   ├── weak_hash.c                     # Weak default hash implementation
│   ├── weak_key_delete.c               # Weak default key-delete implementation
│   ├── weak_key_export.c               # Weak default key-export implementation
│   ├── weak_keygen_asym.c              # Weak default asymmetric keygen implementation
│   ├── weak_keygen_sym.c               # Weak default symmetric keygen implementation
│   └── weak_mac.c                      # Weak default MAC implementation
│   └── weak_rng.c                      # Weak default RNG implementation
│
├── inc/                                # Public headers
│   ├── apis_dispatcher.h               # Backend dispatcher declarations (PSA/SMW routing)
│   ├── cli_print.h                     # CLI output formatting helpers
│   ├── error_handler.h                 # API status checking and error descriptions
│   ├── helper.h                        # Safe I/O macros (FPRINTF, FCLOSE, etc.)
│   ├── key_asym_mappings.h             # Backend-agnostic asymmetric key mappings
│   ├── key_sym_mappings.h              # Backend-agnostic key type/algo mappings
│   ├── logger.h                        # Logging API
│   ├── mac_algo_mappings.h             # Backend-agnostic MAC algorithm mappings
│   ├── opt_parser.h                    # CLI parser API
│   ├── parser_device_attestation.h     # Device attestation parser API
│   ├── parser_device_get_lifecycle.h   # Get-lifecycle parser API
│   ├── parser_device_set_lifecycle.h   # Set-lifecycle parser API
│   ├── parser_device_uuid.h            # Device UUID parser API
│   ├── parser_encrypt.h                # Encrypt/decrypt parser API
│   ├── parser_hash.h                   # Hash parser API
│   ├── parser_key_delete.h             # Key delete parser API
│   ├── parser_key_export.h             # Key export parser API
│   ├── parser_keygen_asym.h            # Asymmetric key generation parser API
│   ├── parser_keygen_sym.h             # Symmetric key generation parser API
│   ├── parser_mac.h                    # MAC parser API
│   ├── parser_rng.h                    # RNG parser API
│   ├── pubkey_encode.h                 # Public key encoding API (DER/PEM wrapper)
│   └── utils.h                         # Utility function declarations
│
├── psa/                                # PSA backend implementation
│   ├── CMakeLists.txt
│   ├── asym_enc.c                      # PSA asymmetric encrypt/decrypt operation
│   ├── cipher.c                        # PSA cipher encrypt/decrypt operation
│   ├── common.c                        # PSA common utilities (subsystem names, etc.)
│   ├── common.h                        # Common PSA definitions and macros
│   ├── hash.c                          # PSA hash operation
│   ├── init.c                          # PSA crypto initialization
│   ├── key_delete.c                    # PSA key delete operation
│   ├── key_export.c                    # PSA key export operation
│   ├── keygen_asym.c                   # PSA asymmetric key generation operation
│   ├── keygen_common.c                 # PSA common key generation utilities
│   ├── keygen_common.h                 # PSA common key generation header
│   ├── keygen_sym.c                    # PSA symmetric key generation operation
│   ├── mac.c                           # PSA MAC operation
│   └── rng.c                           # PSA RNG operation
│
├── scripts/                            # Build-time code generation scripts
│   ├── generate_asym_enc_table.py      # Generate asymmetric encryption algo enum, table, SMW and PSA mappings
│   ├── generate_cipher_table.py        # Generate cipher algo enum, table, SMW and PSA mappings
│   ├── generate_hash_common_table.py   # Generate common hash algorithm enum and table
│   ├── generate_lifecycle_table.py     # Generate lifecycle enum and table
│   ├── generate_psa_error_table.py     # Generate PSA error handler
│   ├── generate_psa_hash_table.py      # Generate PSA hash algorithm mapping table
│   ├── generate_psa_key_asym_table.py  # Generate PSA asymmetric key mapping table
│   ├── generate_psa_key_sym_table.py   # Generate PSA symmetric key mapping table
│   ├── generate_psa_mac_algo_table.py  # Generate PSA MAC algorithm mapping table
│   ├── generate_smw_error_table.py     # Generate SMW error handler
│   ├── generate_smw_hash_table.py      # Generate SMW hash algorithm mapping table
│   ├── generate_smw_key_asym_table.py  # Generate SMW asymmetric key type mapping table
│   ├── generate_smw_key_sym_table.py   # Generate SMW symmetric key mapping table
│   ├── generate_smw_mac_algo_table.py  # Generate SMW MAC algorithm mapping table
│   ├── nxp_psa_completion.bash         # Bash completion for nxp_psa CLI
│   ├── nxp_smw_completion.bash         # Bash completion for nxp_smw CLI
│   └── pubkey_convert.py               # Runtime public key format conversion (DER/PEM)
│
├── smw/                                # SMW backend implementation
│   ├── CMakeLists.txt
│   ├── asym_enc.c                      # SMW asymmetric encrypt/decrypt operation
│   ├── cipher.c                        # SMW cipher encrypt/decrypt operation
│   ├── common.c                        # SMW common utilities (subsystem names, etc.)
│   ├── common.h                        # Common SMW definitions and macros
│   ├── device_attestation.c            # SMW dev-get-attestation operation
│   ├── device_get_lifecycle.c          # SMW dev-get-lifecycle operation
│   ├── device_set_lifecycle.c          # SMW dev-set-lifecycle operation
│   ├── device_uuid.c                   # SMW dev-get-uuid operation
│   ├── hash.c                          # SMW hash operation
│   ├── init.c                          # SMW library initialization
│   ├── key_delete.c                    # SMW key delete operation
│   ├── key_export.c                    # SMW key export operation
│   ├── keygen_asym.c                   # SMW asymmetric key generation operation
│   ├── keygen_common.c                 # SMW common key generation utilities
│   ├── keygen_common.h                 # SMW common key generation header
│   ├── keygen_sym.c                    # SMW symmetric key generation operation
│   ├── mac.c                           # SMW MAC operation
│   └── rng.c                           # SMW RNG operation
|
├── tests/                              # Test suites
│   ├── lib_asym_enc.sh                 # Shared library for asymmetric encryption test suites
│   ├── lib_cipher.sh                   # Shared library for cipher test suites
│   ├── lib_keygen_asym.sh              # Shared library for asymmetric key generation test suites
│   ├── lib_keygen_sym.sh               # Shared library for symmetric key generation test suites
│   ├── lib_mac.sh                      # Shared library for MAC test suites
│   ├── psa_asym_enc.sh                 # PSA asymmetric encryption test suite
│   ├── psa_cipher.sh                   # PSA cipher algorithm test suite
│   ├── psa_keygen_asym.sh              # PSA asymmetric key generation test suite
│   ├── psa_keygen_sym.sh               # PSA symmetric key generation test suite
│   ├── psa_mac.sh                      # PSA MAC algorithm test suite
│   ├── smw_asym_enc.sh                 # SMW asymmetric encryption test suite
│   ├── smw_cipher.sh                   # SMW cipher algorithm test suite
│   ├── smw_keygen_asym.sh              # SMW asymmetric key generation test suite
│   ├── smw_keygen_sym.sh               # SMW symmetric key generation test suite
│   └── smw_mac.sh                      # SMW MAC algorithm test suite
│
├── CMakeLists.txt                      # Main build configuration
└── README.md                           # Documentation
```

## 📝 Logging Mechanism

The CLI provides **two independent logging systems** that can run simultaneously:

### 1. Automatic Logging (Environment Variable)

**Always active** unless explicitly disabled. Logs to a file automatically.

**Default behavior** (no environment variable set):
```bash
# Automatically logs to smw_cli.log
./nxp_smw <operation> [OPTIONS]
./nxp_psa <operation> [OPTIONS]
```

**Custom log file location:**
```bash
export SMW_LOG_FILE="/var/log/smw_operations.log"
```

**Disable automatic logging:**
```bash
export SMW_LOG_FILE=none
export SMW_LOG_FILE=off
export SMW_LOG_FILE=""      # empty string
```

**Re-enable automatic logging to default file:**
```bash
unset SMW_LOG_FILE
```

### 2. Manual Logging (CLI Option)

**Disabled by default**. User explicitly enables with `-L`:

```bash
# Log to terminal output (no timestamps)
./nxp_smw <operation> [OPTIONS] -L
./nxp_psa <operation> [OPTIONS] -L

# Log to custom file (with timestamps)
./nxp_smw <operation> [OPTIONS] -L debug.log
./nxp_psa <operation> [OPTIONS] -L debug.log
```

### Log Levels

When enabled, **all levels** are logged:
- **ERROR** - Operation failures, allocation errors
- **INFO** - API calls, operation status, file I/O

### Log Format Example

**Terminal output (no timestamps):**
```
[CLI] RNG operation (SMW API)
[CLI] smw_rng() succeeded: SMW_STATUS_OK (0)
```

**File output (with timestamps):**
```
[2024-01-15 10:30:45] [CLI] ========== New logging session ==========
[2024-01-15 10:30:45] [CLI] RNG operation (SMW API)
[2024-01-15 10:30:45] [CLI] === SMW RNG Parameters ===
[2024-01-15 10:30:45] [CLI]   version: 0
[2024-01-15 10:30:45] [CLI]   subsystem_name: SMW_SUBSYSTEM_NAME_NONE
[2024-01-15 10:30:45] [CLI]   output: 0x7ffed2b0
[2024-01-15 10:30:45] [CLI]   output_length: 32
[2024-01-15 10:30:45] [CLI] ==========================
[2024-01-15 10:30:45] [CLI] smw_rng() succeeded: SMW_STATUS_OK (0)
[2024-01-15 10:30:45] [CLI] ========== End logging session ==========
```

## Adding New Operations

To add a new operation (e.g., `key_import`):

1. **Add operation enum** in `opt_parser.h`:
   ```c
   enum operation {
        OP_NONE = 0,
        OP_RNG,
        OP_HASH,
        OP_KEY_IMPORT   // new
   };
    ```
2. **Create parser header** in `cli/inc/parser_<operation>.h`
3. **Implement parser** in `cli/core/parser_<operation>.c`
4.  **Add to operation parser table** in `core/opt_parser.c`:
    ```c
    { .name = "key_import",
      .op = OP_KEY_IMPORT,
      .parse_func = parse_key_import_options,
      .special_func = NULL },
    ```
5. **Create weak implementation** in `cli/core/weak_<operation>.c`
6. **Implement SMW version** in `cli/smw/key_import.c`
7. **Implement PSA version** in `cli/psa/key_import.c`
8. **Add operation function** in `cli/inc/apis_dispatcher.h`
9. **Add to operation table** in `handler.c`:
   ```c
   {
       .operation_name = "key_import",
       .operation_func = cli_key_import_operation,
       .help_func = cli_key_import_help,
       .inline_desc_func = cli_key_import_inline_desc
   },
   ```

## Available Operations

| Operation | Description | SMW | PSA |
|-----------|-------------|-----|-----|
| `decrypt` | Decrypt data using a generated key | ✅ | ✅ |
| `dev-get-attestation` | Get device attestation | ✅ | ❌ |
| `dev-get-lifecycle` | Get device lifecycle | ✅ | ❌ |
| `dev-get-uuid` | Get device UUID | ✅ | ❌ |
| `dev-set-lifecycle` | Set device lifecycle | ✅ | ❌ |
| `encrypt` | Encrypt data using a generated key | ✅ | ✅ |
| `hash` | Compute cryptographic hash | ✅ | ✅ |
| `keygen-asym` | Generate asymmetric key | ✅ | ✅ |
| `keygen-sym` | Generate symmetric key | ✅ | ✅ |
| `key-export` | Export key material | ✅ | ✅ |
| `key-delete` | Delete a key | ✅ | ✅ |
| `rng` | Generate random numbers | ✅ | ✅ |
*(More operations coming soon: cipher, sign, verify, etc.)*

### Dependencies

- **SMW version**: NXP Security Middleware library
- **PSA version**: ARM PSA Crypto implementation
- **Common**: Standard C library (C99), `libcrypto.so.3` (for DER/PEM encoding)
