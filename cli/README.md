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
# Basic usage
./nxp_smw <operation> [OPTIONS]
./nxp_psa <operation> [OPTIONS]
```
## Help Usage

### Getting Help

```bash
# SMW version
./nxp_smw --help

# PSA version
./nxp_psa --help
```

### Show operation-specific help:

```bash
# Get help for RNG operation
./nxp_smw rng --help
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
├── core/                     # Shared core implementation
│   ├── handler.c             # Main entry point, operation dispatcher
│   ├── logger.c              # Logging system implementation
│   ├── operations.c          # Operation-specific helpers
│   ├── opt_parser.c          # Command-line argument parsing
│   ├── parser_hash.c         # Hash-specific option parsing
│   ├── parser_rng.c          # RNG-specific option parsing
│   ├── utils.c               # Utility functions (hex dump, program info)
│   ├── weak_hash.c           # Weak default hash implementation
│   ├── weak_rng.c            # Weak default RNG implementation
│   └── CMakeLists.txt
│
├── inc/                      # Public headers
│   ├── error_handler.h       # API status checking and error descriptions
│   ├── helper.h              # Safe I/O macros (FPRINTF, FCLOSE, etc.)
│   ├── logger.h              # Logging API
│   ├── operations.h          # Operation function declarations
│   ├── opt_parser.h          # CLI parser API
│   ├── parser_hash.h         # Hash parser API
│   ├── parser_rng.h          # RNG parser API
│   └── utils.h               # Utility function declarations
│
├── psa/                      # PSA backend implementation
│   ├── common.c              # PSA common utilities (subsystem names, etc.)
│   ├── common.h              # Common PSA definitions and macros
│   ├── hash.c                # PSA hash operation
│   ├── init.c                # PSA crypto initialization
│   ├── rng.c                 # PSA RNG operation
│   └── CMakeLists.txt
|
├── scripts/                  # Build-time code generation scripts
│   ├── generate_hash_common_table.py    # Generate common hash algorithm enum and table
│   ├── generate_psa_error_table.py      # Generate PSA error handler
│   ├── generate_psa_hash_table.py       # Generate PSA hash algorithm mapping table
│   ├── generate_smw_error_table.py      # Generate SMW error handler
│   └── generate_smw_hash_table.py       # Generate SMW hash algorithm mapping table
|
├── smw/                      # SMW backend implementation
│   ├── common.c              # SMW common utilities (subsystem names, etc.)
│   ├── common.h              # Common SMW definitions and macros
│   ├── hash.c                # SMW hash operation
│   ├── init.c                # SMW library initialization
│   ├── rng.c                 # SMW RNG operation
│   └── CMakeLists.txt
│
├── CMakeLists.txt            # Main build configuration
└── README.md                 # Documentation
```

## 📝 Logging Mechanism

The CLI provides **two independent logging systems** that can run simultaneously:

### 1. Automatic Logging (Environment Variable)

**Always active** unless explicitly disabled. Logs to a file automatically.

**Default behavior** (no environment variable set):
```bash
# Automatically logs to smw_cli.log
./nxp_smw rng -s 32 -o random.bin
```

**Custom log file location:**
```bash
export SMW_LOG_FILE="/var/log/smw_operations.log"
```

**Disable automatic logging:**
```bash
export SMW_LOG_FILE=none
```

### 2. Manual Logging (CLI Option)

**Disabled by default**. User explicitly enables with `-L`:

```bash
#Log to terminal output (no timestamps)
./nxp_smw rng -s 32 -o random.bin -L

#Log to custom file (with timestamps)
./nxp_smw rng -s 32 -o random.bin -L debug.log
```

### Log Levels

When enabled, **all levels** are logged:
- **ERROR** - Operation failures, allocation errors
- **INFO** - API calls, operation status, file I/O

### Log Format

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

To add a new operation (e.g., `cipher`):

1. **Add operation enum** in `opt_parser.h`:
   ```c
   enum operation {
        OP_NONE = 0,
        OP_RNG,
        OP_HASH,
        OP_CIPHER   // new
   };
    ```

2. **Implement SMW version** in `cli/smw/cipher.c`
3. **Implement PSA version** in `cli/psa/cipher.c`
4. **Add to operation table** in `handler.c`:
   ```c
   {
       .operation_name = "cipher",
       .operation_func = cli_cipher_operation,
       .help_func = cli_cipher_help,
       .inline_desc_func = cli_cipher_inline_desc
   },
   ```

5. **Update Makefile** to compile new files

## Available Operations

| Operation | Description | SMW | PSA |
|-----------|-------------|-----|-----|
| `rng` | Generate random numbers | ✅ | ✅ |
| `hash` | Compute cryptographic hash | ✅ | ✅ |
*(More operations coming soon: cipher, sign, verify, etc.)*

### Dependencies

- **SMW version**: NXP Security Middleware library
- **PSA version**: ARM PSA Crypto implementation
- **Common**: Standard C library (C99)