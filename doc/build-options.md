# Build Options

This document describes available options when building with:
- GNU Autotools (hereafter "Autotools")
- CMake
- C toolchain only, for instance, GNU C compiler and GNU Binutils (hereafter "Manual")

Autotools options must be provided to the `./configure` script.

CMake options must be provided to the `cmake` when generating a buildsystem.

In manual builds, options are just compiler flags.

## libsecp256k1 Modules

Modules are optional.

### ECDH Module

|   | Option with the default value | Available option values |
|---|-------------------------------|-------------------------|
| Autotools | `--enable-module-ecdh=yes` | `yes`, `no` |
| CMake | `-DSECP256K1_ENABLE_MODULE_ECDH=ON` | `ON`, `OFF` |
| Manual | `-DENABLE_MODULE_ECDH=1` | `-DENABLE_MODULE_ECDH=1`, `-UENABLE_MODULE_ECDH` |

### ECDSA Pubkey Recovery Module

|   | Option with the default value | Available option values |
|---|-------------------------------|-------------------------|
| Autotools | `--enable-module-recovery=no` | `yes`, `no` |
| CMake | `-DSECP256K1_ENABLE_MODULE_RECOVERY=OFF` | `ON`, `OFF` |
| Manual | `-DENABLE_MODULE_RECOVERY=1` | `-DENABLE_MODULE_RECOVERY=1`, `-UENABLE_MODULE_RECOVERY` |

