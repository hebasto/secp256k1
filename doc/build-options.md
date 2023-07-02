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
| Manual | n/a | `-DENABLE_MODULE_ECDH=1` |

### ECDSA Pubkey Recovery Module

|   | Option with the default value | Available option values |
|---|-------------------------------|-------------------------|
| Autotools | `--enable-module-recovery=no` | `yes`, `no` |
| CMake | `-DSECP256K1_ENABLE_MODULE_RECOVERY=OFF` | `ON`, `OFF` |
| Manual | n/a | `-DENABLE_MODULE_RECOVERY=1` |

### Extrakeys Module

|   | Option with the default value | Available option values |
|---|-------------------------------|-------------------------|
| Autotools | `--enable-module-extrakeys=yes` | `yes`, `no` |
| CMake | `-DSECP256K1_ENABLE_MODULE_EXTRAKEYS=ON` | `ON`, `OFF` |
| Manual | n/a | `-DENABLE_MODULE_EXTRAKEYS=1` |

### Schnorrsig Module

|   | Option with the default value | Available option values |
|---|-------------------------------|-------------------------|
| Autotools | `--enable-module-extrakeys=yes` | `yes`, `no` |
| CMake | `-DSECP256K1_ENABLE_MODULE_SCHNORRSIG=ON` | `ON`, `OFF` |
| Manual | n/a | `-DENABLE_MODULE_SCHNORRSIG=1` |

### ElligatorSwift Module

|   | Option with the default value | Available option values |
|---|-------------------------------|-------------------------|
| Autotools | `--enable-module-ellswift=yes` | `yes`, `no` |
| CMake | `-DSECP256K1_ENABLE_MODULE_ELLSWIFT=ON` | `ON`, `OFF` |
| Manual | n/a | `-DENABLE_MODULE_ELLSWIFT=1` |

## Library Type

By default, when using Autotools, the user builds both shared and static libsecp256k1 libraries.

When using CMake, only one type of the library is built (see [PR1230](https://github.com/bitcoin-core/secp256k1/pull/1230)).

|   | Option with the default value | Available option values |
|---|-------------------------------|-------------------------|
| Autotools | `--enable-shared=yes` | `yes`, `no` |
| Autotools | `--enable-static=yes` | `yes`, `no` |
| CMake | `-DBUILD_SHARED_LIBS=ON` | `ON`, `OFF` |
| CMake | `-DSECP256K1_DISABLE_SHARED=OFF` | `ON`, `OFF` |


