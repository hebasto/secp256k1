# Build Options

This document describes available options when building with:
- GNU Autotools (hereafter "Autotools")
- CMake
- C toolchain only, for instance, GNU C compiler and GNU Binutils (hereafter "Manual")

Autotools options must be provided to the `./configure` script.

CMake options must be provided to the `cmake` when generating a buildsystem.

In manual builds, options are just compiler flags.

## Library Type

By default, when using Autotools, the user builds both shared and static libsecp256k1 libraries.

When using CMake, only one type of the library is built (see [PR1230](https://github.com/bitcoin-core/secp256k1/pull/1230)).

|   | Option with the default value | Available option values |
|---|-------------------------------|-------------------------|
| Autotools | `--enable-shared=yes` | `yes`, `no` |
| Autotools | `--enable-static=yes` | `yes`, `no` |
| CMake | `-DBUILD_SHARED_LIBS=ON` | `ON`, `OFF` |
| CMake | `-DSECP256K1_DISABLE_SHARED=OFF` | `ON`, `OFF` |

## Optional Modules

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

## Fine Tuning Parameters

### Window Size for ecmult Precomputation

Window size for ecmult precomputation for verification, specified as integer in range [2..24].
Larger values result in possibly better performance at the cost of an exponentially larger precomputed table.
The table will store 2^(SIZE-1) * 64 bytes of data but can be larger in memory due to platform-specific padding and alignment.
A window size larger than 15 will require you delete the prebuilt `precomputed_ecmult.c` file so that it can be rebuilt.
For very large window sizes, use `make -j 1` to reduce memory use during compilation.
"auto"/"AUTO" is a reasonable setting for desktop machines (currently 15).

|   | Option with the default value | Available option values |
|---|-------------------------------|-------------------------|
| Autotools | `--with-ecmult-window=auto` | `auto`, [`2`..`24`] |
| CMake | `-DSECP256K1_ECMULT_WINDOW_SIZE=ON` | `AUTO`, [`2`..`24`] |
| Manual | `-DECMULT_WINDOW_SIZE=15` | [`2`..`24`] |

