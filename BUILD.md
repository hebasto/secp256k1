# Table of Contents

* [Building Tools](#building-tools)
* [Platforms](#platforms)
* [Building with Autotools](#building-with-autotools)
  * [Dependencies](#dependencies)
  * [Configuration and Building](#configuration-and-building)
* [Building with CMake (experimental)](#building-with-cmake-experimental)
  * [Dependencies](#dependencies-1)
  * [Configuration and Building](#configuration-and-building)
* [Get the source code](#get-the-source-code)
* [Get the source code](#get-the-source-code)


* [Get the source code](#get-the-source-code)
* [Dependencies](#dependencies)
  * [Windows dependencies](#windows-dependencies)
  * [macOS dependencies](#macos-dependencies)
  * [Linux dependencies](#linux-dependencies)
* [Compiling](#compiling)
  * [Windows details](#windows-details)
    * [MinGW](#mingw)
  * [macOS details](#macos-details)
    * [Issues with Retina displays](#issues-with-retina-displays)
  * [Linux details](#linux-details)
* [Using shared third party libraries](#using-shared-third-party-libraries)

# Building Tools



The libsecp256k1 project supports GNU Autotools and CMake.

# Platforms

The user should be able to build the libsecp256k1 library natively on the following platforms:
- Linux
- macOS
- Windows (CMake only)

Additionally, on Linux and macOS, the user should be able to cross build the libsecp256k1 library for the following platforms:
- Linux
- macOS
- Windows
- Android

Unless specifically stated otherwise, the instructions provided are for native builds.

# Building with Autotools

This document describes the building of the libsecp256k1 library using GNU Autotools on the following POSIX-compliant systems:
- Linux
- macOS

## Dependencies

In additional to C compiler of the user's choice, to the libsecp256k1 project requires dependencies as follows:

| Dependency | Minimum required | Package name on Debian/Ubuntu, Fedora or Homebrew |
| --- | --- | --- |
| [Autoconf](https://www.gnu.org/software/autoconf/) | [2.60](https://github.com/bitcoin-core/secp256k1/commit/78cd96b15153e209cf4829a511f9efdfdcf7e4d0) | autoconf |
| [Automake](https://www.gnu.org/software/automake/) | [1.11.2](https://github.com/bitcoin-core/secp256k1/pull/1088) | automake |
| [Libtool](https://www.gnu.org/software/libtool/) | | libtool |
| [Make](https://www.gnu.org/software/make/) | | make |


## Configuration and Building

    $ ./autogen.sh
    $ ./configure  # add configuration options here
    $ make
    $ make check  # run the test suite
    $ sudo make install  # optional

To configure the build system in a non-default way, run the `./configure` script with additional [options](#build-options).


# Building with CMake (experimental)

This document describes the building of the libsecp256k1 library using CMake on the following systems:
- Linux, using the default "Unix Makefiles" generator
- macOS, using the default "Unix Makefiles" generator
- Windows, using the "Visual Studio 17 2022" generator

To use other CMake generators, please consult the CMake online [documentation](https://cmake.org/cmake/help/latest/manual/cmake-generators.7.html).

## Dependencies

In additional to C compiler of the user's choice, to the libsecp256k1 project requires dependencies as follows:

| Dependency | Minimum required | Package name on Debian/Ubuntu, Fedora or Homebrew |
| --- | --- | --- |
| [CMake](https://cmake.org/) | [3.13](https://github.com/bitcoin-core/secp256k1/pull/1238) | cmake |

On Linux and macOS, [GNU Make](dependencies) is required as well.

On modern Windows, CMake is bundled into ...

## Configuration and Building

To maintain a pristine source tree, CMake encourages to perform an out-of-source build by using a separate dedicated build tree.

    $ mkdir build && cd build
    $ cmake ..  # add configuration options here
    $ cmake --build .
    $ ctest  # run the test suite
    $ sudo cmake --build . --target install  # optional

To configure the build system in a non-default way, run `cmake` in the clean build tree with additional [options](#build-options).

Windows-specific example??????



### Building on POSIX systems


    $ ./autogen.sh
    $ ./configure
    $ make
    $ make check  # run the test suite
    $ sudo make install  # optional

To configure the build system, run the `./configure` script with additional [options](#build-options).

## Building with CMake (experimental)

To maintain a pristine source tree, CMake encourages to perform an out-of-source build by using a separate dedicated build tree.

### Building on POSIX systems

    $ cmake -S . -B ../build
    $ cd ../build
    $ cmake --build .
    $ ctest  # run the test suite
    $ sudo cmake --build . --target install  # optional

To generate a project build system with additional [settings](#build-options), specify them on the command line with the `-D` option.

### Building on Windows

To build on Windows with Visual Studio, specify a proper [generator](https://cmake.org/cmake/help/latest/manual/cmake-generators.7.html#visual-studio-generators) for a new build tree.

The following example assumes using of Visual Studio 2022 and CMake v3.21+.

In "Developer Command Prompt for VS 2022":

    >cmake -G "Visual Studio 17 2022" -A x64 -S . -B ..\build
    >cd ..\build
    >cmake --build . --config RelWithDebInfo
    >ctest -C RelWithDebInfo

## Build Options

To see the full list of available options:
- using Autotools, run `./configure --help`
- using CMake, run `cmake -S . -B ../build -LH` or use interactive tools `cmake-gui` or `ccmake`

### Common Build Options

| Description | Autotools | CMake |
|---|---|---|
| Build benchmarks | `--enable-benchmark` | `-DSECP256K1_BUILD_BENCHMARK=ON` |
| Enable coverage analysis support | `--enable-coverage` | `-DSECP256K1_COVERAGE=ON` |
| Build tests | `--enable-tests` | `-DSECP256K1_BUILD_TESTS=ON` |
| Build constant-time tests | `--enable-ctime-tests` | `-DSECP256K1_BUILD_CTIME_TESTS=ON` |
| Build exhaustive tests | `--enable-exhaustive-tests` | `-DSECP256K1_BUILD_EXHAUSTIVE_TESTS=ON` |
| Build examples | `--enable-examples` | `-DSECP256K1_BUILD_EXAMPLES=ON` |
| Enable ECDH module | `--enable-module-ecdh` | `-DSECP256K1_ENABLE_MODULE_ECDH=ON` |
| Enable ECDSA pubkey recovery module | `--enable-module-recovery` | `-DSECP256K1_ENABLE_MODULE_RECOVERY=ON` |
| Enable extrakeys module | `--enable-module-extrakeys` | `-DSECP256K1_ENABLE_MODULE_EXTRAKEYS=ON` |
| Enable schnorrsig module | `--enable-module-schnorrsig` | `-DSECP256K1_ENABLE_MODULE_SCHNORRSIG=ON` |
| Enable external default callback functions | `--enable-external-default-callbacks` | `-DSECP256K1_USE_EXTERNAL_DEFAULT_CALLBACKS=ON` |
|| `--with-asm` | `-DSECP256K1_ASM` |
|| `--with-ecmult-window` | `-DSECP256K1_ECMULT_WINDOW_SIZE` |
|| `--with-ecmult-gen-precision` | `-DSECP256K1_ECMULT_GEN_PREC_BITS` |
|| `--with-valgrind` | `-DSECP256K1_VALGRIND` |
|| `--with-test-override-wide-multiply` _hidden_ | `-DSECP256K1_TEST_OVERRIDE_WIDE_MULTIPLY` |

### Experimental Build Options

The experimental build options are as follows:
- ARM assembly optimization (`--with-asm=arm` using Autotools, `-DSECP256K1_ASM=arm` using CMake)

To be able to specify experimental build options, enable them explicitly:
- using Autotools -- `--enable-experimental`
- using CMake -- `-DSECP256K1_EXPERIMENTAL=ON`
