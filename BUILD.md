# Build instructions

The libsecp256k1 project supports Autotools and CMake.

## Building with Autotools

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
