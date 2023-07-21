#!/bin/sh

set -eux

configure_and_build() {
    cmake -S "$1" --preset dev-mode \
        -DCMAKE_C_COMPILER=gcc -DCMAKE_BUILD_TYPE=None -DCMAKE_C_FLAGS="-g -Og -gdwarf-4" \
        -DSECP256K1_BUILD_BENCHMARK=OFF \
        -DSECP256K1_BUILD_TESTS=OFF \
        -DSECP256K1_BUILD_EXHAUSTIVE_TESTS=OFF \
        -DSECP256K1_BUILD_CTIME_TESTS=OFF \
        -DSECP256K1_BUILD_EXAMPLES=OFF
    cmake --build . -j "$(nproc)"
}

source_dir=$(pwd)

git checkout "$1"
base_build_dir=$(mktemp -d)
cd "$base_build_dir"
configure_and_build "$source_dir"
abi-dumper src/libsecp256k1.so -o ABI.dump -lver "$1"
cd "$source_dir"

git checkout "$2"
current_build_dir=$(mktemp -d)
cd "$current_build_dir"
configure_and_build "$source_dir"
abi-dumper src/libsecp256k1.so -o ABI.dump -lver "$2"
cd "$source_dir"

abi-compliance-checker -lib libsecp256k1 -old "${base_build_dir}/ABI.dump" -new "${current_build_dir}/ABI.dump"
