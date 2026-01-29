#!/bin/sh

set -eux

export LC_ALL=C

# Print commit and relevant CI environment to allow reproducing the job outside of CI.
git show --no-patch
print_environment() {
    # Turn off -x because it messes up the output
    set +x
    # There are many ways to print variable names and their content. This one
    # does not rely on bash.
    for var in WERROR_CFLAGS MAKEFLAGS BUILD \
            ECMULTWINDOW ECMULTGENKB ASM WIDEMUL WITH_VALGRIND EXTRAFLAGS \
            EXPERIMENTAL ECDH RECOVERY EXTRAKEYS MUSIG SCHNORRSIG ELLSWIFT \
            SECP256K1_TEST_ITERS BENCH SECP256K1_BENCH_ITERS CTIMETESTS SYMBOL_CHECK \
            EXAMPLES \
            HOST WRAPPER_CMD \
            CC CFLAGS CPPFLAGS AR NM \
            UBSAN_OPTIONS ASAN_OPTIONS LSAN_OPTIONS
    do
        eval "isset=\${$var+x}"
        if [ -n "$isset" ]; then
            eval "val=\${$var}"
            # shellcheck disable=SC2154
            printf '%s="%s" ' "$var" "$val"
        fi
    done
    echo "$0"
    set -x
}
print_environment

which -a gcc || true
which -a clang || true
which -a valgrind || true
