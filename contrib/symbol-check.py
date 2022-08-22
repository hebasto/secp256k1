#!/usr/bin/env python3
# Copyright (c) 2014 Wladimir J. van der Laan
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
'''
A script to check that a secp256k1 shared library
exports only expected symbols.

Example usage:

    contrib/symbol-check.py .libs/libsecp256k1.so.0.0.0
or
    contrib/symbol-check.py .libs/libsecp256k1-0.dll
'''
import sys
from typing import List

import lief #type:ignore

MAX_VERSIONS = {
'GLIBC': {
    lief.ELF.ARCH.x86_64: (2,4),
    lief.ELF.ARCH.ARM:    (2,4),
    lief.ELF.ARCH.AARCH64:(2,17),
    lief.ELF.ARCH.PPC64:  (2,17),
    lief.ELF.ARCH.RISCV:  (2,27),
},
}

# Symbols being expected to be exported by the secp256k1 shared library.
EXPECTED_EXPORTS = {
'secp256k1_context_clone',
'secp256k1_context_create',
'secp256k1_context_destroy',
'secp256k1_context_no_precomp',
'secp256k1_context_preallocated_clone',
'secp256k1_context_preallocated_clone_size',
'secp256k1_context_preallocated_create',
'secp256k1_context_preallocated_destroy',
'secp256k1_context_preallocated_size',
'secp256k1_context_randomize',
'secp256k1_context_set_error_callback',
'secp256k1_context_set_illegal_callback',
'secp256k1_ec_privkey_negate',
'secp256k1_ec_privkey_tweak_add',
'secp256k1_ec_privkey_tweak_mul',
'secp256k1_ec_pubkey_cmp',
'secp256k1_ec_pubkey_combine',
'secp256k1_ec_pubkey_create',
'secp256k1_ec_pubkey_negate',
'secp256k1_ec_pubkey_parse',
'secp256k1_ec_pubkey_serialize',
'secp256k1_ec_pubkey_tweak_add',
'secp256k1_ec_pubkey_tweak_mul',
'secp256k1_ec_seckey_negate',
'secp256k1_ec_seckey_tweak_add',
'secp256k1_ec_seckey_tweak_mul',
'secp256k1_ec_seckey_verify',
'secp256k1_ecdsa_sign',
'secp256k1_ecdsa_signature_normalize',
'secp256k1_ecdsa_signature_parse_compact',
'secp256k1_ecdsa_signature_parse_der',
'secp256k1_ecdsa_signature_serialize_compact',
'secp256k1_ecdsa_signature_serialize_der',
'secp256k1_ecdsa_verify',
'secp256k1_nonce_function_default',
'secp256k1_nonce_function_rfc6979',
'secp256k1_scratch_space_create',
'secp256k1_scratch_space_destroy',
'secp256k1_tagged_sha256',
# ECDH module:
'secp256k1_ecdh',
'secp256k1_ecdh_hash_function_default',
'secp256k1_ecdh_hash_function_sha256',
# ECDSA pubkey recovery module:
'secp256k1_ecdsa_recover',
'secp256k1_ecdsa_recoverable_signature_convert',
'secp256k1_ecdsa_recoverable_signature_parse_compact',
'secp256k1_ecdsa_recoverable_signature_serialize_compact',
'secp256k1_ecdsa_sign_recoverable',
# extrakeys module:
'secp256k1_keypair_create',
'secp256k1_keypair_pub',
'secp256k1_keypair_sec',
'secp256k1_keypair_xonly_pub',
'secp256k1_keypair_xonly_tweak_add',
'secp256k1_xonly_pubkey_cmp',
'secp256k1_xonly_pubkey_from_pubkey',
'secp256k1_xonly_pubkey_parse',
'secp256k1_xonly_pubkey_serialize',
'secp256k1_xonly_pubkey_tweak_add',
'secp256k1_xonly_pubkey_tweak_add_check',
# schnorrsig module:
'secp256k1_nonce_function_bip340',
'secp256k1_schnorrsig_sign',
'secp256k1_schnorrsig_sign32',
'secp256k1_schnorrsig_sign_custom',
'secp256k1_schnorrsig_verify',
}

def check_version(max_versions, version, arch) -> bool:
    (lib, _, ver) = version.rpartition('_')
    ver = tuple([int(x) for x in ver.split('.')])
    if not lib in max_versions:
        return False
    if isinstance(max_versions[lib], tuple):
        return ver <= max_versions[lib]
    else:
        return ver <= max_versions[lib][arch]

def check_ELF_imported_symbols(library) -> bool:
    ok: bool = True
    elf_lib: lief.ELF.Binary = library.concrete

    for symbol in elf_lib.imported_symbols:
        if not symbol.imported:
            continue

        version = symbol.symbol_version if symbol.has_version else None
        if version:
            aux_version = version.symbol_version_auxiliary.name if version.has_auxiliary_version else None
            if aux_version and not check_version(MAX_VERSIONS, aux_version, elf_lib.header.machine_type):
                print(f'{filename}: symbol {symbol.name} from unsupported version {version}')
                ok = False
    return ok

def check_ELF_exported_symbols(library) -> bool:
    ok: bool = True
    elf_lib: lief.ELF.Binary = library.concrete

    for symbol in elf_lib.exported_symbols:
        name: str = symbol.name
        if name in EXPECTED_EXPORTS:
            continue
        print(f'{filename}: export of symbol {name} not expected')
        ok = False
    return ok

def check_PE_exported_functions(library) -> bool:
    ok: bool = True
    pe_lib: lief.PE.Binary = library.concrete

    for function in pe_lib.exported_functions:
        name: str = function.name
        if name in EXPECTED_EXPORTS:
            continue
        print(f'{filename}: export of function {name} not expected')
        ok = False
    return ok

CHECKS = {
lief.EXE_FORMATS.ELF: [
    ('EXPORTED_SYMBOLS', check_ELF_exported_symbols),
    ('IMPORTED_SYMBOLS', check_ELF_imported_symbols),
],
lief.EXE_FORMATS.PE: [
    ('EXPORTED_FUNCTIONS', check_PE_exported_functions),
]
}

USAGE = """
symbol-check.py is a script to check that a secp256k1 shared library
exports only expected symbols.

Usage:
    ./contrib/symbol-check.py <library>

"""

if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit(USAGE)

    filename: str = sys.argv[1]
    try:
        library: lief.Binary = lief.parse(filename)
        exe_format: lief.EXE_FORMATS = library.format
        if exe_format != lief.EXE_FORMATS.ELF and exe_format != lief.EXE_FORMATS.PE:
            print(f'{filename}: unsupported executable format, only ELF and PE formats are supported')
            sys.exit(1)

        obj_type = library.abstract.header.object_type
        if obj_type != lief.OBJECT_TYPES.LIBRARY:
            print(f'{filename}: unsupported object type, only LIBRARY type is supported')
            sys.exit(1)

        failed: List[str] = []
        for (name, func) in CHECKS[exe_format]:
            if not func(library):
                failed.append(name)
        if failed:
            print(f'{filename}: failed {" ".join(failed)}')
            sys.exit(1)
    except IOError:
        print(f'{filename}: cannot open')
        sys.exit(1)
