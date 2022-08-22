#!/usr/bin/env python3
# Copyright (c) 2014 Wladimir J. van der Laan
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
'''
A script to check that the secp256k1 shared library only contain certain symbols
and are only linked against allowed libraries.

Example usage:

    contrib/symbol-check.py .libs/libsecp256k1.so.0.0.0
or
    contrib/symbol-check.py .libs/libsecp256k1-0.dll
'''
import sys
from typing import List, Dict

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

# Allowed NEEDED libraries
ELF_ALLOWED_LIBRARIES = {
'libc.so.6', # C library
'ld-linux-aarch64.so.1', # 64-bit ARM dynamic linker
'ld-linux-armhf.so.3', # 32-bit ARM dynamic linker
'ld-linux-riscv64-lp64d.so.1', # 64-bit RISC-V dynamic linker
}

MACHO_ALLOWED_LIBRARIES = {
'libsecp256k1.0.dylib',
'libSystem.B.dylib', # libc, libm, libpthread, libinfo
}

PE_ALLOWED_LIBRARIES = {
'KERNEL32.dll', # win32 base APIs
'msvcrt.dll', # C standard library for MSVC
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

def check_ELF_imported_symbols(binary) -> bool:
    ok: bool = True

    for symbol in binary.concrete.imported_symbols:
        if not symbol.imported:
            continue

        version = symbol.symbol_version if symbol.has_version else None

        if version:
            aux_version = version.symbol_version_auxiliary.name if version.has_auxiliary_version else None
            if aux_version and not check_version(MAX_VERSIONS, aux_version, binary.concrete.header.machine_type):
                print(f'{filename}: symbol {symbol.name} from unsupported version {version}')
                ok = False
    return ok

def check_ELF_exported_symbols(binary) -> bool:
    ok: bool = True
    for symbol in binary.concrete.dynamic_symbols:
        if not symbol.exported:
            continue
        name = symbol.name
        if binary.concrete.header.machine_type == lief.ELF.ARCH.RISCV or name in EXPECTED_EXPORTS:
            continue
        print(f'{filename}: export of symbol {name} not allowed!')
        ok = False
    return ok

def check_ELF_libraries(binary) -> bool:
    ok: bool = True
    for library in binary.concrete.libraries:
        if library not in ELF_ALLOWED_LIBRARIES:
            print(f'{filename}: {library} is not in ALLOWED_LIBRARIES!')
            ok = False
    return ok

def check_MACHO_libraries(binary) -> bool:
    ok: bool = True
    for dylib in binary.concrete.libraries:
        library = dylib.name.split('/')[-1]
        if binary.abstract.header.object_type == lief.OBJECT_TYPES.LIBRARY and library == 'libbitcoinconsensus.0.dylib':
            continue
        if library not in MACHO_ALLOWED_LIBRARIES:
            print(f'{filename}: {library} is not in ALLOWED_LIBRARIES!')
            ok = False
    return ok

def check_MACHO_min_os(binary) -> bool:
    if binary.concrete.build_version.minos == [10,15,0]:
        return True
    return False

def check_MACHO_sdk(binary) -> bool:
    if binary.concrete.build_version.sdk == [11, 0, 0]:
        return True
    return False

def check_PE_exported_functions(binary) -> bool:
    ok: bool = True
    for function in binary.concrete.exported_functions:
        name = function.name
        if name in EXPECTED_EXPORTS:
            continue
        print(f'{filename}: export of function {name} not allowed!')
        ok = False
    return ok

def check_PE_libraries(binary) -> bool:
    ok: bool = True
    for dylib in binary.concrete.libraries:
        if dylib not in PE_ALLOWED_LIBRARIES:
            print(f'{filename}: {dylib} is not in ALLOWED_LIBRARIES!')
            ok = False
    return ok

def check_PE_subsystem_version(binary) -> bool:
    major: int = binary.concrete.optional_header.major_subsystem_version
    minor: int = binary.concrete.optional_header.minor_subsystem_version
    if major == 5 and minor == 2:
        return True
    return False

CHECKS = {
lief.EXE_FORMATS.ELF: [
    ('EXPORTED_SYMBOLS', check_ELF_exported_symbols),
    ('IMPORTED_SYMBOLS', check_ELF_imported_symbols),
    ('LIBRARY_DEPENDENCIES', check_ELF_libraries),
],
lief.EXE_FORMATS.MACHO: [
    ('DYNAMIC_LIBRARIES', check_MACHO_libraries),
    ('MIN_OS', check_MACHO_min_os),
    ('SDK', check_MACHO_sdk),
],
lief.EXE_FORMATS.PE: [
    ('EXPORTED_FUNCTIONS', check_PE_exported_functions),
    ('DYNAMIC_LIBRARIES', check_PE_libraries),
    ('SUBSYSTEM_VERSION', check_PE_subsystem_version),
]
}

if __name__ == '__main__':
    retval: int = 0
    for filename in sys.argv[1:]:
        try:
            binary = lief.parse(filename)
            etype = binary.concrete.format
            if etype == lief.EXE_FORMATS.UNKNOWN:
                print(f'{filename}: unknown executable format')
                retval = 1
                continue

            obj_type = binary.abstract.header.object_type
            if obj_type != lief.OBJECT_TYPES.LIBRARY:
                print(f'{filename}: unsupported file type')
                retval = 1
                continue

            failed: List[str] = []
            for (name, func) in CHECKS[etype]:
                if not func(binary):
                    failed.append(name)
            if failed:
                print(f'{filename}: failed {" ".join(failed)}')
                retval = 1
        except IOError:
            print(f'{filename}: cannot open')
            retval = 1
    sys.exit(retval)
