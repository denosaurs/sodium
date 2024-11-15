// Type definitions for libsodium-wrappers-sumo 0.7
// Project: https://github.com/jedisct1/libsodium.js
// Definitions by: Florian Keller <https://github.com/ffflorian>
// Definitions: https://github.com/DefinitelyTyped/DefinitelyTyped
// TypeScript Version: 2.1

// Copyright 2020-present the denosaurs team. All rights reserved. MIT license.

export * from "./basic.ts";

import {
  KeyPair,
  StateAddress,
  StringKeyPair,
  StringOutputFormat,
  Uint8ArrayOutputFormat,
} from "./basic.ts";

export interface SumoAddons {
  readonly crypto_auth_hmacsha256_BYTES: number;
  readonly crypto_auth_hmacsha256_KEYBYTES: number;
  readonly crypto_auth_hmacsha512_BYTES: number;
  readonly crypto_auth_hmacsha512_KEYBYTES: number;
  readonly crypto_box_curve25519xchacha20poly1305_NONCEBYTES: number;
  readonly crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES: number;
  readonly crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES: number;
  readonly crypto_core_hchacha20_CONSTBYTES: number;
  readonly crypto_core_hchacha20_INPUTBYTES: number;
  readonly crypto_core_hchacha20_KEYBYTES: number;
  readonly crypto_core_hchacha20_OUTPUTBYTES: number;
  readonly crypto_core_ristretto255_BYTES: number;
  readonly crypto_core_ristretto255_HASHBYTES: number;
  readonly crypto_core_ristretto255_NONREDUCEDSCALARBYTES: number;
  readonly crypto_core_ristretto255_SCALARBYTES: number;
  readonly crypto_generichash_blake2b_BYTES_MAX: number;
  readonly crypto_generichash_blake2b_BYTES_MIN: number;
  readonly crypto_generichash_blake2b_BYTES: number;
  readonly crypto_generichash_blake2b_KEYBYTES_MAX: number;
  readonly crypto_generichash_blake2b_KEYBYTES_MIN: number;
  readonly crypto_generichash_blake2b_KEYBYTES: number;
  readonly crypto_generichash_blake2b_PERSONALBYTES: number;
  readonly crypto_generichash_blake2b_SALTBYTES: number;
  readonly crypto_hash_sha256_BYTES: number;
  readonly crypto_hash_sha512_BYTES: number;
  readonly crypto_onetimeauth_BYTES: number;
  readonly crypto_onetimeauth_KEYBYTES: number;
  readonly crypto_pwhash_scryptsalsa208sha256_BYTES_MAX: number;
  readonly crypto_pwhash_scryptsalsa208sha256_BYTES_MIN: number;
  readonly crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE: number;
  readonly crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MAX: number;
  readonly crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN: number;
  readonly crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE: number;
  readonly crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE: number;
  readonly crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MAX: number;
  readonly crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN: number;
  readonly crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE: number;
  readonly crypto_pwhash_scryptsalsa208sha256_SALTBYTES: number;
  readonly crypto_pwhash_scryptsalsa208sha256_STR_VERIFY: number;
  readonly crypto_pwhash_scryptsalsa208sha256_STRBYTES: number;
  readonly crypto_pwhash_scryptsalsa208sha256_STRPREFIX: string;
  readonly crypto_scalarmult_ristretto255_BYTES: number;
  readonly crypto_scalarmult_ristretto255_SCALARBYTES: number;
  readonly crypto_shorthash_siphashx24_BYTES: number;
  readonly crypto_shorthash_siphashx24_KEYBYTES: number;
  readonly crypto_stream_chacha20_ietf_KEYBYTES: number;
  readonly crypto_stream_chacha20_ietf_MESSAGEBYTES_MAX: number;
  readonly crypto_stream_chacha20_ietf_NONCEBYTES: number;
  readonly crypto_stream_chacha20_KEYBYTES: number;
  readonly crypto_stream_chacha20_NONCEBYTES: number;
  readonly crypto_stream_KEYBYTES: number;
  readonly crypto_stream_MESSAGEBYTES_MAX: number;
  readonly crypto_stream_NONCEBYTES: number;
  readonly crypto_stream_xchacha20_KEYBYTES: number;
  readonly crypto_stream_xchacha20_MESSAGEBYTES_MAX: number;
  readonly crypto_stream_xchacha20_NONCEBYTES: number;

  crypto_auth_hmacsha256(
    message: string | Uint8Array,
    key: Uint8Array,
    outputFormat?: Uint8ArrayOutputFormat | null,
  ): Uint8Array;
  crypto_auth_hmacsha256(
    message: string | Uint8Array,
    key: Uint8Array,
    outputFormat: StringOutputFormat,
  ): string;

  crypto_auth_hmacsha256_keygen(
    outputFormat?: Uint8ArrayOutputFormat | null,
  ): Uint8Array;
  crypto_auth_hmacsha256_keygen(outputFormat: StringOutputFormat): string;

  crypto_auth_hmacsha256_verify(
    tag: Uint8Array,
    message: string | Uint8Array,
    key: Uint8Array,
  ): boolean;

  crypto_auth_hmacsha512(
    message: string | Uint8Array,
    key: Uint8Array,
    outputFormat?: Uint8ArrayOutputFormat | null,
  ): Uint8Array;
  crypto_auth_hmacsha512(
    message: string | Uint8Array,
    key: Uint8Array,
    outputFormat: StringOutputFormat,
  ): string;

  crypto_auth_hmacsha512_keygen(outputFormat: StringOutputFormat): string;
  crypto_auth_hmacsha512_keygen(
    outputFormat?: Uint8ArrayOutputFormat | null,
  ): Uint8Array;

  crypto_auth_hmacsha512_verify(
    tag: Uint8Array,
    message: string | Uint8Array,
    key: Uint8Array,
  ): boolean;

  crypto_box_curve25519xchacha20poly1305_keypair(
    publicKey: Uint8Array,
    secretKey: Uint8Array,
    outputFormat: StringOutputFormat,
  ): StringKeyPair;
  crypto_box_curve25519xchacha20poly1305_keypair(
    publicKey: Uint8Array,
    secretKey: Uint8Array,
    outputFormat?: Uint8ArrayOutputFormat | null,
  ): KeyPair;

  crypto_box_curve25519xchacha20poly1305_seal(
    message: Uint8Array,
    publicKey: Uint8Array,
    outputFormat: StringOutputFormat,
  ): string;
  crypto_box_curve25519xchacha20poly1305_seal(
    message: Uint8Array,
    publicKey: Uint8Array,
    outputFormat?: Uint8ArrayOutputFormat | null,
  ): Uint8Array;

  crypto_box_curve25519xchacha20poly1305_seal_open(
    ciphertext: Uint8Array,
    publicKey: Uint8Array,
    secretKey: Uint8Array,
    outputFormat: StringOutputFormat,
  ): string;
  crypto_box_curve25519xchacha20poly1305_seal_open(
    ciphertext: Uint8Array,
    publicKey: Uint8Array,
    secretKey: Uint8Array,
    outputFormat?: Uint8ArrayOutputFormat | null,
  ): Uint8Array;

  crypto_core_ristretto255_add(
    p: Uint8Array,
    q: Uint8Array,
    outputFormat?: Uint8ArrayOutputFormat | null,
  ): Uint8Array;
  crypto_core_ristretto255_add(
    p: Uint8Array,
    q: Uint8Array,
    outputFormat: StringOutputFormat,
  ): string;

  crypto_core_ristretto255_from_hash(
    r: Uint8Array,
    outputFormat?: Uint8ArrayOutputFormat | null,
  ): Uint8Array;
  crypto_core_ristretto255_from_hash(
    r: Uint8Array,
    outputFormat: StringOutputFormat,
  ): string;

  crypto_core_ristretto255_is_valid_point(point: string | Uint8Array): boolean;

  crypto_core_ristretto255_random(
    outputFormat?: Uint8ArrayOutputFormat | null,
  ): Uint8Array;
  crypto_core_ristretto255_random(outputFormat: StringOutputFormat): string;

  crypto_core_ristretto255_scalar_add(
    x: Uint8Array,
    y: Uint8Array,
    outputFormat?: Uint8ArrayOutputFormat | null,
  ): Uint8Array;
  crypto_core_ristretto255_scalar_add(
    x: Uint8Array,
    y: Uint8Array,
    outputFormat: StringOutputFormat,
  ): string;

  crypto_core_ristretto255_scalar_complement(
    scalar: string | Uint8Array,
    outputFormat?: Uint8ArrayOutputFormat | null,
  ): Uint8Array;
  crypto_core_ristretto255_scalar_complement(
    scalar: string | Uint8Array,
    outputFormat: StringOutputFormat,
  ): string;

  crypto_core_ristretto255_scalar_invert(
    scalar: string | Uint8Array,
    outputFormat?: Uint8ArrayOutputFormat | null,
  ): Uint8Array;
  crypto_core_ristretto255_scalar_invert(
    scalar: string | Uint8Array,
    outputFormat: StringOutputFormat,
  ): string;

  crypto_core_ristretto255_scalar_mul(
    x: Uint8Array,
    y: Uint8Array,
    outputFormat?: Uint8ArrayOutputFormat | null,
  ): Uint8Array;
  crypto_core_ristretto255_scalar_mul(
    x: Uint8Array,
    y: Uint8Array,
    outputFormat: StringOutputFormat,
  ): string;

  crypto_core_ristretto255_scalar_negate(
    scalar: string | Uint8Array,
    outputFormat?: Uint8ArrayOutputFormat | null,
  ): Uint8Array;
  crypto_core_ristretto255_scalar_negate(
    scalar: string | Uint8Array,
    outputFormat: StringOutputFormat,
  ): string;

  crypto_core_ristretto255_scalar_random(
    outputFormat?: Uint8ArrayOutputFormat | null,
  ): Uint8Array;
  crypto_core_ristretto255_scalar_random(
    outputFormat: StringOutputFormat,
  ): string;

  crypto_core_ristretto255_scalar_reduce(
    secret: string | Uint8Array,
    outputFormat?: Uint8ArrayOutputFormat | null,
  ): Uint8Array;
  crypto_core_ristretto255_scalar_reduce(
    secret: string | Uint8Array,
    outputFormat: StringOutputFormat,
  ): string;

  crypto_core_ristretto255_scalar_sub(
    x: Uint8Array,
    y: Uint8Array,
    outputFormat?: Uint8ArrayOutputFormat | null,
  ): Uint8Array;
  crypto_core_ristretto255_scalar_sub(
    x: Uint8Array,
    y: Uint8Array,
    outputFormat: StringOutputFormat,
  ): string;

  crypto_core_ristretto255_sub(
    p: Uint8Array,
    q: Uint8Array,
    outputFormat?: Uint8ArrayOutputFormat | null,
  ): Uint8Array;
  crypto_core_ristretto255_sub(
    p: Uint8Array,
    q: Uint8Array,
    outputFormat: StringOutputFormat,
  ): string;

  crypto_generichash_blake2b_salt_personal(
    subkey_len: number,
    key: string | Uint8Array | null,
    id: Uint8Array,
    ctx: Uint8Array,
    outputFormat?: Uint8ArrayOutputFormat | null,
  ): Uint8Array;
  crypto_generichash_blake2b_salt_personal(
    subkey_len: number,
    key: string | Uint8Array | null,
    id: Uint8Array,
    ctx: Uint8Array,
    outputFormat: StringOutputFormat,
  ): string;

  crypto_hash_sha256(
    message: string | Uint8Array,
    outputFormat?: Uint8ArrayOutputFormat | null,
  ): Uint8Array;
  crypto_hash_sha256(
    message: string | Uint8Array,
    outputFormat: StringOutputFormat,
  ): string;

  crypto_hash_sha512(
    message: string | Uint8Array,
    outputFormat?: Uint8ArrayOutputFormat | null,
  ): Uint8Array;
  crypto_hash_sha512(
    message: string | Uint8Array,
    outputFormat: StringOutputFormat,
  ): string;

  crypto_onetimeauth(
    message: string | Uint8Array,
    key: Uint8Array,
    outputFormat?: Uint8ArrayOutputFormat | null,
  ): Uint8Array;
  crypto_onetimeauth(
    message: string | Uint8Array,
    key: Uint8Array,
    outputFormat: StringOutputFormat,
  ): string;

  crypto_onetimeauth_final(
    state_address: StateAddress,
    outputFormat?: Uint8ArrayOutputFormat | null,
  ): Uint8Array;
  crypto_onetimeauth_final(
    state_address: StateAddress,
    outputFormat: StringOutputFormat,
  ): string;

  crypto_onetimeauth_init(key?: string | Uint8Array | null): StateAddress;

  crypto_onetimeauth_keygen(
    outputFormat?: Uint8ArrayOutputFormat | null,
  ): Uint8Array;
  crypto_onetimeauth_keygen(outputFormat: StringOutputFormat): string;

  crypto_onetimeauth_update(
    state_address: StateAddress,
    message_chunk: string | Uint8Array,
  ): void;

  crypto_onetimeauth_verify(
    hash: Uint8Array,
    message: string | Uint8Array,
    key: Uint8Array,
  ): boolean;

  crypto_pwhash(
    keyLength: number,
    password: string | Uint8Array,
    salt: Uint8Array,
    opsLimit: number,
    memLimit: number,
    algorithm: number,
    outputFormat?: Uint8ArrayOutputFormat | null,
  ): Uint8Array;

  crypto_pwhash(
    keyLength: number,
    password: string | Uint8Array,
    salt: Uint8Array,
    opsLimit: number,
    memLimit: number,
    algorithm: number,
    outputFormat: StringOutputFormat,
  ): string;

  crypto_pwhash_str(
    password: string | Uint8Array,
    opsLimit: number,
    memLimit: number,
  ): string;

  crypto_pwhash_scryptsalsa208sha256(
    keyLength: number,
    password: string | Uint8Array,
    salt: Uint8Array,
    opsLimit: number,
    memLimit: number,
    outputFormat?: Uint8ArrayOutputFormat | null,
  ): Uint8Array;
  crypto_pwhash_scryptsalsa208sha256(
    keyLength: number,
    password: string | Uint8Array,
    salt: Uint8Array,
    opsLimit: number,
    memLimit: number,
    outputFormat: StringOutputFormat,
  ): string;

  crypto_pwhash_scryptsalsa208sha256_ll(
    password: string | Uint8Array,
    salt: string | Uint8Array,
    opsLimit: number,
    r: number,
    p: number,
    keyLength: number,
    outputFormat?: Uint8ArrayOutputFormat | null,
  ): Uint8Array;
  crypto_pwhash_scryptsalsa208sha256_ll(
    password: string | Uint8Array,
    salt: string | Uint8Array,
    opsLimit: number,
    r: number,
    p: number,
    keyLength: number,
    outputFormat: StringOutputFormat,
  ): string;

  crypto_pwhash_scryptsalsa208sha256_str(
    password: string | Uint8Array,
    opsLimit: number,
    memLimit: number,
  ): string;

  crypto_pwhash_scryptsalsa208sha256_str_verify(
    hashed_password: string,
    password: string | Uint8Array,
  ): boolean;

  crypto_scalarmult_ristretto255(
    scalar: Uint8Array,
    point: Uint8Array,
  ): Uint8Array;

  crypto_scalarmult_ristretto255_base(scalar: Uint8Array): Uint8Array;

  crypto_shorthash_siphashx24(
    message: string | Uint8Array,
    key: Uint8Array,
    outputFormat?: Uint8ArrayOutputFormat | null,
  ): Uint8Array;
  crypto_shorthash_siphashx24(
    message: string | Uint8Array,
    key: Uint8Array,
    outputFormat: StringOutputFormat,
  ): string;

  crypto_sign_ed25519_sk_to_pk(
    privateKey: Uint8Array,
    outputFormat?: Uint8ArrayOutputFormat | null,
  ): Uint8Array;
  crypto_sign_ed25519_sk_to_pk(
    privateKey: Uint8Array,
    outputFormat: StringOutputFormat,
  ): string;

  crypto_sign_ed25519_sk_to_seed(
    privateKey: Uint8Array,
    outputFormat?: Uint8ArrayOutputFormat | null,
  ): Uint8Array;
  crypto_sign_ed25519_sk_to_seed(
    privateKey: Uint8Array,
    outputFormat: StringOutputFormat,
  ): string;

  crypto_stream_chacha20(
    outLength: number,
    key: Uint8Array,
    nonce: Uint8Array,
    outputFormat: StringOutputFormat,
  ): string;
  crypto_stream_chacha20(
    outLength: number,
    key: Uint8Array,
    nonce: Uint8Array,
    outputFormat?: Uint8ArrayOutputFormat | null,
  ): Uint8Array;

  crypto_stream_chacha20_ietf_xor(
    input_message: string | Uint8Array,
    nonce: Uint8Array,
    key: Uint8Array,
    outputFormat?: Uint8ArrayOutputFormat | null,
  ): Uint8Array;
  crypto_stream_chacha20_ietf_xor(
    input_message: string | Uint8Array,
    nonce: Uint8Array,
    key: Uint8Array,
    outputFormat: StringOutputFormat,
  ): string;

  crypto_stream_chacha20_ietf_xor_ic(
    input_message: string | Uint8Array,
    nonce: Uint8Array,
    nonce_increment: number,
    key: Uint8Array,
    outputFormat?: Uint8ArrayOutputFormat | null,
  ): Uint8Array;
  crypto_stream_chacha20_ietf_xor_ic(
    input_message: string | Uint8Array,
    nonce: Uint8Array,
    nonce_increment: number,
    key: Uint8Array,
    outputFormat: StringOutputFormat,
  ): string;

  crypto_stream_chacha20_keygen(
    outputFormat?: Uint8ArrayOutputFormat | null,
  ): Uint8Array;
  crypto_stream_chacha20_keygen(outputFormat: StringOutputFormat): string;

  crypto_stream_chacha20_xor(
    input_message: string | Uint8Array,
    nonce: Uint8Array,
    key: Uint8Array,
    outputFormat?: Uint8ArrayOutputFormat | null,
  ): Uint8Array;
  crypto_stream_chacha20_xor(
    input_message: string | Uint8Array,
    nonce: Uint8Array,
    key: Uint8Array,
    outputFormat: StringOutputFormat,
  ): string;

  crypto_stream_chacha20_xor_ic(
    input_message: string | Uint8Array,
    nonce: Uint8Array,
    nonce_increment: number,
    key: Uint8Array,
    outputFormat?: Uint8ArrayOutputFormat | null,
  ): Uint8Array;
  crypto_stream_chacha20_xor_ic(
    input_message: string | Uint8Array,
    nonce: Uint8Array,
    nonce_increment: number,
    key: Uint8Array,
    outputFormat: StringOutputFormat,
  ): string;

  crypto_stream_keygen(
    outputFormat?: Uint8ArrayOutputFormat | null,
  ): Uint8Array;
  crypto_stream_keygen(outputFormat: StringOutputFormat): string;

  crypto_stream_xchacha20_keygen(
    outputFormat?: Uint8ArrayOutputFormat | null,
  ): Uint8Array;
  crypto_stream_xchacha20_keygen(outputFormat: StringOutputFormat): string;

  crypto_stream_xchacha20_xor(
    input_message: string | Uint8Array,
    nonce: Uint8Array,
    key: Uint8Array,
    outputFormat?: Uint8ArrayOutputFormat | null,
  ): Uint8Array;
  crypto_stream_xchacha20_xor(
    input_message: string | Uint8Array,
    nonce: Uint8Array,
    key: Uint8Array,
    outputFormat: StringOutputFormat,
  ): string;

  crypto_stream_xchacha20_xor_ic(
    input_message: string | Uint8Array,
    nonce: Uint8Array,
    nonce_increment: number,
    key: Uint8Array,
    outputFormat?: Uint8ArrayOutputFormat | null,
  ): Uint8Array;
  crypto_stream_xchacha20_xor_ic(
    input_message: string | Uint8Array,
    nonce: Uint8Array,
    nonce_increment: number,
    key: Uint8Array,
    outputFormat: StringOutputFormat,
  ): string;
}
