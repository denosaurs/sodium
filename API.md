# Libsodium.js wrapper - API usage

To learn about the role of each method, please refer to the original [documentation](https://doc.libsodium.org) of libsodium

List of existing types:

- `Buf`: An Uint8Array of a determined size. Used for keys, nonces, etc...
- `Unsized Buf`: An Uint8Array of an arbitrary size. Used for messages to sign, encrypt, hash, etc...
- `Minsized Buf`: An Uint8Array of a minimum size. Used for ciphertexts
- `Optional unsized buf`
- `Unsigned Integer`
- `Generichash state`
- `OneTimeAuth state`
- `Secretstream XChaCha20Poly1305 state`
- `Signature state`
- `Randombytes implementation`
- `String`
- outputFormat: A string indicating in which output format you want the result to be returned. Supported values are "uint8array", "text", "hex", "base64". Optional parameter. Not available on all functions. Defaults to uint8array.

Please note that a function that returns more than one variable will in fact return an object, which will contain the outputs in question and whose attributes will be named after the outputs' names

Please also note that these are the function available "in general" in the wrapper. The actual number of available functions in given build may be inferior to that, depending on what functions you choose to build to JS.

In addition to the main functions listed below, the library comes with a short list of helper methods. And here they are:

- `from_string(string)`: converts a standard string into a Uint8Array
- `to_string(buf)`: converts a Uint8Array to a standard string
- `to_hex(buf)`: returns the hexadecimal representation of the provided buf
- `from_hex(string)`: converts the provided hex-string into a Uint8Array and returns it
- `to_base64(buf, variant)`: returns the base64 representation of the provided buf
- `from_base64(string, variant)`: tries to convert the supposedly base64 string into a Uint8Array
- `symbols()`: returns a list of the currently methods and constants
- `raw`: attribute referencing the raw emscripten-built libsodium library that we are wrapping

## crypto_aead_chacha20poly1305_decrypt

Function

**Parameters:**

- `secret_nonce`: Optional unsized buf
- `ciphertext`: Minsized buf
- `additional_data`: Optional unsized buf
- `public_nonce`: Buf (size: undefined)
- `key`: Buf (size: undefined)

**Outputs:**

- `message`: Buf (size: undefined)

## crypto_aead_chacha20poly1305_decrypt_detached

Function

**Parameters:**

- `secret_nonce`: Optional unsized buf
- `ciphertext`: Unsized buf
- `mac`: Buf (size: undefined)
- `additional_data`: Optional unsized buf
- `public_nonce`: Buf (size: undefined)
- `key`: Buf (size: undefined)

**Outputs:**

- `message`: Buf (size: undefined)

## crypto_aead_chacha20poly1305_encrypt

Function

**Parameters:**

- `message`: Unsized buf
- `additional_data`: Optional unsized buf
- `secret_nonce`: Optional unsized buf
- `public_nonce`: Buf (size: undefined)
- `key`: Buf (size: undefined)

**Outputs:**

- `ciphertext`: Buf (size: undefined)

## crypto_aead_chacha20poly1305_encrypt_detached

Function

**Parameters:**

- `message`: Unsized buf
- `additional_data`: Optional unsized buf
- `secret_nonce`: Optional unsized buf
- `public_nonce`: Buf (size: undefined)
- `key`: Buf (size: undefined)

**Outputs:**

- `ciphertext`: Buf (size: undefined)
- `mac`: Buf (size: undefined)

## crypto_aead_chacha20poly1305_ietf_decrypt

Function

**Parameters:**

- `secret_nonce`: Optional unsized buf
- `ciphertext`: Minsized buf
- `additional_data`: Optional unsized buf
- `public_nonce`: Buf (size: undefined)
- `key`: Buf (size: undefined)

**Outputs:**

- `message`: Buf (size: undefined)

## crypto_aead_chacha20poly1305_ietf_decrypt_detached

Function

**Parameters:**

- `secret_nonce`: Optional unsized buf
- `ciphertext`: Unsized buf
- `mac`: Buf (size: undefined)
- `additional_data`: Optional unsized buf
- `public_nonce`: Buf (size: undefined)
- `key`: Buf (size: undefined)

**Outputs:**

- `message`: Buf (size: undefined)

## crypto_aead_chacha20poly1305_ietf_encrypt

Function

**Parameters:**

- `message`: Unsized buf
- `additional_data`: Optional unsized buf
- `secret_nonce`: Optional unsized buf
- `public_nonce`: Buf (size: undefined)
- `key`: Buf (size: undefined)

**Outputs:**

- `ciphertext`: Buf (size: undefined)

## crypto_aead_chacha20poly1305_ietf_encrypt_detached

Function

**Parameters:**

- `message`: Unsized buf
- `additional_data`: Optional unsized buf
- `secret_nonce`: Optional unsized buf
- `public_nonce`: Buf (size: undefined)
- `key`: Buf (size: undefined)

**Outputs:**

- `ciphertext`: Buf (size: undefined)
- `mac`: Buf (size: undefined)

## crypto_aead_chacha20poly1305_ietf_keygen

Function

**Parameters:**

**Outputs:**

- `output`: Buf (size: undefined)

## crypto_aead_chacha20poly1305_keygen

Function

**Parameters:**

**Outputs:**

- `output`: Buf (size: undefined)

## crypto_aead_xchacha20poly1305_ietf_decrypt

Function

**Parameters:**

- `secret_nonce`: Optional unsized buf
- `ciphertext`: Minsized buf
- `additional_data`: Optional unsized buf
- `public_nonce`: Buf (size: undefined)
- `key`: Buf (size: undefined)

**Outputs:**

- `message`: Buf (size: undefined)

## crypto_aead_xchacha20poly1305_ietf_decrypt_detached

Function

**Parameters:**

- `secret_nonce`: Optional unsized buf
- `ciphertext`: Unsized buf
- `mac`: Buf (size: undefined)
- `additional_data`: Optional unsized buf
- `public_nonce`: Buf (size: undefined)
- `key`: Buf (size: undefined)

**Outputs:**

- `message`: Buf (size: undefined)

## crypto_aead_xchacha20poly1305_ietf_encrypt

Function

**Parameters:**

- `message`: Unsized buf
- `additional_data`: Optional unsized buf
- `secret_nonce`: Optional unsized buf
- `public_nonce`: Buf (size: undefined)
- `key`: Buf (size: undefined)

**Outputs:**

- `ciphertext`: Buf (size: undefined)

## crypto_aead_xchacha20poly1305_ietf_encrypt_detached

Function

**Parameters:**

- `message`: Unsized buf
- `additional_data`: Optional unsized buf
- `secret_nonce`: Optional unsized buf
- `public_nonce`: Buf (size: undefined)
- `key`: Buf (size: undefined)

**Outputs:**

- `ciphertext`: Buf (size: undefined)
- `mac`: Buf (size: undefined)

## crypto_aead_xchacha20poly1305_ietf_keygen

Function

**Parameters:**

**Outputs:**

- `output`: Buf (size: undefined)

## crypto_auth

Function

**Parameters:**

- `message`: Unsized buf
- `key`: Buf (size: undefined)

**Outputs:**

- `tag`: Buf (size: undefined)

## crypto_auth_hmacsha256

Function

**Parameters:**

- `message`: Unsized buf
- `key`: Buf (size: undefined)

**Outputs:**

- `hash`: Buf (size: undefined)

## crypto_auth_hmacsha256_keygen

Function

**Parameters:**

**Outputs:**

- `output`: Buf (size: undefined)

## crypto_auth_hmacsha256_verify

Function

**Parameters:**

- `tag`: Buf (size: undefined)
- `message`: Unsized buf
- `key`: Buf (size: undefined)

**Outputs:**
Boolean. True if method executed with success; false otherwise

## crypto_auth_hmacsha512

Function

**Parameters:**

- `message`: Unsized buf
- `key`: Buf (size: undefined)

**Outputs:**

- `hash`: Buf (size: undefined)

## crypto_auth_hmacsha512_keygen

Function

**Parameters:**

**Outputs:**

- `output`: Buf (size: undefined)

## crypto_auth_hmacsha512_verify

Function

**Parameters:**

- `tag`: Buf (size: undefined)
- `message`: Unsized buf
- `key`: Buf (size: undefined)

**Outputs:**
Boolean. True if method executed with success; false otherwise

## crypto_auth_keygen

Function

**Parameters:**

**Outputs:**

- `output`: Buf (size: undefined)

## crypto_auth_verify

Function

**Parameters:**

- `tag`: Buf (size: undefined)
- `message`: Unsized buf
- `key`: Buf (size: undefined)

**Outputs:**
Boolean. True if method executed with success; false otherwise

## crypto_box_beforenm

Function

**Parameters:**

- `publicKey`: Buf (size: undefined)
- `privateKey`: Buf (size: undefined)

**Outputs:**

- `sharedKey`: Buf (size: undefined)

## crypto_box_curve25519xchacha20poly1305_keypair

Function

**Parameters:**

**Outputs:**

- `publicKey`: Buf (size: undefined)
- `secretKey`: Buf (size: undefined)

## crypto_box_curve25519xchacha20poly1305_seal

Function

**Parameters:**

- `message`: Unsized buf
- `publicKey`: Buf (size: undefined)

**Outputs:**

- `ciphertext`: Buf (size: undefined)

## crypto_box_curve25519xchacha20poly1305_seal_open

Function

**Parameters:**

- `ciphertext`: Minsized buf
- `publicKey`: Buf (size: undefined)
- `secretKey`: Buf (size: undefined)

**Outputs:**

- `plaintext`: Buf (size: undefined)

## crypto_box_detached

Function

**Parameters:**

- `message`: Unsized buf
- `nonce`: Buf (size: undefined)
- `publicKey`: Buf (size: undefined)
- `privateKey`: Buf (size: undefined)

**Outputs:**

- `ciphertext`: Buf (size: undefined)
- `mac`: Buf (size: undefined)

## crypto_box_easy

Function

**Parameters:**

- `message`: Unsized buf
- `nonce`: Buf (size: undefined)
- `publicKey`: Buf (size: undefined)
- `privateKey`: Buf (size: undefined)

**Outputs:**

- `ciphertext`: Buf (size: undefined)

## crypto_box_easy_afternm

Function

**Parameters:**

- `message`: Unsized buf
- `nonce`: Buf (size: undefined)
- `sharedKey`: Buf (size: undefined)

**Outputs:**

- `ciphertext`: Buf (size: undefined)

## crypto_box_keypair

Function

**Parameters:**

**Outputs:**

- `publicKey`: Buf (size: undefined)
- `privateKey`: Buf (size: undefined)

## crypto_box_open_detached

Function

**Parameters:**

- `ciphertext`: Unsized buf
- `mac`: Buf (size: undefined)
- `nonce`: Buf (size: undefined)
- `publicKey`: Buf (size: undefined)
- `privateKey`: Buf (size: undefined)

**Outputs:**

- `plaintext`: Buf (size: undefined)

## crypto_box_open_easy

Function

**Parameters:**

- `ciphertext`: Minsized buf
- `nonce`: Buf (size: undefined)
- `publicKey`: Buf (size: undefined)
- `privateKey`: Buf (size: undefined)

**Outputs:**

- `plaintext`: Buf (size: undefined)

## crypto_box_open_easy_afternm

Function

**Parameters:**

- `ciphertext`: Unsized buf
- `nonce`: Buf (size: undefined)
- `sharedKey`: Buf (size: undefined)

**Outputs:**

- `plaintext`: Buf (size: undefined)

## crypto_box_seal

Function

**Parameters:**

- `message`: Unsized buf
- `publicKey`: Buf (size: undefined)

**Outputs:**

- `ciphertext`: Buf (size: undefined)

## crypto_box_seal_open

Function

**Parameters:**

- `ciphertext`: Minsized buf
- `publicKey`: Buf (size: undefined)
- `privateKey`: Buf (size: undefined)

**Outputs:**

- `plaintext`: Buf (size: undefined)

## crypto_box_seed_keypair

Function

**Parameters:**

- `seed`: Buf (size: undefined)

**Outputs:**

- `publicKey`: Buf (size: undefined)
- `privateKey`: Buf (size: undefined)

## crypto_core_ristretto255_add

Function

**Parameters:**

- `p`: Buf (size: undefined)
- `q`: Buf (size: undefined)

**Outputs:**

- `r`: Buf (size: undefined)

## crypto_core_ristretto255_from_hash

Function

**Parameters:**

- `r`: Unsized buf

**Outputs:**

- `point`: Buf (size: undefined)

## crypto_core_ristretto255_is_valid_point

Function

**Parameters:**

- `point`: Unsized buf

**Outputs:**
Boolean. True if method executed with success; false otherwise

## crypto_core_ristretto255_random

Function

**Parameters:**

**Outputs:**

- `p`: Buf (size: undefined)

## crypto_core_ristretto255_scalar_add

Function

**Parameters:**

- `x`: Buf (size: undefined)
- `y`: Buf (size: undefined)

**Outputs:**

- `z`: Buf (size: undefined)

## crypto_core_ristretto255_scalar_complement

Function

**Parameters:**

- `s`: Unsized buf

**Outputs:**

- `comp`: Buf (size: undefined)

## crypto_core_ristretto255_scalar_invert

Function

**Parameters:**

- `s`: Unsized buf

**Outputs:**

- `recip`: Buf (size: undefined)

## crypto_core_ristretto255_scalar_mul

Function

**Parameters:**

- `x`: Buf (size: undefined)
- `y`: Buf (size: undefined)

**Outputs:**

- `z`: Buf (size: undefined)

## crypto_core_ristretto255_scalar_negate

Function

**Parameters:**

- `s`: Unsized buf

**Outputs:**

- `neg`: Buf (size: undefined)

## crypto_core_ristretto255_scalar_random

Function

**Parameters:**

**Outputs:**

- `r`: Buf (size: undefined)

## crypto_core_ristretto255_scalar_reduce

Function

**Parameters:**

- `sample`: Unsized buf

**Outputs:**

- `result`: Buf (size: undefined)

## crypto_core_ristretto255_scalar_sub

Function

**Parameters:**

- `x`: Buf (size: undefined)
- `y`: Buf (size: undefined)

**Outputs:**

- `z`: Buf (size: undefined)

## crypto_core_ristretto255_sub

Function

**Parameters:**

- `p`: Buf (size: undefined)
- `q`: Buf (size: undefined)

**Outputs:**

- `r`: Buf (size: undefined)

## crypto_generichash

Function

**Parameters:**

- `hash_length`: Unsigned Integer
- `message`: Unsized buf
- `key`: Optional unsized buf

**Outputs:**

- `hash`: Buf (size: undefined)

## crypto_generichash_blake2b_salt_personal

Function

**Parameters:**

- `subkey_len`: Unsigned Integer
- `key`: Optional unsized buf
- `id`: Buf (size: undefined)
- `ctx`: Buf (size: undefined)

**Outputs:**

- `subkey`: Buf (size: undefined)

## crypto_generichash_final

Function

**Parameters:**

- `state_address`: Generichash state address
- `hash_length`: Unsigned Integer

**Outputs:**

- `hash`: Buf (size: undefined)

## crypto_generichash_init

Function

**Parameters:**

- `key`: Optional unsized buf
- `hash_length`: Unsigned Integer

**Outputs:**

- `state`: Generichash state

## crypto_generichash_keygen

Function

**Parameters:**

**Outputs:**

- `output`: Buf (size: undefined)

## crypto_generichash_update

Function

**Parameters:**

- `state_address`: Generichash state address
- `message_chunk`: Unsized buf

**Outputs:**
Boolean. True if method executed with success; false otherwise

## crypto_hash

Function

**Parameters:**

- `message`: Unsized buf

**Outputs:**

- `hash`: Buf (size: undefined)

## crypto_hash_sha256

Function

**Parameters:**

- `message`: Unsized buf

**Outputs:**

- `hash`: Buf (size: undefined)

## crypto_hash_sha256_final

Function

**Parameters:**

- `state_address`: Sha256 state address

**Outputs:**

- `hash`: Buf (size: undefined)

## crypto_hash_sha256_init

Function

**Parameters:**

**Outputs:**

- `state`: Sha256 state

## crypto_hash_sha256_update

Function

**Parameters:**

- `state_address`: Sha256 state address
- `message_chunk`: Unsized buf

**Outputs:**
Boolean. True if method executed with success; false otherwise

## crypto_hash_sha512

Function

**Parameters:**

- `message`: Unsized buf

**Outputs:**

- `hash`: Buf (size: undefined)

## crypto_hash_sha512_final

Function

**Parameters:**

- `state_address`: Sha512 state address

**Outputs:**

- `hash`: Buf (size: undefined)

## crypto_hash_sha512_init

Function

**Parameters:**

**Outputs:**

- `state`: Sha512 state

## crypto_hash_sha512_update

Function

**Parameters:**

- `state_address`: Sha512 state address
- `message_chunk`: Unsized buf

**Outputs:**
Boolean. True if method executed with success; false otherwise

## crypto_kdf_derive_from_key

Function

**Parameters:**

- `subkey_len`: Unsigned Integer
- `subkey_id`: Unsigned Integer
- `ctx`: A string
- `key`: Buf (size: undefined)

**Outputs:**

- `subkey`: Buf (size: undefined)

## crypto_kdf_keygen

Function

**Parameters:**

**Outputs:**

- `output`: Buf (size: undefined)

## crypto_kx_client_session_keys

Function

**Parameters:**

- `clientPublicKey`: Buf (size: undefined)
- `clientSecretKey`: Buf (size: undefined)
- `serverPublicKey`: Buf (size: undefined)

**Outputs:**

- `sharedRx`: Buf (size: undefined)
- `sharedTx`: Buf (size: undefined)

## crypto_kx_keypair

Function

**Parameters:**

**Outputs:**

- `publicKey`: Buf (size: undefined)
- `privateKey`: Buf (size: undefined)

## crypto_kx_seed_keypair

Function

**Parameters:**

- `seed`: Buf (size: undefined)

**Outputs:**

- `publicKey`: Buf (size: undefined)
- `privateKey`: Buf (size: undefined)

## crypto_kx_server_session_keys

Function

**Parameters:**

- `serverPublicKey`: Buf (size: undefined)
- `serverSecretKey`: Buf (size: undefined)
- `clientPublicKey`: Buf (size: undefined)

**Outputs:**

- `sharedRx`: Buf (size: undefined)
- `sharedTx`: Buf (size: undefined)

## crypto_onetimeauth

Function

**Parameters:**

- `message`: Unsized buf
- `key`: Buf (size: undefined)

**Outputs:**

- `hash`: Buf (size: undefined)

## crypto_onetimeauth_final

Function

**Parameters:**

- `state_address`: OneTimeAuth state address

**Outputs:**

- `hash`: Buf (size: undefined)

## crypto_onetimeauth_init

Function

**Parameters:**

- `key`: Optional unsized buf

**Outputs:**

- `state`: OneTimeAuth state

## crypto_onetimeauth_keygen

Function

**Parameters:**

**Outputs:**

- `output`: Buf (size: undefined)

## crypto_onetimeauth_update

Function

**Parameters:**

- `state_address`: OneTimeAuth state address
- `message_chunk`: Unsized buf

**Outputs:**
Boolean. True if method executed with success; false otherwise

## crypto_onetimeauth_verify

Function

**Parameters:**

- `hash`: Buf (size: undefined)
- `message`: Unsized buf
- `key`: Buf (size: undefined)

**Outputs:**
Boolean. True if method executed with success; false otherwise

## crypto_pwhash

Function

**Parameters:**

- `keyLength`: Unsigned Integer
- `password`: Unsized buf
- `salt`: Buf (size: undefined)
- `opsLimit`: Unsigned Integer
- `memLimit`: Unsigned Integer
- `algorithm`: Unsigned Integer

**Outputs:**

- `derivedKey`: Buf (size: undefined)

## crypto_pwhash_scryptsalsa208sha256

Function

**Parameters:**

- `keyLength`: Unsigned Integer
- `password`: Unsized buf
- `salt`: Buf (size: undefined)
- `opsLimit`: Unsigned Integer
- `memLimit`: Unsigned Integer

**Outputs:**

- `derivedKey`: Buf (size: undefined)

## crypto_pwhash_scryptsalsa208sha256_ll

Function

**Parameters:**

- `password`: Unsized buf
- `salt`: Unsized buf
- `opsLimit`: Unsigned Integer
- `r`: Unsigned Integer
- `p`: Unsigned Integer
- `keyLength`: Unsigned Integer

**Outputs:**

- `derivedKey`: Buf (size: undefined)

## crypto_pwhash_scryptsalsa208sha256_str

Function

**Parameters:**

- `password`: Unsized buf
- `opsLimit`: Unsigned Integer
- `memLimit`: Unsigned Integer

**Outputs:**

- `hashed_password`: Buf (size: undefined)

## crypto_pwhash_scryptsalsa208sha256_str_verify

Function

**Parameters:**

- `hashed_password`: A string
- `password`: Unsized buf

**Outputs:**
Boolean. True if method executed with success; false otherwise

## crypto_pwhash_str

Function

**Parameters:**

- `password`: Unsized buf
- `opsLimit`: Unsigned Integer
- `memLimit`: Unsigned Integer

**Outputs:**

- `hashed_password`: Buf (size: undefined)

## crypto_pwhash_str_needs_rehash

Function

**Parameters:**

- `hashed_password`: A string
- `opsLimit`: Unsigned Integer
- `memLimit`: Unsigned Integer

**Outputs:**
Boolean. True if method executed with success; false otherwise

## crypto_pwhash_str_verify

Function

**Parameters:**

- `hashed_password`: A string
- `password`: Unsized buf

**Outputs:**
Boolean. True if method executed with success; false otherwise

## crypto_scalarmult

Function

**Parameters:**

- `privateKey`: Buf (size: undefined)
- `publicKey`: Buf (size: undefined)

**Outputs:**

- `sharedSecret`: Buf (size: undefined)

## crypto_scalarmult_base

Function

**Parameters:**

- `privateKey`: Buf (size: undefined)

**Outputs:**

- `publicKey`: Buf (size: undefined)

## crypto_scalarmult_ristretto255

Function

**Parameters:**

- `scalar`: Buf (size: undefined)
- `privateKey`: Buf (size: undefined)

**Outputs:**

- `q`: Buf (size: undefined)

## crypto_scalarmult_ristretto255_base

Function

**Parameters:**

- `scalar`: Unsized buf

**Outputs:**

- `element`: Buf (size: undefined)

## crypto_secretbox_detached

Function

**Parameters:**

- `message`: Unsized buf
- `nonce`: Buf (size: undefined)
- `key`: Buf (size: undefined)

**Outputs:**

- `cipher`: Buf (size: undefined)
- `mac`: Buf (size: undefined)

## crypto_secretbox_easy

Function

**Parameters:**

- `message`: Unsized buf
- `nonce`: Buf (size: undefined)
- `key`: Buf (size: undefined)

**Outputs:**

- `cipher`: Buf (size: undefined)

## crypto_secretbox_keygen

Function

**Parameters:**

**Outputs:**

- `output`: Buf (size: undefined)

## crypto_secretbox_open_detached

Function

**Parameters:**

- `ciphertext`: Unsized buf
- `mac`: Buf (size: undefined)
- `nonce`: Buf (size: undefined)
- `key`: Buf (size: undefined)

**Outputs:**

- `message`: Buf (size: undefined)

## crypto_secretbox_open_easy

Function

**Parameters:**

- `ciphertext`: Minsized buf
- `nonce`: Buf (size: undefined)
- `key`: Buf (size: undefined)

**Outputs:**

- `message`: Buf (size: undefined)

## crypto_secretstream_xchacha20poly1305_init_pull

Function

**Parameters:**

- `header`: Buf (size: undefined)
- `key`: Buf (size: undefined)

**Outputs:**

- `state`: Secretstream XChaCha20Poly1305 state

## crypto_secretstream_xchacha20poly1305_init_push

Function

**Parameters:**

- `key`: Buf (size: undefined)

**Outputs:**

- `state`: Secretstream XChaCha20Poly1305 state
- `header`: Buf (size: undefined)

## crypto_secretstream_xchacha20poly1305_keygen

Function

**Parameters:**

**Outputs:**

- `output`: Buf (size: undefined)

## crypto_secretstream_xchacha20poly1305_pull

Function

**Parameters:**

- `state_address`: Secretstream XChaCha20Poly1305 state address
- `cipher`: Minsized buf
- `ad`: Optional unsized buf

**Outputs:**

- `message_chunk`: Buf (size: undefined)

## crypto_secretstream_xchacha20poly1305_push

Function

**Parameters:**

- `state_address`: Secretstream XChaCha20Poly1305 state address
- `message_chunk`: Unsized buf
- `ad`: Optional unsized buf
- `tag`: Unsigned Integer

**Outputs:**

- `cipher`: Buf (size: undefined)

## crypto_secretstream_xchacha20poly1305_rekey

Function

**Parameters:**

- `state_address`: Secretstream XChaCha20Poly1305 state address

**Outputs:**
Boolean. True if method executed with success; false otherwise

## crypto_shorthash

Function

**Parameters:**

- `message`: Unsized buf
- `key`: Buf (size: undefined)

**Outputs:**

- `hash`: Buf (size: undefined)

## crypto_shorthash_keygen

Function

**Parameters:**

**Outputs:**

- `output`: Buf (size: undefined)

## crypto_shorthash_siphashx24

Function

**Parameters:**

- `message`: Unsized buf
- `key`: Buf (size: undefined)

**Outputs:**

- `hash`: Buf (size: undefined)

## crypto_sign

Function

**Parameters:**

- `message`: Unsized buf
- `privateKey`: Buf (size: undefined)

**Outputs:**

- `signature`: Buf (size: undefined)

## crypto_sign_detached

Function

**Parameters:**

- `message`: Unsized buf
- `privateKey`: Buf (size: undefined)

**Outputs:**

- `signature`: Buf (size: undefined)

## crypto_sign_ed25519_pk_to_curve25519

Function

**Parameters:**

- `edPk`: Buf (size: undefined)

**Outputs:**

- `cPk`: Buf (size: undefined)

## crypto_sign_ed25519_sk_to_curve25519

Function

**Parameters:**

- `edSk`: Buf (size: undefined)

**Outputs:**

- `cSk`: Buf (size: undefined)

## crypto_sign_ed25519_sk_to_pk

Function

**Parameters:**

- `privateKey`: Buf (size: undefined)

**Outputs:**

- `publicKey`: Buf (size: undefined)

## crypto_sign_ed25519_sk_to_seed

Function

**Parameters:**

- `privateKey`: Buf (size: undefined)

**Outputs:**

- `seed`: Buf (size: undefined)

## crypto_sign_final_create

Function

**Parameters:**

- `state_address`: Signature state address
- `privateKey`: Buf (size: undefined)

**Outputs:**

- `signature`: Buf (size: undefined)

## crypto_sign_final_verify

Function

**Parameters:**

- `state_address`: Signature state address
- `signature`: Buf (size: undefined)
- `publicKey`: Buf (size: undefined)

**Outputs:**
Boolean. True if method executed with success; false otherwise

## crypto_sign_init

Function

**Parameters:**

**Outputs:**

- `state`: Signature state

## crypto_sign_keypair

Function

**Parameters:**

**Outputs:**

- `publicKey`: Buf (size: undefined)
- `privateKey`: Buf (size: undefined)

## crypto_sign_open

Function

**Parameters:**

- `signedMessage`: Minsized buf
- `publicKey`: Buf (size: undefined)

**Outputs:**

- `message`: Buf (size: undefined)

## crypto_sign_seed_keypair

Function

**Parameters:**

- `seed`: Buf (size: undefined)

**Outputs:**

- `publicKey`: Buf (size: undefined)
- `privateKey`: Buf (size: undefined)

## crypto_sign_update

Function

**Parameters:**

- `state_address`: Signature state address
- `message_chunk`: Unsized buf

**Outputs:**
Boolean. True if method executed with success; false otherwise

## crypto_sign_verify_detached

Function

**Parameters:**

- `signature`: Buf (size: undefined)
- `message`: Unsized buf
- `publicKey`: Buf (size: undefined)

**Outputs:**
Boolean. True if method executed with success; false otherwise

## crypto_stream_chacha20

Function

**Parameters:**

- `outLength`: Unsigned Integer
- `key`: Buf (size: undefined)
- `nonce`: Buf (size: undefined)

**Outputs:**

- `out`: Buf (size: undefined)

## crypto_stream_chacha20_ietf_xor

Function

**Parameters:**

- `input_message`: Unsized buf
- `nonce`: Buf (size: undefined)
- `key`: Buf (size: undefined)

**Outputs:**

- `output_message`: Buf (size: undefined)

## crypto_stream_chacha20_ietf_xor_ic

Function

**Parameters:**

- `input_message`: Unsized buf
- `nonce`: Buf (size: undefined)
- `nonce_increment`: Unsigned Integer
- `key`: Buf (size: undefined)

**Outputs:**

- `output_message`: Buf (size: undefined)

## crypto_stream_chacha20_keygen

Function

**Parameters:**

**Outputs:**

- `output`: Buf (size: undefined)

## crypto_stream_chacha20_xor

Function

**Parameters:**

- `input_message`: Unsized buf
- `nonce`: Buf (size: undefined)
- `key`: Buf (size: undefined)

**Outputs:**

- `output_message`: Buf (size: undefined)

## crypto_stream_chacha20_xor_ic

Function

**Parameters:**

- `input_message`: Unsized buf
- `nonce`: Buf (size: undefined)
- `nonce_increment`: Unsigned Integer
- `key`: Buf (size: undefined)

**Outputs:**

- `output_message`: Buf (size: undefined)

## crypto_stream_keygen

Function

**Parameters:**

**Outputs:**

- `output`: Buf (size: undefined)

## crypto_stream_xchacha20_keygen

Function

**Parameters:**

**Outputs:**

- `output`: Buf (size: undefined)

## crypto_stream_xchacha20_xor

Function

**Parameters:**

- `input_message`: Unsized buf
- `nonce`: Buf (size: undefined)
- `key`: Buf (size: undefined)

**Outputs:**

- `output_message`: Buf (size: undefined)

## crypto_stream_xchacha20_xor_ic

Function

**Parameters:**

- `input_message`: Unsized buf
- `nonce`: Buf (size: undefined)
- `nonce_increment`: Unsigned Integer
- `key`: Buf (size: undefined)

**Outputs:**

- `output_message`: Buf (size: undefined)

## randombytes_buf

Function

**Parameters:**

- `length`: Unsigned Integer

**Outputs:**

- `output`: Buf (size: undefined)

## randombytes_buf_deterministic

Function

**Parameters:**

- `length`: Unsigned Integer
- `seed`: Buf (size: undefined)

**Outputs:**

- `output`: Buf (size: undefined)

## randombytes_close

Function

**Parameters:**

**Outputs:**
Boolean. True if method executed with success; false otherwise

## randombytes_random

Function

**Parameters:**

**Outputs:**
Boolean. True if method executed with success; false otherwise

## randombytes_set_implementation

Function

**Parameters:**

- `implementation`: Randombytes implementation

**Outputs:**
Boolean. True if method executed with success; false otherwise

## randombytes_stir

Function

**Parameters:**

**Outputs:**
Boolean. True if method executed with success; false otherwise

## randombytes_uniform

Function

**Parameters:**

- `upper_bound`: Unsigned Integer

**Outputs:**
Boolean. True if method executed with success; false otherwise

## sodium_version_string

Function

**Parameters:**

**Outputs:**
Boolean. True if method executed with success; false otherwise
