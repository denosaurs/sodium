// Copyright 2020-present the denosaurs team. All rights reserved. MIT license.

import { assert, assertEquals, assertNotEquals, encode } from "./test_deps.ts";
import _sodium, { Sodium } from "../basic.ts";

async function initSodium(): Promise<Sodium> {
  await _sodium.ready;
  return _sodium;
}

function bufferFrom(value: string | Uint8Array, format?: "hex"): Uint8Array {
  if (typeof value !== "string") return value;
  if (format === "hex") {
    const match = value.match(/.{1,2}/g);
    if (!match) return new Uint8Array();
    return new Uint8Array(match.map((byte) => parseInt(byte, 16)));
  } else {
    return encode(value);
  }
}

let sodium: Sodium = await initSodium();

Deno.test({
  name: "crypto_aead_xchacha20poly1305_ietf_*",
  fn(): void {
    let plaintext = bufferFrom(
      "4c616469657320616e642047656e746c656d656e206f662074686520636c6173" +
        "73206f66202739393a204966204920636f756c64206f6666657220796f75206f" +
        "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73" +
        "637265656e20776f756c642062652069742e",
      "hex",
    );
    let assocData = bufferFrom("50515253c0c1c2c3c4c5c6c7", "hex");
    let nonce = bufferFrom(
      "404142434445464748494a4b4c4d4e4f5051525354555657",
      "hex",
    );
    let key = bufferFrom(
      "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
      "hex",
    );

    let ciphertext = bufferFrom(
      sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext,
        assocData,
        null,
        nonce,
        key,
      ),
    );

    let expected = bufferFrom(
      "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb" +
        "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452" +
        "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9" +
        "21f9664c97637da9768812f615c68b13b52e" +
        "c0875924c1c7987947deafd8780acf49",
      "hex",
    );
    assertEquals(ciphertext.toString(), expected.toString());

    let decrypted = bufferFrom(
      sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null,
        ciphertext,
        assocData,
        nonce,
        key,
      ),
    );
    assertEquals(decrypted.toString(), plaintext.toString());

    let randomKey = bufferFrom(
      sodium.crypto_aead_xchacha20poly1305_ietf_keygen(),
    );

    let ciphertext2 = bufferFrom(
      sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext,
        null,
        null,
        nonce,
        randomKey,
      ),
    );
    decrypted = bufferFrom(
      sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null,
        ciphertext2,
        null,
        nonce,
        randomKey,
      ),
    );
    assertEquals(decrypted.toString(), plaintext.toString());
    assertNotEquals(ciphertext.toString(), ciphertext2.toString());
  },
});

Deno.test({
  name: "crypto_auth",
  fn(): void {
    let key = bufferFrom(sodium.crypto_auth_keygen());
    let message =
      "Science, math, technology, engineering, and compassion for others.";
    let mac = bufferFrom(sodium.crypto_auth(message, key));
    assert(sodium.crypto_auth_verify(mac, message, key) === true);
  },
});

Deno.test({
  name: "crypto_box",
  fn(): void {
    let plaintext =
      "Science, math, technology, engineering, and compassion for others.";

    let aliceKeypair = sodium.crypto_box_keypair();
    let aliceSecret = bufferFrom(aliceKeypair.privateKey);
    let alicePublic = bufferFrom(aliceKeypair.publicKey);
    let bobKeypair = sodium.crypto_box_keypair();
    let bobSecret = bufferFrom(bobKeypair.privateKey);
    let bobPublic = bufferFrom(bobKeypair.publicKey);

    let nonce = sodium.randombytes_buf(24);

    let ciphertext = bufferFrom(
      sodium.crypto_box_easy(plaintext, nonce, bobPublic, aliceSecret),
    );
    let decrypted = bufferFrom(
      sodium.crypto_box_open_easy(ciphertext, nonce, alicePublic, bobSecret),
    );
    assertEquals(decrypted.toString(), bufferFrom(plaintext).toString());
  },
});

Deno.test({
  name: "crypto_box_seal",
  fn(): void {
    let plaintext =
      "Science, math, technology, engineering, and compassion for others.";

    let aliceKeypair = sodium.crypto_box_keypair();
    let aliceSecret = bufferFrom(aliceKeypair.privateKey);
    let alicePublic = bufferFrom(aliceKeypair.publicKey);

    let ciphertext = bufferFrom(sodium.crypto_box_seal(plaintext, alicePublic));
    let decrypted = bufferFrom(
      sodium.crypto_box_seal_open(ciphertext, alicePublic, aliceSecret),
    );
    assertEquals(decrypted.toString(), bufferFrom(plaintext).toString());
  },
});

Deno.test({
  name: "crypto_generichash",
  fn(): void {
    let message =
      "Science, math, technology, engineering, and compassion for others.";
    let piece1 = message.slice(0, 16);
    let piece2 = message.slice(16);

    let hash1 = bufferFrom(sodium.crypto_generichash(32, message));
    assertEquals(
      hash1.toString(),
      bufferFrom(
        "47c1fdbde32b30b9c54dd47cf88ba92d2d05df1265e342c9563ed56aee84ab02",
        "hex",
      ).toString(),
    );

    let state = sodium.crypto_generichash_init(null, 32);
    sodium.crypto_generichash_update(state, piece1);
    sodium.crypto_generichash_update(state, piece2);
    let hash2 = bufferFrom(sodium.crypto_generichash_final(state, 32));
    assertEquals(hash1.toString(), hash2.toString());

    let key = bufferFrom(sodium.crypto_generichash_keygen());
    hash1 = bufferFrom(sodium.crypto_generichash(32, message, key));
    state = sodium.crypto_generichash_init(key, 32);
    sodium.crypto_generichash_update(state, piece1);
    sodium.crypto_generichash_update(state, piece2);
    hash2 = bufferFrom(sodium.crypto_generichash_final(state, 32));
    assertEquals(hash1.toString(), hash2.toString());
  },
});

Deno.test({
  name: "crypto_kdf",
  fn(): void {
    let subkey, expected;
    let key = bufferFrom(
      "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
      "hex",
    );
    let context = "NaClTest";
    subkey = bufferFrom(sodium.crypto_kdf_derive_from_key(32, 1, context, key));
    expected = bufferFrom(
      "bce6fcf118cac2691bb23975a63dfac02282c1cd5de6ab9febcbb0ec4348181b",
      "hex",
    );
    assertEquals(subkey.toString(), expected.toString());

    subkey = bufferFrom(sodium.crypto_kdf_derive_from_key(32, 2, context, key));
    expected = bufferFrom(
      "877cf1c1a2da9b900c79464acebc3731ed4ebe326a7951911639821d09dc6dda",
      "hex",
    );
    assertEquals(subkey.toString(), expected.toString());

    let key2 = bufferFrom(sodium.crypto_kdf_keygen());
    let subkey2 = bufferFrom(
      sodium.crypto_kdf_derive_from_key(32, 1, context, key2),
    );
    assertNotEquals(subkey2.toString(), key2.toString());
    assertNotEquals(subkey2.toString(), subkey.toString());
  },
});

Deno.test({
  name: "crypto_kx",
  fn(): void {
    let clientKeys = sodium.crypto_kx_keypair();
    let clientSecret = bufferFrom(clientKeys.privateKey);
    let clientPublic = bufferFrom(clientKeys.publicKey);
    let seed = bufferFrom(
      sodium.crypto_generichash(
        32,
        "Unit test static key seed goes here. Nothing too complicated. No randomness needed, really.",
      ),
    );
    let serverKeys = sodium.crypto_kx_seed_keypair(seed);
    let serverSecret = bufferFrom(serverKeys.privateKey);
    let serverPublic = bufferFrom(serverKeys.publicKey);
    let clientRx, clientTx, serverRx, serverTx;

    let clientOut = sodium.crypto_kx_client_session_keys(
      clientPublic,
      clientSecret,
      serverPublic,
    );
    clientRx = bufferFrom(clientOut.sharedRx);
    clientTx = bufferFrom(clientOut.sharedTx);
    let serverOut = sodium.crypto_kx_server_session_keys(
      serverPublic,
      serverSecret,
      clientPublic,
    );
    serverRx = bufferFrom(serverOut.sharedRx);
    serverTx = bufferFrom(serverOut.sharedTx);

    assertEquals(clientRx.toString(), serverTx.toString());
    assertEquals(clientTx.toString(), serverRx.toString());
  },
});

Deno.test({
  name: "crypto_pwhash",
  fn(): void {
    let password = "correct horse battery staple";
    let salt = bufferFrom("808182838485868788898a8b8c8d8e8f", "hex");
    let hashed = bufferFrom(
      sodium.crypto_pwhash(16, password, salt, 2, 65536 << 10, 2),
    );
    assertEquals(
      hashed.toString(),
      bufferFrom("720f95400220748a811bca9b8cff5d6e", "hex").toString(),
    );
  },
});

Deno.test({
  name: "crypto_pwhash_str",
  fn(): void {
    let password = "correct horse battery staple";
    let hashed = sodium.crypto_pwhash_str(password, 2, 65536 << 10);
    assert(hashed);
    assert(sodium.crypto_pwhash_str_verify(hashed, password));
    assert(
      sodium.crypto_pwhash_str_verify(hashed, "incorrect password") === false,
    );
    assert(
      sodium.crypto_pwhash_str_needs_rehash(hashed, 2, 65536 << 10) === false,
    );
    assert(
      sodium.crypto_pwhash_str_needs_rehash(hashed, 3, 65536 << 10) === true,
    );
  },
});

Deno.test({
  name: "crypto_scalarmult",
  fn(): void {
    let aliceKeypair = sodium.crypto_box_keypair();
    let aliceSecret = bufferFrom(aliceKeypair.privateKey);
    let alicePublic = bufferFrom(aliceKeypair.publicKey);

    // crypto_scalarmult_base test:
    let testPublic = bufferFrom(sodium.crypto_scalarmult_base(aliceSecret));
    assertEquals(testPublic.toString(), alicePublic.toString());

    // crypto_scalarmult test:
    let bobKeypair = sodium.crypto_box_keypair();
    let bobSecret = bufferFrom(bobKeypair.privateKey);
    let bobPublic = bufferFrom(bobKeypair.publicKey);

    assertEquals(alicePublic.toString(), alicePublic.toString());

    let ab = bufferFrom(sodium.crypto_scalarmult(aliceSecret, bobPublic));
    assertNotEquals(
      ab.toString(),
      bufferFrom(
        "0000000000000000000000000000000000000000000000000000000000000000",
      ).toString(),
    );
    let ba = bufferFrom(sodium.crypto_scalarmult(bobSecret, alicePublic));
    assertNotEquals(
      ba.toString(),
      bufferFrom(
        "0000000000000000000000000000000000000000000000000000000000000000",
      ).toString(),
    );
    assertEquals(ab.toString(), ba.toString());
  },
});

Deno.test({
  name: "crypto_secretbox",
  fn(): void {
    let plaintext =
      "Science, math, technology, engineering, and compassion for others.";

    let key = bufferFrom(sodium.crypto_secretbox_keygen());
    let nonce = bufferFrom(sodium.randombytes_buf(24));

    let ciphertext = bufferFrom(
      sodium.crypto_secretbox_easy(plaintext, nonce, key),
    );
    let decrypted = bufferFrom(
      sodium.crypto_secretbox_open_easy(ciphertext, nonce, key),
    );
    assertEquals(decrypted.toString(), bufferFrom(plaintext).toString());
  },
});

Deno.test({
  name: "crypto_shorthash",
  fn(): void {
    let key = bufferFrom("808182838485868788898a8b8c8d8e8f", "hex");
    let message;
    let hash;

    message = "This is short input0";
    hash = bufferFrom(sodium.crypto_shorthash(message, key));
    assertEquals(
      hash.toString(),
      bufferFrom("ef589fb9ef4196b3", "hex").toString(),
    );

    message = "This is short input1";
    hash = bufferFrom(sodium.crypto_shorthash(message, key));
    assertEquals(
      hash.toString(),
      bufferFrom("5e8f01039bc53eb7", "hex").toString(),
    );
  },
});

Deno.test({
  name: "crypto_sign",
  fn(): void {
    let aliceKeypair = sodium.crypto_sign_keypair();
    let aliceSecret = bufferFrom(aliceKeypair.privateKey);
    let alicePublic = bufferFrom(aliceKeypair.publicKey);

    let plaintext =
      "Science, math, technology, engineering, and compassion for others.";
    let signed = bufferFrom(sodium.crypto_sign(plaintext, aliceSecret));
    let opened = bufferFrom(sodium.crypto_sign_open(signed, alicePublic));
    assertEquals(signed.slice(64).toString(), opened.toString());
    assertEquals(opened.toString(), bufferFrom(plaintext).toString());

    let signature = bufferFrom(
      sodium.crypto_sign_detached(plaintext, aliceSecret),
    );
    let valid = sodium.crypto_sign_verify_detached(
      signature,
      plaintext,
      alicePublic,
    );
    assert(valid);
    let invalid = sodium.crypto_sign_verify_detached(
      signature,
      plaintext + " extra",
      alicePublic,
    );
    assert(!invalid);
  },
});

Deno.test({
  name: "crypto_sign_ed25519_to_curve25519",
  fn(): void {
    let aliceKeypair = bufferFrom(
      "411a2c2227d2a799ebae0ed94417d8e8ed1ca9b0a9d5f4cd743cc52d961e94e2" +
        "da49154c9e700b754199df7974e9fa4ee4b6ebbc71f89d8d8938335ea4a1409d" +
        "da49154c9e700b754199df7974e9fa4ee4b6ebbc71f89d8d8938335ea4a1409d",
      "hex",
    );
    let aliceSecret = bufferFrom(aliceKeypair.slice(0, 64));
    let alicePublic = bufferFrom(aliceKeypair.slice(64, 96));

    let ecdhSecret = bufferFrom(
      sodium.crypto_sign_ed25519_sk_to_curve25519(aliceSecret),
    );
    assertEquals(
      ecdhSecret.toString(),
      bufferFrom(
        "60c783b8d1674b7081b72a105b55872502825d4ec638028152e085b54705ad7e",
        "hex",
      ).toString(),
    );
    let ecdhPublic = bufferFrom(
      sodium.crypto_sign_ed25519_pk_to_curve25519(alicePublic),
    );
    assertEquals(
      ecdhPublic.toString(),
      bufferFrom(
        "5a791d07cfb39060c8e9b641b6a915a3126cd14ddc243a9928c490c8e1f59e7c",
        "hex",
      ).toString(),
    );
  },
});

Deno.test({
  name: "randombytes_buf",
  fn(): void {
    let a, b;
    for (let i = 0; i < 100; i++) {
      a = sodium.randombytes_buf(64);
      b = sodium.randombytes_buf(64);
      assertNotEquals(a.toString(), b.toString());
    }
  },
});

Deno.test({
  name: "randombytes_uniform",
  fn(): void {
    let a, b;
    for (let i = 0; i < 100; i++) {
      a = sodium.randombytes_uniform(0x3fffffff);
      b = sodium.randombytes_uniform(0x3fffffff);
      assertNotEquals(a.toString(), b.toString());
    }
  },
});

Deno.test({
  name: "sodium_compare",
  fn(): void {
    let a = bufferFrom("80808080", "hex");
    let b = bufferFrom("81808080", "hex");
    let c = bufferFrom("80808081", "hex");

    assert(sodium.compare(a, a) === 0);
    assert(sodium.compare(b, b) === 0);
    assert(sodium.compare(c, c) === 0);
    assert(sodium.compare(a, b) < 0);
    assert(sodium.compare(b, a) > 0);
    assert(sodium.compare(a, c) < 0);
    assert(sodium.compare(c, a) > 0);
    assert(sodium.compare(b, c) < 0);
    assert(sodium.compare(c, b) > 0);
  },
});

Deno.test({
  name: "sodium_increment",
  fn(): void {
    let a = bufferFrom("80808080", "hex");
    let b = bufferFrom("81808080", "hex");
    sodium.increment(a);
    assertEquals(sodium.compare(b, a), 0);

    a = bufferFrom("ffffffff", "hex");
    b = bufferFrom("00000000", "hex");
    sodium.increment(a);
    assertEquals(sodium.compare(b, a), 0);
  },
});

Deno.test({
  name: "sodium_is_zero",
  fn(): void {
    let buf;
    buf = bufferFrom("00", "hex");
    assert(sodium.is_zero(buf));
    buf = bufferFrom("01", "hex");
    assert(!sodium.is_zero(buf));
  },
});

Deno.test({
  name: "sodium_memcmp",
  fn(): void {
    let a, b, c;
    a = bufferFrom(sodium.randombytes_buf(32));
    b = bufferFrom(sodium.randombytes_buf(32));
    c = new Uint8Array(b);

    assert(!sodium.memcmp(a, b));
    assert(!sodium.memcmp(a, c));
    assert(sodium.memcmp(b, c));
    assert(sodium.memcmp(c, b));
  },
});

Deno.test({
  name: "sodium_memzero",
  fn(): void {
    let buf = bufferFrom(sodium.randombytes_buf(16));
    assertNotEquals(
      buf.toString(),
      bufferFrom("00000000000000000000000000000000", "hex").toString(),
    );
    sodium.memzero(buf);
    assertEquals(
      buf.toString(),
      bufferFrom("00000000000000000000000000000000", "hex").toString(),
    );
  },
});

Deno.test({
  name: "sodium_pad",
  fn(): void {
    let buf, size, padded, unpadded;
    for (let i = 0; i < 100; i++) {
      buf = bufferFrom(
        sodium.randombytes_buf(sodium.randombytes_uniform(96) + 16),
      );
      size = sodium.randombytes_uniform(96) + 5;
      padded = bufferFrom(sodium.pad(buf, size));
      unpadded = bufferFrom(sodium.unpad(padded, size));
      assertEquals(unpadded.toString(), buf.toString());
    }
  },
});

Deno.test({
  name: "sodium_add",
  fn(): void {
    let one = bufferFrom("01000000", "hex");
    let big = bufferFrom("fe000000", "hex");

    sodium.add(big, one);
    assertEquals(big.toString(), bufferFrom("ff000000", "hex").toString());

    sodium.add(big, one);
    assertEquals(big.toString(), bufferFrom("00010000", "hex").toString());
  },
});

Deno.test({
  name: "crypto_kdf_derive_from_key",
  fn(): void {
    let key = bufferFrom(
      "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
      "hex",
    );
    let subkey = sodium.crypto_kdf_derive_from_key(32, 1, "NaClTest", key);
    assertEquals(
      bufferFrom(subkey).toString(),
      bufferFrom(
        "bce6fcf118cac2691bb23975a63dfac02282c1cd5de6ab9febcbb0ec4348181b",
        "hex",
      ).toString(),
    );
  },
});
