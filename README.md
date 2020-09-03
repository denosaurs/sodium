# sodium

[![Tags](https://img.shields.io/github/release/denosaurs/sodium)](https://github.com/denosaurs/sodium/releases)
[![CI Status](https://img.shields.io/github/workflow/status/denosaurs/sodium/check)](https://github.com/denosaurs/sodium/actions)
[![License](https://img.shields.io/github/license/denosaurs/sodium)](https://github.com/denosaurs/sodium/blob/master/LICENSE)

Extremely fast WASM wrapper of [libsodium] by @jedisct1, based on the work from the [libsodium.js] repository.

```typescript
import sodium from "https://deno.land/x/sodium/basic.ts";

await sodium.ready;

let key = sodium.crypto_secretstream_xchacha20poly1305_keygen();

let res = sodium.crypto_secretstream_xchacha20poly1305_init_push(key);
let [state_out, header] = [res.state, res.header];
let c1 = sodium.crypto_secretstream_xchacha20poly1305_push(
  state_out,
  sodium.from_string("message 1"),
  null,
  sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE,
);
let c2 = sodium.crypto_secretstream_xchacha20poly1305_push(
  state_out,
  sodium.from_string("message 2"),
  null,
  sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL,
);

let state_in = sodium.crypto_secretstream_xchacha20poly1305_init_pull(
  header,
  key,
);
let r1 = sodium.crypto_secretstream_xchacha20poly1305_pull(state_in, c1);
let [m1, tag1] = [sodium.to_string(r1.message), r1.tag];
let r2 = sodium.crypto_secretstream_xchacha20poly1305_pull(state_in, c2);
let [m2, tag2] = [sodium.to_string(r2.message), r2.tag];

console.log(m1);
console.log(m2);

```

## Basic vs Sumo

The **basic** version (in the `dist/browsers` and `dist/modules` directories) contains the high-level functions, and is the recommended one for most projects.

Alternatively, the **sumo** version, available in the `dist/browsers-sumo` and `dist/modules-sumo` directories contains all the symbols from the original library. This includes undocumented, untested, deprecated, low-level and easy to misuse functions.

The `crypto_pwhash_*` function set is included in both versions.

The **sumo** version is slightly larger than the **basic** version, and should be used only if you really need the extra symbols it provides.

### Documentation

- **basic**: [API]
- **sumo**: [API_sumo]

### Imports

To import **basic**:

```typescript
import sodium from "https://deno.land/x/sodium/basic.ts";
```

To import **sumo**:

```typescript
import sodium from "https://deno.land/x/sodium/sumo.ts";
```

## Building

### Requirements

- emscripten
- binaryen
- git
- nodejs
- make

### Compilation

```bash
$ make
```

This will create the following directory structure.

```text
dist
├── browsers
│   └── sodium.js              # basic libsodium
├── browsers-sumo
│   └── sodium.js              # sumo libsodium
├── modules
│   ├── libsodium-wrappers.js  # not used (nodejs)
│   └── libsodium.js           # not used (nodejs)
└── modules-sumo
    ├── libsodium-sumo.js      # not used (nodejs)
    └── libsodium-wrappers.js  # not used (nodejs)
```

## Maintainers

- [Filippo Rossi](https://github.com/qu4k) - Deno support
- Ahmad Ben Mrad - original wrapper
- Frank Denis - original wrapper
- Ryan Lester - original wrapper

## Other

### Related

- [libsodium] - A modern, portable, easy to use crypto library.
- [libsodium.js] - ... and it's wasm release

### Contribution

Pull request, issues and feedback are very welcome. Code style is formatted with `deno fmt` and commit messages are done following Conventional Commits spec.

### Licence

- **Modifications**: Copyright 2020-present, the denosaurs team. All rights reserved. MIT license.

- **Original work**: ISC License.

[libsodium]: https://github.com/jedisct1/libsodium
[libsodium.js]: https://github.com/jedisct1/libsodium.js
[api]: API.md
[api_sumo]: API_sumo.md
