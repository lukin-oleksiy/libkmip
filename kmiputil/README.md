# kmiputil

Helpers for `kmipclient` key objects that are not part of the KMIP protocol:
reading keys from external formats, writing them back, and generating keys
locally. They are kept out of the `kmipclient::Key` class hierarchy so the key
classes only model KMIP objects.

Link the `kmiputil` CMake target; it brings in `kmipclient` and `kmipcore`.

## Public headers

| Header | Class | Purpose |
|---|---|---|
| `kmiputil/KeyReader.hpp` | `KeyReader` | Build keys from hex, Base64, raw bytes or PEM |
| `kmiputil/KeyWriter.hpp` | `KeyWriter` | Serialize keys to hex, Base64 or PEM |
| `kmiputil/KeyGenerator.hpp` | `KeyGenerator` | Generate random AES keys |
| `kmiputil/kmiputil_version.hpp` | — | Version macros (`KMIPUTIL_VERSION_STR`) |

The first three are static-only helper classes.

### `KeyReader`

| Method | Result |
|---|---|
| `aes_from_hex(hex)` | `SymmetricKey`; hex is case-insensitive |
| `aes_from_base64(b64)` | `SymmetricKey` from padded Base64; whitespace and line breaks are ignored |
| `aes_from_value(bytes)` | `SymmetricKey` from any contiguous byte range |
| `from_PEM(pem)` | `std::unique_ptr<Key>`: `X509Certificate`, `PrivateKey`, `PublicKey`, or `SymmetricKey` |

AES keys must be 128, 192 or 256 bits long. They get the AES algorithm, their
length and the `ENCRYPT | DECRYPT` usage mask as attributes, which strict
servers (e.g. Vault) require on registration.

`from_PEM` tries, in order: an X.509 certificate, an unencrypted private key
(PKCS#8 or the traditional per-algorithm format), a public key, and finally
Base64 key material between `SYMMETRIC KEY` `BEGIN`/`END` lines, read as an
AES key.
Encrypted private keys are rejected; the reader never prompts for a
passphrase.

A private key's value is stored as PKCS#8 `PrivateKeyInfo` whichever form the
PEM held, since that is the Key Format Type `KmipClient` registers it with.
Private keys, public keys and certificates get the key's algorithm (RSA, DSA,
DH, EC, Ed25519 or Ed448) and its size in bits (e.g. the RSA modulus) as
attributes.

### `KeyWriter`

| Method | Result |
|---|---|
| `to_hex(key)` | Key material as lowercase hex |
| `to_base64(key)` | Key material as padded Base64, one line |
| `to_PEM(key)` | PEM text that `KeyReader::from_PEM` reads back to the same key type |

`to_PEM` writes certificates as `CERTIFICATE`, private keys as unencrypted
PKCS#8 `PRIVATE KEY`, public keys as `PUBLIC KEY` (SubjectPublicKeyInfo, also
when the server returned a bare PKCS#1 RSA key), and AES keys as Base64
between `SYMMETRIC KEY` lines. There is no standard PEM type for symmetric
keys; that last form is only meant to be read back by `KeyReader`, which reads
it as AES, so other symmetric keys (e.g. HMAC) are rejected rather than
written as PEM that would read back as the wrong key.

All results are `kmipcore::secure_string`, which is zeroed when freed.

### `KeyGenerator`

| Method | Result |
|---|---|
| `generate_aes(size = AES_256)` | Random `SymmetricKey` from the OpenSSL CSPRNG |

## Example

```cpp
#include "kmipclient/Kmip.hpp"
#include "kmiputil/KeyGenerator.hpp"
#include "kmiputil/KeyReader.hpp"
#include "kmiputil/KeyWriter.hpp"

using namespace kmipclient;

Kmip kmip(host, port, client_cert, client_key, server_ca, timeout_ms);

auto key = kmiputil::KeyGenerator::generate_aes(aes_key_size::AES_256);
auto id = kmip.client().op_register_key("mykey", "mygroup", key);

auto fetched = kmip.client().op_get_key(id);
auto hex = kmiputil::KeyWriter::to_hex(*fetched);

auto cert = kmiputil::KeyReader::from_PEM(pem_text);
```

## Migrating from the `kmipclient` factories

| Before | After |
|---|---|
| `SymmetricKey::aes_from_hex(hex)` | `kmiputil::KeyReader::aes_from_hex(hex)` |
| `SymmetricKey::aes_from_base64(b64)` | `kmiputil::KeyReader::aes_from_base64(b64)` |
| `SymmetricKey::aes_from_value(bytes)` | `kmiputil::KeyReader::aes_from_value(bytes)` |
| `SymmetricKey::generate_aes(size)` | `kmiputil::KeyGenerator::generate_aes(size)` |
| `PEMReader::from_PEM(pem)` | `kmiputil::KeyReader::from_PEM(pem)` |

`aes_from_base64` is stricter than the factory it replaces, which silently
skipped characters outside the Base64 alphabet and ignored anything after the
first `=`: it now throws on such input, on missing padding, and on nonzero
unused bits before the padding (e.g. `Zh==`, where only `Zg==` is canonical,
RFC 4648 §3.5).

The `aes_from_*` functions throw for an invalid AES key length with
`kmipcore::KmipException` code General Failure (0x100), as for invalid hex or
Base64, where the old factories used -1.

`from_PEM` now stores private keys as PKCS#8 rather than the per-algorithm DER
`PEMReader` produced (PKCS#1 for RSA, SEC1 for EC), so their `value()` bytes
differ for the same PEM.

`from_PEM` reads Base64 key material only between `-----BEGIN SYMMETRIC KEY-----`
and `-----END SYMMETRIC KEY-----` lines (the form `KeyWriter::to_PEM` writes).
`PEMReader` took it between any `BEGIN`/`END` labels, even with no `END` line,
so a file labelled e.g. `AES KEY` now throws: relabel it `SYMMETRIC KEY`.

Projects that build this repository's libraries with their own CMake files
need to add the `kmiputil` subdirectory and link the `kmiputil` target.

## Tests

`kmiputil_test` (built with `-DBUILD_TESTS=ON`) needs no KMIP server.
