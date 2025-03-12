# The `kmipclient` library

`kmipclient` is a C++20 library that provides a clean, high-level interface to
KMIP servers.  It wraps the low-level `kmipcore` (and ultimately `libkmip`)
into safe C++ types, hiding raw memory management, buffer handling, and
TTLV encoding/decoding details from library users.

Everything lives in the `kmipclient` namespace.

---

## Design goals

1. Easy to use and hard to misuse — forced error handling via exceptions.
2. Hide low-level details (no raw `KMIP` context, no manual buffer management).
3. Minimize manual memory management; prefer stack-allocated objects.
4. Make the library easy to extend.
5. Use only the low-level `kmipcore` layer; no mid-level `kmip_bio.c`.
6. Replaceable network communication layer (dependency injection).
7. Testability.

---

## External dependencies

The only external dependency is **OpenSSL** (already required by `kmipcore`).
`KmipClient` itself depends only on `kmipcore`.  The network layer is injected
as an implementation of the `NetClient` interface.  The library ships a
ready-to-use `NetClientOpenSSL` implementation; any custom transport can be
used by implementing the four-method `NetClient` interface.

---

## Public headers

| Header | Purpose |
|---|---|
| `kmipclient/KmipClient.hpp` | Main KMIP operations class |
| `kmipclient/KmipClientPool.hpp` | Thread-safe connection pool |
| `kmipclient/Kmip.hpp` | Simplified facade (bundles `NetClientOpenSSL` + `KmipClient`) |
| `kmipclient/NetClient.hpp` | Abstract network interface |
| `kmipclient/NetClientOpenSSL.hpp` | OpenSSL BIO implementation of `NetClient` |
| `kmipclient/Key.hpp` | Client-level crypto-key type with factory helpers |
| `kmipclient/KmipIOException.hpp` | Exception for network/IO errors |
| `kmipclient/types.hpp` | Type aliases re-exported from `kmipcore` |
| `kmipclient/kmipclient_version.hpp` | Version macros (`KMIPCLIENT_VERSION_STR`) |

---

## High-level design

### `NetClient` interface

Abstract base class for network transport.  Defines four virtual methods:

```cpp
virtual bool connect();           // establish TLS connection
virtual void close();             // close TLS connection
virtual int  send(const void *data, int dlen);
virtual int  recv(void *data,       int dlen);
```

`NetClientOpenSSL` is the ready-to-use implementation based on OpenSSL BIO.

### `KmipClient`

The main KMIP protocol client.  It is constructed with a reference to an
already-created `NetClient` instance (dependency injection) and an optional
`kmipcore::Logger`:

```cpp
NetClientOpenSSL net_client(host, port, client_cert, client_key, server_ca, timeout_ms);
net_client.connect();
KmipClient client(net_client);          // no logger
// or:
KmipClient client(net_client, logger);  // with protocol logger
```

Copy and move are disabled.

### `Kmip` façade

`Kmip` bundles `NetClientOpenSSL` + `KmipClient` into a single object for the
common case where OpenSSL BIO transport is sufficient:

```cpp
Kmip kmip(host, port, client_cert, client_key, server_ca, timeout_ms);
auto key_id = kmip.client().op_create_aes_key("mykey", "mygroup");
```

### `Key`

`kmipclient::Key` extends `kmipcore::Key` and adds factory helpers:

| Factory | Description |
|---|---|
| `Key::aes_from_hex(hex)` | Create AES key from hexadecimal string |
| `Key::aes_from_base64(b64)` | Create AES key from Base64 string |
| `Key::aes_from_value(bytes)` | Create AES key from raw byte vector |
| `Key::generate_aes(size_bits)` | Generate a random AES key (128/192/256 bits) |
| `Key::from_PEM(pem)` | Parse a PEM-encoded certificate/public-key/private-key |

### `KmipClientPool`

Thread-safe pool of `KmipClient` connections.  Connections are created lazily
on demand up to `max_connections`.  Threads borrow a client via RAII:

```cpp
KmipClientPool pool(KmipClientPool::Config{
    .host            = "kmip-server",
    .port            = "5696",
    .client_cert     = "/path/to/cert.pem",
    .client_key      = "/path/to/key.pem",
    .server_ca_cert  = "/path/to/ca.pem",
    .timeout_ms      = 5000,
    .max_connections = 8,
});

// In any thread:
auto conn   = pool.borrow();                       // blocks if all busy
auto key_id = conn->op_create_aes_key("k", "g");
// conn returned to pool automatically on scope exit
```

Timed and non-blocking variants are also available:

```cpp
auto conn    = pool.borrow(std::chrono::seconds(10)); // throws on timeout
auto opt_conn = pool.try_borrow();                     // returns std::nullopt if busy
```

If an operation throws an unrecoverable exception, mark the connection
unhealthy before the guard goes out of scope so the pool discards it:

```cpp
try {
  conn->op_get_key(id);
} catch (...) {
  conn.markUnhealthy();
  throw;
}
```

Diagnostic accessors: `pool.available_count()`, `pool.total_count()`,
`pool.max_connections()`.

### `KmipIOException`

Thrown for network/IO errors (TLS handshake failure, send/receive error).
Inherits from `kmipcore::KmipException` so a single `catch` clause handles
both protocol and transport errors.

---

## Available KMIP operations

All operations are methods of `KmipClient`.  They throw `kmipcore::KmipException`
(or `KmipIOException` for transport errors) on failure.

| Method | Description |
|---|---|
| `op_create_aes_key(name, group)` | Server-side AES-256 key generation (KMIP CREATE) |
| `op_register_key(name, group, key)` | Register an existing key (KMIP REGISTER) |
| `op_register_secret(name, group, secret, type)` | Register a secret / password |
| `op_get_key(id [, all_attributes])` | Retrieve a symmetric key with optional attributes |
| `op_get_secret(id [, all_attributes])` | Retrieve a secret / password |
| `op_activate(id)` | Activate an entity (pre-active → active) |
| `op_revoke(id, reason, message, time)` | Revoke/deactivate an entity |
| `op_destroy(id)` | Destroy an entity (must be revoked first) |
| `op_locate_by_name(name, object_type)` | Find entity IDs by name |
| `op_locate_by_group(group, object_type [, max_ids])` | Find entity IDs by group |
| `op_all(object_type [, max_ids])` | Retrieve all entity IDs of a given type |
| `op_get_attribute_list(id)` | List attribute names for an entity |
| `op_get_attributes(id, attr_names)` | Retrieve specific attributes by name |

---

## Usage examples

### Get a symmetric key

```cpp
#include "kmipclient/KmipClient.hpp"
#include "kmipclient/NetClientOpenSSL.hpp"
using namespace kmipclient;

NetClientOpenSSL net_client(host, port, client_cert, client_key, server_ca, 200);
KmipClient client(net_client);

try {
  auto key = client.op_get_key(id);
  // key.value()  → std::vector<uint8_t> with the raw key bytes
  // key.attribute_value(KMIP_ATTR_NAME_STATE) → attribute string
  // key.attribute_value(KMIP_ATTR_NAME_NAME)  → key name
} catch (const std::exception &e) {
  std::cerr << e.what() << '\n';
}
```

### Create an AES-256 key on the server

```cpp
#include "kmipclient/Kmip.hpp"
using namespace kmipclient;

Kmip kmip(host, port, client_cert, client_key, server_ca, 200);
auto key_id = kmip.client().op_create_aes_key("mykey", "mygroup");
```

### Register an existing key

```cpp
NetClientOpenSSL net_client(host, port, client_cert, client_key, server_ca, 200);
KmipClient client(net_client);

auto k  = Key::aes_from_hex("0102030405060708090a0b0c0d0e0f10...");
auto id = client.op_register_key("mykey", "mygroup", k);
```

### Register a secret / password

```cpp
Kmip kmip(host, port, client_cert, client_key, server_ca, 200);
auto id = kmip.client().op_register_secret("mysecret", "mygroup", "s3cr3t!", PASSWORD);
```

### Lifecycle: activate → revoke → destroy

```cpp
client.op_activate(id);
client.op_revoke(id, UNSPECIFIED, "Deactivate", 0L);
client.op_destroy(id);
```

### Locate entities by name or group

```cpp
auto ids = client.op_locate_by_name("mykey", KMIP_OBJTYPE_SYMMETRIC_KEY);
auto all = client.op_all(KMIP_OBJTYPE_SYMMETRIC_KEY);
auto grp = client.op_locate_by_group("mygroup", KMIP_OBJTYPE_SYMMETRIC_KEY);
```

### Retrieve attributes

```cpp
auto attr_names = client.op_get_attribute_list(id);
auto attrs      = client.op_get_attributes(id, attr_names);
```

### Protocol logging

Pass any `kmipcore::Logger`-derived instance to enable TTLV message logging:

```cpp
class StdoutLogger final : public kmipcore::Logger {
public:
  bool shouldLog(kmipcore::LogLevel) const override { return true; }
  void log(const kmipcore::LogRecord &r) override {
    std::cout << '[' << kmipcore::to_string(r.level) << "] "
              << r.component << ' ' << r.event << '\n' << r.message << '\n';
  }
};

auto logger = std::make_shared<StdoutLogger>();
KmipClient client(net_client, logger);
```

### Connection pool (multi-threaded)

```cpp
#include "kmipclient/KmipClientPool.hpp"
using namespace kmipclient;

KmipClientPool pool(KmipClientPool::Config{
    .host = host, .port = port,
    .client_cert = cert, .client_key = key, .server_ca_cert = ca,
    .timeout_ms = 5000, .max_connections = 8,
});

std::vector<std::thread> threads;
for (int i = 0; i < 16; ++i) {
  threads.emplace_back([&pool, i] {
    auto conn   = pool.borrow(std::chrono::seconds(10));
    auto key_id = conn->op_create_aes_key("key_" + std::to_string(i), "group");
    std::cout << "thread " << i << " → " << key_id << '\n';
  });
}
for (auto &t : threads) t.join();
```

---

## Build

```bash
mkdir build
cd build
cmake ..
cmake --build .
```

The library requires **C++20** and **OpenSSL**.

---

## Integration testing

Tests use the Google Test framework (fetched automatically when
`BUILD_TESTS=ON`).

1. Export connection variables:

```bash
export KMIP_ADDR=127.0.0.1
export KMIP_PORT=5696
export KMIP_CLIENT_CA=/path/to/client_cert.pem
export KMIP_CLIENT_KEY=/path/to/client_key.pem
export KMIP_SERVER_CA=/path/to/server_cert.pem
```

2. Configure and build:

```bash
cmake -DBUILD_TESTS=ON ..
cmake --build .
```

3. Run:

```bash
ctest --output-on-failure
# or directly:
./kmipclient_test
```

---

## Example programs

| Binary | Description |
|---|---|
| `example_create_aes` | Create a server-side AES-256 key |
| `example_register_key` | Register an existing AES key |
| `example_register_secret` | Register a secret / password |
| `example_get` | Retrieve a symmetric key by ID |
| `example_get_logger` | Same as `example_get` with protocol-level TTLV logging |
| `example_get_secret` | Retrieve a secret by ID |
| `example_get_name` | Retrieve a key name attribute |
| `example_get_attributes` | List and print all attributes of a key |
| `example_get_all_ids` | List all symmetric-key and secret IDs on the server |
| `example_activate` | Activate (pre-active → active) a key or secret |
| `example_revoke` | Revoke / deactivate a key or secret |
| `example_destroy` | Destroy a revoked key or secret |
| `example_locate` | Find entity IDs by name |
| `example_locate_by_group` | Find entity IDs by group |
| `example_pool` | Multi-threaded pool demo (concurrent key creation) |

All examples follow the same argument pattern:

```
<example_binary> <host> <port> <client_cert> <client_key> <server_ca_cert> [extra args…]
```
