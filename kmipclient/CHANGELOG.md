Oct, 2026 Version 0.4.0

    Key reading, writing and generation moved out of the Key classes into the
    new "kmiputil" library (KeyReader, KeyWriter, KeyGenerator).
    Removed: SymmetricKey::aes_from_hex/aes_from_base64/aes_from_value/
    generate_aes and PEMReader; see kmiputil/README.md for the replacements.
    New: writing keys as hex, Base64 and PEM.
    Fixed: keys read from PEM got Name = true instead of their name; reading
    an encrypted private key could prompt for a passphrase on the terminal;
    a private key read from PEM was registered as PKCS#8 but held PKCS#1/SEC1
    bytes, with the DER encoding's size as its Cryptographic Length.
    Register sends Cryptographic Algorithm and Length only as a pair, as KMIP
    requires (1.4 §2.1.3): never the encoding's size as an asymmetric key's
    length, never a length without an algorithm, and no 2.0-only algorithm
    (e.g. Ed25519) over KMIP 1.x. Registering a symmetric key without a
    Cryptographic Algorithm (defined in the client's KMIP version) now throws
    instead of sending a Key Block KMIP does not allow.
    Requires kmipcore 0.3.0.

Mar, 2026 Version 0.2.0

    Interface optimization
    Test suite update;
    Now it uses completely new low-level KMIP protocol implementation from "kmipcore" library,
    instead of old "libkmip" code.

Dec, 2025 Version 0.1.1

    Interface optimization 
    Test suite added
    Bugs fixed

Apr, 2025 Version 0.1.0

    Initial implementation of all functionality available in "kmippp"
