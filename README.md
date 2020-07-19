# Use Case
A native DLL to provide a mechanism for encryption and transparent mutual authentication that's cross-compatible between Python and C#. Sure, I could have just used libsodium or openssl, but what's the fun in that? This library is a toy that I mostly wrote to learn how to use Rust more effectively.

# Implementation Details
Authentication is provided using a static ECDSA keypair on curve secp256k1 implemented within the libsecp256k1 crate. The key exchange is performed using ECDH on the same curve after identity has been verified.

ChaCha20/Poly1305 is used to provide authenticated encryption.  The tag for each message is detached, signed with the identity key, and stored as part of the message header.  In this way, confidentiality, message integrity, and message authenticity is maintained.

# Known Issues
This library is currently vulnerable to replay attacks.  The handshake can't be replayed, but a properly signed and sealed message can be replayed.  That doesn't matter much for my use case, and I'm in a rush to get this done, so it's a low priority for me to fix.  That being said, you probably don't want to use this thing for anything important.
