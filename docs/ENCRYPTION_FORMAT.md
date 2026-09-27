# Encryption format

How TeiFS encrypts objects at rest: the key hierarchy, how keys are sealed, and the byte
layout of encrypted data. This is a contract like [ON_DISK_FORMAT.md](ON_DISK_FORMAT.md):
changing it means a new version, and every release reads every version before it.
`crates/crypto` implements it.

All primitives come from [aws-lc-rs](https://github.com/aws/aws-lc-rs): AES-256-GCM,
HKDF-SHA256 and HMAC-SHA256.

## Key hierarchy

```
KMS key (a named, versioned 256-bit key in the KMS; never leaves it)
  └─ seals ─▶ data key (random 256 bits, one per object)
               └─ derives ─▶ part key (one per part: HKDF, info "teifs data v1" ‖ part)
                              └─ encrypts ─▶ 64 KiB packages of the object's bytes
```

| Mode | What seals the data key |
|---|---|
| SSE-S3 | The drive's managed KMS key, `teifs-default` |
| SSE-KMS | The KMS key the request or the bucket names (`teifs-default` if none) |
| SSE-C | A key derived from the customer's key; TeiFS never stores the customer's key |

## Sealing a data key

A seal binds the data key to its **context**, a set of key-value pairs that must be
presented again to unseal:

| Pair | Value |
|---|---|
| `teifs:drive` | The drive id from `format.json` |
| `teifs:bucket` | The bucket's id |
| `teifs:object` | The object's id (stable across renames) |
| anything else | The client's SSE-KMS encryption context, if given |

The context is serialized canonically: pairs sorted by key, each as
`u32 length ‖ key ‖ u32 length ‖ value` (lengths big-endian).

To seal with a key-encryption key `KEK` (the KMS key, or the key derived from an SSE-C
key):

1. `salt` = 32 random bytes.
2. `k` = HKDF-SHA256(ikm = `KEK`, salt = `salt`, info = `"teifs seal v1"` ‖ context),
   32 bytes. Every seal uses a fresh key.
3. `sealed` = AES-256-GCM(key = `k`, nonce = 12 zero bytes, aad = context,
   plaintext = data key): 32 bytes of ciphertext and a 16-byte tag.

Stored: `version` (1), the KMS key name and version, `salt`, `sealed`. Unsealing redoes
step 2 and authenticates with the tag; a different context, key or salt fails.

### Sealing with a transit engine (Vault, OpenBao)

When the KMS is a Vault or OpenBao transit engine, TeiFS still generates the data key; the
engine seals it: `POST /v1/<mount>/encrypt/<key>` with the data key as `plaintext` and the
canonical context as `associated_data` (AES-256-GCM keys, so the context is
authenticated). Stored: `provider` = `transit`, the key name, the version from the
engine's `vault:v<N>:` ciphertext, and that ciphertext as `sealed` (no salt). Unsealing
sends the ciphertext and the same associated data to `/decrypt`. TeiFS checks a key exists
before using it, because the engine's `encrypt` would otherwise create a missing key.
A key sealed by one provider is never handed to another.

### SSE-C

The customer's 256-bit key is checked with `HMAC-SHA256(key = check salt, message =
customer key)`, stored with a random 32-byte check salt. `KEK` is
HKDF-SHA256(ikm = customer key, salt = check salt, info = `"teifs sse-c v1"`).

## Encrypted data

An object's bytes (or each part's, for a multipart upload) are cut into packages of
65,536 bytes of plaintext; the last package of a part may be shorter, and an empty part
is one empty package. Each package is stored as its ciphertext followed by its 16-byte
tag, so package `i` of a part starts at `i × 65,552` bytes into that part's encrypted
data.

| Field | Value |
|---|---|
| Key | Part key = HKDF-SHA256(ikm = data key, salt = none, info = `"teifs data v1"` ‖ part number as u32 big-endian); part 1 for a single-part object |
| Nonce | The package's index in its part as a 96-bit big-endian integer |
| AAD | `"TFS1"` ‖ part number (u32 BE) ‖ package index (u64 BE) ‖ final flag (1 byte: 1 for the part's last package, else 0) |

Because the position and the final flag are authenticated, packages can't be reordered,
dropped, duplicated, moved between parts or objects, or cut off at the end without
decryption failing.

A range read decrypts only the packages that hold the range.

## ETags and checksums

| Mode | ETag | Stored checksums |
|---|---|---|
| SSE-S3 | MD5 of the plaintext (as AWS) | In the clear |
| SSE-KMS, SSE-C | `HMAC-SHA256(data key, "teifs etag v1" ‖ MD5 of the plaintext)`, first 16 bytes, hex (not the MD5, as AWS) | Sealed with the data key |

Multipart objects follow the same rule per part, then the usual `-N` multipart ETag.
Under SSE-KMS and SSE-C each part's checksums are sealed too, from the moment the part
is stored: the checksum map then holds a single `sealed` entry (base64 of the sealed
JSON map), in the upload's `parts` rows and, after Complete, in the object's `parts`.
Listing parts opens them with the data key (SSE-C: only when the request carries the
customer's key). A completed upload's remembered answer keeps no checksums for these
modes.

"Sealed with the data key" means AES-256-GCM with the key HKDF-SHA256(ikm = data key,
salt = none, info = `"teifs meta v1"`), a random 12-byte nonce stored in front, and no
AAD. Each object's data key is unique, so random nonces here are never near their limit.

## Versions

| Version | Change |
|---|---|
| 1 | This document |
