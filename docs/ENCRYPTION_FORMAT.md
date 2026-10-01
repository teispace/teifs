# Encryption format

How TeiFS encrypts objects at rest: the key hierarchy, how keys are sealed, and the byte
layout of encrypted data. This is a contract like [ON_DISK_FORMAT.md](ON_DISK_FORMAT.md):
changing it means a new version, and every release reads every version before it.
`crates/crypto` implements it.

All primitives come from [aws-lc-rs](https://github.com/aws/aws-lc-rs): AES-256-GCM,
AES-256-CTR, HKDF-SHA256 and HMAC-SHA256.

## Key hierarchy

```
KMS key (a named, versioned 256-bit key in the KMS; never leaves it)
  └─ seals ─▶ data key (random 256 bits, one per object)
               └─ derives ─▶ part key (one per part: HKDF of the part number and salt)
                              └─ encrypts ─▶ 64 KiB packages of the object's bytes
```

| Mode | What seals the data key |
|---|---|
| SSE-S3 | The drive's managed KMS key, `teifs-default` |
| SSE-KMS | The KMS key the request or the bucket names (`teifs-default` if none) |
| DSSE-KMS | As SSE-KMS; a second data key, for the outer layer, is sealed by `teifs-default` |
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

### Sealing with KES

When the KMS is KES, KES seals the data key TeiFS generated: `PUT /v1/key/encrypt/<key>`
with the data key as `plaintext` and the canonical context as `context` (both base64).
Stored: `provider` = `kes`, the key name, version 1 (KES shows no versions), and KES's
ciphertext as `sealed`. Unsealing sends both to `/v1/key/decrypt/<key>`; KES refuses
(`400`) a ciphertext with another context.

### Sealing with AWS KMS

When the KMS is AWS KMS, `Encrypt` seals the data key under the key's alias (or the key id
or ARN given), with the context's pairs as the encryption context (none for an empty
context). Stored: `provider` = `aws-kms`, the key name as given, the key's version (one
more than its completed rotations), and the `CiphertextBlob` as `sealed`. Unsealing calls
`Decrypt` with the blob and the same encryption context and no key id: the blob names its
key and material, so it opens after the alias moves or the key rotates.

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
| Key | Part key = HKDF-SHA256(ikm = data key, salt = none, info = `"teifs data v2"` ‖ part number as u32 big-endian ‖ part salt) for a part of a multipart upload; `"teifs data v1"` ‖ part number, with no part salt, for a single-part object (part 1) and for parts stored before format 2 |
| Nonce | The package's index in its part as a 96-bit big-endian integer |
| AAD | `"TFS1"` ‖ part number (u32 BE) ‖ package index (u64 BE) ‖ final flag (1 byte: 1 for the part's last package, else 0) |

A part of a multipart upload gets a random 16-byte **part salt** when it's written, so
a part number sent again (S3 allows it, and clients retry) is never encrypted under the
same key and nonces as before. The salt is kept with the part (`parts.salt`) and, after
Complete, in the object's parts record, with the number each part was uploaded as
(`keys`: `number` and `salt` hex, in the object's part order), since Complete may
list numbers with gaps. An encrypted multipart object without `keys` (stored before
format 2) has parts numbered 1, 2, … with no salt.

Because the position and the final flag are authenticated, packages can't be reordered,
dropped, duplicated, moved between parts or objects, or cut off at the end without
decryption failing.

A range read decrypts only the packages that hold the range.

### DSSE-KMS's second layer

A DSSE-KMS object has a second random 256-bit data key, independent of the first and
sealed by the managed key `teifs-default` under the object's context plus the pair
`teifs:layer` = `outer` (so neither sealed key opens as the other). Each stored package
(ciphertext and tag, as above) is encrypted again with AES-256-CTR:

| Field | Value |
|---|---|
| Key | Outer part key = HKDF-SHA256(ikm = second data key, salt = none, info = `"teifs dsse v1"` ‖ part number as u32 big-endian ‖ part salt, if the part has one) |
| Initial counter block | The package's index as u64 big-endian, then 64 zero bits (a package is far fewer than 2^64 blocks) |

Reading removes the outer layer, then opens the package as above. Sizes and offsets are
the same as a single layer's. The second sealed key is `outer` in the record, beside
`sealed`.

## ETags and checksums

| Mode | ETag | Stored checksums |
|---|---|---|
| SSE-S3 | MD5 of the plaintext (as AWS) | In the clear |
| SSE-KMS, DSSE-KMS, SSE-C | `HMAC-SHA256(data key, "teifs etag v1" ‖ MD5 of the plaintext)`, first 16 bytes, hex (not the MD5, as AWS) | Sealed with the data key |

Multipart objects follow the same rule per part, then the usual `-N` multipart ETag.
Under SSE-KMS, DSSE-KMS and SSE-C each part's checksums are sealed too, from the moment the part
is stored: the checksum map then holds a single `sealed` entry (base64 of the sealed
JSON map), in the upload's `parts` rows and, after Complete, in the object's `parts`.
Listing parts opens them with the data key (SSE-C: only when the request carries the
customer's key). A completed upload's remembered answer keeps no checksums for these
modes.

"Sealed with the data key" means AES-256-GCM with the key HKDF-SHA256(ikm = data key,
salt = none, info = `"teifs meta v1"`), a random 12-byte nonce stored in front, and no
AAD. Each object's data key is unique, so random nonces here are never near their limit.

## Changing an object's encryption

UpdateObjectEncryption moves an SSE-S3 or SSE-KMS version to SSE-KMS under another key
without touching its data: the data key is unsealed and sealed again under the new KMS
key, with the same context (the object id, and the client's SSE-KMS pairs), so the
packages, the ETag, the modification time and the checksums stay. Checksums an SSE-S3
object kept in the clear (the object's and its parts') are sealed with the data key, as
SSE-KMS keeps them. The new record replaces the old one only if the version's record is
still the one read (else the object was written again meanwhile, and the request fails
with `409 OperationAborted`). DSSE-KMS, SSE-C and unencrypted objects can't be changed this way. The
record is `crypt` in the index; `bucketKey: true` marks one reported as using an S3 Bucket
Key.

## Rotating and rewrapping keys

Rotating a KMS key (`teifs key rotate NAME`) adds a version that seals new data keys;
the versions before it keep unsealing what they sealed (`sealed.kmsVersion` in each
record). `teifs key rewrap NAME` seals again, under the newest version, every data key an
older version of `NAME` sealed (a DSSE-KMS object's second key too, when `NAME` is
`teifs-default`): object versions (Object Lock doesn't stop it, since only
the sealed key changes) and multipart uploads in progress. Each record keeps its mode,
context, Bucket Key and checksums, and is replaced only if it's still the one read; one
written again meanwhile is left for another run. It runs on a drive `teifs serve` isn't
using, and running it again carries on. The copy of the sealed key in a data file's
footer is written once and keeps the older version: the index is authoritative.

## Versions

| Version | Change |
|---|---|
| 1 | This document |
| 2 | Parts of multipart uploads: a random salt in each part's key (`"teifs data v2"`), and each encrypted object's parts record lists the number and salt of every part |
