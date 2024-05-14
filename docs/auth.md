In this document, we will introduce a new concept, `auth` (authentication). It
was firstly introduced in [RFC:
Omnilock](https://github.com/nervosnetwork/rfcs/pull/343). It's used for
authentication by validating signature for different blockchains.

### Compile dependencies
Before using the following APIs, it is necessary to compile CKB scripts.

To compile, use the following commands in the root directory. The generated files will be located in the `build` directory.

```
git submodule update --init
make all-via-docker
```

For detailed instructions, please refer to the [README.md](../README.md) or [CI](../.github/workflows/rust.yml).

### Definition

```C
typedef struct CkbAuthType {
  uint8_t algorithm_id;
  uint8_t content[AUTH160_SIZE];  // #define AUTH160_SIZE 20
} CkbAuthType;
```

It is a data structure with 21 bytes. The content can be hash (blake160 or some
other hashes) of public key, preimage, or some others. The blake160 hash function
is defined as first 20 bytes of [blake2b
hash](https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0022-transaction-structure/0022-transaction-structure.md#crypto-primitives).

### Auth Algorithm Id
Here we list some known `algorithm_id` which have been implemented already:

#### CKB(algorithm_id=0)

It is implemented by default CKB lock script: secp256k1_blake160_sighash_all. More details in [reference implementation](https://github.com/nervosnetwork/ckb-system-scripts/blob/master/c/secp256k1_blake160_sighash_all.c).

Key parameters:
* signature: a 65-byte signature defined in [secp256k1 library](https://github.com/bitcoin-core/secp256k1)
* pubkey: 33-byte compressed pubkey
* pubkey hash: blake160 of pubkey


#### Ethereum(algorithm_id=1)

It is implemented by blockchain Ethereum.
[reference implementation](https://github.com/XuJiandong/pw-lock/blob/e7f5f2379185d4acf18af38645559102e100a545/c/pw_lock.h#L199)

Key parameters:

  - signature: a 65-byte signature defined in [secp256k1 library](https://github.com/bitcoin-core/secp256k1)
  - pubkey: 64-byte uncompressed pubkey
  - pubkey hash: last 20 bytes of pubkey keccak hash

#### EOS(algorithm_id=2)

[reference implementation](https://github.com/XuJiandong/pw-lock/blob/e7f5f2379185d4acf18af38645559102e100a545/c/pw_lock.h#L206)

Key parameters: Same as ethereum

#### Tron(algorithm_id=3)
[reference implementation](https://github.com/XuJiandong/pw-lock/blob/e7f5f2379185d4acf18af38645559102e100a545/c/pw_lock.h#L213)

Key parameters: Same as ethereum

#### Bitcoin(algorithm_id=4)

[reference implementation](https://github.com/XuJiandong/pw-lock/blob/e7f5f2379185d4acf18af38645559102e100a545/c/pw_lock.h#L220)

Key parameters:
- signature: a 65-byte signature defined in [secp256k1 library](https://github.com/bitcoin-core/secp256k1)
- pubkey: 65-byte uncompressed pubkey
- pubkey hash: first 20 bytes of sha256 and ripemd160 on pubkey

#### Dogecoin(algorithm_id=5)

[reference implementation](https://github.com/XuJiandong/pw-lock/blob/e7f5f2379185d4acf18af38645559102e100a545/c/pw_lock.h#L227)

Key parameters: same as bitcoin

#### CKB MultiSig(algorithm_id=6)

[reference implementation](https://github.com/nervosnetwork/ckb-system-scripts/blob/master/c/secp256k1_blake160_multisig_all.c)

Key parameters:
- signature: multisig_script | Signature1 | Signature2 | ...
- pubkey: variable length, defined as multisig_script(S | R | M | N | PubKeyHash1 | PubKeyHash2 | ...)
- pubkey hash: blake160 on pubkey

`multisig_script` has following structure:
```
+-------------+------------------------------------+-------+
|             |           Description              | Bytes |
+-------------+------------------------------------+-------+
| S           | reserved field, must be zero       |     1 |
| R           | first nth public keys must match   |     1 |
| M           | threshold                          |     1 |
| N           | total public keys                  |     1 |
| PubkeyHash1 | blake160 hash of compressed pubkey |    20 |
|  ...        |           ...                      |  ...  |
| PubkeyHashN | blake160 hash of compressed pubkey |    20 |
```


#### Schnorr(algorithm_id=7)

Key parameters:
- signature: 32 bytes pubkey + 64 bytes signature
- pubkey: 32 compressed pubkey
- pubkey hash: blake160 of pubkey

#### Litecoin(algorithm_id=10)

Key parameters: same as bitcoin

#### CardanoLock(algorithm_id=11)

Key parameters:
- signature: cardano signed data.
- pubkey: 32 compressed pubkey
- pubkey hash: blake160 of pubkey

#### Monero(algorithm_id=12)

Key parameters:
- signature: monero signature
- mode: 1 byte hardcoded to 00 to indicate we are using spend key to sign transactions
- spend key: 32 bytes of the public spend key
- view key: 32 bytes of the public view key
- pubkey hash: blake160 of (mode || spend key || view key)

#### Solana(algorithm_id=13)
The witness of a valid solana transaction should be a sequence of the following data.
The whole length of the witness must be exactly 512. If there are any space left, pad it with zero.

- size of the following data combined (little-endian `uint16_t`)
- signature: solana signature
- public key: the public key of the signer
- message: the message solana client signed

#### Ripple(algorithm_id=14)

Key parameters:
- signature: ripple signature (tx_blob field).
- pubkey: 32 compressed pubkey.
- pubkey hash: sha256 and ripemd160 of pubkey, refer to [ckb-auth-cli ripple parse](../tools/ckb-auth-cli/src/ripple.rs).

### Low Level APIs

We define some low level APIs to auth libraries, which can be also used for other purposes.
It is based on the following idea:
* [RFC: Swappable Signature Verification Protocol Spec](https://talk.nervos.org/t/rfc-swappable-signature-verification-protocol-spec/4802)

First we define the "EntryType":
```C
typedef struct CkbEntryType {
    uint8_t code_hash[BLAKE2B_BLOCK_SIZE];
    uint8_t hash_type;
    uint8_t entry_category;
} CkbEntryType;
```

* code_hash/hash_type

  the cell which contains the code binary
* entry_category

  The entry to the algorithm. Now there are 3 categories:
  - dynamic library
  - exec
  - spawn (will be activated after hardfork 2023/2024)

### Entry Category: Dynamic Library
We should export the follow function from dynamic library when entry category is
`dynamic library`:
```C
int ckb_auth_load_prefilled_data(uint8_t auth_algorithm_id, void *prefilled_data, size_t *len);
```
The first argument denotes the `algorithm_id` in `CkbAuthType`. The `prefilled`
and `len` will be described below.

It gives a chance for different algorithms to load necessary data. For example,
a [precomputed table](https://github.com/bitcoin-core/secp256k1) is necessary
for secp256k1. So far, this is the only data should be loaded. In the full
lifetime of a CKB script, it is expected to only call this function once to
initialize the data. All latter invocations can share the same prefilled data.

This function should support 2 invocation modes:

- When `data` is NULL, and `len` is an address for a variable with value 0, the
  function is expected to fill in the length required by the prefilled data into
  the address denoted by `len`. This can be used by the caller to allocate
  enough prefilled data for the library.

- When `data` is not NULL, and the variable denoted by `len` contains enough
length, the function is expected to fill prefilled data in the memory buffer
started from data, and then fill the actual length of the prefilled data in `len`
field. The `len` value is suggested to be 1048576 for secp256k1.

In either mode, a return value of 0 denoting success, other values denote
failures, and should immediately trigger a script failure.

We should also export the following important function from dynamic library:
```C
int ckb_auth_validate(void *prefilled_data, uint8_t auth_algorithm_id, const uint8_t *signature,
    uint32_t signature_size, const uint8_t *message, uint32_t message_size,
    uint8_t *pubkey_hash, uint32_t pubkey_hash_size);
```
The first argument denotes the `prefilled_data` returned from
`ckb_auth_load_prefilled_data`. The second argument denotes the `algorithm_id` in
`CkbAuthType` described above. The arguments `signature` and `pubkey_hash` are
described in `key parameters` mentioned above. A return value of 0 denoting
success, other values denote failures, and should immediately trigger a script
failure.

A valid dynamic library denoted by `EntryType` should provide
`ckb_auth_load_prefilled_data` and `ckb_auth_validate` exported functions.

### Entry Category: Spawn
This category shares same arguments and behavior to dynamic library. It uses `spawn` instead of `dynamic library`. When
entry category is `spawn`, its arguments format is below:

```text
<auth algorithm id>  <signature>  <message>  <pubkey hash>
```
They will be passed as `argv` in `spawn` syscall, in hex format. An example of arguments:
```
20 000000000000AA11 000000000000BB22 000000000000CC33
```

The `auth algorithm id` denotes the `algorithm_id` in `CkbAuthType` described above. The fields `signature` and
`pubkey_hash` are described in `key parameters` mentioned above.

We can implement different auth algorithm ids in same code binary. 

### Entry Category: Exec
The invocation method is the same as that of `Spawn`.


### High Level APIs
The following API can combine the low level APIs together:
```C
int ckb_auth_load_prefilled_data(uint8_t auth_algorithm_id, void *prefilled_data, size_t *len);
int ckb_auth(EntryType* entry, CkbAuthType *id, uint8_t *signature, uint32_t signature_size, const uint8_t *message32)
```
Most of developers only need to use these functions without knowing the low level APIs.


### Rust High Level APIs
Provide a Rust interface, you can directly call the related functions of ckb-auth in rust.

Dependencies name: `ckb-auth-rs`

#### API Description
``` rust
pub fn ckb_auth_load_prefilled_data(auth_algorithm_id: u8, prefilled_data: &mut[u8]);
pub fn ckb_auth(
    entry: &CkbEntryType,
    id: &CkbAuthType,
    signature: &[u8],
    message: &[u8; 32],
) -> Result<(), CkbAuthError>
```

`CkbEntryType` : On-chain information and calling method of auth script.

`CkbAuthType` : Auth Algorithm Id and public key hash

`signature` : signature data.

`message` : Participate in the message data of the signature.

#### Other Issues for High Level C APIs
A dynamic library will create a cache in static memory for loading ckb-auth.
This cache is initially set to 200k, and if adjustments are necessary, you can
modify it by defining the macro CKB_AUTH_DL_BUFF_SIZE in C. However, it's
important to note that the ckb-auth default is around 100k, and setting it too
small may result in execution failure. CKB-VM allocates a maximum of 4M memory,
and setting it too large may lead to insufficient memory.

By default, you can load up to 8 different ckb-auth libraries. If this is
insufficient, you can modify it by defining CKB_AUTH_DL_MAX_COUNT. If you prefer
not to use this feature, you can disable it by including
CKB_AUTH_DISABLE_DYNAMIC_LIB. This will help conserve memory and reduce the size
of the script.
