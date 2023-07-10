# IntegrityProofs

Some Elixir functions to implement [Verifiable Credential Data Integrity 1.0](https://www.w3.org/TR/vc-data-integrity/) using the 
[EdDSA Cryptosuite](https://www.w3.org/TR/vc-di-eddsa/) and the
[JSON Canonicalization Scheme (JCS)](https://www.rfc-editor.org/rfc/rfc8785).

See also:

* [Fediverse Enhancement Proposal FEP-c390: Identity Proofs](https://codeberg.org/silverpill/feps/src/branch/main/c390/fep-c390.md)
* [Decentralized Identifiers (DIDs) v1.0](https://www.w3.org/TR/did-core/)
* [The did:key Method v0.7](https://w3c-ccg.github.io/did-method-key/)

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `integrity_proofs` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:integrity_proofs, "~> 0.1.0"}
  ]
end
```

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at <https://hexdocs.pm/integrity_proofs>.

## Status and roadmap

Right now, fetching verification methods, controller documents, and keys are all
done in memory, using the options shown in the tests. 

A future version should utilize registered verification handler
behaviour modules that can dereference remote key stores, and 
(with proper authorization) look up private keys that correspond
to exposed public keys.

Implementations of hosted (non-decentralized) DID systems,
using the "did:web" and "did:plc" methods are also planned.

## Implementation notes

Uses the Erlang modules `:crypto`, `:public_key` and `:ssh_file`. For some reason,
I cannot get the simple `:public_key.sign/5` and `:public_key.verify/6` functions
to work (they fail with `:badarg` errors), so I re-format the keys myself using 
Erlang code directly copied from the `:public_key` module source, 
and then call `:crypto.sign/5` and `:crypto.verify/6`. 

## Generating and parsing ED25119 key pairs

"PEM" encoded key pairs that use the ED25519 curve can be parsed by
`IntegrityProofs.decode_ed25519_pem/3` function. These key pairs
can be generated from the command line with:

```sh
ssh-keygen -t ed25519 -C "bob@example.com" -f test/fixtures/bob_example_ed25519
mv test/fixtures/bob_example_ed25519 test/fixtures/bob_example_ed25519.pub

openssl ecparam -name prime256v1 -genkey -noout -out test/fixtures/p256.priv
openssl ec -in test/fixtures/p256.priv -pubout > test/fixtures/p256.pub

openssl ecparam -name secp256k1 -genkey -noout -out test/fixtures/secp256k1.priv
openssl ec -in test/fixtures/secp256k1.priv -pubout > test/fixtures/secp256k1.pub
```

## did:key implementation

The examples in the [The did:key Method v0.7](https://w3c-ccg.github.io/did-method-key/) 
draft seem not to jibe with algorithms described there. I'm not sure where the 
multibase values for the key agreement parts come from, or whether anyone
has actually tried to follow this spec.
