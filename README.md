# IntegrityProofs

Some Elixir functions to implement [Verifiable Credential Data Integrity 1.0](https://www.w3.org/TR/vc-data-integrity/) using the 
[EdDSA Cryptosuite](https://www.w3.org/TR/vc-di-eddsa/) and the
[JSON Canonicalization Scheme (JCS)](https://www.rfc-editor.org/rfc/rfc8785).

See also:

* [Fediverse Enhancement Proposal FEP-c390: Identity Proofs](https://codeberg.org/silverpill/feps/src/branch/main/c390/fep-c390.md)
* [Decentralized Identifiers (DIDs) v1.0](https://www.w3.org/TR/did-core/)

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

## Status and roadman

Right now, fetching verification methods, controller documents, and keys are all
done in memory, using the options shown in the tests. Implementation of 
a hosted DID system is in the plan.

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
ssh-keygen -t ed25519 -C "bob@example.com" -f bob_example_ed25519
```
