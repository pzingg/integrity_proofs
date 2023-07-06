# IntegrityProofs

Some functions to implement the [EdDSA Cryptosuite](https://www.w3.org/TR/vc-di-eddsa/)
in Elixir.

See also 

* [Verifiable Credential Data Integrity 1.0](https://www.w3.org/TR/vc-data-integrity/)
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

## Generating ed25119 key pairs

```sh
ssh-keygen -t ed25519 -C "bob@example.com" -f bob_example_ed25519
```
