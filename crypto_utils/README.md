# CryptoUtils

A library of some functions used by the `integrity` application.

The library defines a `CID` structure and works around limitations
of existing Elixir projects that do not deal with certain elliptical
curve and hashes encoded in the multiformats system. Besides relying
on Erlang's `:crypto` and `:ssh_file` applications, the library
makes partial use of these other Elixir projects:

* `multibase`
* `multicodec`
* `cbor`

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `crypto_utils` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:crypto_utils, "~> 0.1.0"}
  ]
end
```

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at <https://hexdocs.pm/crypto_utils>.

