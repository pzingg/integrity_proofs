# IntegrityProofs

Some Elixir functions to implement [Verifiable Credential Data Integrity 1.0](https://www.w3.org/TR/vc-data-integrity/) using the 
[EdDSA Cryptosuite](https://www.w3.org/TR/vc-di-eddsa/) and the
[JSON Canonicalization Scheme (JCS)](https://www.rfc-editor.org/rfc/rfc8785).

See also:

* [Fediverse Enhancement Proposal FEP-c390: Identity Proofs](https://codeberg.org/silverpill/feps/src/branch/main/c390/fep-c390.md)
* [Decentralized Identifiers (DIDs) v1.0](https://www.w3.org/TR/did-core/)
* [The did:key Method v0.7](https://w3c-ccg.github.io/did-method-key/)

This project contains three "poncho" Elixir applications. Consult the 
README files in these sub-folders for more information:

* `crypto_utils` - low-level functions for keys and elliptic curves
* `did_server` - a Phoenix server that implements both a did:web and a 
  did:plc server
* `integrity` - functions for signing and verifying documents and 
  resolving DIDs
