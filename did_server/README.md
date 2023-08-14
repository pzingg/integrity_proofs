# DidServer

A Phoenix-based web server backed by a PostgreSQL database
to demonstrate delivery and updating of DID identities.

Also exposes a basic user account schema for roaming identities
that might be extended to support both ActivityPub and
the Bluesky AT Protocol.

Both did:web and did:plc methods are implemented.

To start your Phoenix server:

- Run `mix setup` to install and setup dependencies
- Start Phoenix endpoint with `mix phx.server` or inside IEx with `iex -S mix phx.server`

Now you can visit [`localhost:4000`](http://localhost:4000) from your browser.

Ready to run in production? Please [check our deployment guides](https://hexdocs.pm/phoenix/deployment.html).

## Learn more

- Official website: https://www.phoenixframework.org/
- Guides: https://hexdocs.pm/phoenix/overview.html
- Docs: https://hexdocs.pm/phoenix
- Forum: https://elixirforum.com/c/phoenix-forum
- Source: https://github.com/phoenixframework/phoenix

## Identity ideas from Bluesky

Bluesky says that out of the box they support both the did:web and did:plc
methods to resolve identities. The did:web method is only supported at
the domain level, with the URL of

- `https://[<username>.]<domain.com>/.well-known/did.json`

That is, no path elements in the DID are supported.

In addition Bluesky will use either a DNS TXT records or a well-known web
address, to resolve the DID for a particular custom domain or sub-domain.
To support more than one user at a hosted domain probably would require
staging per-user sub-domains through a DNS service and web server that
can proxy and respond correctly to any request for sub-domains like
`<username>.<domain.com>`.

As of July 5, 2023, Bluesky is now in the per-user domain reselling
business, so they obviously believe that this is something users
will want to take adavantage of.

More information is here:

- [ATProtocol: Identity](https://atproto.com/guides/identity)
- [did-method-plc repository](https://github.com/bluesky-social/did-method-plc)
- [How to set your domain as your handle](https://blueskyweb.xyz/blog/4-28-2023-domain-handle-tutorial)

## "Persona" and identity model

Discussion from https://matrix.to/#/!vpdMrhHjzaPbBUSgOs:matrix.org/$Gc0872Gfhxin3tY66DTigS9CkSnhNNroS14hAwNMkCM

I am experimenting with an idea of multiple user "personas" all under the
umbrella of a single identity, which is represented by a DID.

Each persona has its own display name, user name, domain name, and profile
information (description, avatar, banner). The schema for the persona is the
`DidServer.Accounts.Account` module.

The identity DID holds the single hashed password for authentication. Any of
the personas linked to the DID can use this password for authentication.
The schema for the DID is the `DidServer.Identities.Key` module.

The thing I'm finding difficult to understand from the Bluesky protocols,
is where the private keys for the "signing key" (a public-private keypair)
and for the "rotation keys" (each one a keypair) come from, and if and where
they need to be stored.

The [indigo repository](https://github.com/bluesky-social/indigo) seems to
use a single, server-wide signing key, read at start up from a "server.key"
file on disk in the function `cmd.laputa.main.run`.

When user accounts are created in the `pds.handlers.handleComAtprotoServerCreateAccount`
function, the recovery key is optional and is passed in via arguments. Its
DID (public key, potentially empty) is stored with the user, and if the key
is not given in the command input, the server-wide signing key is used as
the single rotation key for the DID that is created for the user.

The command-line command `gosky newAccount` does not parse or send a recovery
key, so in effect the user always has an empty string its `recoveryKey` field.

To sign documents and verify documents, indigo uses a `KeyManager` interface.
When signing, the KeyManager must hold a valid private keypair in its
`signingKey` field, although this seems never to be set. Instead, the only
signing is inside the `api.plc.CreateDID` function, which gets passed the
server-wide signing key as an argument.

To verify DID documents, the document is resolved and the KeyManager extracts
the public key from the "#atproto" verification method.

Thus no private key is ever stored in a database, but is it safe to use a
single site-wide key this way?

## Implmentation: user model and authentication

The "user" (`DidServer.Accounts.User`), which is able to log in with a password
or WebAuthn passkey, and which creates and verifies session tokens, binds
an "account" (`DidServer.Accounts.Account`; the user's account and profile on
a specific internet domain or instance) to a DID. The DID (`DidServer.Identities.Key`)
holds a single hashed password and a private key, held in a key vault
(extremely insecure in this development demo). In production, the key vault
should be kept in an separate secure storage.

`User`s can store multiple WebAuthn credentials (`DidServer.Identities.Credential`)
on different devices.

I don't know enough about HSMs like the Yubikey or Apple's iCloud Keychain
to understand how or if you can programmatically use these securely stored
keypairs to sign a document. AFAICT, the access granted to these stored keys
by browsers supporting the Credential Management and Web Authentication APIs
is limited to authentication challenges and attestations; the private key
cannot be used for signing arbitrary hashes.

Mulitple `User`s can be represented in the same DID (as they are listed in the
DID document's `alsoKnownAs` field), and thus they all share the same password,
but they will have distinct WebAuthn passkeys.

## did:web method support

(Development) URLs for fetching DID documents are, e.g.

For a DID like `did:web:localhost%3A4000`:

- http://localhost:4000/.well-known/did.json

For a DID with path elements like `did:web:localhost%3A4000:user:alice`
(not supported by Bluesky):

- http://localhost:4000/users/alice/did.json

## did:plc method support

The `https://plc.directory` described in the did-method-plc README
is served at `http://localhost:4000/plc` in the development server,
so URLs for fetching DID documents are, e.g.

- http://localhost:4000/plc/did%3Aplc%3A4heftswx5xresjexdo4nnpmj
