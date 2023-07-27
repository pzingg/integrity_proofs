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

That is, no path elements in the did are supported.

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

## Personal and identity model

Discussion from https://matrix.to/#/!vpdMrhHjzaPbBUSgOs:matrix.org/$Gc0872Gfhxin3tY66DTigS9CkSnhNNroS14hAwNMkCM

I am experimenting with an idea of multiple user "personas" all under the umbrella of a single identity, which is represented by a did.

Each persona has its own display name, user name, domain name, and profile information (description, avatar, banner). The schema for the persona is the `DidServer.Accounts.User` module.

The identity did holds the single hashed password for authentication. Any of the personas linked to the did can use this password for authentication. The schema for the did is the `DidServer.Log.Key` module.

The thing I'm finding difficult to understand from the Bluesky protocols, is where the private keys for the "signing key" (a public-private keypair) and for the "rotation keys" (each one a keypair) come from, and if and where they need to be stored.

The [indigo repository](https://github.com/bluesky-social/indigo) seems to use a single, server-wide signing key, read at start up from a "server.key" file on disk in the function `cmd.laputa.main.run`.

When user accounts are created in the `pds.handlers.handleComAtprotoServerCreateAccount` function, the recovery key is optional and is passed in via arguments. Its did (public key, potentially empty) is stored with the user, and if the key is not given in the command input, the server-wide signing key is used as the single rotation key for the did that is created for the user.

The command-line command `gosky newAccount` does not parse or send a recovery key, so in effect the user always has an empty string its `recoveryKey` field.

To sign documents and verify documents, indigo uses a `KeyManager` interface. When signing, the KeyManager must hold a valid private keypair in its `signingKey` field, although this seems never to be set. Instead, the only signing is inside the `api.plc.CreateDID` function, which gets passed the server-wide signing key as an argument.

To verify did documents, the document is resolved and the KeyManager extracts the public key from the "#atproto" verification method.

Thus no private key is ever stored in a database, but is it safe to use a single site-wide key this way?

## did:web

(Development) URLs for fetching DID documents are, e.g.

For a DID like `did:web:localhost%3A4000`:

- http://localhost:4000/.well-known/did.json

For a DID with path elements like `did:web:localhost%3A4000:user:alice`
(not supported by Bluesky):

- http://localhost:4000/users/alice/did.json

## did:plc

The `https://plc.directory` described in the did-method-plc README
is served at `http://localhost:4000/plc` in the development server,
so URLs for fetching DID documents are, e.g.

- http://localhost:4000/plc/did%3Aplc%3A4heftswx5xresjexdo4nnpmj
