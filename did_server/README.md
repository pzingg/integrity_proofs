# DidServer

A Phoenix-based web server backed by a PostgreSQL database 
to demonstrate delivery and updating of DID identities.

Both did:web and did:plc methods are implemented.

To start your Phoenix server:

  * Run `mix setup` to install and setup dependencies
  * Start Phoenix endpoint with `mix phx.server` or inside IEx with `iex -S mix phx.server`

Now you can visit [`localhost:4000`](http://localhost:4000) from your browser.

Ready to run in production? Please [check our deployment guides](https://hexdocs.pm/phoenix/deployment.html).

## Learn more

  * Official website: https://www.phoenixframework.org/
  * Guides: https://hexdocs.pm/phoenix/overview.html
  * Docs: https://hexdocs.pm/phoenix
  * Forum: https://elixirforum.com/c/phoenix-forum
  * Source: https://github.com/phoenixframework/phoenix

## Identity ideas from Bluesky

Bluesky says that out of the box they support both the did:web and did:plc 
methods to resolve identities. The did:web method is only supported at
the domain level, with the URL of 

  * `https://[<username>.]<domain.com>/.well-known/did.json`

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

  * [ATProtocol: Identity](https://atproto.com/guides/identity)
  * [did-method-plc repository](https://github.com/bluesky-social/did-method-plc)
  * [How to set your domain as your handle](https://blueskyweb.xyz/blog/4-28-2023-domain-handle-tutorial)

## did:web

(Development) URLs for fetching DID documents are, e.g.

For a DID like `did:web:localhost%3A4000`:

  * http://localhost:4000/.well-known/did.json

For a DID with path elements like `did:web:localhost%3A4000:user:alice` 
(not supported by Bluesky):

  * http://localhost:4000/users/alice/did.json

## did:plc

The `https://plc.directory` described in the did-method-plc README
is served at `http://localhost:4000/plc` in the development server,
so URLs for fetching DID documents are, e.g.

  * http://localhost:4000/plc/did%3Aplc%3A4heftswx5xresjexdo4nnpmj
