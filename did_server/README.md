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

## did:web

(Development) URLs for fetching DID documents are, e.g.

* http://localhost:4000/.well-known/did.json
* http://localhost:4000/user/alice/did.json

## did:plc

(Development) URLs for fetching DID documents are, e.g.

* http://localhost:4000/plc/did%3Aplc%3A4heftswx5xresjexdo4nnpmj
