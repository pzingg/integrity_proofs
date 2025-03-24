# This file is responsible for configuring your application
# and its dependencies with the aid of the Config module.
#
# This configuration file is loaded before any dependency and
# is restricted to this project.

# General application configuration
import Config

config :did_server,
  ecto_repos: [DidServer.Repo]

# Configures the endpoint
config :did_server, DidServerWeb.Endpoint,
  url: [host: "localhost"],
  adapter: Bandit.PhoenixAdapter,
  render_errors: [
    formats: [html: DidServerWeb.ErrorHTML, json: DidServerWeb.ErrorJSON],
    layout: false
  ],
  pubsub_server: DidServer.PubSub,
  live_view: [signing_salt: "xy8rTkUe"]

config :esbuild,
  version: "0.17.11",
  default: [
    args:
      ~w(js/app.js --bundle --target=es2017 --outdir=../priv/static/assets --external:/fonts/* --external:/images/*),
    cd: Path.expand("../assets", __DIR__),
    env: %{"NODE_PATH" => Path.expand("../deps", __DIR__)}
  ]

# Configure tailwind (the version is required)
config :tailwind,
  version: "3.2.4",
  default: [
    args: ~w(
      --config=tailwind.config.js
      --input=css/app.css
      --output=../priv/static/assets/app.css
    ),
    cd: Path.expand("../assets", __DIR__)
  ]

# Configures Elixir's Logger
config :logger, :console,
  format: "$time $metadata[$level] $message\n",
  metadata: [:request_id]

# Use Jason for JSON parsing in Phoenix
config :phoenix, :json_library, Jason

# WebAuthn configuration
config :wax_,
  # If set to :auto, rp_id is automatically determined from the origin (set to the host)
  rp_id: :auto,
  update_metadata: true,
  allowed_attestation_types: [:basic, :uncertain, :attca, :self],
  metadata_dir: "priv/fido2_metadata/"

# Import environment specific config. This must remain at the bottom
# of this file so it overrides the configuration defined above.
import_config "#{config_env()}.exs"
