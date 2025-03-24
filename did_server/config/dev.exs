import Config

# Configure your database
config :did_server, DidServer.Repo,
  username: "postgres_super",
  password: "postgres",
  hostname: "localhost",
  database: "did_server",
  stacktrace: true,
  show_sensitive_data_on_connection_error: true,
  pool_size: 10

use_ssl? = false

# Choose whether to use SSL on an ip address or plain HTTP on "localhost".
# Wax library requires "https" scheme for any origin other than "localhost".
{scheme, host, ip, port} =
  if use_ssl? do
    {"https", "10.0.0.95", {10, 0, 0, 95}, 4000}
  else
    {"http", "localhost", {127, 0, 0, 1}, 4000}
  end

# For development, we disable any cache and enable
# debugging and code reloading.
#
# The watchers configuration can be used to run external
# watchers to your application. For example, we use it
# with esbuild to bundle .js and .css sources.
config :did_server, DidServerWeb.Endpoint,
  # Binding to loopback ipv4 address prevents access from other machines.
  # Change to `ip: {0, 0, 0, 0}` to allow access from other machines.
  http: [ip: ip, port: port],
  check_origin: false,
  code_reloader: true,
  debug_errors: false,
  secret_key_base: "XSIJUjzie0dBqOk1aqIIfsBIuHKcdrUz92K9k+gh6rq29Qv5mIaEOH7caWlU5auF",
  watchers: [
    esbuild: {Esbuild, :install_and_run, [:default, ~w(--sourcemap=inline --watch)]},
    tailwind: {Tailwind, :install_and_run, [:default, ~w(--watch)]}
  ]

## SSL Support
# Using Self-signed SSL certificate from mix phx.gen.cert
#
# WARNING: only use the generated certificate for testing in a closed network
# environment, such as running a development server on `localhost`.
# For production, staging, or testing servers on the public internet, obtain a
# proper certificate, for example from [Let's Encrypt](https://letsencrypt.org).
#
# NOTE: when using Google Chrome, open chrome://flags/#allow-insecure-localhost
# to enable the use of self-signed certificates on `localhost`.
#
# If desired, both `:http` and `:https` keys can be configured to run both
# http and https servers on different ports.
if scheme == "https" do
  config :did_server, DidServerWeb.Endpoint,
    https: [
      port: port + 1,
      cipher_suite: :strong,
      certfile: "priv/cert/selfsigned.pem",
      keyfile: "priv/cert/selfsigned_key.pem"
    ]
end

# WebAuthn configuration
config :wax_,
  # Because :check_origin is false in the dev endpoint, we supply the origin here
  origin: "#{scheme}://#{host}:#{port}"

# Watch static and templates for browser reloading.
config :did_server, DidServerWeb.Endpoint,
  live_reload: [
    patterns: [
      ~r"priv/static/.*(js|css|png|jpeg|jpg|gif|svg)$",
      ~r"lib/did_server_web/(controllers|live|components)/.*(ex|heex)$"
    ]
  ]

# Enable dev routes for dashboard and mailbox
config :did_server, dev_routes: true

# Do not include metadata nor timestamps in development logs
config :logger, :console, format: "[$level] $message\n"

# Set a higher stacktrace during development. Avoid configuring such
# in production as building large stacktraces may be expensive.
config :phoenix, :stacktrace_depth, 20

# Initialize plugs at runtime for faster development compilation
config :phoenix, :plug_init_mode, :runtime
