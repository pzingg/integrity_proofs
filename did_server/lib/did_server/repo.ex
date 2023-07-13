defmodule DidServer.Repo do
  use Ecto.Repo,
    otp_app: :did_server,
    adapter: Ecto.Adapters.Postgres
end
