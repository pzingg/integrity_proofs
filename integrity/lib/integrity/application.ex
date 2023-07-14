defmodule Integrity.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    did_server_start = System.get_env("DID_SERVER_START")

    if is_nil(did_server_start) do
      IO.puts("Integrity.Application.start: not using DID server")
      continue_startup()
    else
      IO.puts("Integrity.Application.start: starting DID server")

      case Application.ensure_all_started(:did_server, :permanent) do
        {:ok, _apps} ->
          continue_startup()

        {:error, reason} ->
          IO.puts("DID server failed to start: #{inspect(reason)}")
          {:error, reason}
      end
    end
  end

  def continue_startup() do
    children = []

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: Integrity.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
