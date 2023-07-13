defmodule IntegrityProofs.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    plc_repo_start = System.get_env("PLC_REPO_START")

    children =
      if is_nil(plc_repo_start) do
        IO.puts("IntegrityProofs: not using database")
        []
      else
        IO.puts("IntegrityProofs: using PlcRepo")

        [
          # Start the Ecto repository
          IntegrityProofs.Did.PlcRepo
        ]
      end

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: IntegrityProofs.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
