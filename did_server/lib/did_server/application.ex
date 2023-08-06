defmodule DidServer.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      # Start the Telemetry supervisor
      DidServerWeb.Telemetry,
      # Start the Ecto repository
      DidServer.Repo,
      # Start the PubSub system
      {Phoenix.PubSub, name: DidServer.PubSub},
      # Start the Endpoint (http/https)
      DidServerWeb.Endpoint
      # Start a worker by calling: DidServer.Worker.start_link(arg)
      # {DidServer.Worker, arg}
    ]

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: DidServer.Supervisor]
    Supervisor.start_link(children, opts)
  end

  # Tell Phoenix to update the endpoint configuration
  # whenever the application is updated.
  @impl true
  def config_change(changed, _new, removed) do
    DidServerWeb.Endpoint.config_change(changed, removed)
    :ok
  end

  def name do
    Application.get_env(:did_server, :server_name, "DID Server")
  end

  def domain do
    Application.get_env(:did_server, :server_domain, "example.com")
  end

  def version do
    {:ok, vsn} = :application.get_key(:did_server, :vsn)
    List.to_string(vsn)
  end

  def services do
    Application.get_env(
      :did_server,
      :supported_services,
      "did_web,did_plc,atproto_pds,activitypub"
    )
    |> String.split(",")
  end
end
