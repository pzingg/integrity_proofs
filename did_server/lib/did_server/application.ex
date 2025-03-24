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
      DidServerWeb.Endpoint,
      # Start a worker by calling: DidServer.Worker.start_link(arg)
      DidServer.AgentKeyStore
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

  def email_from do
    Application.get_env(:did_server, :email_from, "support@example.com")
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

  def at_pds_server_url do
    {scheme, host_port} = scheme_host_port()
    "#{scheme}://pds.#{host_port}"
  end

  def ap_server_url do
    {scheme, host_port} = scheme_host_port()
    "#{scheme}://#{host_port}"
  end

  defp scheme_host_port do
    %URI{scheme: scheme, host: host, port: port} =
      Application.get_env(:did_server, :base_server_url, "https://example.com") |> URI.parse()

    host =
      if host == "127.0.0.1" do
        "localhost"
      else
        host
      end

    {scheme,
     case {scheme, port} do
       {_, nil} -> host
       {:https, 443} -> host
       {:http, 80} -> host
       _ -> "#{host}:#{port}"
     end}
  end
end
