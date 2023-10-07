defmodule DidServer.DidOrbServer do
  use GenServer

  # require Logger

  @orb_executable "/home/pzingg/Projects/misc/orb/.build/bin/orb"

  # GenServer API
  def start_link(args \\ [], opts \\ []) do
    GenServer.start_link(__MODULE__, args, opts)
  end

  def ready?(pid) do
    GenServer.call(pid, :ready?, 100)
  end

  def init(args \\ []) do
    listen_port = Keyword.get(args, :port, 7890)
    did_namespace = Keyword.get(args, :did_namespace, "test")
    did_aliases = Keyword.get(args, :did_aliases, "did:orb")
    allowed_origins = Keyword.get(args, :allowed_origins, "*")

    port =
      Port.open(
        {:spawn_executable, @orb_executable},
        [
          {:args,
           [
             "start",
             "--host-url=localhost:#{listen_port}",
             "--external-endpoint=http://localhost:#{listen_port}",
             "--anchor-credential-domain=http://localhost:#{listen_port}",
             "--did-namespace=#{did_namespace}",
             "--did-aliases=#{did_aliases}",
             "--allowed-origins=#{allowed_origins}",
             "--current-sidetree-protocol-version=1.0",
             "--batch-writer-timeout=1000",
             "--anchor-status-monitoring-interval=1s",
             "--kms-type=local",
             "--cas-type=local",
             "--database-type=mem",
             "--kms-secrets-database-type=mem"
           ]},
          {:line, 2048},
          :exit_status
        ]
      )

    IO.puts("orb server started")
    {:ok, %{port: port, ready?: false, latest_output: nil, exit_status: nil}}
  end

  # This callback handles data incoming from the command's STDOUT
  def handle_info({_port, {:data, {:eol, text_line}}}, state) do
    latest_output = to_string(text_line) |> String.trim()
    IO.puts(latest_output)

    state =
      if String.contains?(latest_output, "Started Orb services") do
        %{state | ready?: true, latest_output: latest_output}
      else
        %{state | latest_output: latest_output}
      end

    {:noreply, state}
  end

  # This callback tells us when the process exits
  def handle_info({_port, {:exit_status, status}}, state) do
    IO.puts("orb server exit_status: #{status}")

    {:noreply, %{state | ready?: false, exit_status: status}}
  end

  # no-op catch-all callback for unhandled messages
  def handle_info(_msg, state), do: {:noreply, state}

  def handle_call(:ready?, _from, %{ready?: ready} = state) do
    {:reply, ready, state}
  end
end
