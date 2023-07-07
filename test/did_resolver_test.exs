defmodule IntegrityProofs.DidResolverTest do
  use ExUnit.Case

  @identifier "did:web:server.example:users:alice"

  setup do
    TestServer.start()

    TestServer.add("/users/alice/did.json",
      to: fn conn ->
        Plug.Conn.send_resp(conn, 200, "success")
      end
    )
  end

  def request(%URI{path: path} = uri, opts \\ []) do
    url =
      TestServer.url(path)
      |> String.to_charlist()

    httpc_http_opts = Keyword.get(opts, :http_opts, [])
    httpc_opts = Keyword.get(opts, :opts, [])

    opts
    |> Keyword.get(:method, :get)
    |> case do
      :post -> :httpc.request(:post, {url, [], 'plain/text', 'OK'}, httpc_http_opts, httpc_opts)
      :get -> :httpc.request(:get, {url, []}, httpc_http_opts, httpc_opts)
    end
    |> case do
      {:ok, {{_, 200, _}, _headers, body}} -> {:ok, to_string(body)}
      {:ok, {{_, _, _}, _headers, body}} -> {:error, to_string(body)}
      {:error, error} -> {:error, error}
    end
  end

  test "resolves a did:web identifier" do
    {:ok, uri} = IntegrityProofs.Did.did_web_url(@identifier)
    assert URI.to_string(uri) == "https://server.example/users/alice/did.json"

    resp = request(uri)
    assert {:ok, "success"} = resp
  end
end
