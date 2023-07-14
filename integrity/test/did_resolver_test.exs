defmodule Integrity.DidResolverTest do
  use ExUnit.Case

  @public_key_bytes <<243, 105, 212, 154, 54, 128, 250, 99, 47, 184, 242, 248, 144, 45, 17, 70,
                      176, 243, 220, 174, 103, 200, 4, 192, 33, 143, 102, 29, 234, 149, 1, 188>>

  @multibase_value CryptoUtils.Keys.make_public_key(@public_key_bytes, :ed25519, :multikey)

  @identifier "did:web:server.example:users:alice"

  setup do
    TestServer.start()

    TestServer.add("/users/alice/did.json",
      to: fn conn ->
        body =
          DidServer.format_did_document!(@identifier,
            multibase_value: @multibase_value,
            signature_method_fragment: "keys-1"
          )
          |> Jason.encode!()

        conn
        |> Plug.Conn.put_resp_header("content-type", "application/json")
        |> Plug.Conn.send_resp(200, body)
      end
    )
  end

  def fetch(url, opts) do
    %URI{path: path} = URI.parse(url)

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
    {:ok, uri} = Integrity.Did.did_web_uri(@identifier)
    url = URI.to_string(uri)
    assert url == "https://server.example/users/alice/did.json"

    resp = fetch(url, [])
    assert {:ok, json} = resp
    assert {:ok, document} = Jason.decode(json)
    assert document["id"] == @identifier
  end

  test "resolves a did:web identifier using web_resolver" do
    assert document =
             Integrity.Did.resolve_did_web!(@identifier,
               web_resolver: __MODULE__
             )

    assert document["id"] == @identifier
  end
end
