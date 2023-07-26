defmodule DidServerWeb.ResolverTest do
  # async: false, because otherwise one test will create a did:plc
  # and the other won't see it?
  @behaviour CryptoUtils.Fetcher

  use DidServerWeb.ConnCase

  alias CryptoUtils.Keys.Keypair

  @impl true
  def fetch(url, opts) do
    conn = Keyword.fetch!(opts, :test_conn)

    %URI{path: path} =
      url
      |> CryptoUtils.Resolver.maybe_rewrite(opts)
      |> URI.parse()

    {_conn, resp} =
      case Keyword.get(opts, :method, :get) do
        :get ->
          conn = get(conn, path)
          {conn, response(conn, 200)}

        :post ->
          body = Keyword.fetch!(opts, :body)
          conn = post(conn, path, body)
          {conn, response(conn, 200)}
      end

    {:ok, resp}
  end

  def resolver_opts do
    rewrite_patterns = [
      {~r|^https?://example\.com/.well-known(/.*)$|, fn _, path -> "/.well-known/#{path}" end},
      {~r|^https?://plc.directory(/.*)$|, fn _, path -> "/plc/#{path}" end}
    ]

    [rewrite_patterns: rewrite_patterns, fetcher: __MODULE__]
  end

  describe "resolves dids" do
    test "resolves a did:web", %{conn: conn} do
      opts = resolver_opts() |> Keyword.put(:test_conn, conn)
      assert {:ok, doc} = CryptoUtils.Resolver.resolve_did("did:web:example.com", opts)
      assert "@admin@example.com" in doc["alsoKnownAs"]
    end

    test "resolves a did:plc", %{conn: conn} do
      signing_key = Keypair.generate(:p256, :did_key)
      recovery_key = Keypair.generate(:p256, :did_key)

      params = %{
        type: "create",
        signingKey: Keypair.did(signing_key),
        recoveryKey: Keypair.did(recovery_key),
        signer: Keypair.to_json(recovery_key),
        handle: "bob.bsky.social",
        service: "https://pds.example.com",
        password: "bluesky"
      }

      assert {:ok, %{operation: %{did: did}}} = DidServer.Log.create_operation(params)

      opts = resolver_opts() |> Keyword.put(:test_conn, conn)
      assert {:ok, doc} = CryptoUtils.Resolver.resolve_did(did, opts)
      assert "at://bob.bsky.social" in doc["alsoKnownAs"]
    end
  end
end
