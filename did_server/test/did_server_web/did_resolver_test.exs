defmodule DidServerWeb.ResolverTest do
  # async: false, because otherwise one test will create a did:plc
  # and the other won't see it?
  use DidServerWeb.ConnCase, async: false

  alias CryptoUtils.Keys.Keypair

  setup_all :start_endpoint

  def start_endpoint(_context) do
    endpoint_config =
      Application.get_env(:did_server, DidServerWeb.Endpoint)
      |> Keyword.put(:server, true)

    :ok = Application.put_env(:did_server, DidServerWeb.Endpoint, endpoint_config)
    :ok = Application.stop(:did_server)
    :ok = Application.start(:did_server)
  end

  def resolver_opts do
    base_url = DidServerWeb.Endpoint.url()

    rewrite_patterns = [
      {~r|^https?://example\.com/.well-known(/.*)$|,
       fn _, path -> base_url <> "/.well-known" <> path end},
      {~r|^https?://plc.directory(/.*)$|, fn _, path -> base_url <> "/plc" <> path end}
    ]

    [rewrite_patterns: rewrite_patterns]
  end

  describe "resolves dids" do
    test "resolves a did:web" do
      assert {:ok, doc} = CryptoUtils.Resolver.resolve_did("did:web:example.com", resolver_opts())
      assert "@admin@example.com" in doc["alsoKnownAs"]
    end

    test "resolves a did:plc" do
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
      IO.puts("registered #{did}")
      IO.puts("log: #{inspect(DidServer.Log.list_registered_dids())}")

      assert {:ok, doc} = CryptoUtils.Resolver.resolve_did(did, resolver_opts())
      assert "at://bob.bsky.social" in doc["alsoKnownAs"]
    end
  end
end
