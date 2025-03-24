defmodule DidServerWeb.ResolverTest do
  # async: false, because otherwise one test will create a did:plc
  # and the other won't see it?

  use DidServerWeb.ConnCase

  import DidServer.AccountsFixtures

  alias CryptoUtils.Keys.Keypair

  describe "resolves dids" do
    test "resolves a did:web", %{conn: conn} do
      {:ok, _user} =
        DidServer.Accounts.register_account(
          valid_account_attributes(username: "admin", domain: "example.com")
        )

      opts = [rewrite_patterns: rewrite_patterns()]

      assert {:ok, {_res_meta, doc, _doc_meta}} =
               CryptoUtils.Did.resolve_did!("did:web:example.com", opts)

      assert "https://example.com/users/admin" in doc["alsoKnownAs"]
    end

    test "resolves a did:plc", %{conn: conn} do
      Req.Test.stub(DidPlcStub, fn conn ->
        Req.Test.json(conn, %{"celsius" => 25.0})
      end)

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

      opts = [rewrite_patterns: rewrite_patterns()]
      assert {:ok, {_res_meta, doc, _doc_meta}} = CryptoUtils.Did.resolve_did!(did, opts)
      assert "at://bob.bsky.social" in doc["alsoKnownAs"]
    end
  end

  def rewrite_patterns() do
    localhost = DidServerWeb.Endpoint.url()

    [
      {~r|^https?://example\.com/.well-known(/.*)$|,
       fn _, path -> "#{localhost}/.well-known#{path}" end},
      {~r|^https?://plc.directory(/.*)$|, fn _, path -> "#{localhost}/plc#{path}" end}
    ]
  end
end
