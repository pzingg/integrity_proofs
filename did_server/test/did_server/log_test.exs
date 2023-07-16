defmodule DidServer.LogTest do
  use DidServer.DataCase

  alias DidServer.Log

  describe "dids" do
    alias DidServer.Log.Did

    import DidServer.LogFixtures

    @invalid_attrs %{"did" => nil}

    test "list_dids/0 returns all dids" do
      did = did_fixture()
      assert Log.list_dids() == [did]
    end

    test "get_did!/1 returns the did with given id" do
      did = did_fixture()
      assert Log.get_did!(did.did) == did
    end

    test "create_did/1 succeeds with valid attributes" do
      {:ok, %Did{}} = Log.create_did(%{did: "did:plc:y54rrfl37i5wqztksze4bddl"})
    end

    test "create_did/1 fails with invalid attributes" do
      {:error, _} = Log.create_did(@invalid_attrs)
    end

    test "create_did/1 fails for an existing did" do
      did = did_fixture()
      {:error, _} = Log.create_did(%{did: did.did})
    end
  end

  describe "operations" do
    alias DidServer.Log.Operation

    test "inserts a new create operation" do
      {signing_key, _} = CryptoUtils.Keys.generate_key_pair(:did_key, :secp256k1)

      {recovery_key, {algo, [priv, curve]}} =
        CryptoUtils.Keys.generate_key_pair(:did_key, :secp256k1)

      signer = [recovery_key, to_string(algo), priv, to_string(curve)]

      assert String.starts_with?(signing_key, "did:key:z7")
      assert String.starts_with?(recovery_key, "did:key:z7")

      assert {:ok, {op, did}} =
               CryptoUtils.Did.create_operation(
                 signingKey: signing_key,
                 recoveryKey: recovery_key,
                 signer: signer,
                 handle: "bob.bsky.social",
                 service: "https://pds.example.com"
               )

      assert "did:plc:" <> <<_id::binary-size(24)>> = did

      assert {:ok,
              %{did: %{did: did}, operation: %Operation{did: did} = created_op, most_recent: nil}} =
               DidServer.Log.create_operation(did, op)

      IO.inspect(created_op)
    end
  end
end
