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

    import DidServer.LogFixtures

    test "list_operations/0 returns all operations" do
      %Operation{did: did} = op = operation_fixture()
      assert Log.list_operations(did) == [op]
    end

    @signing_key "did:key:z7r8op7JkEfuM8hD4ZhppR7uS1Nq43pgMuP8q8Un4GvVJSraf1bcToVQav3eY8w9ZoQuibf1aLb9PwPBbHFBanqKVCQNf"
    @recovery_key "did:key:z7r8or2MBTgMnfgSjS2VDou7sLbwWv37Sc3rRyJ7kmjVHzrTfcb7obqjNiV2oJvShFFi4jRD2s8itELsvig6ATvbDjsdK"
    @signer [
      @recovery_key,
      "ecdsa",
      <<253, 249, 135, 239, 146, 2, 35, 75, 76, 166, 15, 121, 230, 110, 238, 184, 210, 95, 61, 38,
        149, 69, 224, 54, 14, 165, 233, 4, 56, 117, 164, 104>>,
      "secp256k1"
    ]
    @genesis_did "did:plc:kb6whcb3dlbajvkhmnabaqmy"

    test "inserts a new create operation" do
      params = %{
        # type: "create",
        signingKey: @signing_key,
        recoveryKey: @recovery_key,
        signer: @signer,
        handle: "bob.bsky.social",
        service: "https://pds.example.com"
      }

      assert {:ok, %{operation: %Operation{did: did}}} = DidServer.Log.create_operation(params)
      assert did == @genesis_did
    end

    test "updates an operation with a new handle" do
      create_params = %{
        # type: "create",
        signingKey: @signing_key,
        recoveryKey: @recovery_key,
        signer: @signer,
        handle: "bob.bsky.social",
        service: "https://pds.example.com"
      }

      assert {:ok, %{operation: created_op}} = DidServer.Log.create_operation(create_params)

      created_op_data = Operation.to_data(created_op)
      assert Map.get(created_op_data, "alsoKnownAs") == ["at://bob.bsky.social"]

      update_params = %{
        did: @genesis_did,
        signer: @signer,
        handle: "alice.bsky.social"
      }

      assert {:ok, %{operation: updated_op}} = DidServer.Log.update_operation(update_params)

      updated_op_data = Operation.to_data(updated_op)
      assert Map.get(updated_op_data, "alsoKnownAs") == ["at://alice.bsky.social"]
    end

    test "tombstones a DID" do
      create_params = %{
        # type: "create",
        signingKey: @signing_key,
        recoveryKey: @recovery_key,
        signer: @signer,
        handle: "bob.bsky.social",
        service: "https://pds.example.com"
      }

      assert {:ok, %{operation: created_op}} = DidServer.Log.create_operation(create_params)

      created_op_data = Operation.to_data(created_op)
      assert Map.get(created_op_data, "alsoKnownAs") == ["at://bob.bsky.social"]

      tombstone_params = %{
        type: "plc_tombstone",
        did: @genesis_did,
        signer: @signer
      }

      assert {:ok, %{operation: tombstone}} = DidServer.Log.update_operation(tombstone_params)
      assert Operation.tombstone?(tombstone)
    end
  end
end
