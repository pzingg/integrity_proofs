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

    test "creates a valid create op" do
      [signing_key | _] = signing_keypair_fixture()
      [recovery_key | _] = signer = recovery_keypair_fixture()

      params = %{
        # type: "create",
        signingKey: signing_key,
        recoveryKey: recovery_key,
        signer: signer,
        handle: "bob.bsky.social",
        service: "https://pds.example.com"
      }

      assert {:ok, %{operation: created_op}} = DidServer.Log.create_operation(params)
      assert created_op.did == "did:plc:tuoulvfey6235ijox23kr6zj"
      assert %{"type" => "plc_operation"} = DidServer.Log.validate_operation_log(created_op.did)
    end

    test "updates handle" do
      [signing_key | _] = signing_keypair_fixture()
      [recovery_key | _] = signer = recovery_keypair_fixture()

      create_params = %{
        # type: "create",
        signingKey: signing_key,
        recoveryKey: recovery_key,
        signer: signer,
        handle: "bob.bsky.social",
        service: "https://pds.example.com"
      }

      assert {:ok, %{operation: created_op}} = DidServer.Log.create_operation(create_params)

      created_op_data = Operation.to_data(created_op)
      assert Map.get(created_op_data, "alsoKnownAs") == ["at://bob.bsky.social"]

      update_params = %{
        did: created_op.did,
        signer: signer,
        handle: "alice.bsky.social"
      }

      assert {:ok, %{operation: updated_op}} = DidServer.Log.update_operation(update_params)

      updated_op_data = Operation.to_data(updated_op)
      assert Map.get(updated_op_data, "alsoKnownAs") == ["at://alice.bsky.social"]
      assert %{"type" => "plc_operation"} = DidServer.Log.validate_operation_log(created_op.did)
    end

    test "does not allow operations from the signingKey" do
      [signing_key | _] = signing_keypair = signing_keypair_fixture()
      [recovery_key | _] = signer = recovery_keypair_fixture()

      create_params = %{
        # type: "create",
        signingKey: signing_key,
        recoveryKey: recovery_key,
        signer: signer,
        handle: "bob.bsky.social",
        service: "https://pds.example.com"
      }

      assert {:ok, %{operation: created_op}} = DidServer.Log.create_operation(create_params)

      update_params = %{
        did: created_op.did,
        signer: signing_keypair,
        handle: "alice.bsky.social"
      }

      # Should raise
      assert {:ok, %{operation: _updated_op}} = DidServer.Log.update_operation(update_params)
      assert %{"type" => "plc_operation"} = DidServer.Log.validate_operation_log(created_op.did)
    end

    test "tombstones a DID" do
      [signing_key | _] = signing_keypair_fixture()
      [recovery_key | _] = signer = recovery_keypair_fixture()

      create_params = %{
        # type: "create",
        signingKey: signing_key,
        recoveryKey: recovery_key,
        signer: signer,
        handle: "bob.bsky.social",
        service: "https://pds.example.com"
      }

      assert {:ok, %{operation: created_op}} = DidServer.Log.create_operation(create_params)

      created_op_data = Operation.to_data(created_op)
      assert Map.get(created_op_data, "alsoKnownAs") == ["at://bob.bsky.social"]

      tombstone_params = %{
        type: "plc_tombstone",
        did: created_op.did,
        signer: signer
      }

      assert {:ok, %{operation: tombstone}} = DidServer.Log.update_operation(tombstone_params)
      assert Operation.tombstone?(tombstone)
      assert DidServer.Log.validate_operation_log(created_op.did) == nil
    end
  end
end
