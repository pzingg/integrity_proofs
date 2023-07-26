defmodule DidServer.LogTest do
  use DidServer.DataCase

  alias CryptoUtils.Keys.Keypair
  alias DidServer.Log

  @signing_key Keypair.generate(:secp256k1, :did_key)
  @rotation_key_1 Keypair.generate(:secp256k1, :did_key)
  @rotation_key_2 Keypair.generate(:secp256k1, :did_key)

  describe "keys" do
    alias DidServer.Log.Key

    import DidServer.LogFixtures

    @invalid_attrs %{"did" => nil, "password" => nil}

    test "list_keys/0 returns all dids" do
      %{did: did} = key_fixture()
      assert [%Key{did: ^did}] = Log.list_keys()
    end

    test "get_key!/1 returns the did with given id" do
      %{did: did} = key_fixture()
      assert %Key{did: ^did} = Log.get_key!(did)
    end

    test "create_key/1 succeeds with valid attributes" do
      did = "did:plc:y54rrfl37i5wqztksze4bddl"
      password = "bluesky"
      {:ok, %Key{did: ^did}} = Log.create_key(%{did: did, password: password})
    end

    test "create_key/1 fails with invalid attributes" do
      {:error, _} = Log.create_key(@invalid_attrs)
    end

    test "create_key/1 fails for an existing did" do
      %{did: did} = key_fixture()
      {:error, _} = Log.create_key(%{did: did})
    end
  end

  describe "operations" do
    alias DidServer.Log.Operation

    import DidServer.LogFixtures

    test "list_operations/0 returns all operations" do
      %Operation{did: did} = op = operation_fixture()
      assert Log.list_operations(did, true) == [%{op | password: nil}]
    end

    def genesis_op() do
      params = %{
        type: "plc_operation",
        signingKey: Keypair.did(@signing_key),
        rotationKeys: [Keypair.did(@rotation_key_1), Keypair.did(@rotation_key_2)],
        signer: Keypair.to_json(@rotation_key_1),
        handle: "bob.bsky.social",
        service: "https://pds.example.com",
        password: "bluesky"
      }

      DidServer.Log.create_operation(params)
    end

    test "creates a valid create op" do
      assert {:ok, %{operation: created_op}} = genesis_op()

      created_op_data = CryptoUtils.Did.to_data(created_op)

      assert %{"type" => "plc_operation", "alsoKnownAs" => ["at://bob.bsky.social"]} =
               created_op_data
    end

    test "parses an operation log with no updates" do
      assert {:ok, %{operation: %{did: did} = created_op}} = genesis_op()

      assert %{"type" => "plc_operation", "alsoKnownAs" => ["at://bob.bsky.social"]} =
               DidServer.Log.validate_operation_log!(did)
    end

    test "updates handle" do
      assert {:ok, %{operation: %{did: did} = created_op}} = genesis_op()

      update_params = %{
        did: did,
        alsoKnownAs: ["alice.bsky.social"],
        signer: Keypair.to_json(@rotation_key_1)
      }

      assert {:ok, %{operation: updated_op}} =
               DidServer.Log.update_operation(created_op, update_params)

      updated_op_data = CryptoUtils.Did.to_data(updated_op)

      assert %{"type" => "plc_operation", "alsoKnownAs" => ["at://alice.bsky.social"]} =
               updated_op_data

      assert %{"type" => "plc_operation", "alsoKnownAs" => ["at://alice.bsky.social"]} =
               DidServer.Log.validate_operation_log!(created_op.did)
    end

    test "allows for operations from either rotation key" do
      assert {:ok, %{operation: %{did: did} = created_op}} = genesis_op()

      update_params = %{
        did: did,
        alsoKnownAs: ["alice.bsky.social"],
        signer: Keypair.to_json(@rotation_key_2)
      }

      assert {:ok, %{operation: updated_op}} =
               DidServer.Log.update_operation(created_op, update_params)

      updated_op_data = CryptoUtils.Did.to_data(updated_op)

      assert %{"type" => "plc_operation", "alsoKnownAs" => ["at://alice.bsky.social"]} =
               updated_op_data

      assert %{"type" => "plc_operation"} = DidServer.Log.validate_operation_log!(created_op.did)
    end

    test "rotates signing key" do
      assert {:ok, %{operation: %{did: did} = created_op}} = genesis_op()

      new_signing_key = Keypair.generate(:secp256k1, :did_key)

      update_params = %{
        did: did,
        siginingKey: Keypair.did(new_signing_key),
        signer: Keypair.to_json(@rotation_key_1)
      }

      assert {:ok, %{operation: updated_op}} =
               DidServer.Log.update_operation(created_op, update_params)
    end

    test "rotates rotation keys" do
      assert {:ok, %{operation: %{did: did} = created_op}} = genesis_op()

      new_rotation_key = Keypair.generate(:secp256k1, :did_key)

      update_params = %{
        did: did,
        rotationKeys: [Keypair.did(new_rotation_key), Keypair.did(@rotation_key_2)],
        signer: Keypair.to_json(@rotation_key_1)
      }

      assert {:ok, %{operation: updated_op}} =
               DidServer.Log.update_operation(created_op, update_params)
    end

    test "no longer allows operations from old rotation key" do
      assert {:ok, %{operation: %{did: did} = created_op}} = genesis_op()

      new_rotation_key = Keypair.generate(:secp256k1, :did_key)

      update_params = %{
        did: did,
        rotationKeys: [Keypair.did(new_rotation_key), Keypair.did(@rotation_key_2)],
        signer: Keypair.to_json(@rotation_key_1)
      }

      assert {:ok, %{operation: updated_op}} =
               DidServer.Log.update_operation(created_op, update_params)

      update_params = %{
        did: did,
        alsoKnownAs: ["alice.bsky.social"],
        signer: Keypair.to_json(@rotation_key_1)
      }

      assert_raise(CryptoUtils.Did.InvalidSignatureError, fn ->
        DidServer.Log.update_operation(updated_op, update_params)
      end)
    end

    test "does not allow operations from the signingKey" do
      assert {:ok, %{operation: %{did: did} = created_op}} = genesis_op()

      new_rotation_key = Keypair.generate(:secp256k1, :did_key)

      update_params = %{
        did: did,
        rotationKeys: [Keypair.did(new_rotation_key), Keypair.did(@rotation_key_2)],
        signer: Keypair.to_json(@rotation_key_1)
      }

      assert {:ok, %{operation: updated_op}} =
               DidServer.Log.update_operation(created_op, update_params)

      update_params = %{
        did: did,
        alsoKnownAs: ["alice.bsky.social"],
        signer: Keypair.to_json(@signing_key)
      }

      assert_raise(CryptoUtils.Did.InvalidSignatureError, fn ->
        DidServer.Log.update_operation(created_op, update_params)
      end)
    end

    test "allows tombstoning a DID" do
      assert {:ok, %{operation: %{did: did} = created_op}} = genesis_op()

      tombstone_params = %{
        did: did,
        type: "plc_tombstone",
        signer: Keypair.to_json(@rotation_key_1)
      }

      assert {:ok, %{operation: tombstone}} =
               DidServer.Log.update_operation(created_op, tombstone_params)

      assert Operation.tombstone?(tombstone)
      assert DidServer.Log.validate_operation_log!(did) == nil
    end

    test "requires operations to be in order" do
    end

    test "does not allow a create operation in the middle of the log" do
    end

    test "does not allow a tombstone in the middle of the log" do
      assert {:ok, %{operation: %{did: did} = created_op}} = genesis_op()

      tombstone_params = %{
        did: did,
        type: "plc_tombstone",
        signer: Keypair.to_json(@rotation_key_1)
      }

      assert {:ok, %{operation: tombstone_op}} =
               DidServer.Log.update_operation(created_op, tombstone_params)

      update_params = %{
        did: did,
        alsoKnownAs: ["alice.bsky.social"],
        signer: Keypair.to_json(@rotation_key_1)
      }

      assert_raise(CryptoUtils.Did.MisorderedOperationError, fn ->
        DidServer.Log.update_operation(tombstone_op, update_params)
      end)
    end

    test "requires that the did is the hash of the genesis op" do
    end

    test "requires that the log starts with a create op (no prev)" do
    end
  end
end
