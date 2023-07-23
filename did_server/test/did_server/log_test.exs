defmodule DidServer.LogTest do
  use DidServer.DataCase

  alias DidServer.Log

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
      assert Log.list_operations(did) == [%{op | password: nil}]
    end

    test "creates a valid create op" do
      [signing_key | _] = signing_keypair_fixture()
      [recovery_key | _] = signer = recovery_keypair_fixture()

      params = %{
        type: "create",
        signingKey: signing_key,
        recoveryKey: recovery_key,
        signer: signer,
        handle: "bob.bsky.social",
        service: "https://pds.example.com",
        password: "bluesky"
      }

      assert {:ok, %{operation: created_op}} = DidServer.Log.create_operation(params)
      assert created_op.did == "did:plc:vve2x2or6xnchxc5dxky4gbf"

      created_op_data = CryptoUtils.Did.to_data(created_op)
      assert %{"handle" => "at://bob.bsky.social"} = created_op_data

      assert %{"type" => "create"} = DidServer.Log.validate_operation_log(created_op.did)
    end

    test "updates handle" do
      [signing_key | _] = signing_keypair_fixture()
      [recovery_key | _] = signer = recovery_keypair_fixture()

      create_params = %{
        type: "create",
        signingKey: signing_key,
        recoveryKey: recovery_key,
        signer: signer,
        alsoKnownAs: ["bob.bsky.social"],
        service: "https://pds.example.com",
        password: "bluesky"
      }

      assert {:ok, %{operation: %{did: did} = created_op}} =
               DidServer.Log.create_operation(create_params)

      created_op_data = CryptoUtils.Did.to_data(created_op)
      assert %{"handle" => "at://bob.bsky.social"} = created_op_data

      update_params = %{
        did: did,
        signer: signer,
        alsoKnownAs: ["alice.bsky.social"]
      }

      assert {:ok, %{operation: updated_op}} =
               DidServer.Log.update_operation(created_op, update_params)

      updated_op_data = CryptoUtils.Did.to_data(updated_op)

      assert %{"type" => "plc_operation", "alsoKnownAs" => ["at://alice.bsky.social"]} =
               updated_op_data

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
        alsoKnownAs: ["bob.bsky.social"],
        service: "https://pds.example.com",
        password: "bluesky"
      }

      assert {:ok, %{operation: %{did: did} = created_op}} =
               DidServer.Log.create_operation(create_params)

      update_params = %{
        did: did,
        signer: signing_keypair,
        alsoKnownAs: ["alice.bsky.social"]
      }

      assert_raise(CryptoUtils.Did.InvalidSignatureError, fn ->
        DidServer.Log.update_operation(created_op, update_params)
      end)
    end

    test "tombstones a DID" do
      [signing_key | _] = signing_keypair_fixture()
      [recovery_key | _] = signer = recovery_keypair_fixture()

      create_params = %{
        type: "create",
        signingKey: signing_key,
        recoveryKey: recovery_key,
        signer: signer,
        handle: "bob.bsky.social",
        service: "https://pds.example.com",
        password: "bluesky"
      }

      assert {:ok, %{operation: %{did: did} = created_op}} =
               DidServer.Log.create_operation(create_params)

      created_op_data = CryptoUtils.Did.to_data(created_op)
      assert %{"type" => "create", "handle" => "at://bob.bsky.social"} = created_op_data

      tombstone_params = %{
        did: did,
        type: "plc_tombstone",
        signer: signer
      }

      assert {:ok, %{operation: tombstone}} =
               DidServer.Log.update_operation(created_op, tombstone_params)

      assert Operation.tombstone?(tombstone)
      assert DidServer.Log.validate_operation_log(created_op.did) == nil
    end

    test "does not allow a tombstone in the middle of the log" do
      [signing_key | _] = signing_keypair_fixture()
      [recovery_key | _] = signer = recovery_keypair_fixture()

      create_params = %{
        type: "create",
        signingKey: signing_key,
        recoveryKey: recovery_key,
        signer: signer,
        handle: "bob.bsky.social",
        service: "https://pds.example.com",
        password: "bluesky"
      }

      assert {:ok, %{operation: %{did: did} = created_op}} =
               DidServer.Log.create_operation(create_params)

      created_op_data = CryptoUtils.Did.to_data(created_op)
      assert %{"type" => "create", "handle" => "at://bob.bsky.social"} = created_op_data

      tombstone_params = %{
        did: did,
        type: "plc_tombstone",
        signer: signer
      }

      assert {:ok, %{operation: tombstone_op}} =
               DidServer.Log.update_operation(created_op, tombstone_params)

      update_params = %{
        did: did,
        signer: signer,
        handle: "alice.bsky.social"
      }

      assert_raise(CryptoUtils.Did.MisorderedOperationError, fn ->
        DidServer.Log.update_operation(tombstone_op, update_params)
      end)
    end
  end
end
