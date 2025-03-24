defmodule DidServer.RecoveryTest do
  use DidServer.DataCase

  import Ecto.Changeset

  alias CryptoUtils.Did.Methods.DidPlc.{InvalidSignatureError, LateRecoveryError}
  alias CryptoUtils.Did.Methods.DidPlc
  alias CryptoUtils.Keys.Keypair
  alias DidServer.{Log, Repo}
  alias DidServer.Log.Operation

  # @signing_key Keypair.generate(:secp256k1, :did_key)
  @rotation_key_1 Keypair.generate(:secp256k1, :did_key)
  @rotation_key_2 Keypair.generate(:secp256k1, :did_key)
  @rotation_key_3 Keypair.generate(:secp256k1, :did_key)
  @handle "alice.example.com"
  @service "https://example.com"

  describe "key recovery" do
    test "allows a rotation key with higher authority to rewrite history" do
      DateTime.utc_now() |> key_2_asserts_control()
    end

    test "does not allow the lower authority key to take control back" do
      DateTime.utc_now() |> key_3_attempts_control()
    end

    test "allows a rotation key with even higher authority to rewrite history" do
      DateTime.utc_now() |> key_1_asserts_control_after_key_2()
    end

    test "does not allow the either invalidated key to take control back" do
      DateTime.utc_now() |> invalidated_keys_fail_to_take_back_control()
    end

    test "does not allow recovery outside of 72 hrs" do
      DateTime.utc_now() |> fails_expired_recovery()
    end

    test "allows recovery from a tombstoned DID" do
      DateTime.utc_now() |> nullifies_tombstone()
    end
  end

  defp setup_genesis(now) do
    seven_days_ago = DateTime.add(now, -(7 * 24 * 3600), :second)

    create_changeset =
      sign_op_for_keys(
        [@rotation_key_1, @rotation_key_2, @rotation_key_3],
        @rotation_key_1,
        seven_days_ago
      )

    assert {:ok, %{operation: %Operation{} = create}} =
             create_changeset
             |> Log.multi_insert(false)
             |> Repo.transaction()

    {:ok, create}
  end

  # Creates 3 operations
  # [0] -> creation did with [key_1, key_2, key_3], signed by key_1
  # [1] -> rotation to [key_3], signed by key_3
  # [2] -> update handle (same rotation to [key_3], signed by key_3)
  defp setup_rotation(now) do
    {:ok, %{did: did, cid: create_cid} = create} = setup_genesis(now)
    create_op = DidPlc.to_data(create)
    assert Map.get(create_op, "rotationKeys") |> Enum.count() == 3

    # key 3 tries to usurp control
    one_day_ago = DateTime.add(now, -(24 * 3600), :second)

    rotate_changeset =
      sign_op_for_keys([@rotation_key_3], @rotation_key_3, one_day_ago,
        did: did,
        prev: create_cid
      )

    assert {:ok, %{operation: %Operation{cid: rotate_cid}}} =
             rotate_changeset
             |> Log.multi_insert(false)
             |> Repo.transaction()

    # and does some additional ops
    one_hour_ago = DateTime.add(now, -(24 * 3600), :second)

    another_changeset =
      sign_op_for_keys([@rotation_key_3], @rotation_key_3, one_hour_ago,
        did: did,
        prev: rotate_cid,
        changes: %{alsoKnownAs: ["newhandle.test"]}
      )

    assert {:ok, %{operation: %Operation{cid: _another_cid}}} =
             another_changeset
             |> Log.multi_insert(false)
             |> Repo.transaction()

    ops = Log.list_operations(did, true)
    assert Enum.count(ops) == 3

    {:ok, %{ops: ops}}
  end

  # Proposes a new operation
  # [3] -> rotation to [key_2], signed by key_2, prev [0]
  # key_2 asserts control over key_3
  defp key_2_asserts_control(now) do
    {:ok, %{ops: [%{did: did, cid: create_cid}, op_1, op_2] = ops}} = setup_rotation(now)

    rotate_changeset =
      sign_op_for_keys([@rotation_key_2], @rotation_key_2, now, did: did, prev: create_cid)

    rotate_op = apply_changes(rotate_changeset) |> DidPlc.to_data()

    # Nullified are [1, 2]
    # Disputed signer is key_3
    # More powerful keys are [key_1, key_2]
    # [3] will verify with key_2
    {proposed, nullified_cids} = DidPlc.assure_valid_next_op(did, ops, rotate_op)

    assert [cid_1, cid_2] = nullified_cids
    assert cid_1 == op_1.cid
    assert cid_2 == op_2.cid

    prev = Map.get(proposed, "prev")
    assert prev == create_cid

    assert {:ok, %{operation: %Operation{cid: key_2_asserts_control_cid} = _rotate}} =
             rotate_changeset
             |> Log.multi_insert(false)
             |> Repo.transaction()

    assert {:ok, ops} = Log.reset_log(did, cids_to_keep: [create_cid, key_2_asserts_control_cid])
    assert Enum.count(ops) == 2
    ops
  end

  # Proposes a new operation
  # [3] -> rotation to [key_3], signed by key_3, prev [0]
  defp key_3_attempts_control(now) do
    [%{did: did, cid: create_cid} | _] = ops = key_2_asserts_control(now)

    rotate_changeset =
      sign_op_for_keys([@rotation_key_3], @rotation_key_3, now, did: did, prev: create_cid)

    rotate_op = apply_changes(rotate_changeset) |> DidPlc.to_data()

    # Nullified are [1, 2]
    # Disputed signer is key_3
    # More powerful keys are [key_1, key_2]
    # [3] fails to verify with these keys (it was signed with key_3)
    assert_raise(InvalidSignatureError, fn ->
      DidPlc.assure_valid_next_op(did, ops, rotate_op)
    end)

    ops
  end

  defp key_1_asserts_control_after_key_2(now) do
    [%{did: did, cid: create_cid}, op_1] = ops = key_2_asserts_control(now)

    # Proposes a new operation
    # [2] -> rotation to [key_1], signed by key_1, prev [0]
    rotate_changeset =
      sign_op_for_keys([@rotation_key_1], @rotation_key_1, now, did: did, prev: create_cid)

    rotate_op = apply_changes(rotate_changeset) |> DidPlc.to_data()

    # Nullified are [1]
    # Disputed signer is key_2
    # More powerful keys are [key_1]
    # [3] will verify with key_1
    {proposed, nullified_cids} = DidPlc.assure_valid_next_op(did, ops, rotate_op)

    assert [cid_1] = nullified_cids
    assert cid_1 == op_1.cid

    prev = Map.get(proposed, "prev")
    assert prev == create_cid

    assert {:ok, %{operation: %Operation{cid: rotate_cid} = _rotate}} =
             rotate_changeset
             |> Log.multi_insert(false)
             |> Repo.transaction()

    assert {:ok, ops} = Log.reset_log(did, cids_to_keep: [create_cid, rotate_cid])
    assert Enum.count(ops) == 2
    ops
  end

  defp invalidated_keys_fail_to_take_back_control(now) do
    [%{did: did, cid: create_cid} | _] = ops = key_1_asserts_control_after_key_2(now)

    rotate_changeset =
      sign_op_for_keys([@rotation_key_3], @rotation_key_3, now, did: did, prev: create_cid)

    rotate_op = apply_changes(rotate_changeset) |> DidPlc.to_data()

    assert_raise(InvalidSignatureError, fn ->
      DidPlc.assure_valid_next_op(did, ops, rotate_op)
    end)

    rotate_changeset =
      sign_op_for_keys([@rotation_key_2], @rotation_key_2, now, did: did, prev: create_cid)

    rotate_op = apply_changes(rotate_changeset) |> DidPlc.to_data()

    assert_raise(InvalidSignatureError, fn ->
      DidPlc.assure_valid_next_op(did, ops, rotate_op)
    end)

    ops
  end

  defp fails_expired_recovery(now) do
    {:ok, %{did: did, cid: create_cid}} = setup_genesis(now)

    ninety_six_hours_ago = DateTime.add(now, -(4 * 24 * 3600), :second)

    rotate_changeset =
      sign_op_for_keys([@rotation_key_3], @rotation_key_3, ninety_six_hours_ago,
        did: did,
        prev: create_cid
      )

    assert {:ok, %{operation: %Operation{} = _rotate}} =
             rotate_changeset
             |> Log.multi_insert(false)
             |> Repo.transaction()

    ops = Log.list_operations(did, true)

    rotate_back_changeset =
      sign_op_for_keys([@rotation_key_2], @rotation_key_2, now, did: did, prev: create_cid)

    rotate_back_op = apply_changes(rotate_back_changeset) |> DidPlc.to_data()

    assert_raise(LateRecoveryError, fn ->
      DidPlc.assure_valid_next_op(did, ops, rotate_back_op)
    end)
  end

  defp nullifies_tombstone(now) do
    {:ok, %{did: did, cid: create_cid}} = setup_genesis(now)

    twenty_four_hours_ago = DateTime.add(now, -(24 * 3600), :second)

    tombstone_changeset =
      sign_op_for_keys([@rotation_key_3], @rotation_key_3, twenty_four_hours_ago,
        did: did,
        prev: create_cid,
        type: "plc_tombstone"
      )

    assert {:ok, %{operation: %Operation{} = tombstone}} =
             tombstone_changeset
             |> Log.multi_insert(false)
             |> Repo.transaction()

    ops = Log.list_operations(did, true)

    rotate_back_changeset =
      sign_op_for_keys([@rotation_key_1], @rotation_key_1, now, did: did, prev: create_cid)

    rotate_back_op = apply_changes(rotate_back_changeset) |> DidPlc.to_data()
    {_proposed, nullified_cids} = DidPlc.assure_valid_next_op(did, ops, rotate_back_op)

    assert [cid_1] = nullified_cids
    assert cid_1 == tombstone.cid
  end

  defp sign_op_for_keys(
         keys,
         signing_keypair,
         inserted_at,
         opts \\ []
       ) do
    type = Keyword.get(opts, :type, "plc_operation")
    did = Keyword.get(opts, :did)
    prev = Keyword.get(opts, :prev)
    signer = Keypair.to_json(signing_keypair)

    params = %{
      type: type,
      did: did,
      prev: prev,
      signingKey: Keypair.did(signing_keypair),
      rotationKeys: Enum.map(keys, &Keypair.did(&1)),
      handle: @handle,
      service: @service,
      signer: signer,
      password: "bluesky"
    }

    params =
      case Keyword.get(opts, :changes) do
        changes when is_map(changes) -> Map.merge(params, changes)
        nil -> params
      end

    {did, signed_op, password, keys_pem} =
      if is_nil(did) || is_nil(prev) do
        assert {:ok, keys_pem} = Keypair.encode_pem_private_key(signing_keypair)

        assert {:ok, {did, signed_op, password, _keys_pem}} = DidPlc.create_operation(params)

        {did, signed_op, password, keys_pem}
      else
        assert %{did: ^did, operation: op_json} = Log.get_operation_by_cid(did, prev)

        assert {:ok, {did, updated_op}} =
                 DidPlc.update_operation(
                   %{did: did, cid: prev, operation: Jason.decode!(op_json)},
                   params
                 )

        {did, updated_op, nil, nil}
      end

    changeset(did, signed_op, prev, inserted_at, password, keys_pem)
  end

  defp changeset(did, op, prev, inserted_at, password, keys_pem) do
    Operation.raw_changeset(%Operation{}, %{
      did: did,
      cid: DidPlc.cid_for_op(op),
      operation: Jason.encode!(op),
      nullified: false,
      inserted_at: inserted_at,
      prev: prev,
      password: password,
      keys_pem: keys_pem
    })
  end
end
