defmodule DidSever.RecoveryTest do
  use DidServer.DataCase

  import Ecto.Changeset

  alias CryptoUtils.Did.InvalidSignatureError
  alias DidServer.{Log, Repo}
  alias DidServer.Log.Operation

  @signing_key CryptoUtils.Keys.generate_keypair(:did_key, :secp256k1)
  @rotation_key_1 CryptoUtils.Keys.generate_keypair(:did_key, :secp256k1)
  @rotation_key_2 CryptoUtils.Keys.generate_keypair(:did_key, :secp256k1)
  @rotation_key_3 CryptoUtils.Keys.generate_keypair(:did_key, :secp256k1)
  @handle "alice.example.com"
  @service "https://example.com"

  setup_all do
    # IO.puts("rotation_key_1 #{elem(@rotation_key_1, 0) |> CryptoUtils.display_did()}")
    # IO.puts("rotation_key_2 #{elem(@rotation_key_2, 0) |> CryptoUtils.display_did()}")
    # IO.puts("rotation_key_3 #{elem(@rotation_key_3, 0) |> CryptoUtils.display_did()}")

    :ok
  end

  def step_1(now) do
    {:ok, %{ops: [%{did: did, cid: create_cid}, op_1, op_2] = ops}} = setup_rotation(now)

    # Proposes a new operation
    # [3] -> rotation to [key_2], signed by key_2, prev [0]
    # key_2 asserts control over key_3
    rotate_changeset =
      sign_op_for_keys([@rotation_key_2], @rotation_key_2, did: did, prev: create_cid)

    rotate_op = apply_changes(rotate_changeset) |> Operation.to_data()
    # IO.inspect(rotate_op, label: :apply_changes)

    # Nullified are [1, 2]
    # Disputed signer is key_3
    # More powerful keys are [key_1, key_2]
    # [3] will verify with key_2
    {proposed, nullified_cids} = CryptoUtils.Did.assure_valid_next_op(did, ops, rotate_op)

    assert Enum.count(nullified_cids) == 2

    [cid_1, cid_2] = nullified_cids
    assert cid_1 == op_1.cid
    assert cid_2 == op_2.cid

    prev = Map.get(proposed, "prev")
    assert prev == create_cid

    assert {:ok, %{operation: %Operation{cid: step_1_cid} = _rotate}} =
             rotate_changeset
             |> put_change(:inserted_at, DateTime.add(now, -(24 * 3600), :second))
             |> Log.multi_insert(false)
             |> Repo.transaction()

    _ = Log.reset_log(did, [create_cid, step_1_cid])
    ops = Log.list_operations(did, true)
    assert Enum.count(ops) == 2
    ops
  end

  def step_2(now) do
    [%{did: did, cid: create_cid} | _] = ops = step_1(now)

    # Proposes a new operation
    # [3] -> rotation to [key_3], signed by key_3, prev [0]
    rotate_changeset =
      sign_op_for_keys([@rotation_key_3], @rotation_key_3, did: did, prev: create_cid)

    rotate_op = apply_changes(rotate_changeset) |> Operation.to_data()

    # Nullified are [1, 2]
    # Disputed signer is key_3
    # More powerful keys are [key_1, key_2]
    # [3] fails to verify with these keys (it was signed with key_3)
    assert_raise(InvalidSignatureError, fn ->
      CryptoUtils.Did.assure_valid_next_op(did, ops, rotate_op)
    end)

    ops
  end

  def step_3(now) do
    [%{did: did, cid: create_cid}, op_1] = ops = step_1(now)

    # Proposes a new operation
    # [2] -> rotation to [key_1], signed by key_1, prev [0]
    rotate_changeset =
      sign_op_for_keys([@rotation_key_1], @rotation_key_1, did: did, prev: create_cid)

    rotate_op = apply_changes(rotate_changeset) |> Operation.to_data()

    # Nullified are [1]
    # Disputed signer is key_2
    # More powerful keys are [key_1]
    # [3] will verify with key_1
    {proposed, nullified_cids} = CryptoUtils.Did.assure_valid_next_op(did, ops, rotate_op)

    assert Enum.count(nullified_cids) == 1

    [cid_1] = nullified_cids
    assert cid_1 == op_1.cid

    prev = Map.get(proposed, "prev")
    assert prev == create_cid

    assert {:ok, %{operation: %Operation{cid: step_3_cid} = _rotate}} =
             rotate_changeset
             |> put_change(:inserted_at, DateTime.add(now, -(24 * 3600), :second))
             |> Log.multi_insert(false)
             |> Repo.transaction()

    _ = Log.reset_log(did, [create_cid, step_3_cid])
    ops = Log.list_operations(did, true)
    assert Enum.count(ops) == 2
    ops
  end

  def step_4(now) do
    [%{did: did, cid: create_cid} | _] = ops = step_3(now)

    rotate_changeset =
      sign_op_for_keys([@rotation_key_3], @rotation_key_3, did: did, prev: create_cid)

    rotate_op = apply_changes(rotate_changeset) |> Operation.to_data()

    assert_raise(InvalidSignatureError, fn ->
      CryptoUtils.Did.assure_valid_next_op(did, ops, rotate_op)
    end)

    rotate_changeset =
      sign_op_for_keys([@rotation_key_2], @rotation_key_2, did: did, prev: create_cid)

    rotate_op = apply_changes(rotate_changeset) |> Operation.to_data()

    assert_raise(InvalidSignatureError, fn ->
      CryptoUtils.Did.assure_valid_next_op(did, ops, rotate_op)
    end)

    ops
  end

  describe "key recovery" do
    test "allows a rotation key with higher authority to rewrite history" do
      DateTime.utc_now() |> step_1()
    end

    test "does not allow the lower authority key to take control back" do
      DateTime.utc_now() |> step_2()
    end

    test "allows a rotation key with even higher authority to rewrite history" do
      DateTime.utc_now() |> step_3()
    end

    test "does not allow the either invalidated key to take control back" do
      DateTime.utc_now() |> step_4()
    end
  end

  # Creates 3 operations
  # [0] -> creation did with [key_1, key_2, key_3], signed by key_1
  # [1] -> rotation to [key_3], signed by key_3
  # [2] -> update handle (same rotation to [key_3], signed by key_3)
  defp setup_rotation(now) do
    create_changeset =
      sign_op_for_keys([@rotation_key_1, @rotation_key_2, @rotation_key_3], @rotation_key_1)

    assert {:ok, %{operation: %Operation{cid: create_cid, did: did} = create}} =
             create_changeset
             |> put_change(:inserted_at, DateTime.add(now, -(7 * 24 * 3600), :second))
             |> Log.multi_insert(false)
             |> Repo.transaction()

    create_op = Operation.to_data(create)
    assert Map.get(create_op, "rotationKeys") |> Enum.count() == 3

    # key 3 tries to usurp control
    rotate_changeset =
      sign_op_for_keys([@rotation_key_3], @rotation_key_3, did: did, prev: create_cid)

    assert {:ok, %{operation: %Operation{cid: rotate_cid}}} =
             rotate_changeset
             |> put_change(:inserted_at, DateTime.add(now, -(24 * 3600), :second))
             |> Log.multi_insert(false)
             |> Repo.transaction()

    # and does some additional ops
    another_changeset =
      sign_op_for_keys([@rotation_key_3], @rotation_key_3,
        did: did,
        prev: rotate_cid,
        changes: %{handle: "newhandle.test"}
      )

    assert {:ok, %{operation: %Operation{cid: _another_cid}}} =
             another_changeset
             |> put_change(:inserted_at, DateTime.add(now, -3600, :second))
             |> Log.multi_insert(false)
             |> Repo.transaction()

    ops = Log.list_operations(did)
    # IO.puts("ops #{inspect(Enum.map(ops, fn %{cid: cid} -> cid end))}")

    {:ok, %{ops: ops}}
  end

  defp sign_op_for_keys(keys, {signer_did, {algorithm, [priv, curve]}}, opts \\ []) do
    prev = Keyword.get(opts, :prev)

    params = %{
      type: "create",
      did: Keyword.get(opts, :did),
      prev: prev,
      signingKey: elem(@signing_key, 0),
      rotationKeys: Enum.map(keys, &elem(&1, 0)),
      handle: @handle,
      service: @service,
      signer: [signer_did, to_string(algorithm), priv, to_string(curve)]
    }

    params =
      case Keyword.get(opts, :changes) do
        changes when is_map(changes) -> Map.merge(params, changes)
        nil -> params
      end

    {:ok, {op, did}} = CryptoUtils.Did.create_operation(params)
    changeset(op, did, prev)
  end

  defp changeset(op, did, prev) do
    Operation.changeset_raw(%Operation{}, %{
      did: did,
      cid: CryptoUtils.Did.cid_for_op(op),
      operation: Jason.encode!(op),
      nullified: false,
      inserted_at: DateTime.utc_now(),
      prev: prev
    })
  end
end
