defmodule DidSever.RecoveryTest do
  use DidServer.DataCase

  import Ecto.Changeset

  alias DidServer.{Log, Repo}
  alias DidServer.Log.Operation

  @signing_key CryptoUtils.Keys.generate_keypair(:did_key, :secp256k1)
  @rotation_key_1 CryptoUtils.Keys.generate_keypair(:did_key, :secp256k1)
  @rotation_key_2 CryptoUtils.Keys.generate_keypair(:did_key, :secp256k1)
  @rotation_key_3 CryptoUtils.Keys.generate_keypair(:did_key, :secp256k1)
  @handle "alice.example.com"
  @service "https://example.com"

  def changeset(op, did, prev) do
    Operation.changeset_raw(%Operation{}, %{
      did: did,
      cid: CryptoUtils.Did.cid_for_op(op),
      operation: Jason.encode!(op),
      nullified: false,
      inserted_at: DateTime.utc_now(),
      prev: prev
    })
  end

  def sign_op_for_keys(keys, {signer_did, {algorithm, [priv, curve]}}, opts \\ []) do
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

  def setup_rotation(now) do
    create_changeset =
      sign_op_for_keys([@rotation_key_1, @rotation_key_2, @rotation_key_3], @rotation_key_1)

    assert {:ok, %{operation: %Operation{cid: create_cid, did: did}}} =
             create_changeset
             |> put_change(:inserted_at, DateTime.add(now, -(7 * 24 * 3600), :second))
             |> Log.multi_insert(false)
             |> Repo.transaction()

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

    {:ok, %{ops: Log.list_operations(did)}}
  end

  describe "key recovery" do
    test "allows a rotation key with higher authority to rewrite history" do
      # key 2 asserts control over key 3
      now = DateTime.utc_now()
      {:ok, %{ops: [%{did: did} = create, op_1, op_2]}} = setup_rotation(now)

      rotate_changeset =
        sign_op_for_keys([@rotation_key_2], @rotation_key_2, did: did, prev: create.cid)

      assert {:ok, %{operation: %Operation{} = rotate}} =
               rotate_changeset
               |> put_change(:inserted_at, DateTime.add(now, -(24 * 3600), :second))
               |> Log.multi_insert(false)
               |> Repo.transaction()

      rotate_op = Operation.to_data(rotate) |> Map.put("prev", rotate.prev)
      ops = Log.list_operations(did)

      {proposed, nullified_cids} =
        CryptoUtils.Did.assure_valid_next_op(did, ops, rotate_op)

      assert Enum.count(nullified_cids) == 2

      [cid_1, cid_2] = nullified_cids
      assert cid_1 == op_1.cid
      assert cid_2 == op_2.cid

      prev = Map.get(proposed, "prev")
      assert prev == create.cid
    end
  end
end
