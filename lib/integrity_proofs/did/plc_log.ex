defmodule IntegrityProofs.Did.PlcLog do
  @moduledoc """
  Context for did:plc audit log.
  """

  import Ecto.Query

  alias IntegrityProofs.Did.Plc.{LateRecoveryError, MisorderedOperationError, PrevMismatchError}
  alias IntegrityProofs.Did.PlcLog.{Did, Operation}
  alias IntegrityProofs.Did.PlcRepo, as: Repo

  def validate_and_add_op(did, proposed) do
    ops = indexed_ops_for_did(did)
    {proposed, nullified_strs, prev} = assure_valid_next_op(did, ops, proposed)
    nullified? = !Enum.empty?(nullified_strs)

    did_changeset = Did.changeset(%Did{}, %{did: did})

    op_attrs = %{
      cid: IntegrityProofs.Did.Plc.cid_for_op(proposed),
      did: did,
      operation: Jason.encode!(proposed),
      nullified: nullified?
    }

    op_changeset = Operation.changeset(%Operation{}, op_attrs)

    multi =
      Ecto.Multi.new()
      # grab a row lock on did table
      |> Ecto.Multi.insert(:did, did_changeset, returning: true)
      |> Ecto.Multi.insert(:operation, op_changeset, returning: true)

    multi =
      if nullified? do
        Ecto.Multi.update_all(
          multi,
          :nullified,
          fn _multi -> nullify(did, nullified_strs) end,
          []
        )
      else
        multi
      end

    multi
    |> Ecto.Multi.run(:most_recent, fn _repo, _multi -> verify_most_recent(did, prev) end)
    |> Repo.transaction()
  end

  def nullify(did, nullified_strs) do
    from(op in Operation,
      where: op.did == ^did,
      where: op.cid in ^nullified_strs,
      update: [set: [nullified: true]]
    )
  end

  def verify_most_recent(did, prev) do
    most_recent =
      from(op in Operation,
        select: [:cid],
        where: op.did == ^did,
        where: op.nullified == false,
        order_by: [desc: :inserted_at],
        limit: 2
      )
      |> Repo.all()

    case most_recent do
      [_last | [%{cid: next_to_last_cid} | _]] ->
        cond do
          is_nil(prev) ->
            raise PrevMismatchError,
                  "Proposed has no prev, but there is a most recent operation #{next_to_last_cid}"

          prev != next_to_last_cid ->
            raise PrevMismatchError,
                  "Proposed prev does not match the most recent operation #{next_to_last_cid}"

          true ->
            {:ok, next_to_last_cid}
        end

      _ ->
        if is_nil(prev) do
          {:ok, nil}
        else
          raise PrevMismatchError, "Proposed has prev, but there is no most recent operation"
        end
    end
  end

  def most_recent_cid(did, not_included \\ []) do
    not_included_strs = Enum.map(not_included, &to_string/1)

    from(op in Operation,
      select: [:cid],
      where: op.did == ^did,
      where: op.nullified == false,
      where: op.cid not in ^not_included_strs,
      order_by: [desc: :inserted_at]
    )
    |> Repo.one()
    |> case do
      nil -> nil
      %{cid: cid} -> cid
    end
  end

  def ops_for_did(did) do
    did
    |> indexed_ops_for_did()
    |> Enum.map(fn %{operation: operation} -> operation end)
  end

  def indexed_ops_for_did(did, include_nullified \\ false)

  def indexed_ops_for_did(did, false) do
    from(op in Operation,
      select: [:cid],
      where: op.did == ^did,
      where: op.nullified == false,
      order_by: [:inserted_at]
    )
    |> Repo.all()
  end

  def indexed_ops_for_did(did, true) do
    from(op in Operation,
      select: [:cid],
      where: op.did == ^did,
      order_by: [:inserted_at]
    )
    |> Repo.all()
  end

  def last_op_for_did(did) do
    from(op in Operation,
      select: [:cid],
      where: op.did == ^did,
      where: op.nullified == false,
      order_by: [desc: :inserted_at]
    )
    |> Repo.one()
  end

  def assure_valid_next_op(did, ops, proposed) do
    proposed =
      proposed
      |> IntegrityProofs.Did.Plc.normalize_op()
      |> IntegrityProofs.Did.Plc.assure_valid_op()

    # special case if account creation
    if Enum.empty?(ops) do
      {IntegrityProofs.Did.Plc.assure_valid_creation_op(did, proposed), [], nil}
    else
      proposed_prev = proposed.prev

      if is_nil(proposed_prev) do
        raise MisorderedOperationError
      end

      index_of_prev = Enum.find_index(ops, fn %{cid: cid} -> proposed_prev == cid end)

      if is_nil(index_of_prev) do
        raise MisorderedOperationError
      end

      # if we are forking history, these are the ops still in the proposed canonical history
      {ops_in_history, nullified} = Enum.split(ops, index_of_prev + 1)
      last_op = List.last(ops_in_history)

      if is_nil(last_op) do
        raise MisorderedOperationError
      end

      if last_op.operation == "plc_tombstone" do
        raise MisorderedOperationError
      end

      last_op_normalized = IntegrityProofs.Did.Plc.normalize_op(last_op)
      first_nullified = hd(nullified)

      # if this does not involve nullification
      if is_nil(first_nullified) do
        _did_key =
          IntegrityProofs.Did.Plc.assure_valid_sig(last_op_normalized.rotation_keys, proposed)

        {proposed, [], proposed_prev}
      end

      disputed_signer =
        IntegrityProofs.Did.Plc.assure_valid_sig(
          last_op_normalized.rotation_keys,
          first_nullified.operation
        )

      index_of_signer =
        Enum.find_index(last_op_normalized.rotation_keys, fn key -> key == disputed_signer end)

      more_powerful_keys = Enum.take(last_op_normalized.rotation_keys, index_of_signer)

      _did_key = IntegrityProofs.Did.Plc.assure_valid_sig(more_powerful_keys, proposed)

      # recovery key gets a 72hr window to do historical re-wrties
      if !Enum.empty?(nullified) do
        time_lapsed = DateTime.diff(DateTime.utc_now(), first_nullified.inserted_at, :second)

        if time_lapsed > 72 * 3600 do
          raise LateRecoveryError, time_lapsed
        end
      end

      {proposed, Enum.map(nullified, fn %{cid: cid} -> cid end), proposed_prev}
    end
  end
end
