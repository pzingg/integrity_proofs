defmodule DidServer.Log do
  @moduledoc """
  The Log context.
  """

  import Ecto.Query, warn: false

  alias DidServer.Log.{Did, Operation}
  alias DidServer.Repo

  alias DidServer.{
    LateRecoveryError,
    MisorderedOperationError,
    PrevMismatchError
  }

  @doc """
  Returns the list of dids.

  ## Examples

      iex> list_dids()
      [%Did{}, ...]

  """
  def list_dids do
    Repo.all(Did)
  end

  @doc """
  Gets a single did.

  Raises `Ecto.NoResultsError` if the Did does not exist.

  ## Examples

      iex> get_did!(123)
      %Did{}

      iex> get_did!(456)
      ** (Ecto.NoResultsError)

  """
  def get_did!(id), do: Repo.get!(Did, id)

  @doc """
  Creates a did.

  ## Examples

      iex> create_did(%{field: value})
      {:ok, %Did{}}

      iex> create_did(%{field: bad_value})
      {:error, %Ecto.Changeset{}}

  """
  def create_did(attrs \\ %{}) do
    %Did{}
    |> Did.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Returns an `%Ecto.Changeset{}` for tracking did changes.

  ## Examples

      iex> change_did(did)
      %Ecto.Changeset{data: %Did{}}

  """
  def change_did(%Did{} = did, attrs \\ %{}) do
    Did.changeset(did, attrs)
  end

  def validate_and_add_op(did, proposed) do
    ops = indexed_ops_for_did(did)
    {%{"prev" => prev} = proposed, nullified_strs} = assure_valid_next_op(did, ops, proposed)
    nullified? = !Enum.empty?(nullified_strs)

    did_changeset = Did.changeset(%Did{}, %{did: did})

    op_attrs = %{
      cid: DidServer.cid_for_op(proposed),
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
      |> DidServer.normalize_op()
      |> DidServer.assure_valid_op()

    if Enum.empty?(ops) do
      # special case if account creation
      {DidServer.assure_valid_creation_op(did, proposed), []}
    else
      assure_valid_op_order_and_sig(ops, proposed)
    end
  end

  defp assure_valid_op_order_and_sig(ops, %{"prev" => prev} = proposed) do
    if is_nil(prev) do
      raise MisorderedOperationError
    end

    index_of_prev = Enum.find_index(ops, fn %{cid: cid} -> prev == cid end)

    if is_nil(index_of_prev) do
      raise MisorderedOperationError
    end

    # if we are forking history, these are the ops still in the proposed
    # canonical history
    {ops_in_history, nullified} = Enum.split(ops, index_of_prev + 1)
    last_op = List.last(ops_in_history)

    if is_nil(last_op) do
      raise MisorderedOperationError
    end

    %{"type" => last_op_type, "rotationKeys" => rotation_keys} = Jason.decode!(last_op.operation)

    if last_op_type == "plc_tombstone" do
      raise MisorderedOperationError
    end

    case nullified do
      [] ->
        # does not involve nullification
        _did_key = DidServer.assure_valid_sig(rotation_keys, proposed)
        {proposed, []}

      _ ->
        assure_valid_op_sig_when_nullified(rotation_keys, nullified, proposed)
    end
  end

  defp assure_valid_op_sig_when_nullified(
         rotation_keys,
         [%{operation: op_json, inserted_at: inserted_at} | _] = nullified,
         proposed
       ) do
    first_nullified = Jason.decode!(op_json)
    disputed_signer = DidServer.assure_valid_sig(rotation_keys, first_nullified)
    more_powerful_keys = Enum.take_while(rotation_keys, fn key -> key != disputed_signer end)

    _did_key = DidServer.assure_valid_sig(more_powerful_keys, proposed)

    # recovery key gets a 72hr window to do historical re-writes
    time_lapsed = DateTime.diff(DateTime.utc_now(), inserted_at, :second)

    if time_lapsed > 72 * 3600 do
      raise LateRecoveryError, time_lapsed
    end

    {proposed, Enum.map(nullified, fn %{cid: cid} -> cid end)}
  end
end
