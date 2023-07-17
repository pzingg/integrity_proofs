defmodule DidServer.Log do
  @moduledoc """
  The Log context.
  """

  import Ecto.Query, warn: false

  alias DidServer.{PrevMismatchError, Repo}
  alias DidServer.Log.{Did, Operation}

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

  @doc """
  Returns the list of did:plc operations for a given DID.

  ## Examples

      iex> list_operations("did:plc:0123456")
      [%Operation{}, ...]

  """
  def list_operations(did, include_nullified \\ false)

  def list_operations(did, false) do
    from(op in Operation,
      where: op.did == ^did,
      where: op.nullified == false,
      order_by: [:inserted_at]
    )
    |> Repo.all()
  end

  def list_operations(did, true) do
    from(op in Operation,
      where: op.did == ^did,
      order_by: [:inserted_at]
    )
    |> Repo.all()
  end

  @doc """
  Creates a did:plc operation.

  On success, returns a tuple `{:ok, multi}`, where
  `multi` is an Ecto.Multi` result (map) with `:did`, `:operation` and
  `:most_recent` components.

  ## Examples

      iex> create_operation(%{field: value})
      {:ok, %{operation: %Operation{}}}

      iex> create_operation(%{field: bad_value})
      {:error, %Ecto.Changeset{}}

  """
  def create_operation(params) do
    case CryptoUtils.Did.create_operation(params) do
      {:ok, {%{"sig" => sig} = op, did}} ->
        create_operation(did, op)

      error ->
        error
    end
  end

  @doc """
  Creates a DID operation from valid, normalized data, applying a DID.

  On success, returns a tuple `{:ok, multi}`, where
  `multi` is an Ecto.Multi` result (map) with `:did`, `:operation` and
  `:most_recent` components.

  ## Examples

      iex> create_operation(did, %{field: value})
      {:ok, %{operation: %Operation{}}}

      iex> create_operation(did, %{field: bad_value})
      {:error, %Ecto.Changeset{}}

  """
  def create_operation(did, proposed) when is_binary(did) and is_map(proposed) do
    ops = list_operations(did)

    {proposed, nullified_strs} = CryptoUtils.Did.assure_valid_next_op(did, ops, proposed)

    do_create_operation(did, proposed, nullified_strs)
  end

  @doc """
  Adds an operation to a DID.

  ## Examples

      iex> update_operation(%{field: value})
      {:ok, %{operation: %Operation{}}}

      iex> update_operation(%{field: bad_value})
      {:error, %Ecto.Changeset{}}

  """
  def update_operation(params) do
    did = Map.get(params, :did) || Map.get(params, "did")

    with {:ok, last_op} <- ensure_last_op(did),
         op_data <- Operation.to_data(last_op),
         {:ok, {op, _did}} <- CryptoUtils.Did.update_operation(op_data, params) do
      create_operation(did, op)
    end
  end

  defp do_create_operation(did, %{"prev" => prev} = proposed, nullified_strs) do
    did_changeset = Did.changeset(%Did{}, %{did: did})

    nullified? = !Enum.empty?(nullified_strs)

    op_attrs = %{
      cid: CryptoUtils.Did.cid_for_op(proposed),
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

  def get_last_op(did) do
    from(op in Operation,
      where: op.did == ^did,
      where: op.nullified == false,
      order_by: [desc: :inserted_at]
    )
    |> Repo.one()
  end

  def ensure_last_op(did) when is_binary(did) do
    with {:last_op, %Operation{} = op} <- {:last_op, get_last_op(did)},
         {:tombstone, false} <- {:tombstone, Operation.tombstone?(op)} do
      {:ok, op}
    else
      {:tombstone, _} -> {:error, "cannot update tombstone #{did}"}
      {:last_op, _} -> {:error, "no operations with did #{did}"}
      error -> error
    end
  end

  def ensure_last_op(_), do: {:error, "did cannot be blank"}

  @doc """
  Just a check to see if database is operational.
  """
  def health_check() do
    from(op in Operation, limit: 1) |> Repo.all() |> is_list()
  end
end
