defmodule DidServer.Log do
  @moduledoc """
  The Log context.
  """

  import Ecto.Query, warn: false

  alias DidServer.{PrevMismatchError, Repo, UpdateOperationError}
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

      iex> get_did!("did:plc:012345")
      %Did{}

      iex> get_did!("did:plc:nosuchkey")
      ** (Ecto.NoResultsError)

  """
  def get_did!(did), do: Repo.get!(Did, did, preload: :users)

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
      {:ok, {%{"sig" => _sig} = op, did, password}} ->
        create_operation(did, op, password)

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

      iex> create_operation(did, %{field: value}, "new password")
      {:ok, %{operation: %Operation{}}}

      iex> create_operation(did, %{field: bad_value})
      {:error, %Ecto.Changeset{}}

  """
  def create_operation(did, proposed, password \\ nil) when is_binary(did) and is_map(proposed) do
    ops = list_operations(did)

    {proposed, nullified_cids} = CryptoUtils.Did.assure_valid_next_op(did, ops, proposed)

    multi_insert(did, proposed, nullified_cids, password)
    |> Repo.transaction()
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

    with {:ok, %{did: did, cid: cid} = last_op} <- ensure_last_op(did),
         {:data, data} when is_map(data) <- {:data, Operation.to_data(last_op)},
         {:ok, {op, _did}} <-
           CryptoUtils.Did.update_operation(
             %{did: did, cid: cid, operation: data},
             params
           ) do
      create_operation(did, op)
    else
      {:data, _} -> raise UpdateOperationError, "no data in last operation"
      {:error, reason} -> raise UpdateOperationError, reason
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
      order_by: [desc: :inserted_at],
      limit: 1
    )
    |> Repo.one()
  end

  def reset_log(did, cids) do
    from(op in Operation,
      where: op.did == ^did,
      where: op.cid not in ^cids
    )
    |> Repo.delete_all()
  end

  def ensure_last_op(did) when is_binary(did) do
    with {:last_op, %Operation{} = op} <- {:last_op, get_last_op(did)},
         {:tombstone, false} <- {:tombstone, Operation.tombstone?(op)} do
      {:ok, op}
    else
      {:tombstone, _} -> raise UpdateOperationError, "cannot update tombstone #{did}"
      {:last_op, _} -> raise UpdateOperationError, "no operations with did #{did}"
      error -> error
    end
  end

  def ensure_last_op(_), do: raise(UpdateOperationError, "did can't be blank")

  def validate_operation_log(did) do
    ops = list_operations(did, true)
    validate_operation_log(did, ops)
  end

  def validate_operation_log(_did, []), do: nil

  def validate_operation_log(did, ops) do
    ops =
      Enum.map(ops, fn op ->
        %{op_data: op_data} = Operation.decode(op)
        op_data
      end)

    CryptoUtils.Did.validate_operation_log(did, ops)
  end

  @doc """
  Just a check to see if database is operational.
  """
  def health_check() do
    from(op in Operation, limit: 1) |> Repo.all() |> is_list()
  end

  def multi_insert(did, %{"prev" => prev} = proposed, nullified_cids, password) do
    op_attrs = %{
      cid: CryptoUtils.Did.cid_for_op(proposed),
      did: did,
      operation: Jason.encode!(proposed),
      prev: prev,
      nullified_cids: nullified_cids,
      password: password
    }

    Operation.changeset(%Operation{}, op_attrs)
    |> multi_insert()
  end

  def multi_insert(op_changeset, verify? \\ true) do
    did = Ecto.Changeset.get_change(op_changeset, :did)
    prev = Ecto.Changeset.get_change(op_changeset, :prev)
    password = Ecto.Changeset.get_change(op_changeset, :password)
    did_changeset = Did.changeset(%Did{}, %{did: did, password: password})

    multi =
      if is_nil(prev) do
        Ecto.Multi.new()
        |> Ecto.Multi.insert(:did, did_changeset, returning: true)
      else
        Ecto.Multi.new()
        |> Ecto.Multi.one(:did, Did)
      end

    multi = Ecto.Multi.insert(multi, :operation, op_changeset, returning: true)

    nullified_cids = Ecto.Changeset.get_change(op_changeset, :nullified_cids, [])

    multi =
      if !Enum.empty?(nullified_cids) do
        Ecto.Multi.update_all(
          multi,
          :nullified,
          fn _multi -> nullify(did, nullified_cids) end,
          []
        )
      else
        multi
      end

    if verify? do
      multi
      |> Ecto.Multi.run(:most_recent, fn _repo, _multi -> verify_most_recent(did, prev) end)
    else
      multi
    end
  end

  @doc """
  Returns an `%Ecto.Changeset{}` for changing the DID password.

  ## Examples

      iex> change_did_password(user)
      %Ecto.Changeset{data: %User{}}

  """
  def change_did_password(did, attrs \\ %{}) do
    Did.password_changeset(did, attrs, hash_password: false)
  end

  @doc """
  Updates the DID password.

  ## Examples

      iex> update_did_password(user, "valid password", %{password: ...})
      {:ok, %User{}}

      iex> update_did_password(user, "invalid password", %{password: ...})
      {:error, %Ecto.Changeset{}}

  """
  def update_did_password(did, password, attrs) do
    changeset =
      did
      |> Did.password_changeset(attrs)
      |> Did.validate_current_password(password)

    Ecto.Multi.new()
    |> Ecto.Multi.update(:did, changeset)
    # |> Ecto.Multi.del|ete_all(:tokens, UserToken.user_and_contexts_query(user, :all))
    |> Repo.transaction()
    |> case do
      {:ok, %{did: did}} -> {:ok, did}
      {:error, :did, changeset, _} -> {:error, changeset}
    end
  end

  @doc """
  Resets the DID password.

  ## Examples

      iex> reset_did_password(user, %{password: "new long password", password_confirmation: "new long password"})
      {:ok, %User{}}

      iex> reset_did_password(user, %{password: "valid", password_confirmation: "not the same"})
      {:error, %Ecto.Changeset{}}

  """
  def reset_did_password(did, attrs) do
    Ecto.Multi.new()
    |> Ecto.Multi.update(:did, Did.password_changeset(did, attrs))
    # |> Ecto.Multi.delete_all(:tokens, UserToken.user_and_contexts_query(user, :all))
    |> Repo.transaction()
    |> case do
      {:ok, %{did: did}} -> {:ok, did}
      {:error, :did, changeset, _} -> {:error, changeset}
    end
  end

  # Private functions

  defp nullify(did, nullified_cids) do
    from(op in Operation,
      where: op.did == ^did,
      where: op.cid in ^nullified_cids,
      update: [set: [nullified: true]]
    )
  end

  defp verify_most_recent(did, prev) do
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
end
