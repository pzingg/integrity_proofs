defmodule DidServer.Log do
  @moduledoc """
  The Log context.
  """

  import Ecto.Query, warn: false

  alias DidServer.{PrevMismatchError, Repo, UpdateOperationError}
  alias DidServer.Accounts
  alias DidServer.Accounts.{User, UserKey}
  alias DidServer.Log.{Key, Operation}
  alias DidServer.Vault

  @doc """
  Returns the list of keys.

  ## Examples

      iex> list_keys()
      [%Key{}, ...]

  """
  def list_keys do
    Repo.all(Key)
  end

  @doc """
  Gets a single did.

  Raises `Ecto.NoResultsError` if the Did does not exist.

  ## Examples

      iex> get_key!("did:plc:012345")
      %Key{}

      iex> get_key!("did:plc:nosuchkey")
      ** (Ecto.NoResultsError)

  """
  def get_key!(did) when is_binary(did), do: Repo.get!(Key, did, preload: :users)

  def get_domain_key() do
    domain = DidServer.Application.domain()

    with %User{} = user <- Accounts.get_user_by_username("admin", domain),
         [did | _] <- Accounts.list_keys_by_user(user) do
      {:ok, did}
    else
      _ -> {:error, "not found"}
    end
  end

  @doc """
  Creates a did key.

  ## Examples

      iex> create_key(%{field: value})
      {:ok, %Key{}}

      iex> create_key(%{field: bad_value})
      {:error, %Ecto.Changeset{}}

  """
  def create_key(attrs \\ %{}) do
    %Key{}
    |> Key.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Returns an `%Ecto.Changeset{}` for tracking did changes.

  ## Examples

      iex> change_key(did)
      %Ecto.Changeset{data: %Key{}}

  """
  def change_key(%Key{} = did, attrs \\ %{}) do
    Key.changeset(did, attrs)
  end

  @doc """
  Links a user to a DID.
  """
  def add_also_known_as(did, nil) do
    _ =
      from(user_key in UserKey,
        where: user_key.key_id == ^did
      )
      |> Repo.delete_all()

    nil
  end

  def add_also_known_as(did, user) do
    UserKey.build_link(did, user)
    |> Repo.insert!()

    {:ok, user}
  end

  def remove_also_known_as(did, user) do
    _ =
      from(user_key in UserKey,
        where: user_key.user_id == ^user.id,
        where: user_key.key_id == ^did
      )
      |> Repo.delete_all()

    {:ok, user}
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
  def create_operation(did, proposed, password \\ nil, keys_pem \\ nil)
      when is_binary(did) and is_map(proposed) do
    ops = list_operations(did)

    {proposed, nullified_cids} = CryptoUtils.Did.assure_valid_next_op(did, ops, proposed)

    multi_insert(did, proposed, nullified_cids, password, keys_pem)
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
         {:data, data} when is_map(data) <-
           {:data, CryptoUtils.Did.to_plc_operation_data(last_op)},
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

  def most_recent_cid(did, excluded_cids \\ []) do

    from(op in Operation,
      select: [:cid],
      where: op.did == ^did,
      where: op.nullified == false,
      where: op.cid not in ^excluded_cids,
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

  def multi_insert(did, %{"prev" => prev} = proposed, nullified_cids, password, keys_pem) do
    op_attrs = %{
      cid: CryptoUtils.Did.cid_for_op(proposed),
      did: did,
      operation: Jason.encode!(proposed),
      prev: prev,
      nullified_cids: nullified_cids,
      password: password,
      keys_pem: keys_pem
    }

    Operation.changeset(%Operation{}, op_attrs)
    |> multi_insert()
  end

  def multi_insert(op_changeset, verify? \\ true) do
    did = Ecto.Changeset.get_change(op_changeset, :did)
    prev = Ecto.Changeset.get_change(op_changeset, :prev)
    password = Ecto.Changeset.get_change(op_changeset, :password)
    keys_pem = Ecto.Changeset.get_change(op_changeset, :keys_pem)
    key_changeset = Key.changeset(%Key{}, %{did: did, password: password})

    multi =
      if is_nil(prev) do
        Ecto.Multi.new()
        |> Ecto.Multi.insert(:key, key_changeset, returning: true)
      else
        Ecto.Multi.new()
        |> Ecto.Multi.one(:key, Key)
      end

    multi =
      multi
      |> Ecto.Multi.run(:secret, fn _, _ -> update_secret(did, keys_pem) end)
      |> Ecto.Multi.insert(:operation, op_changeset, returning: true)

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

  def update_secret(_did, nil), do: {:ok, nil}

  def update_secret(did, "delete") do
    Vault.delete_secret(did)
  end

  def update_secret(did, keys_pem) do
    Vault.create_secret(did, keys_pem)
  end

  @doc """
  Returns an `%Ecto.Changeset{}` for changing the DID password.

  ## Examples

      iex> change_did_password(user)
      %Ecto.Changeset{data: %User{}}

  """
  def change_did_password(did, attrs \\ %{}) do
    Key.password_changeset(did, attrs, hash_password: false)
  end

  @doc """
  Updates the DID key password.

  ## Examples

      iex> update_key_password(key, "valid password", %{password: ...})
      {:ok, %User{}}

      iex> update_key_password(key, "invalid password", %{password: ...})
      {:error, %Ecto.Changeset{}}

  """
  def update_key_password(key, password, attrs) do
    # |> Ecto.Multi.delete_all(:tokens, UserToken.user_and_contexts_query(user, :all))

    key
    |> Key.password_changeset(attrs)
    |> Key.validate_current_password(password)
    |> Repo.update()
  end

  @doc """
  Resets the DID key password.

  ## Examples

      iex> reset_did_password(key, %{password: "new long password", password_confirmation: "new long password"})
      {:ok, %User{}}

      iex> reset_did_password(key, %{password: "valid", password_confirmation: "not the same"})
      {:error, %Ecto.Changeset{}}

  """
  def reset_did_password(key, attrs) do
    # |> Ecto.Multi.delete_all(:tokens, UserToken.user_and_contexts_query(user, :all))
    Key.password_changeset(key, attrs)
    |> Repo.update()
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
