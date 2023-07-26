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
  Just a check to see if database is operational.
  """
  def health_check do
    try do
      from(op in Operation, limit: 1) |> Repo.all() |> is_list()
    rescue
      _ -> false
    end
  end

  ## Keys (dids with passwords)

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
  Links a user to a DID. If the `user` argument is `nil`,
  removes all user links for the did, otherwise creates
  a new link from the DID to the user.

  On success, returns `{:ok, user}`.
  """
  def add_also_known_as(did, user)

  def add_also_known_as(did, nil) when is_binary(did) do
    _ =
      from(user_key in UserKey,
        where: user_key.key_id == ^did
      )
      |> Repo.delete_all()

    {:ok, nil}
  end

  def add_also_known_as(did, %User{} = user) when is_binary(did) do
    UserKey.build_link(did, user)
    |> Repo.insert()
    |> case do
      {:ok, _} -> {:ok, user}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Removes the link from the DID to a single user.

  On success, returns `{:ok, user}`.
  """
  def remove_also_known_as(did, %User{} = user) when is_binary(did) do
    {n, _} =
      from(user_key in UserKey,
        where: user_key.user_id == ^user.id,
        where: user_key.key_id == ^did
      )
      |> Repo.delete_all()

    if n == 0 do
      {:error, "not found"}
    else
      {:ok, user}
    end
  end

  ## Operation log

  def list_registered_dids() do
    from(op in Operation, distinct: :did)
    |> Repo.all()
    |> Enum.map(fn %{did: did} -> did end)
  end

  @doc """
  Returns the list of did:plc operations for a given did.

  If `include_nullified?` is `true`, nullified operations
  will be returned in the list, otherwise only the currently
  active fork of the did operations will be returned.

  ## Examples

      iex> list_operations("did:plc:0123456", true)
      [%Operation{}, ...]

      iex> list_operations("did:plc:notvalid", true)
      []

  """
  def list_operations(did, include_nullified?) when is_binary(did) do
    list_query(did, include_nullified?, [], :asc) |> Repo.all()
  end

  @doc """
  Returns the operation (nullified or not) for a given did and cid.

  ## Examples

      iex> get_operation_by_cid("did:plc:0123456", "b2345")
      %Operation{}

      iex> get_operation_by_cid("did:plc:notvalid", "b2345")
      nil

  """
  def get_operation_by_cid(did, cid) when is_binary(did) and is_binary(cid) do
    from(op in Operation,
      where: op.did == ^did,
      where: op.cid == ^cid
    )
    |> Repo.one()
  end

  @doc """
  Returns the most recent active operation for a given did.

  ## Examples

      iex> get_last_op("did:plc:0123456")
      %Operation{}

      iex> get_last_op("did:plc:notvalid")
      nil

  """
  def get_last_op(did) when is_binary(did) do
    from(op in Operation,
      where: op.did == ^did,
      where: op.nullified == false,
      order_by: [desc: :inserted_at],
      limit: 1
    )
    |> Repo.one()
  end

  @doc """
  Returns the most recent active operation for a given did.

  Returns `{:ok, op}` if there is an active operation
  and it is not a tombstone.

  ## Examples

      iex> ensure_last_op("did:plc:0123456")
      {:ok, %Operation{}}

      iex> ensure_last_op("did:plc:notvalid")
      {:error, "no operations with did did:plc:notvalid"}

  """
  def ensure_last_op(did) when is_binary(did) do
    with {:last_op, %Operation{} = op} <- {:last_op, get_last_op(did)},
         {:tombstone, false} <- {:tombstone, Operation.tombstone?(op)} do
      {:ok, op}
    else
      {:tombstone, _} -> {:error, "did #{did} is tombstoned"}
      {:last_op, _} -> {:error, "no operations with did #{did}"}
      error -> error
    end
  end

  @doc """
  Returns the cid of the most recent active operation for a
  given did, filtering out any cids passed in the `excluded_dids`
  argument.

  ## Examples

      iex> most_recent_cid("did:plc:0123456")
      "b23466"

      iex> most_recent_cid("did:plc:notvalid")
      nil

  """
  def most_recent_cid(did, excluded_cids \\ []) do
    list_query(did, false, excluded_cids, :desc)
    |> Repo.one()
    |> case do
      nil -> nil
      %{cid: cid} -> cid
    end
  end

  @doc """
  Nullifies a list of operations, identified by cids.

  Returns an `:ok` tuple with the operation log after the nullification.

  ## Examples

      iex> nullify("did:plc:012435", ["b2345])
      {:ok, [%Operation{}]}

  """
  def nullify(did, nullified_cids, opts \\ []) do
    include_nullified? = Keyword.get(opts, :include_nullified?, false)

    multi =
      Ecto.Multi.new()
      |> Ecto.Multi.update_all(:nullified, fn _ -> nullify_query(did, nullified_cids) end, [])
      |> Ecto.Multi.all(:list, list_query(did, include_nullified?, [], :asc))
      |> Repo.transaction()

    case multi do
      {:ok, %{list: ops}} -> {:ok, ops}
      error -> error
    end
  end

  @doc """
  Permanemently deletes all or part of the operations for a did.

  Use with caution!

  Returns an `:ok` tuple with the operation log after the deletion.

  ## Examples

      iex> reset_log("did:plc:0123456")
      {:ok, []}

  """
  def reset_log(did, opts \\ []) do
    include_nullified? = Keyword.get(opts, :include_nullified?, false)
    cids_to_keep = Keyword.get(opts, :cids_to_keep, [])

    query =
      from(op in Operation,
        where: op.did == ^did,
        where: op.cid not in ^cids_to_keep
      )

    multi =
      Ecto.Multi.new()
      |> Ecto.Multi.delete_all(:delete_all, query)
      |> Ecto.Multi.all(:list, list_query(did, include_nullified?, [], :asc))
      |> Repo.transaction()

    case multi do
      {:ok, %{list: ops}} -> {:ok, ops}
      error -> error
    end
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
      {:ok, {did, signed_op, password, keys_pem}} ->
        validate_and_insert_operation(did, signed_op, password, keys_pem)

      error ->
        error
    end
  end

  @doc """
  Adds an operation to a DID.

  ## Examples

      iex> update_operation(%{field: value})
      {:ok, %{operation: %Operation{}}}

      iex> update_operation(%{field: bad_value})
      {:error, %Ecto.Changeset{}}

  """
  def update_operation(%{did: did, cid: cid, operation: op_json}, params) do
    case CryptoUtils.Did.update_operation(
           %{did: did, cid: cid, operation: Jason.decode!(op_json)},
           params
         ) do
      {:ok, {_did, op}} ->
        validate_and_insert_operation(did, op)

      {:error, reason} ->
        raise UpdateOperationError, reason
    end
  end

  @doc """
  Performs validation checks on the operation log for a did.

  Returns the last operation if the log is valid.

  Raises errors if the log has problems.
  """
  def validate_operation_log!(did) do
    ops = list_operations(did, true)
    validate_operation_log!(did, ops)
  end

  @doc """
  Creates an `Ecto.Multi` pipeline for inserting a new operation
  into the log.

  See `multi_insert/2` for more details.
  """
  def multi_insert(did, %{"prev" => prev} = proposed, nullified_cids, password, keys_pem) do
    op_attrs = %{
      cid: CryptoUtils.Did.cid_for_op(proposed),
      did: did,
      operation: Jason.encode!(proposed),
      nullified: false,
      prev: prev,
      nullified_cids: nullified_cids,
      password: password,
      keys_pem: keys_pem
    }

    Operation.changeset(%Operation{}, op_attrs)
    |> multi_insert()
  end

  @doc """
  Creates an `Ecto.Multi` pipeline for inserting a new operation
  into the log.

  Returns an `Ecto.Multi` struct with the following components,
  which will be created when the multi is transacted:

    * `:operation` - the newly inserted `Operation`.
    * `:key` - the `Key` associated with the did.
    * `:secret` - the `Vault.Secret` associated with the did.
    * `:most_recent_op` - the verified cid for the "prev" operation
      (only set if `verify?` is true).
  """
  def multi_insert(op_changeset, verify? \\ true) do
    did = Ecto.Changeset.get_change(op_changeset, :did)
    prev = Ecto.Changeset.get_change(op_changeset, :prev)
    keys_pem = Ecto.Changeset.get_change(op_changeset, :keys_pem)
    nullified_cids = Ecto.Changeset.get_change(op_changeset, :nullified_cids, [])

    multi =
      if is_nil(prev) do
        # If this is a create op, store the password for the did
        password = Ecto.Changeset.get_change(op_changeset, :password)
        key_changeset = Key.changeset(%Key{}, %{did: did, password: password})

        Ecto.Multi.new()
        |> Ecto.Multi.insert(:key, key_changeset, returning: true)
      else
        # Otherwise, make sure we get the key
        query = from(key in Key, where: key.did == ^did)

        Ecto.Multi.new()
        |> Ecto.Multi.one(:key, query)
      end

    multi =
      multi
      |> Ecto.Multi.run(:secret, fn _, _ -> update_secret(did, keys_pem) end)
      |> Ecto.Multi.insert(:operation, op_changeset, returning: true)

    multi =
      case nullified_cids do
        [] ->
          multi

        _ ->
          Ecto.Multi.update_all(
            multi,
            :nullified,
            fn _multi -> nullify_query(did, nullified_cids) end,
            []
          )
      end

    if verify? do
      multi
      |> Ecto.Multi.run(:most_recent_op, fn _repo, _multi -> verify_most_recent(did, prev) end)
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

  defp list_query(did, false, excluded_cids, order) do
    from(op in Operation,
      where: op.did == ^did,
      where: op.nullified == false,
      where: op.cid not in ^excluded_cids,
      order_by: [{^order, :inserted_at}]
    )
  end

  defp list_query(did, true, excluded_cids, order) do
    from(op in Operation,
      where: op.did == ^did,
      where: op.cid not in ^excluded_cids,
      order_by: [{^order, :inserted_at}]
    )
  end

  def nullify_query(did, nullified_cids) do
    from(op in Operation,
      where: op.did == ^did,
      where: op.cid in ^nullified_cids,
      update: [set: [nullified: true]]
    )
  end

  defp update_secret(_did, nil), do: {:ok, nil}

  defp update_secret(did, "delete") do
    Vault.delete_secret(did)
  end

  defp update_secret(did, keys_pem) do
    Vault.create_secret(did, keys_pem)
  end

  defp validate_and_insert_operation(did, proposed, password \\ nil, keys_pem \\ nil)
       when is_binary(did) and is_map(proposed) do
    ops = list_operations(did, true)

    {proposed, nullified_cids} = CryptoUtils.Did.assure_valid_next_op(did, ops, proposed)

    multi_insert(did, proposed, nullified_cids, password, keys_pem)
    |> Repo.transaction()
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
                  "update has no prev, but there is a most recent operation #{next_to_last_cid}"

          prev != next_to_last_cid ->
            raise PrevMismatchError,
                  "update's prev does not match the most recent operation #{next_to_last_cid}"

          true ->
            {:ok, next_to_last_cid}
        end

      _ ->
        if is_nil(prev) do
          {:ok, nil}
        else
          raise PrevMismatchError,
                "update has prev, but there are only #{Enum.count(most_recent)} operations"
        end
    end
  end

  defp validate_operation_log!(did, ops) do
    ops =
      Enum.map(ops, fn op ->
        %{op_data: op_data} = Operation.decode(op)
        op_data
      end)

    CryptoUtils.Did.validate_operation_log!(did, ops)
  end
end
