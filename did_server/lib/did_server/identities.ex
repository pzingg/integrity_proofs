defmodule DidServer.Identities do
  @moduledoc """
  A context for DIDs and WebAuthn credentials.
  """

  import Ecto.Query, warn: false

  alias CryptoUtils.Did
  alias DidServer.{Accounts, Repo}
  alias DidServer.Accounts.{Account, User}
  alias DidServer.Identities.{Credential, Key}

  ## Keys (DIDs with passwords and associated credentials)

  @doc """
  Returns the list of keys.

  ## Examples

      iex> list_keys()
      [%Key{}, ...]

  """
  def list_keys do
    Repo.all(Key)
  end

  def list_keys_by_account(account, return_structs? \\ false)

  def list_keys_by_account(%Account{id: account_id}, true) do
    from(key in Key,
      join: account in assoc(key, :accounts),
      where: account.id == ^account_id,
      preload: :users
    )
    |> Repo.all()
  end

  def list_keys_by_account(%Account{id: account_id}, false) do
    from(key in Key,
      select: key.did,
      join: account in assoc(key, :accounts),
      where: account.id == ^account_id
    )
    |> Repo.all()
  end

  def list_keys_by_username(username, domain, return_structs? \\ false) do
    keys =
      from(key in Key,
        join: account in assoc(key, :accounts),
        where: account.username == ^username,
        where: account.domain == ^domain
      )
      |> Repo.all()

    if return_structs? do
      keys
    else
      Enum.map(keys, fn %{did: did} -> did end)
    end
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
  def get_key!(did) when is_binary(did) do
    Repo.get_by!(Key, did: did) |> Repo.preload([:users, :accounts])
  end

  def get_domain_key() do
    domain = DidServer.Application.domain()

    case list_keys_by_username("admin", domain) do
      [did | _] -> {:ok, did}
      _ -> {:error, "not found"}
    end
  end

  def get_account_did(%Account{id: account_id}) do
    from(key in Key,
      join: account in assoc(key, :accounts),
      where: account.id == ^account_id,
      preload: :users
    )
    |> Repo.all()
    |> case do
      [] -> nil
      [key] -> key
      _ -> raise RuntimeError, "multiple DIDs for account"
    end
  end

  @doc """
  Builds a DID document.
  """
  def get_did_document(%Account{} = account) do
    case get_account_did(account) do
      %{did: did} -> format_did_document(did)
      _ -> nil
    end
  end

  def get_did_document(%{username: username, domain: domain}) do
    case list_keys_by_username(username, domain) do
      [did] ->
        format_did_document(did)

      [] ->
        nil
    end
  end

  def get_public_key(account, fmt, purpose \\ "assertionMethod") do
    case get_did_document(account) do
      nil ->
        {:error, "could not locate DID for account"}

      doc ->
        CryptoUtils.Did.get_public_key(doc, fmt, purpose)
    end
  end

  @doc """
  Creates a DID key.

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
  Returns an `%Ecto.Changeset{}` for tracking DID changes.

  ## Examples

      iex> change_key(did)
      %Ecto.Changeset{data: %Key{}}

  """
  def change_key(%Key{} = did, attrs \\ %{}) do
    Key.changeset(did, attrs)
  end

  @doc """
  Links an account to a DID. If the `account` argument is `nil`,
  removes all account links for the DID, otherwise creates
  a new link from the DID to the account.

  On success, returns `{:ok, account}`.
  """
  def add_also_known_as(did, account)

  def add_also_known_as(did, nil) when is_binary(did) do
    _ =
      from(user in User,
        where: user.key_id == ^did
      )
      |> Repo.delete_all()

    {:ok, nil}
  end

  def add_also_known_as(did, %Account{} = account) when is_binary(did) do
    User.build_user(did, account)
    |> Repo.insert()
    |> case do
      {:ok, _} -> {:ok, account}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Removes the link from the DID to a single account.

  On success, returns `{:ok, account}`.
  """
  def remove_also_known_as(did, %Account{} = account) when is_binary(did) do
    {n, _} =
      from(user in User,
        where: user.user_id == ^account.id,
        where: user.key_id == ^did
      )
      |> Repo.delete_all()

    if n == 0 do
      {:error, "not found"}
    else
      {:ok, account}
    end
  end

  ## Documents

  def format_did_document(did) when is_binary(did) do
    %{"verificationMethods" => vms, "alsoKnownAs" => akas} =
      op_data = DidServer.Log.get_last_op(did, :did_data)

    {{signature_method_id, signature_did}, additional_vms} = select_vms(vms)

    if is_nil(signature_method_id) do
      nil
    else
      %{multibase_value: multibase_value} =
        Did.parse_did!(signature_did, expected_did_methods: [:key])

      additional_vms =
        Enum.map(additional_vms, fn {key_id, key_value} ->
          %{multibase_value: multibase_value} =
            Did.parse_did!(key_value, expected_did_methods: [:key])

          {key_id, %{type: "Multikey", value: multibase_value}}
        end)
        |> Map.new()

      CryptoUtils.Did.format_did_document!(did,
        also_known_as: all_akas(did, akas),
        signature_method_fragment: signature_method_id,
        multibase_value: multibase_value,
        additional_vms: additional_vms,
        services: %{
          "atproto_pds" => %{
            type: "AtprotoPersonalDataServer",
            endpoint: DidServer.Application.at_pds_server_url()
          },
          "activitypub" => %{
            type: "ActivityPubServer",
            endpoint: DidServer.Application.ap_server_url()
          }
        }
      )
    end
  end

  def all_akas(did, akas) do
    linked_user_akas =
      Accounts.list_accounts_by_did(did)
      |> Enum.map(fn account -> [Account.ap_id(account), Account.domain_handle(account)] end)
      |> List.flatten()

    (akas ++ linked_user_akas) |> Enum.sort() |> Enum.uniq()
  end

  def select_vms(vms) when is_map(vms) do
    case Map.pop(vms, "atproto") do
      {nil, _} ->
        case Map.to_list(vms) do
          [{signature_method_id, signature_did} | rest] ->
            {{signature_method_id, signature_did}, rest}

          _ ->
            {nil, %{}}
        end

      {signature_did, rest} ->
        {{"atproto", signature_did}, Map.to_list(rest)}
    end
  end

  @doc """
  Returns an `%Ecto.Changeset{}` for changing the DID password.

  ## Examples

      iex> change_did_password(did, 1)
      %Ecto.Changeset{data: %Key{}}

  """
  def change_did_password(did, user_id, attrs \\ %{}) do
    Key.password_changeset(did, Map.put(attrs, :current_user_id, user_id))
  end

  @doc """
  Updates the DID key password.

  ## Examples

      iex> update_did_password(key, "valid password", %{password: ...})
      {:ok, %Account{}}

      iex> update_did_password(key, "invalid password", %{password: ...})
      {:error, %Ecto.Changeset{}}

  """
  def update_did_password(key, password, attrs) do
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
      {:ok, %Account{}}

      iex> reset_did_password(key, %{password: "valid", password_confirmation: "not the same"})
      {:error, %Ecto.Changeset{}}

  """
  def reset_did_password(key, attrs) do
    # |> Ecto.Multi.delete_all(:tokens, UserToken.user_and_contexts_query(user, :all))
    Key.password_changeset(key, attrs)
    |> Repo.update()
  end

  ## WebAuthn credentials

  @doc """
  `user_or_id` is either a `User` struct,
  or the UUID for a `User` record.
  """
  def get_credentials(user_or_id)

  def get_credentials(user_id) when is_binary(user_id) do
    from(credential in Credential,
      join: user in assoc(credential, :user),
      where: user.id == ^user_id
    )
    |> Repo.all()
  end

  def get_credentials(%User{id: user_id}) do
    get_credentials(user_id)
  end

  def get_credentials(_), do: []

  @doc """
  `user_or_id` is either a `User` struct,
  or the UUID for a `User` record.
  """
  def get_wax_params(user_or_id) do
    get_credentials(user_or_id) |> to_wax_params()
  end

  def to_wax_params(credentials) when is_list(credentials) do
    {creds, aaguids} =
      credentials
      |> Enum.map(fn %{raw_id: cred_id, cose_key: cose_key, aaguid: maybe_aaguid} ->
        {{cred_id, cose_key}, {cred_id, maybe_aaguid}}
      end)
      |> Enum.unzip()

    {creds, Map.new(aaguids)}
  end

  @doc """
  `user_id` is the UUID for a `User` record.
  """
  def register_credential(user_id, raw_id, cose_key, maybe_aaguid) do
    # Check that the raw_id is not already in use as per bullet point 17 here:
    # https://www.w3.org/TR/webauthn-1/#registering-a-new-credential
    Credential.changeset(%Credential{user_id: user_id}, %{
      raw_id: raw_id,
      cose_key: cose_key,
      aaguid: maybe_aaguid
    })
    |> Repo.insert()
  end
end
