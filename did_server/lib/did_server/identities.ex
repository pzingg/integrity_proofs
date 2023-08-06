defmodule DidServer.Identities do
  @moduledoc """
  A context for DIDs and WebAuthn credentials.
  """

  import Ecto.Query, warn: false

  alias DidServer.{Accounts, Repo}
  alias DidServer.Accounts.User
  alias DidServer.Identities.{Credential, Key, UserKey}

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

  def list_keys_by_user(user, return_structs? \\ false) do
    user = Repo.preload(user, :keys)

    if return_structs? do
      user.keys
    else
      Enum.map(user.keys, fn %{did: did} -> did end)
    end
  end

  def list_keys_by_username(username, domain, return_structs? \\ false) do
    keys =
      from(key in Key,
        join: user_key in UserKey,
        on: user_key.key_id == key.did,
        join: user in User,
        on: user.id == user_key.user_id,
        where: user.username == ^username,
        where: user.domain == ^domain
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
  def get_key!(did) when is_binary(did), do: Repo.get_by!(Key, [did: did], preload: :users)

  def get_domain_key() do
    domain = DidServer.Application.domain()

    case list_keys_by_username("admin", domain) do
      [did | _] -> {:ok, did}
      _ -> {:error, "not found"}
    end
  end

  def get_user_key(user_id) when is_binary(user_id) do
    Repo.get(UserKey, user_id) |> Repo.preload(:user)
  end

  def get_user_key(%User{} = user) do
    user = Repo.preload(user, :users_keys)

    case user.users_keys do
      [] -> nil
      [user_key] -> %UserKey{user_key | user: user}
      _ -> raise RuntimeError, "multiple DIDs for user"
    end
  end

  def get_user_did(%User{} = user) do
    user = Repo.preload(user, :keys)

    case user.keys do
      [] -> nil
      [key] -> key
      _ -> raise RuntimeError, "multiple DIDs for user"
    end
  end

  @doc """
  Builds a did document.
  """
  def get_did_document(%User{} = user) do
    case get_user_did(user) do
      nil -> nil
      did -> format_did_document(did)
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

  def get_public_key(user, fmt, purpose \\ "assertionMethod") do
    case get_did_document(user) do
      nil ->
        {:error, "could not locate did for user"}

      doc ->
        CryptoUtils.Did.get_public_key(doc, fmt, purpose)
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

  def format_did_document(did) do
    op_data = DidServer.Log.get_last_op(did, :did_data)

    %URI{scheme: scheme, host: host, port: port} =
      Application.get_env(:did_server, :base_server, "https://example.com") |> URI.parse()

    host =
      if host == "127.0.0.1" do
        "localhost"
      else
        host
      end

    host_port =
      case {scheme, port} do
        {_, nil} -> host
        {:https, 443} -> host
        {:http, 80} -> host
        _ -> "#{host}:#{port}"
      end

    case op_data do
      %{"verificationMethods" => vms, "alsoKnownAs" => akas}
      when is_map(vms) and map_size(vms) != 0 ->
        linked_user_akas =
          Accounts.list_users_by_did(did)
          |> Enum.map(fn user -> [User.ap_id(user), User.domain_handle(user)] end)
          |> List.flatten()

        also_known_as = (akas ++ linked_user_akas) |> Enum.sort() |> Enum.uniq()

        {sig_fragment, multibase_value, additional_vms} =
          case Map.to_list(vms) do
            [{key_id, key_value} | rest] ->
              %{public_key_multibase: multibase_value} =
                CryptoUtils.Did.context_and_key_for_did!(key_value)

              more =
                Enum.map(rest, fn {key_id, key_value} ->
                  %{context: context, public_key_multibase: multibase_value} =
                    CryptoUtils.Did.context_and_key_for_did!(key_value)

                  {key_id, %{context: context, type: "Multikey", value: multibase_value}}
                end)
                |> Map.new()

              {key_id, multibase_value, more}

            _ ->
              raise RuntimeError, "whoa"
          end

        CryptoUtils.Did.format_did_document!(did,
          also_known_as: also_known_as,
          signature_method_fragment: sig_fragment,
          multibase_value: multibase_value,
          additional_vms: additional_vms,
          services: %{
            "atproto_pds" => %{
              type: "AtprotoPersonalDataServer",
              endpoint: "#{scheme}://pds.#{host_port}"
            },
            "activitypub" => %{
              type: "ActivityPubServer",
              endpoint: "#{scheme}://#{host_port}"
            }
          }
        )

      _ ->
        nil
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
      {:ok, %User{}}

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
      {:ok, %User{}}

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
  `user_or_id` is either a `User` struct or a `UserKey` struct,
  or the UUID for a `UserKey` record.
  """
  def get_credentials(user_or_id)

  def get_credentials(user_id) when is_binary(user_id) do
    case Repo.get(UserKey, user_id) do
      nil ->
        []

      user_key ->
        get_credentials(user_key)
    end
  end

  def get_credentials(%UserKey{} = user_key) do
    user_key = Repo.preload(user_key, :credentials)
    user_key.credentials
  end

  def get_credentials(%User{} = user) do
    user = Repo.preload(user, :credentials)
    user.credentials
  end

  def get_credentials(_), do: []

  @doc """
  `user_or_id` is either a `User` struct or a `UserKey` struct,
  or the UUID for a `UserKey` record.
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
  `user_id` is the UUID for a `UserKey` record.
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
