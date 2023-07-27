defmodule DidServer.Accounts do
  @moduledoc """
  The Accounts context.
  """

  import Ecto.Query, warn: false
  alias DidServer.Repo

  alias DidServer.Accounts.{User, UserKey, UserToken, UserNotifier}
  alias DidServer.Log.Key

  ## Database getters

  @doc """
  Gets a user by email.

  ## Examples

      iex> get_user_by_email("foo@example.com")
      %User{}

      iex> get_user_by_email("unknown@example.com")
      nil

  """
  def get_user_by_email(email) when is_binary(email) do
    Repo.get_by(User, email: email)
  end

  @doc """
  Gets a user by email and password.

  ## Examples

      iex> get_user_by_email_and_password("foo@example.com", "correct_password")
      %User{}

      iex> get_user_by_email_and_password("foo@example.com", "invalid_password")
      nil

  """
  def get_user_by_email_and_password(email, password)
      when is_binary(email) and is_binary(password) do
    user = Repo.get_by(User, email: email)
    if User.valid_password?(user, password), do: user
  end

  def get_user_by_username(username, domain) when is_binary(username) and is_binary(domain) do
    from(user in User,
      where: user.username == ^username,
      where: user.domain == ^domain
    )
    |> Repo.one()
  end

  def get_user_by_identifier(handle) when is_binary(handle) do
    case parse_user_identifier(handle) do
      {username, domain} ->
        get_user_by_username(username, domain)

      _ ->
        nil
    end
  end

  def get_user_by_domain_handle(handle) when is_binary(handle) do
    case parse_domain_handle(handle) do
      {username, domain} -> get_user_by_username(username, domain)
      _ -> nil
    end
  end

  def get_user_by_ap_id(ap_id) when is_binary(ap_id) do
    case parse_ap_id(ap_id) do
      {username, domain} -> get_user_by_username(username, domain)
      _ -> nil
    end
  end

  def get_user_by_ap_acct(acct) when is_binary(acct) do
    case parse_ap_acct(acct) do
      {username, domain} -> get_user_by_username(username, domain)
      _ -> nil
    end
  end

  def parse_user_identifier(handle) do
    case URI.parse(handle) do
      %URI{scheme: "at"} ->
        parse_domain_handle(handle)

      %URI{scheme: "http"} = uri ->
        parse_ap_id(uri)

      %URI{scheme: "https"} = uri ->
        parse_ap_id(uri)

      %URI{scheme: "acct"} = uri ->
        parse_ap_acct(uri)

      uri ->
        with nil <- parse_domain_handle(handle),
             nil <- parse_ap_id(uri),
             nil <- parse_ap_acct(uri) do
          nil
        else
          {username, domain} -> {username, domain}
        end
    end
  end

  def parse_domain_handle(handle) when is_binary(handle) do
    parts =
      handle
      |> String.replace_leading("at://", "")
      |> String.split(".", parts: 2)

    case parts do
      [username, domain] -> ensure_valid_username_and_domain(username, domain)
      _ -> nil
    end
  end

  def parse_ap_acct(acct) when is_binary(acct) do
    URI.parse(acct) |> parse_ap_acct()
  end

  def parse_ap_acct(%URI{scheme: scheme, path: path}) when is_binary(path) do
    if is_nil(scheme) || scheme == "acct" do
      parts =
        path
        |> String.replace_leading("@", "")
        |> String.split("@", parts: 2)

      case parts do
        [username, domain] -> ensure_valid_username_and_domain(username, domain)
        _ -> nil
      end
    end
  end

  def parse_ap_acct(_), do: nil

  def parse_ap_id(ap_id) when is_binary(ap_id) do
    URI.parse(ap_id) |> parse_ap_id()
  end

  def parse_ap_id(%URI{scheme: nil, path: path}) when is_binary(path) do
    case String.split(path, "/") do
      [domain, "users", username] -> ensure_valid_username_and_domain(username, domain)
      [domain, "@" <> username] -> ensure_valid_username_and_domain(username, domain)
      _ -> nil
    end
  end

  def parse_ap_id(%URI{scheme: scheme, host: domain, path: path})
      when is_binary(domain) and is_binary(path) do
    if scheme in ["http", "https"] do
      case String.split(path, "/") do
        ["", "users", username] -> ensure_valid_username_and_domain(username, domain)
        ["", "@" <> username] -> ensure_valid_username_and_domain(username, domain)
        _ -> nil
      end
    else
      nil
    end
  end

  def parse_ap_id(_), do: nil

  def valid_username?(username), do: valid_segment?(username, false)

  def valid_domain?(domain) do
    String.split(domain, ".")
    |> Enum.reverse()
    |> Enum.with_index()
    |> Enum.all?(fn {segment, i} -> valid_segment?(segment, i == 0) end)
  end

  defp ensure_valid_username_and_domain(username, domain) do
    username = String.trim(username) |> String.downcase()
    domain = String.trim(domain) |> String.downcase()

    if (String.length(username) >= 1 && String.length(username) <= 40 &&
          String.length(domain) >= 3 && String.length(domain) <= 160) ||
         (valid_username?(username) && valid_domain?(domain)) do
      {username, domain}
    else
      IO.puts("rejected invalid '#{username}' dot '#{domain}'")
      nil
    end
  end

  # Per https://atproto.com/specs/handle
  defp valid_segment?(s, top_level)

  defp valid_segment?(s, true) do
    !String.ends_with?(s, "-") && Regex.match?(~r/^[a-z]([-a-z0-9]+)$/, s)
  end

  defp valid_segment?(s, _) do
    !String.ends_with?(s, "-") && Regex.match?(~r/^[a-z0-9]([-a-z0-9]*)$/, s)
  end

  @doc """
  Gets a single user.

  Raises `Ecto.NoResultsError` if the User does not exist.

  ## Examples

      iex> get_user!(123)
      %User{}

      iex> get_user!(456)
      ** (Ecto.NoResultsError)

  """
  def get_user!(id), do: Repo.get!(User, id)

  ## User registration

  @doc """
  Registers a user.

  ## Examples

      iex> register_user(%{field: value})
      {:ok, %User{}}

      iex> register_user(%{field: bad_value})
      {:error, %Ecto.Changeset{}}

  """
  def register_user(attrs) do
    user_changeset = User.registration_changeset(%User{}, attrs)
    multi = Ecto.Multi.new() |> Ecto.Multi.insert(:user, user_changeset)

    existing_did = Ecto.Changeset.get_change(user_changeset, :did)

    multi =
      if is_nil(existing_did) do
        # Create did
        Ecto.Multi.run(multi, :did, fn _, %{user: user} ->
          signer = Ecto.Changeset.get_change(user_changeset, :signing_key)

          signing_key =
            if is_list(signer) do
              hd(signer)
            else
              nil
            end

          recovery_key = Ecto.Changeset.get_change(user_changeset, :recovery_key, signing_key)

          params = %{
            type: "plc_operation",
            signingKey: signing_key,
            recoveryKey: recovery_key,
            handle: User.domain_handle(user),
            service: "https://pds.example.com",
            password: Ecto.Changeset.get_change(user_changeset, :password),
            signer: signer
          }

          try do
            case DidServer.Log.create_operation(params) do
              {:ok, %{operation: %{did: created_did}}} -> multi_add_link(created_did, user)
              {:error, reason} -> {:error, reason}
            end
          rescue
            e ->
              {:error, Exception.message(e)}
          end
        end)
      else
        # Verify and link did
        Ecto.Multi.run(multi, :did, fn _, %{user: user} -> multi_add_link(existing_did, user) end)
      end

    case Repo.transaction(multi) do
      {:ok, %{user: %User{} = user, did: did}} ->
        {:ok, %User{user | did: did, password: nil} |> Repo.preload(:keys)}

      {:error, :user, %Ecto.Changeset{} = changeset, _} ->
        {:error, changeset}

      {:error, :did, _, _} ->
        message =
          if is_nil(existing_did) do
            "could not create did"
          else
            "could not link to did #{existing_did}"
          end

        {:error, Ecto.Changeset.add_error(user_changeset, :did, message)}
    end
  end

  defp multi_add_link(did, user) do
    case DidServer.Log.add_also_known_as(did, user) do
      {:ok, _user} -> {:ok, did}
      _error -> {:error, "failed to link did #{did} to user #{user.email}"}
    end
  end

  @doc """
  Returns an `%Ecto.Changeset{}` for tracking user changes.

  ## Examples

      iex> change_user_registration(user)
      %Ecto.Changeset{data: %User{}}

  """
  def change_user_registration(%User{} = user, attrs \\ %{}) do
    User.registration_changeset(user, attrs, validate_email: false)
  end

  ## DIDs

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

  def list_users_by_did(did) when is_binary(did) do
    did = DidServer.Log.get_key!(did) |> Repo.preload(:users)
    did.users
  end

  def list_also_known_as_users(user) do
    list_keys_by_user(user)
    |> Enum.map(&list_users_by_did(&1))
    |> List.flatten()
  end

  @doc """
  Builds a did document.
  """
  def get_did_document(%User{} = user) do
    case list_keys_by_user(user) do
      [did] ->
        DidServer.Log.format_did_document(did)

      [] ->
        nil
    end
  end

  def get_did_document(%{username: username, domain: domain}) do
    case list_keys_by_username(username, domain) do
      [did] ->
        DidServer.Log.format_did_document(did)

      [] ->
        nil
    end
  end

  def get_public_key(user, fmt, purpose \\ "assertionMethod") do
    case get_did_document(user) do
      nil ->
        {:error, "could not locate did for user"}

      doc ->
        CryptoUtils.Keys.get_public_key(doc, fmt, purpose)
    end
  end

  ## Server statistics

  @doc """
  Usage for nodeinfo requests.
  """
  def usage() do
    %{
      users: count_users(),
      localPosts: 0
    }
  end

  def count_users() do
    now = NaiveDateTime.utc_now()
    one_month = DateTime.add(now, -(31 * 24 * 3600), :second)
    half_year = DateTime.add(now, -(184 * 24 * 3600), :second)
    total = Repo.aggregate(User, :count)

    active_month =
      from(user in User, where: user.updated_at >= ^one_month)
      |> Repo.aggregate(:count)

    active_half_year =
      from(user in User, where: user.updated_at >= ^half_year)
      |> Repo.aggregate(:count)

    %{total: total, activeMonth: active_month, activeHalfYear: active_half_year}
  end

  ## Settings

  @doc """
  Returns an `%Ecto.Changeset{}` for changing the user email.

  ## Examples

      iex> change_user_email(user)
      %Ecto.Changeset{data: %User{}}

  """
  def change_user_email(user, attrs \\ %{}) do
    User.email_changeset(user, attrs, validate_email: false)
  end

  @doc """
  Emulates that the email will change without actually changing
  it in the database.

  ## Examples

      iex> apply_user_email(user, "valid password", %{email: ...})
      {:ok, %User{}}

      iex> apply_user_email(user, "invalid password", %{email: ...})
      {:error, %Ecto.Changeset{}}

  """
  def apply_user_email(user, password, attrs) do
    user
    |> User.email_changeset(attrs)
    |> User.validate_current_password(password)
    |> Ecto.Changeset.apply_action(:update)
  end

  @doc """
  Updates the user email using the given token.

  If the token matches, the user email is updated and the token is deleted.
  The confirmed_at date is also updated to the current time.
  """
  def update_user_email(user, token) do
    context = "change:#{user.email}"

    with {:ok, query} <- UserToken.verify_change_email_token_query(token, context),
         %UserToken{sent_to: email} <- Repo.one(query),
         {:ok, _} <- Repo.transaction(user_email_multi(user, email, context)) do
      :ok
    else
      _ -> :error
    end
  end

  defp user_email_multi(user, email, context) do
    changeset =
      user
      |> User.email_changeset(%{email: email})
      |> User.confirm_changeset()

    Ecto.Multi.new()
    |> Ecto.Multi.update(:user, changeset)
    |> Ecto.Multi.delete_all(:tokens, UserToken.user_and_contexts_query(user, [context]))
  end

  @doc ~S"""
  Delivers the update email instructions to the given user.

  ## Examples

      iex> deliver_user_update_email_instructions(user, current_email, &url(~p"/users/settings/confirm_email/#{&1})")
      {:ok, %{to: ..., body: ...}}

  """
  def deliver_user_update_email_instructions(%User{} = user, current_email, update_email_url_fun)
      when is_function(update_email_url_fun, 1) do
    {encoded_token, user_token} = UserToken.build_email_token(user, "change:#{current_email}")

    Repo.insert!(user_token)
    UserNotifier.deliver_update_email_instructions(user, update_email_url_fun.(encoded_token))
  end

  @doc """
  Returns an `%Ecto.Changeset{}` for changing the user username and domain.

  ## Examples

      iex> change_user_username(user)
      %Ecto.Changeset{data: %User{}}

  """
  def change_user_username(user, attrs \\ %{}) do
    User.username_changeset(user, attrs, validate_username: true)
  end

  @doc """
  Updates the user username and domain.

  ## Examples

      iex> update_user_username(user, "valid password", %{username: ..., domain: ...})
      {:ok, %User{}}

      iex> update_user_username(user, "invalid password", %{username: ..., domain: ...})
      {:error, %Ecto.Changeset{}}

  """
  def update_user_username(user, password, attrs) do
    changeset =
      user
      |> User.username_changeset(attrs)
      |> User.validate_current_password(password)

    Ecto.Multi.new()
    |> Ecto.Multi.update(:user, changeset)
    |> Ecto.Multi.delete_all(:tokens, UserToken.user_and_contexts_query(user, :all))
    |> Repo.transaction()
    |> case do
      {:ok, %{user: user}} -> {:ok, user}
      {:error, :user, changeset, _} -> {:error, changeset}
    end
  end

  ## Session

  @doc """
  Generates a session token.
  """
  def generate_user_session_token(user) do
    {token, user_token} = UserToken.build_session_token(user)
    Repo.insert!(user_token)
    token
  end

  @doc """
  Gets the user with the given signed token.
  """
  def get_user_by_session_token(token) do
    {:ok, query} = UserToken.verify_session_token_query(token)
    Repo.one(query)
  end

  @doc """
  Deletes the signed token with the given context.
  """
  def delete_user_session_token(token) do
    Repo.delete_all(UserToken.token_and_context_query(token, "session"))
    :ok
  end

  ## Confirmation

  @doc ~S"""
  Delivers the confirmation email instructions to the given user.

  ## Examples

      iex> deliver_user_confirmation_instructions(user, &url(~p"/users/confirm/#{&1}"))
      {:ok, %{to: ..., body: ...}}

      iex> deliver_user_confirmation_instructions(confirmed_user, &url(~p"/users/confirm/#{&1}"))
      {:error, :already_confirmed}

  """
  def deliver_user_confirmation_instructions(%User{} = user, confirmation_url_fun)
      when is_function(confirmation_url_fun, 1) do
    if user.confirmed_at do
      {:error, :already_confirmed}
    else
      {encoded_token, user_token} = UserToken.build_email_token(user, "confirm")
      Repo.insert!(user_token)
      UserNotifier.deliver_confirmation_instructions(user, confirmation_url_fun.(encoded_token))
    end
  end

  @doc """
  Confirms a user by the given token.

  If the token matches, the user account is marked as confirmed
  and the token is deleted.
  """
  def confirm_user(token) do
    with {:ok, query} <- UserToken.verify_email_token_query(token, "confirm"),
         %User{} = user <- Repo.one(query),
         {:ok, %{user: user}} <- Repo.transaction(confirm_user_multi(user)) do
      {:ok, user}
    else
      _ -> :error
    end
  end

  defp confirm_user_multi(user) do
    Ecto.Multi.new()
    |> Ecto.Multi.update(:user, User.confirm_changeset(user))
    |> Ecto.Multi.delete_all(:tokens, UserToken.user_and_contexts_query(user, ["confirm"]))
  end

  ## Reset password

  @doc ~S"""
  Delivers the reset password email to the given user.

  ## Examples

      iex> deliver_user_reset_password_instructions(user, &url(~p"/users/reset_password/#{&1}"))
      {:ok, %{to: ..., body: ...}}

  """
  def deliver_user_reset_password_instructions(%User{} = user, reset_password_url_fun)
      when is_function(reset_password_url_fun, 1) do
    {encoded_token, user_token} = UserToken.build_email_token(user, "reset_password")
    Repo.insert!(user_token)
    UserNotifier.deliver_reset_password_instructions(user, reset_password_url_fun.(encoded_token))
  end

  @doc """
  Gets the user by reset password token.

  ## Examples

      iex> get_user_by_reset_password_token("validtoken")
      %User{}

      iex> get_user_by_reset_password_token("invalidtoken")
      nil

  """
  def get_user_by_reset_password_token(token) do
    with {:ok, query} <- UserToken.verify_email_token_query(token, "reset_password"),
         %User{} = user <- Repo.one(query) do
      user
    else
      _ -> nil
    end
  end
end
