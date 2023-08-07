defmodule DidServer.Accounts do
  @moduledoc """
  The Accounts context.
  """

  import Ecto.Query, warn: false

  require Logger

  alias DidServer.Repo
  alias DidServer.Accounts.{Account, User, UserToken, UserNotifier}

  ## Database getters

  def list_accounts_by_did(did) when is_binary(did) do
    from(account in Account,
      join: key in assoc(account, :keys),
      where: key.did == ^did,
      preload: [:users, :keys]
    )
    |> Repo.all()
  end

  def list_also_known_as_accounts(%Account{} = account) do
    DidServer.Identities.list_keys_by_account(account)
    |> Enum.map(&list_accounts_by_did(&1))
    |> List.flatten()
  end

  @doc """
  Gets a single account.

  Raises `Ecto.NoResultsError` if the Account does not exist.

  ## Examples

      iex> get_account!("404f8b73-b59d-45d4-8bcd-f20a7bfe852c")
      %Account{}

      iex> get_account!("404f8b73-beef-45d4-8bcd-f20a7bfe852c")
      ** (Ecto.NoResultsError)

  """
  def get_account!(id) do
    Repo.get!(Account, id) |> Repo.preload([:users, :keys])
  end

  @doc """
  Gets an account by email.

  ## Examples

      iex> get_account_by_email("foo@example.com")
      %Account{}

      iex> get_account_by_email("unknown@example.com")
      nil

  """
  def get_account_by_email(email) when is_binary(email) do
    from(account in Account,
      where: account.email == ^email,
      preload: [:users, :keys]
    )
    |> Repo.one()
  end

  def get_account_by_username(username, domain) when is_binary(username) and is_binary(domain) do
    from(account in Account,
      where: account.username == ^username,
      where: account.domain == ^domain,
      preload: [:users, :keys]
    )
    |> Repo.one()
  end

  def get_account_by_identifier(handle) when is_binary(handle) do
    case parse_account_identifier(handle) do
      {username, domain} ->
        get_account_by_username(username, domain)

      _ ->
        nil
    end
  end

  def get_account_by_domain_handle(handle) when is_binary(handle) do
    case parse_domain_handle(handle) do
      {username, domain} -> get_account_by_username(username, domain)
      _ -> nil
    end
  end

  def get_account_by_ap_id(ap_id) when is_binary(ap_id) do
    case parse_ap_id(ap_id) do
      {username, domain} -> get_account_by_username(username, domain)
      _ -> nil
    end
  end

  def get_account_by_ap_acct(acct) when is_binary(acct) do
    case parse_ap_acct(acct) do
      {username, domain} -> get_account_by_username(username, domain)
      _ -> nil
    end
  end

  def parse_account_identifier(handle) do
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
      Logger.error("rejected invalid '#{username}' dot '#{domain}'")
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

  ## Account registration

  @doc """
  Registers an account.

  ## Examples

      iex> register_account(%{field: value})
      {:ok, %Account{}}

      iex> register_account(%{field: bad_value})
      {:error, %Ecto.Changeset{}}

  """
  def register_account(attrs) do
    account_changeset = Account.registration_changeset(%Account{}, attrs)
    multi = Ecto.Multi.new() |> Ecto.Multi.insert(:account, account_changeset)

    existing_did = Ecto.Changeset.get_change(account_changeset, :did)

    multi =
      if is_nil(existing_did) do
        # Create did
        Ecto.Multi.run(multi, :did, fn _, %{account: account} ->
          signer = Ecto.Changeset.get_change(account_changeset, :signer)
          signing_key = Ecto.Changeset.get_change(account_changeset, :signing_key, hd(signer))
          recovery_key = Ecto.Changeset.get_change(account_changeset, :recovery_key, signing_key)

          params = %{
            type: "plc_operation",
            signingKey: signing_key,
            recoveryKey: recovery_key,
            handle: Account.domain_handle(account),
            service: "https://pds.example.com",
            password: Ecto.Changeset.get_change(account_changeset, :password),
            signer: signer
          }

          try do
            case DidServer.Log.create_operation(params) do
              {:ok, %{operation: %{did: created_did}}} -> multi_add_link(created_did, account)
              {:error, reason} -> {:error, reason}
            end
          rescue
            e ->
              {:error, Exception.message(e)}
          end
        end)
      else
        # Verify and link did
        Ecto.Multi.run(multi, :did, fn _, %{account: account} ->
          multi_add_link(existing_did, account)
        end)
      end

    case Repo.transaction(multi) do
      {:ok, %{account: %Account{} = account, did: did}} ->
        {:ok, %Account{account | did: did, password: nil} |> Repo.preload([:users, :keys])}

      {:error, :account, %Ecto.Changeset{} = changeset, _} ->
        {:error, changeset}

      {:error, :did, {:error, changeset_or_reason}, _} ->
        Logger.error("multi did error #{inspect(changeset_or_reason)}")

        message =
          if is_nil(existing_did) do
            "could not create DID"
          else
            "could not link to DID #{existing_did}"
          end

        {:error, Ecto.Changeset.add_error(account_changeset, :did, message)}
    end
  end

  defp multi_add_link(did, account) do
    case DidServer.Identities.add_also_known_as(did, account) do
      {:ok, _account} -> {:ok, did}
      _error -> {:error, "failed to link did #{did} to account #{account.email}"}
    end
  end

  @doc """
  Returns an `%Ecto.Changeset{}` for tracking account changes.

  ## Examples

      iex> change_account_registration(account)
      %Ecto.Changeset{data: %Account{}}

  """
  def change_account_registration(%Account{} = account, attrs \\ %{}) do
    Account.registration_changeset(account, attrs, validate_email: false)
  end

  ## Settings

  @doc """
  Returns an `%Ecto.Changeset{}` for changing the account email.

  ## Examples

      iex> change_account_email(account)
      %Ecto.Changeset{data: %Account{}}

  """
  def change_account_email(account, attrs \\ %{}) do
    Account.email_changeset(account, attrs, validate_email: false)
  end

  @doc """
  Emulates that the email will change without actually changing
  it in the database.

  ## Examples

      iex> apply_account_email(account, "valid password", %{email: ...})
      {:ok, %Account{}}

      iex> apply_account_email(account, "invalid password", %{email: ...})
      {:error, %Ecto.Changeset{}}

  """
  def apply_account_email(account, password, attrs) do
    account
    |> Account.email_changeset(attrs)
    |> Account.validate_current_password(password)
    |> Ecto.Changeset.apply_action(:update)
  end

  @doc """
  Returns an `%Ecto.Changeset{}` for changing the account username and domain.

  ## Examples

      iex> change_account_username(account)
      %Ecto.Changeset{data: %Account{}}

  """
  def change_account_username(account, attrs \\ %{}) do
    Account.username_changeset(account, attrs, validate_username: true)
  end

  @doc """
  Updates the account username and domain.

  ## Examples

      iex> update_account_username(account, "valid password", %{username: ..., domain: ...})
      {:ok, %Account{}}

      iex> update_account_username(account, "invalid password", %{username: ..., domain: ...})
      {:error, %Ecto.Changeset{}}

  """
  def update_account_username(account, password, attrs) do
    changeset =
      account
      |> Account.username_changeset(attrs)
      |> Account.validate_current_password(password)

    Ecto.Multi.new()
    |> Ecto.Multi.update(:account, changeset)
    |> Ecto.Multi.delete_all(:tokens, UserToken.user_and_contexts_query(account, :all))
    |> Repo.transaction()
    |> case do
      {:ok, %{account: account}} -> {:ok, account}
      {:error, :account, changeset, _} -> {:error, changeset}
    end
  end

  ## Users

  @doc """
  Returns the list of all users.

  ## Examples

      iex> list_users()
      [%User{}, ...]

  """
  def list_users do
    from(user in User, preload: [:account, :key])
    |> Repo.all()
  end

  @doc """
  Returns the list of users associated with an account.
  Each `User` for the account has its own password-protected DID.

  ## Examples

      iex> list_users_by_account(%Account{})
      [%User{}, ...]

  """
  def list_users_by_account(%Account{id: account_id}) do
    from(user in User,
      join: account in assoc(user, :account),
      where: account.id == ^account_id,
      preload: [:account, :key]
    )
    |> Repo.all()
  end

  @doc """
  Gets a single user.

  ## Examples

      iex> get_user("404f8b73-b59d-45d4-8bcd-f20a7bfe852c")
      %User{}

      iex> get_user("404f8b73-beef-45d4-8bcd-f20a7bfe852c")
      nil

  """
  def get_user(user_id) when is_binary(user_id) do
    from(user in User,
      where: user.id == ^user_id,
      preload: [:account, :key]
    )
    |> Repo.one()
  end

  @doc """
  If the account has exactly one password-protected DID,
  returns the associated `User`.

  ## Examples

      iex> get_user_by_account(%Account{})
      %User{}

  """
  def get_user_by_account(%Account{} = account) do
    case list_users_by_account(account) do
      [] -> nil
      [user] -> user
      users -> raise RuntimeError, "#{Enum.count(users)} DIDs for account"
    end
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
    get_account_by_email(email)
    |> Account.valid_password_user(password)
    |> Repo.preload([:account, :key])
  end

  @doc """
  Gets a user by username, domain and password.

  ## Examples

      iex> get_user_by_username_and_password("foo", "example.com", "correct_password")
      %User{}

      iex> get_user_by_username_and_password("foo", "example.com", "invalid_password")
      nil

  """
  def get_user_by_username_and_password(username, domain, password)
      when is_binary(username) and is_binary(domain) and is_binary(password) do
    get_account_by_username(username, domain)
    |> Account.valid_password_user(password)
    |> Repo.preload([:account, :key])
  end

  @doc """
  Updates the account email using the given token.

  If the token matches, the account email is updated and the token is deleted.
  The confirmed_at date is also updated to the current time.
  """
  def update_user_email(%User{account: account} = user, token) do
    context = "change:#{account.email}"

    with {:ok, query} <- UserToken.verify_change_email_token_query(token, context),
         %UserToken{sent_to: email} <- Repo.one(query),
         {:ok, _} <- Repo.transaction(user_email_multi(user, email, context)) do
      :ok
    else
      _ -> :error
    end
  end

  defp user_email_multi(%User{account: account} = user, email, context) do
    account_changeset =
      account
      |> Account.email_changeset(%{email: email})
      |> Account.confirm_changeset()

    Ecto.Multi.new()
    |> Ecto.Multi.update(:account, account_changeset)
    |> Ecto.Multi.delete_all(:tokens, UserToken.user_and_contexts_query(user, [context]))
  end

  @doc ~S"""
  Delivers the update email instructions to the given account.

  ## Examples

      iex> deliver_user_update_email_instructions(user, current_email, &url(~p"/users/settings/confirm_email/#{&1})")
      {:ok, %{to: ..., body: ...}}

  """
  def deliver_user_update_email_instructions(
        %User{account: account} = user,
        current_email,
        update_email_url_fun
      )
      when is_function(update_email_url_fun, 1) do
    {encoded_token, user_token} = UserToken.build_email_token(user, "change:#{current_email}")

    Repo.insert!(user_token)
    UserNotifier.deliver_update_email_instructions(account, update_email_url_fun.(encoded_token))
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
  Gets the `User` with the given signed token.
  """
  def get_user_by_session_token(token) do
    {:ok, query} = UserToken.verify_session_token_query(token)
    Repo.one(query) |> Repo.preload([:account, :key])
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
  Delivers the confirmation email instructions to the given account.

  ## Examples

      iex> deliver_user_confirmation_instructions(user, &url(~p"/users/confirm/#{&1}"))
      {:ok, %{to: ..., body: ...}}

      iex> deliver_user_confirmation_instructions(confirmed_user, &url(~p"/users/confirm/#{&1}"))
      {:error, :already_confirmed}

  """
  def deliver_user_confirmation_instructions(%User{account: account} = user, confirmation_url_fun)
      when is_function(confirmation_url_fun, 1) do
    if account.confirmed_at do
      {:error, :already_confirmed}
    else
      {encoded_token, user_token} = UserToken.build_email_token(user, "confirm")
      Repo.insert!(user_token)

      UserNotifier.deliver_confirmation_instructions(
        account,
        confirmation_url_fun.(encoded_token)
      )
    end
  end

  @doc """
  Confirms an account by the given token.

  If the token matches, the account is marked as confirmed
  and the token is deleted.
  """
  def confirm_user(token) do
    with {:ok, query} <- UserToken.verify_email_token_query(token, "confirm"),
         %User{} = user <- Repo.one(query) |> Repo.preload(:account),
         {:ok, %{account: account}} <- Repo.transaction(confirm_user_multi(user)) do
      {:ok, account |> Repo.preload([:users, :keys])}
    else
      _ -> :error
    end
  end

  defp confirm_user_multi(%User{account: account} = user) do
    Ecto.Multi.new()
    |> Ecto.Multi.update(:account, Account.confirm_changeset(account))
    |> Ecto.Multi.delete_all(:tokens, UserToken.user_and_contexts_query(user, ["confirm"]))
  end

  ## Reset password

  @doc ~S"""
  Delivers the reset password email to the given account.

  ## Examples

      iex> deliver_user_reset_password_instructions(user, &url(~p"/users/reset_password/#{&1}"))
      {:ok, %{to: ..., body: ...}}

  """
  def deliver_user_reset_password_instructions(
        %User{account: account} = user,
        reset_password_url_fun
      )
      when is_function(reset_password_url_fun, 1) do
    {encoded_token, user_token} = UserToken.build_email_token(user, "reset_password")
    Repo.insert!(user_token)

    UserNotifier.deliver_reset_password_instructions(
      account,
      reset_password_url_fun.(encoded_token)
    )
  end

  @doc """
  Gets the account by reset password token.

  ## Examples

      iex> get_user_by_reset_password_token("validtoken")
      %Account{}

      iex> get_user_by_reset_password_token("invalidtoken")
      nil

  """
  def get_user_by_reset_password_token(token) do
    with {:ok, query} <- UserToken.verify_email_token_query(token, "reset_password"),
         %User{} = user <- Repo.one(query) |> Repo.preload([:account, :key]) do
      user
    else
      _ -> nil
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
    total = Repo.aggregate(Account, :count)

    active_month =
      from(account in Account, where: account.updated_at >= ^one_month)
      |> Repo.aggregate(:count)

    active_half_year =
      from(account in Account, where: account.updated_at >= ^half_year)
      |> Repo.aggregate(:count)

    %{total: total, activeMonth: active_month, activeHalfYear: active_half_year}
  end
end
