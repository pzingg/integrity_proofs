defmodule DidServer.Accounts.Account do
  use Ecto.Schema
  import Ecto.Changeset

  alias DidServer.Accounts
  alias DidServer.Accounts.User
  alias __MODULE__

  @primary_key {:id, :binary_id, autogenerate: true}
  schema "accounts" do
    field :email, :string
    field :username, :string
    field :domain, :string
    field :display_name, :string
    field :description, :string
    field :avatar, :binary
    field :avatar_mime_type, :string
    field :banner, :binary
    field :banner_mime_type, :string
    # field :hashed_password, :string, redact: true
    field :confirmed_at, :naive_datetime
    # used when linking to existing DID
    field :did, :string, virtual: true
    # used when creating a new DID
    field :signer, {:array, :binary}, virtual: true
    field :signing_key, :string, virtual: true
    field :recovery_key, :string, virtual: true
    field :password, :string, virtual: true, redact: true

    has_many :users, DidServer.Accounts.User
    has_many :keys, through: [:users, :key]
    has_many :credentials, through: [:users, :credentials]

    timestamps()
  end

  @doc """
  `prefix` could be "", or "at://"
  """
  def domain_handle(%{username: username, domain: domain}, prefix \\ "") do
    "#{prefix}#{username}.#{domain}"
  end

  @doc """
  `prefix` could be "users/", or "@"
  """
  def ap_id(%{username: username, domain: domain}, prefix \\ "users/", scheme \\ "https") do
    "#{scheme}://#{domain}/#{prefix}#{username}"
  end

  @doc """
  `prefix` could be "", "@", "acct:", or "acct:@"
  """
  def ap_acct(%{username: username, domain: domain}, prefix \\ "") do
    "#{prefix}#{username}@#{domain}"
  end

  @doc """
  An account changeset for registration.

  It is important to validate the length of both email and password.
  Otherwise databases may truncate the email without warnings, which
  could lead to unpredictable or insecure behaviour. Long passwords may
  also be very expensive to hash for certain algorithms.

  ## Options

    * `:hash_password` - Hashes the password so it can be stored securely
      in the database and ensures the password field is cleared to prevent
      leaks in the logs. If password hashing is not needed and clearing the
      password field is not desired (like when using this changeset for
      validations on a LiveView form), this option can be set to `false`.
      Defaults to `true`.

    * `:validate_email` - Validates the uniqueness of the email, in case
      you don't want to validate the uniqueness of the email (like when
      using this changeset for validations on a LiveView form before
      submitting the form), this option can be set to `false`.
      Defaults to `true`.
  """
  def registration_changeset(account, attrs, opts \\ []) do
    account
    |> cast(attrs, [
      :email,
      :username,
      :domain,
      :display_name,
      :password,
      :did,
      :signer,
      :signing_key,
      :recovery_key
    ])
    |> validate_email(opts)
    |> validate_domain()
    |> validate_username(opts)
    |> validate_did_params()

    # |> validate_password(opts)
  end

  @doc """
  An account changeset for changing the email.

  It requires the email to change otherwise an error is added.
  """
  def email_changeset(account, attrs, opts \\ []) do
    account
    |> cast(attrs, [:email])
    |> validate_email(opts)
    |> case do
      %{changes: %{email: _}} = changeset -> changeset
      %{} = changeset -> add_error(changeset, :email, "did not change")
    end
  end

  @doc """
  An account changeset for changing the username.
  """
  def username_changeset(account, attrs, opts \\ []) do
    account
    |> cast(attrs, [:username, :domain])
    |> validate_domain()
    |> validate_username(opts)
  end

  @doc """
  Confirms the account by setting `confirmed_at`.
  """
  def confirm_changeset(account) do
    now = NaiveDateTime.utc_now() |> NaiveDateTime.truncate(:second)
    change(account, confirmed_at: now)
  end

  @doc """
  An account changeset for changing profile fields.
  """
  def profile_changeset(account, attrs) do
    account
    |> cast(attrs, [
      :display_name,
      :description,
      :avatar,
      :avatar_mime_type,
      :banner,
      :banner_mime_type
    ])
  end

  @doc """
  Verifies the password by trying the passwords of linked DIDs.
  """
  def valid_password_user(account, password)

  def valid_password_user(%Account{} = account, password) when byte_size(password) > 0 do
    account
    |> Accounts.list_users_by_account()
    |> Enum.find(&User.valid_password?(&1, password))
  end

  def valid_password_user(_, _) do
    Bcrypt.no_user_verify()
    nil
  end

  @doc """
  Validates the current password otherwise adds an error to the changeset.
  """
  def validate_current_password(changeset, password) do
    if valid_password_user(changeset.data, password) do
      changeset
    else
      add_error(changeset, :current_password, "is not valid")
    end
  end

  defp validate_email(changeset, opts) do
    changeset
    |> validate_required([:email])
    |> validate_format(:email, ~r/^[^\s]+@[^\s]+$/, message: "must have the @ sign and no spaces")
    |> validate_length(:email, max: 160)
    |> maybe_validate_unique_email(opts)
  end

  defp validate_domain(changeset) do
    changeset
    |> validate_required([:domain])
    |> validate_length(:domain, min: 3, max: 160)
    |> validate_change(:domain, fn :domain, domain ->
      if Accounts.valid_domain?(domain) do
        []
      else
        [:domain, "segments must contain only a-z, 0-9 and hyphens"]
      end
    end)
  end

  defp validate_username(changeset, opts) do
    changeset
    |> validate_required([:username])
    |> validate_length(:username, min: 1, max: 40)
    |> validate_change(:username, fn :username, username ->
      if Accounts.valid_username?(username) do
        []
      else
        [:username, "must contain only a-z, 0-9 and hyphens"]
      end
    end)
    |> maybe_validate_unique_username(opts)
  end

  defp validate_did_params(changeset) do
    if changed?(changeset, :did) do
      changeset
      |> validate_required([:did])
      |> validate_format(:did, ~r/^did\:([a-z]+)\:[:a-z0-9]+$/, message: "must be a valid DID")
    else
      changeset
      |> validate_required([:signer])
    end
  end

  defp maybe_validate_unique_email(changeset, opts) do
    if Keyword.get(opts, :validate_email, true) do
      changeset
      |> unsafe_validate_unique(:email, DidServer.Repo)
      |> unique_constraint(:email)
    else
      changeset
    end
  end

  defp maybe_validate_unique_username(changeset, opts) do
    if Keyword.get(opts, :validate_username, true) do
      changeset
      |> unsafe_validate_unique([:username, :domain], DidServer.Repo)
      |> unique_constraint([:username, :domain])
    else
      changeset
    end
  end
end
