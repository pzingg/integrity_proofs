defmodule DidServer.Accounts.User do
  use Ecto.Schema
  import Ecto.Changeset

  schema "users" do
    field(:email, :string)
    field(:username, :string)
    field(:domain, :string)
    # field :password, :string, virtual: true, redact: true
    # field :hashed_password, :string, redact: true
    field(:confirmed_at, :naive_datetime)

    has_many(:user_dids, DidServer.Accounts.UserDid)
    has_many(:dids, through: [:user_dids, :did])

    timestamps()
  end

  def ap_id(%__MODULE__{username: username, domain: domain}, scheme \\ "https") do
    "#{scheme}://#{domain}/user/#{username}"
  end

  def domain_handle(%__MODULE__{username: username, domain: domain}) do
    "#{username}/#{domain}"
  end

  @doc """
  A user changeset for registration.

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
  def registration_changeset(user, attrs, opts \\ []) do
    user
    # :password
    |> cast(attrs, [:email, :username, :domain])
    |> validate_email(opts)
    |> validate_domain()
    |> validate_username(opts)

    # |> validate_password(opts)
  end

  @doc """
  A user changeset for changing the email.

  It requires the email to change otherwise an error is added.
  """
  def email_changeset(user, attrs, opts \\ []) do
    user
    |> cast(attrs, [:email])
    |> validate_email(opts)
    |> case do
      %{changes: %{email: _}} = changeset -> changeset
      %{} = changeset -> add_error(changeset, :email, "did not change")
    end
  end

  @doc """
  A user changeset for changing the username.
  """
  def username_changeset(user, attrs, opts \\ []) do
    user
    |> cast(attrs, [:username, :domain])
    |> validate_domain()
    |> validate_username(opts)
  end

  @doc """
  Confirms the account by setting `confirmed_at`.
  """
  def confirm_changeset(user) do
    now = NaiveDateTime.utc_now() |> NaiveDateTime.truncate(:second)
    change(user, confirmed_at: now)
  end

  @doc """
  Verifies the password.

  If there is no user or the user doesn't have a password, we call
  `Bcrypt.no_user_verify/0` to avoid timing attacks.
  """
  def valid_password?(%__MODULE__{} = user, password) when byte_size(password) > 0 do
    did_that_validated =
      user
      |> DidServer.Accounts.list_dids_by_user()
      |> Enum.find(fn did -> DidServer.Log.Did.valid_password?(did, password) end)

    !is_nil(did_that_validated)
  end

  def valid_password?(_, _) do
    Bcrypt.no_user_verify()
    false
  end

  @doc """
  Validates the current password otherwise adds an error to the changeset.
  """
  def validate_current_password(changeset, password) do
    if valid_password?(changeset.data, password) do
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
    |> validate_format(:domain, ~r/^[^\s]+\.[^\s]+$/, message: "must have a . and no spaces")
    |> validate_length(:domain, max: 160)
  end

  defp validate_username(changeset, opts) do
    changeset
    |> validate_required([:username])
    |> validate_format(:username, ~r/^[a-z][-_.a-z0-9]+$/,
      message: "must start with a-z, be only a-z, 0-9, . -, or _"
    )
    |> validate_length(:username, min: 3, max: 40)
    |> maybe_validate_unique_username(opts)
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
