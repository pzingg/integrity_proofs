defmodule DidServer.Identities.Key do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key false
  schema "keys" do
    field :did, :string, primary_key: true
    field :method, :string
    field :current_user_id, :integer, virtual: true
    # Password authentication
    field :password, :string, virtual: true, redact: true
    field :password_confirmation, :string, virtual: true, redact: true
    field :hashed_password, :string, redact: true

    has_many :users, DidServer.Accounts.User, references: :did, foreign_key: :key_id
    has_many :accounts, through: [:users, :account]

    timestamps()
  end

  @doc """
  A changeset for creating a new DID key.

  The password can be omitted for transient DIDs, not associated
  with user accounts.

  It is important to validate the length of the password.
  Otherwise databases may truncate it without warnings, which
  could lead to unpredictable or insecure behaviour. Long passwords may
  also be very expensive to hash for certain algorithms.

  ## Options

    * `:hash_password` - Hashes the password so it can be stored securely
      in the database and ensures the password field is cleared to prevent
      leaks in the logs. If password hashing is not needed and clearing the
      password field is not desired (like when using this changeset for
      validations on a LiveView form), this option can be set to `false`.
      Defaults to `true`.

  """
  def changeset(%__MODULE__{} = key, attrs, opts \\ []) do
    key
    |> cast(attrs, [:did, :method, :password, :password_confirmation])
    |> validate_required([:did])
    |> unique_constraint(:did)
    |> maybe_set_method()
    |> maybe_validate_password(opts)
  end

  @doc """
  A changeset for changing the password.

  ## Options

    * `:hash_password` - Hashes the password so it can be stored securely
      in the database and ensures the password field is cleared to prevent
      leaks in the logs. If password hashing is not needed and clearing the
      password field is not desired (like when using this changeset for
      validations on a LiveView form), this option can be set to `false`.
      Defaults to `true`.
  """
  def password_changeset(user, attrs, opts \\ []) do
    user
    |> cast(attrs, [:current_user_id, :password, :password_confirmation])
    |> validate_required(:current_user_id)
    |> validate_confirmation(:password, message: "does not match password")
    |> validate_password(opts)
  end

  @doc """
  Verifies the password.

  If there is no user or the user doesn't have a password, we call
  `Bcrypt.no_user_verify/0` to avoid timing attacks.
  """
  def valid_password?(%__MODULE__{hashed_password: hashed_password}, password)
      when is_binary(hashed_password) and byte_size(password) > 0 do
    Bcrypt.verify_pass(password, hashed_password)
  end

  def valid_password?(key, _) do
    IO.puts("Did.valid_password? without hashed_password: #{inspect(key)}")
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

  def maybe_set_method(changeset) do
    did = get_change(changeset, :did)

    if is_nil(get_change(changeset, :method)) && !is_nil(did) do
      %{method: method} = CryptoUtils.Did.parse_did!(did, method_only: true)
      put_change(changeset, :method, to_string(method))
    else
      changeset
    end
  end

  def maybe_validate_password(changeset, opts) do
    if changed?(changeset, :password) do
      validate_password(changeset, opts)
    else
      changeset
    end
  end

  def validate_password(changeset, opts) do
    changeset
    |> validate_required([:password])
    |> validate_length(:password, min: 7, max: 72)
    # Examples of additional password validation:
    # |> validate_format(:password, ~r/[a-z]/, message: "at least one lower case character")
    # |> validate_format(:password, ~r/[A-Z]/, message: "at least one upper case character")
    # |> validate_format(:password, ~r/[!?@#$%^&*_0-9]/, message: "at least one digit or punctuation character")
    |> maybe_hash_password(opts)
  end

  def maybe_hash_password(changeset, opts) do
    hash_password? = Keyword.get(opts, :hash_password, true)
    password = get_change(changeset, :password)
    IO.puts("maybe_hash_password #{password} #{hash_password?}")

    if hash_password? && password && changeset.valid? do
      changeset
      # If using Bcrypt, then further validate it is at most 72 bytes long
      |> validate_length(:password, max: 72, count: :bytes)
      # Hashing could be done with `Ecto.Changeset.prepare_changes/2`, but that
      # would keep the database transaction open longer and hurt performance.
      |> put_change(:hashed_password, Bcrypt.hash_pwd_salt(password))
      |> delete_change(:password)
    else
      changeset
    end
  end
end
