defmodule DidServer.Accounts.User do
  use Ecto.Schema

  alias DidServer.Accounts.Account
  alias DidServer.Identities.{Credential, Key}
  alias __MODULE__

  @primary_key {:id, :binary_id, autogenerate: true}
  schema "users" do
    belongs_to :account, Account, type: Ecto.UUID
    belongs_to :key, Key, type: :string, references: :did
    has_many :credentials, Credential, foreign_key: :user_id

    timestamps()
  end

  def build_user(did, %Account{id: account_id}) when is_binary(did) do
    %User{account_id: account_id, key_id: did}
  end

  @doc """
  Verifies the password by trying the password of the linked DID.
  """
  def valid_password?(%User{key: key} = user, password) when byte_size(password) > 0 do
    Key.valid_password?(key, password)
  end

  def valid_password?(_, _, _) do
    Bcrypt.no_user_verify()
    false
  end
end
