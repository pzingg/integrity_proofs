defmodule DidServer.Accounts.User do
  use Ecto.Schema

  alias DidServer.Accounts.Account
  alias __MODULE__

  @primary_key {:id, :binary_id, autogenerate: true}
  schema "users" do
    belongs_to :account, Account, type: Ecto.UUID
    belongs_to :key, DidServer.Identities.Key, type: :string, references: :did
    has_many :credentials, DidServer.Identities.Credential, foreign_key: :user_id

    timestamps()
  end

  def build_link(did, %Account{id: account_id}) when is_binary(did) do
    %User{account_id: account_id, key_id: did}
  end
end
