defmodule DidServer.Identities.UserKey do
  use Ecto.Schema

  @primary_key {:id, :binary_id, autogenerate: true}
  schema "users_keys" do
    belongs_to :user, DidServer.Accounts.User, type: Ecto.UUID
    belongs_to :key, DidServer.Identities.Key, type: :string, references: :did
    has_many :credentials, DidServer.Identities.Credential, foreign_key: :user_id

    timestamps()
  end

  def build_link(did, %{id: user_id}) when is_binary(did) do
    %__MODULE__{user_id: user_id, key_id: did}
  end
end
