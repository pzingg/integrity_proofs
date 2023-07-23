defmodule DidServer.Accounts.UserKey do
  use Ecto.Schema

  schema "users_keys" do
    belongs_to(:user, DidServer.Accounts.User)
    belongs_to(:key, DidServer.Log.Key, type: :string, references: :did)

    timestamps()
  end

  def build_link(did, %{id: user_id}) when is_binary(did) do
    %__MODULE__{user_id: user_id, key_id: did}
  end
end
