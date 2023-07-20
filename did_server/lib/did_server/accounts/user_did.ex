defmodule DidServer.Accounts.UserDid do
  use Ecto.Schema

  schema "users_dids" do
    belongs_to(:user, DidServer.Accounts.User)
    belongs_to(:did, DidServer.Log.Did, type: :string, references: :did, foreign_key: :did_key)

    timestamps()
  end

  def build_link(did, %{id: user_id}) do
    %__MODULE__{user_id: user_id, did_key: did}
  end
end
