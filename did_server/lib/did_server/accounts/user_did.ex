defmodule DidServer.Accounts.UserDid do
  use Ecto.Schema
  alias DidServer.Accounts.UserDid

  schema "users_dids" do
    field :did, :string
    field :username, :string
    field :domain, :string

    timestamps()
  end

  def build_link(did, username, domain) do
    %UserDid{did: did, username: username, domain: domain}
  end
end
