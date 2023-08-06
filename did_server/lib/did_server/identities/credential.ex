defmodule DidServer.Identities.Credential do
  @moduledoc """
  Credential as returned by Wax library.

  Credentials belong to a `User`, a user-DID relationship.

  `:raw_id` is the
  `::aaguid` is the UUID.
  `:cose_key` is a map, like:

  ```elixir
  %{
    -3 => <<194, 205, 110, 162, 76, 177, 22, 116, 178, 100, 136, 7, 54, 20, 182,
      11, 99, 104, 65, 101, 110, 120, 207, 206, 78, 154, 103, 26, 249, 66, 189, 37>>,
    -2 => <<183, 43, 184, 230, 22, 139, 240, 8, 185, 116, 58, 113, 207, 57, 130,
      136, 115, 141, 110, 191, 172, 99, 137, 147, 36, 18, 206, 253, 97, 57, 238, 241>>,
    -1 => 1,
    1 => 2,
    3 => -7
  }
  ```
  """
  use Ecto.Schema

  import Ecto.Changeset

  alias DidServer.Identities

  @primary_key false
  schema "credentials" do
    field :raw_id, :string, primary_key: true
    field :cose_key, Identities.EctoCoseKey
    field :aaguid, :string
    belongs_to :user, Accounts.User, foreign_key: :user_id, type: Ecto.UUID

    timestamps(updated_at: false)
  end

  def changeset(%__MODULE__{} = credential, attrs \\ %{}) do
    credential
    |> cast(attrs, [:raw_id, :cose_key, :aaguid])
    |> validate_required([:raw_id, :cose_key])
  end
end
