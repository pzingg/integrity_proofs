defmodule DidServer.Log.Did do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key false
  schema "dids" do
    field(:did, :string, primary_key: true)
  end

  def changeset(%__MODULE__{} = did, attrs) do
    did
    |> cast(attrs, [:did])
    |> validate_required([:did])
    |> unique_constraint(:did, name: "dids_pkey")
  end
end
