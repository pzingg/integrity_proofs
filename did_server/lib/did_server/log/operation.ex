defmodule DidServer.Log.Operation do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key false
  @timestamps_opts [type: :utc_datetime_usec, updated_at: false]
  schema "operations" do
    field(:did, :string, primary_key: true)
    field(:cid, :string, primary_key: true)
    field(:operation, :string)
    field(:nullified, :boolean)

    timestamps()
  end

  def changeset(%__MODULE__{} = op, attrs) do
    op
    |> cast(attrs, [:did, :cid, :operation, :nullified])
    |> validate_required([:did, :cid, :operation])
  end
end
